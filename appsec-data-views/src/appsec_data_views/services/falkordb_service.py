"""FalkorDB service for graph database operations.

This module provides a service layer for interacting with FalkorDB,
including connection management and common query operations.

OPTIMIZATION NOTES:
- FalkorDB enforces a hard limit (typically 10,000) on nodes/entities matched
  before WHERE clause filtering. This means queries like MATCH (a)-[*1..]->(b)
  can hit this limit even with WHERE filters.
- Cyclic dependencies in the graph can cause query timeouts with unbounded
  traversals.
- To address both issues, transitive queries use an iterative breadth-first
  approach that:
  1. Queries one depth level at a time
  2. Tracks visited nodes to prevent infinite cycles
  3. Uses reasonable default depth limits
"""

import re
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from falkordb import FalkorDB, Graph

from appsec_data_views.config import FalkorDBConfig, get_config

# Default maximum depth for transitive queries to prevent runaway traversals
# Set high enough to capture deep dependency chains (some graphs have 20+ levels)
DEFAULT_MAX_DEPTH = 50

# Maximum nodes to collect in a single transitive query to prevent memory issues
MAX_TRANSITIVE_NODES = 50000

# SemVer regex pattern - matches versions like 1.0.0, 1.2.3-alpha, 1.2.3+build, etc.
# Optionally allows 'v' prefix (e.g., v1.0.0)
# Also allows 2-part versions like 1.0 (common in some ecosystems)
# Also allows Maven-style suffixes like .RELEASE, .Final, .GA, .SNAPSHOT
SEMVER_PATTERN = re.compile(
    r"^v?"  # Optional 'v' prefix
    r"(0|[1-9]\d*)"  # Major version
    r"\.(0|[1-9]\d*)"  # Minor version
    r"(?:\.(0|[1-9]\d*))?"  # Optional patch version
    r"(?:-("  # Optional pre-release
    r"(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*"
    r"))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"  # Optional build metadata
    r"(?:[.\-](?:RELEASE|FINAL|GA|SNAPSHOT))?"  # Optional Maven suffix (including SNAPSHOT)
    r"$",
    re.IGNORECASE,
)


class FalkorDBService:
    """Service for FalkorDB graph database operations."""

    def __init__(self, config: FalkorDBConfig | None = None):
        """Initialize the FalkorDB service.

        Args:
            config: FalkorDB configuration. If None, loads from environment.
        """
        self.config = config or get_config().falkordb
        self._db: FalkorDB | None = None

    @property
    def db(self) -> FalkorDB:
        """Get the FalkorDB connection (lazy initialization)."""
        if self._db is None:
            connection_kwargs: dict[str, Any] = {
                "host": self.config.host,
                "port": self.config.port,
                "socket_timeout": self.config.socket_timeout,
                "socket_connect_timeout": self.config.socket_connect_timeout,
            }
            if self.config.password:
                connection_kwargs["password"] = self.config.password
            self._db = FalkorDB(**connection_kwargs)
        return self._db

    @property
    def graph(self) -> Graph:
        """Get the graph instance."""
        return self.db.select_graph(self.config.graph_name)

    @property
    def internal_label(self) -> str:
        """Get the label used for internal nodes (e.g., INTERNAL)."""
        return self.config.internal_label

    def get_node_label(self, internal_only: bool = False) -> str:
        """Get the node label filter string for queries.

        Args:
            internal_only: If True, returns 'Version:{internal_label}', else 'Version'

        Returns:
            Node label string for use in Cypher queries
        """
        if internal_only:
            return f"Version:{self.internal_label}"
        return "Version"

    @contextmanager
    def get_graph(self) -> Generator[Graph, None, None]:
        """Context manager for graph operations."""
        yield self.graph

    def execute_query(self, query: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Execute a read-only query and return results.

        Args:
            query: Cypher query string
            params: Query parameters

        Returns:
            List of result rows
        """
        result = self.graph.ro_query(query, params or {})
        return result.result_set

    def find_version(self, project_name: str, version_name: str) -> dict[str, Any] | None:
        """Find a specific version node.

        Args:
            project_name: The project name
            version_name: The version string

        Returns:
            Dict with 'properties' and 'labels' keys, or None if not found
        """
        query = """
            MATCH (v:Version {project_name: $project_name, name: $version_name})
            RETURN v
        """
        result = self.execute_query(
            query, {"project_name": project_name, "version_name": version_name}
        )
        if result:
            node = result[0][0]
            return {
                "properties": node.properties,
                "labels": list(node.labels),
            }
        return None

    def get_all_projects(
        self, limit: int = 1000, internal_only: bool = False
    ) -> list[dict[str, Any]]:
        """Get all projects with their versions.

        Args:
            limit: Maximum number of results
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of project/version dicts
        """
        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{node_label})
            RETURN DISTINCT v.project_name as project_name, v.name as version
            ORDER BY v.project_name, v.name
            LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})
        return [{"project_name": row[0], "version": row[1]} for row in result]

    def get_all_applications(
        self,
        limit: int = 1000,
        internal_only: bool = False,
        latest_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get all applications with their versions.

        Applications are nodes with the 'Application' label.

        Args:
            limit: Maximum number of results
            internal_only: If True, only include internal-labeled nodes
            latest_only: If True, only return the latest version per application

        Returns:
            List of application dicts with project_name, version, and metadata
        """
        # Build label filter
        if internal_only:
            label_filter = f"Application:{self.internal_label}"
        else:
            label_filter = "Application"

        query = f"""
            MATCH (app:{label_filter})
            RETURN DISTINCT app.project_name as project_name,
                   app.name as version,
                   app.scan_id as scan_id,
                   app.app_id as app_id,
                   app.public_id as public_id,
                   app.repo_url as repo_url,
                   labels(app) as labels
            ORDER BY app.project_name, app.name
            LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})

        applications = []
        for row in result:
            applications.append({
                "project_name": row[0],
                "version": row[1],
                "scan_id": row[2],
                "app_id": row[3],
                "public_id": row[4],
                "repo_url": row[5],
                "labels": row[6] if row[6] else [],
                "is_internal": self.internal_label in (row[6] or []),
            })

        if latest_only:
            # Group by project_name and get the latest version for each
            project_versions: dict[str, list[dict[str, Any]]] = {}
            for app in applications:
                project_name = app["project_name"]
                if project_name not in project_versions:
                    project_versions[project_name] = []
                project_versions[project_name].append(app)

            # For each project, try to get the latest semver version
            latest_apps = []
            for project_name, versions in project_versions.items():
                # Try to find the latest semver version
                latest_version = self.get_latest_semver_version(
                    project_name, internal_only
                )

                if latest_version:
                    # Find the app with the latest version
                    for app in versions:
                        if app["version"] == latest_version:
                            latest_apps.append(app)
                            break
                else:
                    # Not semver compliant, use the last version alphabetically
                    # (already sorted by version in the query)
                    if versions:
                        latest_apps.append(versions[-1])

            return sorted(latest_apps, key=lambda x: x["project_name"])

        return applications

    def get_direct_dependants(
        self,
        project_name: str,
        version_name: str | None = None,
        internal_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get direct dependants of a project version.

        Args:
            project_name: The project name
            version_name: Optional specific version
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of dependant project/version dicts
        """
        dep_label = self.get_node_label(internal_only)
        target_label = self.get_node_label(internal_only)

        if version_name:
            query = f"""
                MATCH (dep:{dep_label})-[r]->(v:{target_label} {{project_name: $project_name, name: $version_name}})
                RETURN DISTINCT dep.project_name as dependant_project,
                       dep.name as dependant_version,
                       v.project_name as target_project,
                       v.name as target_version
                ORDER BY dep.project_name, dep.name
            """
            params = {"project_name": project_name, "version_name": version_name}
        else:
            query = f"""
                MATCH (dep:{dep_label})-[r]->(v:{target_label} {{project_name: $project_name}})
                RETURN DISTINCT dep.project_name as dependant_project,
                       dep.name as dependant_version,
                       v.project_name as target_project,
                       v.name as target_version
                ORDER BY dep.project_name, dep.name
            """
            params = {"project_name": project_name}

        result = self.execute_query(query, params)
        return [
            {
                "dependant_project": row[0],
                "dependant_version": row[1],
                "target_project": row[2],
                "target_version": row[3],
            }
            for row in result
        ]

    def get_all_versions_of_project(
        self, project_name: str, internal_only: bool = False
    ) -> list[str]:
        """Get all versions of a project.

        Args:
            project_name: The project name
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of version strings
        """
        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{node_label} {{project_name: $project_name}})
            RETURN v.name as version
            ORDER BY v.name
        """
        result = self.execute_query(query, {"project_name": project_name})
        return [row[0] for row in result]

    def is_project_semver_compliant(
        self, project_name: str, internal_only: bool = False
    ) -> tuple[bool, list[str]]:
        """Check if all versions of a project follow SemVer naming convention.

        Args:
            project_name: The project name to check
            internal_only: If True, only include internal-labeled nodes

        Returns:
            Tuple of (is_compliant, non_compliant_versions)
            - is_compliant: True if all versions are SemVer compliant
            - non_compliant_versions: List of versions that don't follow SemVer
        """
        versions = self.get_all_versions_of_project(project_name, internal_only)
        non_compliant = [v for v in versions if v and not SEMVER_PATTERN.match(v)]
        return (len(non_compliant) == 0, non_compliant)

    def get_latest_semver_version(
        self, project_name: str, internal_only: bool = False
    ) -> str | None:
        """Get the latest (highest) SemVer version of a project.

        Only returns a version if all versions are SemVer compliant.
        Compares versions semantically (1.10.0 > 1.9.0).

        Args:
            project_name: The project name
            internal_only: If True, only include internal-labeled nodes

        Returns:
            The latest version string, or None if:
            - No versions exist
            - Any version is not SemVer compliant
        """
        is_compliant, _ = self.is_project_semver_compliant(project_name, internal_only)
        if not is_compliant:
            return None

        versions = self.get_all_versions_of_project(project_name, internal_only)
        if not versions:
            return None

        # Parse and sort versions semantically
        def parse_semver(version: str) -> tuple[int, int, int, str]:
            """Parse a SemVer string into comparable tuple."""
            # Remove 'v' prefix if present
            v = version.lstrip("vV")

            # Remove Maven suffixes for comparison
            v = re.sub(r"[.\-](?:RELEASE|FINAL|GA|SNAPSHOT)$", "", v, flags=re.IGNORECASE)

            # Split on '-' to separate pre-release
            parts = v.split("-", 1)
            version_part = parts[0]
            prerelease = parts[1] if len(parts) > 1 else ""

            # Split on '+' to remove build metadata
            version_part = version_part.split("+")[0]

            # Parse major.minor.patch
            version_nums = version_part.split(".")
            major = int(version_nums[0]) if len(version_nums) > 0 else 0
            minor = int(version_nums[1]) if len(version_nums) > 1 else 0
            patch = int(version_nums[2]) if len(version_nums) > 2 else 0

            # Pre-release versions are lower than release versions
            # Empty prerelease string sorts after any prerelease
            prerelease_sort = prerelease if prerelease else "~"  # '~' sorts after letters

            return (major, minor, patch, prerelease_sort)

        try:
            sorted_versions = sorted(versions, key=parse_semver, reverse=True)
            return sorted_versions[0] if sorted_versions else None
        except (ValueError, IndexError):
            # If parsing fails, return None
            return None

    def get_transitive_dependencies_for_report(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get transitive dependencies in a flat list format suitable for reports.

        Uses the same BFS traversal as get_transitive_dependencies but returns
        a flat list with depth information instead of nodes/edges.

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse (defaults to DEFAULT_MAX_DEPTH)
            internal_only: Only include internal-labeled nodes

        Returns:
            List of dicts with dependency_project, dependency_version, depth
        """
        # Use the existing transitive dependencies method
        nodes, edges = self.get_transitive_dependencies(
            project_name, version_name, max_depth, internal_only
        )

        if not nodes:
            return []

        # Build adjacency list from edges for depth calculation
        adjacency: dict[str, list[str]] = {}
        for edge in edges:
            src = edge["source"]
            tgt = edge["target"]
            if src not in adjacency:
                adjacency[src] = []
            adjacency[src].append(tgt)

        # BFS to calculate depth from root
        root_id = f"{project_name}:{version_name}"
        depths: dict[str, int] = {root_id: 0}
        queue = [root_id]

        while queue:
            current = queue.pop(0)
            current_depth = depths[current]
            for neighbor in adjacency.get(current, []):
                if neighbor not in depths:
                    depths[neighbor] = current_depth + 1
                    queue.append(neighbor)

        # Convert to flat list, excluding the root node
        dependencies = []
        for node in nodes:
            node_id = node["id"]
            if node_id == root_id:
                continue  # Skip the source node itself

            depth = depths.get(node_id, 1)
            dependencies.append(
                {
                    "dependency_project": node["project_name"],
                    "dependency_version": node["version"],
                    "depth": depth,
                    "is_internal": self.internal_label in node.get("labels", []),
                }
            )

        # Sort by depth, then project, then version
        dependencies.sort(
            key=lambda x: (x["depth"], x["dependency_project"], x["dependency_version"])
        )
        return dependencies

    def _get_node_id(self, node: Any) -> str:
        """Generate a unique string ID for a node."""
        project_name = node.properties.get("project_name", "unknown")
        version = node.properties.get("name", "unknown")
        return f"{project_name}:{version}"

    def _node_to_dict(self, node: Any) -> dict[str, Any]:
        """Convert a FalkorDB node to a dictionary."""
        project_name = node.properties.get("project_name", "unknown")
        version = node.properties.get("name", "unknown")
        return {
            "id": f"{project_name}:{version}",
            "project_name": project_name,
            "version": version,
            "labels": list(node.labels),
            "properties": node.properties,
        }

    def _parse_node_id(self, node_id: str) -> tuple[str, str] | None:
        """Parse a node ID string into (project_name, version) tuple.

        Args:
            node_id: String in format "project_name:version"

        Returns:
            Tuple of (project_name, version) or None if invalid format
        """
        parts = node_id.rsplit(":", 1)
        if len(parts) == 2:
            return (parts[0], parts[1])
        return None

    def _build_node_conditions(
        self,
        node_ids: list[str],
        params: dict[str, Any],
        node_alias: str,
        param_prefix: str,
    ) -> list[str]:
        """Build WHERE clause conditions for a list of node IDs.

        Args:
            node_ids: List of node ID strings (project:version format)
            params: Dictionary to add query parameters to (modified in place)
            node_alias: The node alias in the query (e.g., 'src', 'tgt')
            param_prefix: Prefix for parameter names to avoid collisions

        Returns:
            List of condition strings for use in WHERE clause
        """
        conditions = []
        for i, node_id in enumerate(node_ids):
            parsed = self._parse_node_id(node_id)
            if parsed:
                proj, ver = parsed
                params[f"{param_prefix}_proj_{i}"] = proj
                params[f"{param_prefix}_ver_{i}"] = ver
                conditions.append(
                    f"({node_alias}.project_name = ${param_prefix}_proj_{i} "
                    f"AND {node_alias}.name = ${param_prefix}_ver_{i})"
                )
        return conditions

    def _add_edge_if_new(
        self,
        src_id: str,
        tgt_id: str,
        rel_type: str,
        edges: list[dict[str, Any]],
        seen_edges: set[tuple[str, str]],
    ) -> bool:
        """Add an edge to the edges list if not already seen.

        Args:
            src_id: Source node ID
            tgt_id: Target node ID
            rel_type: Relationship type
            edges: List to append edge to (modified in place)
            seen_edges: Set of seen edge tuples (modified in place)

        Returns:
            True if edge was added, False if it was already seen
        """
        edge_key = (src_id, tgt_id)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append(
                {
                    "source": src_id,
                    "target": tgt_id,
                    "type": rel_type,
                }
            )
            return True
        return False

    def _build_dependants_query(
        self, target_conditions: list[str], filter_mode: str, internal_only: bool = False
    ) -> str:
        """Build the Cypher query for finding dependants.

        Args:
            target_conditions: WHERE conditions for target nodes
            filter_mode: One of "single", "any", or "none" for scan_id filtering
            internal_only: If True, only include internal-labeled nodes

        Returns:
            Cypher query string
        """
        where_clause = " OR ".join(target_conditions)
        node_label = self.get_node_label(internal_only)

        if filter_mode == "single":
            # Application node: filter by single scan_id
            return f"""
                MATCH (src:{node_label})-[r]->(tgt:{node_label})
                WHERE ({where_clause})
                AND $scan_id IN src.scan_ids
                RETURN src, tgt, type(r) as rel_type
                LIMIT $query_limit
            """
        elif filter_mode == "any":
            # Library node: filter by ANY of the scan_ids
            # Include dependants that share at least one scan_id with root
            return f"""
                MATCH (src:{node_label})-[r]->(tgt:{node_label})
                WHERE ({where_clause})
                AND ANY(sid IN $scan_ids WHERE sid IN src.scan_ids)
                RETURN src, tgt, type(r) as rel_type
                LIMIT $query_limit
            """
        else:
            # No filtering - include all dependants
            return f"""
                MATCH (src:{node_label})-[r]->(tgt:{node_label})
                WHERE {where_clause}
                RETURN src, tgt, type(r) as rel_type
                LIMIT $query_limit
            """

    def get_transitive_dependencies(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Get transitive dependencies as nodes and edges.

        Uses iterative breadth-first traversal to avoid FalkorDB's node limit
        and handle cyclic dependencies gracefully.

        Filtering behavior based on root node type:
        - Application nodes (with scan_id property): Filter to include only nodes
          that have this scan_id in their scan_ids array.
        - Library nodes (with scan_ids but no scan_id): Filter to include only
          nodes that share at least one scan_id with the root (i.e., they appeared
          in at least one of the same application scans). This shows all dependencies
          that are relevant to this library version across all the apps that use it.

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse (defaults to DEFAULT_MAX_DEPTH)
            internal_only: Only include internal-labeled nodes

        Returns:
            Tuple of (nodes list, edges list)
        """
        effective_max_depth = max_depth if max_depth is not None else DEFAULT_MAX_DEPTH
        node_label = self.get_node_label(internal_only)

        # Track visited nodes to handle cycles
        visited_ids: set[str] = set()
        nodes_dict: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str]] = set()

        # Start with the root node
        root_id = f"{project_name}:{version_name}"
        current_frontier: set[str] = {root_id}
        visited_ids.add(root_id)

        # Fetch root node data
        root = self.find_version(project_name, version_name)
        root_properties = root["properties"] if root else {}
        root_labels = root["labels"] if root else []

        # Determine filtering strategy based on node type:
        # - Application nodes have a single scan_id property
        # - Library nodes have scan_ids list (from all app scans that include them)
        scan_id = root_properties.get("scan_id") if root else None
        scan_ids = root_properties.get("scan_ids", []) if root else []

        # Filter mode:
        # - "single": Application node - filter by single scan_id
        # - "any": Library node - filter by ANY of the scan_ids (at least one in common)
        # - "none": No scan info available - no filtering
        if scan_id is not None:
            filter_mode = "single"
        elif scan_ids:
            filter_mode = "any"
        else:
            filter_mode = "none"

        if root:
            nodes_dict[root_id] = {
                "id": root_id,
                "project_name": project_name,
                "version": version_name,
                "labels": root_labels,
                "properties": root_properties,
            }

        # Iterative BFS - query one depth level at a time
        for _ in range(effective_max_depth):
            if not current_frontier:
                break

            # Safety check: prevent memory exhaustion
            if len(nodes_dict) >= MAX_TRANSITIVE_NODES:
                break

            # Build a query for direct dependencies of the current frontier
            # We filter by specific node IDs to avoid the 10k node limit issue
            next_frontier: set[str] = set()

            # Process frontier in batches to avoid query size limits
            frontier_list = list(current_frontier)
            batch_size = 100

            for batch_start in range(0, len(frontier_list), batch_size):
                batch = frontier_list[batch_start : batch_start + batch_size]

                # Parse batch IDs back to project_name/version pairs
                batch_conditions = []
                batch_params: dict[str, Any] = {}
                for i, node_id in enumerate(batch):
                    parts = node_id.rsplit(":", 1)
                    if len(parts) == 2:
                        proj, ver = parts
                        batch_params[f"proj_{i}"] = proj
                        batch_params[f"ver_{i}"] = ver
                        batch_conditions.append(
                            f"(src.project_name = $proj_{i} AND src.name = $ver_{i})"
                        )

                if not batch_conditions:
                    continue

                where_clause = " OR ".join(batch_conditions)

                # Build query based on filter mode
                if filter_mode == "single":
                    # Application node: filter by single scan_id
                    batch_params["scan_id"] = scan_id
                    query = f"""
                        MATCH (src:{node_label})-[r]->(tgt:{node_label})
                        WHERE ({where_clause})
                        AND $scan_id IN tgt.scan_ids
                        RETURN DISTINCT src, tgt, type(r) as rel_type
                    """
                elif filter_mode == "any":
                    # Library node: filter by ANY of the scan_ids
                    # Include targets that share at least one scan_id with root
                    # (i.e., they appeared in at least one of the same app scans)
                    batch_params["scan_ids"] = scan_ids
                    query = f"""
                        MATCH (src:{node_label})-[r]->(tgt:{node_label})
                        WHERE ({where_clause})
                        AND ANY(sid IN $scan_ids WHERE sid IN tgt.scan_ids)
                        RETURN DISTINCT src, tgt, type(r) as rel_type
                    """
                else:
                    # No filtering - include all dependencies
                    query = f"""
                        MATCH (src:{node_label})-[r]->(tgt:{node_label})
                        WHERE {where_clause}
                        RETURN DISTINCT src, tgt, type(r) as rel_type
                    """

                try:
                    result = self.execute_query(query, batch_params)
                except (TimeoutError, ConnectionError, RuntimeError):
                    # If query fails (e.g., timeout), continue with what we have
                    continue

                for row in result:
                    src_node, tgt_node, rel_type = row

                    src_id = self._get_node_id(src_node)
                    tgt_id = self._get_node_id(tgt_node)

                    # Add source node if not already present
                    if src_id not in nodes_dict:
                        nodes_dict[src_id] = self._node_to_dict(src_node)

                    # Add target node if not already present
                    if tgt_id not in nodes_dict:
                        nodes_dict[tgt_id] = self._node_to_dict(tgt_node)

                    # Add edge if not duplicate
                    edge_key = (src_id, tgt_id)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append(
                            {
                                "source": src_id,
                                "target": tgt_id,
                                "type": rel_type,
                            }
                        )

                    # Add to next frontier if not yet visited
                    if tgt_id not in visited_ids:
                        visited_ids.add(tgt_id)
                        next_frontier.add(tgt_id)

            current_frontier = next_frontier

        return list(nodes_dict.values()), edges

    def get_transitive_dependants(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
        skip_scan_filter: bool = False,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Get transitive dependants (reverse dependencies) as nodes and edges.

        Uses iterative breadth-first traversal with visitor pattern to:
        - Avoid FalkorDB's node limit issues
        - Handle cyclic dependencies gracefully (each node visited only once)
        - Prevent memory exhaustion from large fan-out

        Filtering behavior based on root node type (ensures dependants are actually
        using the specified version, not just any version of the project):
        - Application nodes (with scan_id property): Filter to include only
          dependant nodes that have this scan_id in their scan_ids array.
        - Library nodes (with scan_ids but no scan_id): Filter to include only
          dependant nodes that share at least one scan_id with the root (i.e.,
          they appeared in at least one of the same application scans).

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse (defaults to DEFAULT_MAX_DEPTH)
            internal_only: If True, only include internal-labeled nodes
            skip_scan_filter: If True, skip scan_id filtering (useful for visualizations
                showing raw graph structure)

        Returns:
            Tuple of (nodes list, edges list)
        """
        effective_max_depth = max_depth if max_depth is not None else DEFAULT_MAX_DEPTH

        # Initialize traversal state (includes scan_id filtering info)
        state = self._init_dependants_traversal_state(
            project_name, version_name, internal_only, skip_scan_filter
        )

        # Iterative BFS - traverse in reverse direction (find nodes that depend ON frontier)
        for _ in range(effective_max_depth):
            if not state["current_frontier"]:
                break
            if self._is_at_capacity(state["nodes_dict"]):
                break

            next_frontier = self._process_dependants_depth_level(state)
            state["current_frontier"] = next_frontier
            if len(next_frontier) == 0:
                break

        return list(state["nodes_dict"].values()), state["edges"]

    def _init_dependants_traversal_state(
        self,
        project_name: str,
        version_name: str,
        internal_only: bool = False,
        skip_scan_filter: bool = False,
    ) -> dict[str, Any]:
        """Initialize the traversal state for dependants BFS.

        Args:
            project_name: The root project name
            version_name: The root version string
            internal_only: If True, only include internal-labeled nodes
            skip_scan_filter: If True, use "none" filter mode regardless of scan data

        Returns:
            Dictionary containing all traversal state including scan_id filter info
        """
        root_id = f"{project_name}:{version_name}"
        visited_ids: set[str] = set[str]()
        nodes_dict: dict[str, dict[str, Any]] = {}

        # Fetch and add root node
        root = self.find_version(project_name, version_name)
        root_properties = root["properties"] if root else {}

        # Determine filtering strategy based on node type:
        # - Application nodes have a single scan_id property
        # - Library nodes have scan_ids list (from all app scans that include them)
        scan_id = root_properties.get("scan_id") if root else None
        scan_ids = root_properties.get("scan_ids", []) if root else []

        # Filter mode:
        # - "single": Application node - filter by single scan_id
        # - "any": Library node - filter by ANY of the scan_ids (at least one in common)
        # - "none": No scan info available - no filtering
        # If skip_scan_filter is True, always use "none" to show raw graph structure
        if skip_scan_filter:
            filter_mode = "none"
        elif scan_id is not None:
            filter_mode = "single"
        elif scan_ids:
            filter_mode = "any"
        else:
            filter_mode = "none"

        if root:
            nodes_dict[root_id] = {
                "id": root_id,
                "project_name": project_name,
                "version": version_name,
                "labels": root["labels"],
                "properties": root_properties,
            }

        return {
            "visited_ids": visited_ids,
            "nodes_dict": nodes_dict,
            "edges": [],
            "seen_edges": set(),
            "current_frontier": {root_id},
            "filter_mode": filter_mode,
            "scan_id": scan_id,
            "scan_ids": scan_ids,
            "internal_only": internal_only,
        }

    def _is_at_capacity(self, nodes_dict: dict[str, Any]) -> bool:
        """Check if we've reached the maximum node capacity."""
        return len(nodes_dict) >= MAX_TRANSITIVE_NODES

    def _get_remaining_capacity(self, nodes_dict: dict[str, Any]) -> int:
        """Get the remaining capacity for nodes."""
        return MAX_TRANSITIVE_NODES - len(nodes_dict)

    def _process_dependants_depth_level(
        self,
        state: dict[str, Any],
    ) -> set[str]:
        """Process one depth level of the dependants BFS traversal.

        Args:
            state: The traversal state dictionary

        Returns:
            Set of node IDs for the next frontier
        """
        next_frontier: set[str] = set()
        frontier_list = [
            element for element in state["current_frontier"] if element not in state["visited_ids"]
        ]
        batch_size = 50

        for batch_start in range(0, len(frontier_list), batch_size):
            if self._is_at_capacity(state["nodes_dict"]):
                break

            batch = frontier_list[batch_start : batch_start + batch_size]
            batch_frontier = self._process_dependants_batch(batch, state)
            next_frontier.update(batch_frontier)

        return next_frontier

    def _process_dependants_batch(
        self,
        batch: list[str],
        state: dict[str, Any],
    ) -> set[str]:
        """Process a single batch of nodes for dependants traversal.

        Args:
            batch: List of node IDs to find dependants for
            state: The traversal state dictionary

        Returns:
            Set of newly discovered node IDs for next frontier
        """
        batch_frontier: set[str] = set()
        batch_params: dict[str, Any] = {}

        # Build target conditions
        target_conditions = self._build_node_conditions(batch, batch_params, "tgt", "tgt")
        if not target_conditions:
            return batch_frontier

        # Set query limit
        batch_params["query_limit"] = min(self._get_remaining_capacity(state["nodes_dict"]), 5000)

        # Add scan_id filtering parameters based on filter mode
        filter_mode = state.get("filter_mode", "none")
        internal_only = state.get("internal_only", False)
        if filter_mode == "single":
            batch_params["scan_id"] = state.get("scan_id")
        elif filter_mode == "any":
            batch_params["scan_ids"] = state.get("scan_ids", [])

        # Execute query
        query = self._build_dependants_query(target_conditions, filter_mode, internal_only)
        try:
            result = self.execute_query(query, batch_params)
        except (TimeoutError, ConnectionError, RuntimeError, MemoryError):
            return batch_frontier

        # Use set to deduplicate results by (src_id, tgt_id) pair
        seen_in_batch: set[tuple[str, str]] = set()

        for row in result:
            if self._is_at_capacity(state["nodes_dict"]):
                break

            src_node, tgt_node, rel_type = row
            src_id = self._get_node_id(src_node)
            tgt_id = self._get_node_id(tgt_node)
            # Skip duplicates within this batch
            edge_key = (src_id, tgt_id)
            if edge_key in seen_in_batch:
                continue
            seen_in_batch.add(edge_key)

            # Skip if source already visited (visitor pattern)
            if src_id in state["visited_ids"]:
                # Still record the edge
                if src_id != tgt_id:
                    self._add_edge_if_new(
                        src_id, tgt_id, rel_type, state["edges"], state["seen_edges"]
                    )
                continue

            # Process new node
            new_node = self._process_new_dependant(
                src_node, tgt_node, src_id, tgt_id, rel_type, state
            )
            batch_frontier.add(new_node)

        return batch_frontier

    def _process_new_dependant(
        self,
        src_node: Any,
        tgt_node: Any,
        src_id: str,
        tgt_id: str,
        rel_type: str,
        state: dict[str, Any],
    ) -> str:
        """Process a newly discovered dependant node.

        Args:
            src_node: The source (dependant) node from query
            tgt_node: The target node from query
            src_id: Source node ID
            tgt_id: Target node ID
            rel_type: Relationship type
            state: The traversal state dictionary

        Returns:
            The source node ID (for adding to frontier)
        """
        # Mark as visited
        state["visited_ids"].add(tgt_id)

        # Add nodes
        state["nodes_dict"][src_id] = self._node_to_dict(src_node)
        if tgt_id not in state["nodes_dict"]:
            state["nodes_dict"][tgt_id] = self._node_to_dict(tgt_node)

        # Add edge
        self._add_edge_if_new(src_id, tgt_id, rel_type, state["edges"], state["seen_edges"])

        return src_id

    def get_dependants_with_partitions_and_paths(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
        longest_only: bool = True,
    ) -> dict[str, Any]:
        """Get dependants with partition levels and dependency paths.

        For each dependant, calculates:
        - Partition level (longest path from target - for vulnerability prioritization)
        - Dependency paths (longest only by default, or all paths up to 50)

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse
            internal_only: If True, only include internal-labeled nodes
            longest_only: If True (default), only include the longest path per dependant

        Returns:
            Dict with target info, stats, and dependants list
        """
        import networkx as nx

        # Get transitive dependants
        nodes, edges = self.get_transitive_dependants(
            project_name, version_name, max_depth, internal_only
        )

        root_id = f"{project_name}:{version_name}"

        # Build NetworkX graph for path analysis
        G = nx.DiGraph()
        node_data = {n["id"]: n for n in nodes}

        for node in node_data.values():
            G.add_node(node["id"])

        # Add edges (dependant -> target direction)
        for edge in edges:
            G.add_edge(edge["source"], edge["target"])

        # Remove cycles to prevent infinite loops
        # Use efficient DFS-based back-edge removal (O(V+E)) instead of
        # nx.simple_cycles which has exponential complexity on cyclic graphs
        def remove_cycles_dfs(graph: nx.DiGraph) -> None:
            """Remove back-edges to break cycles using DFS traversal."""
            visited = set()
            rec_stack = set()
            edges_to_remove = []

            def dfs(node):
                visited.add(node)
                rec_stack.add(node)
                for successor in list(graph.successors(node)):
                    if successor not in visited:
                        dfs(successor)
                    elif successor in rec_stack:
                        # Back-edge found - this creates a cycle
                        edges_to_remove.append((node, successor))
                rec_stack.remove(node)

            for node in graph.nodes():
                if node not in visited:
                    dfs(node)

            for u, v in edges_to_remove:
                if graph.has_edge(u, v):
                    graph.remove_edge(u, v)

        try:
            # Also remove self-loops first
            self_loops = list(nx.selfloop_edges(G))
            G.remove_edges_from(self_loops)
            # Then remove back-edges to break cycles
            remove_cycles_dfs(G)
        except nx.NetworkXError:
            pass  # Graph error, continue with what we have

        # Calculate partitions using LONGEST path from root to each dependant
        # Use proper DAG longest path algorithm (topological sort based)
        # Since G has edges dependant -> target, we work on the reversed graph
        G_reversed = G.reverse(copy=True)

        # For DAG longest path: use topological sort and dynamic programming
        # Initialize distances from root
        partitions = dict.fromkeys(G_reversed.nodes(), -1)
        partitions[root_id] = 0

        # Get topological order starting from root (BFS-based for nodes reachable from root)
        # Process in BFS order to ensure we process shorter paths before longer ones
        from collections import deque

        # Use BFS to get nodes in level order, then process
        visited_order = []
        queue = deque([root_id])
        visited_for_order = {root_id}

        while queue:
            node = queue.popleft()
            visited_order.append(node)
            for successor in G_reversed.successors(node):
                if successor not in visited_for_order:
                    visited_for_order.add(successor)
                    queue.append(successor)

        # Now do longest path: process each node and update successors
        # Repeat until no changes (handles the DAG properly)
        changed = True
        iterations = 0
        max_iterations = len(G_reversed.nodes()) + 1

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for node in visited_order:
                if partitions[node] < 0:
                    continue
                for successor in G_reversed.successors(node):
                    new_dist = partitions[node] + 1
                    if new_dist > partitions[successor]:
                        partitions[successor] = new_dist
                        changed = True

        # Build dependants list with partition and paths
        dependants_list = []
        max_partition = 0
        unique_projects = set()

        for node_id, data in node_data.items():
            if node_id == root_id:
                continue  # Skip the target itself

            partition = partitions.get(node_id, -1)
            if partition < 0:
                continue  # Not reachable

            max_partition = max(max_partition, partition)
            unique_projects.add(data.get("project_name", ""))

            # Find paths from dependant to target
            # The partition value is the longest path length, so use it as cutoff
            paths = []
            max_path_edges = 0
            try:
                # Use partition as the cutoff - this is the known longest path length
                # Add small buffer in case of rounding/edge cases
                path_cutoff = partition + 2
                all_paths = nx.all_simple_paths(G, node_id, root_id, cutoff=path_cutoff)
                # Collect paths, sort by length descending (longest first)
                raw_paths = list(all_paths)
                raw_paths.sort(key=len, reverse=True)

                if raw_paths:
                    max_path_edges = len(raw_paths[0]) - 1  # Longest path edges

                    if longest_only:
                        # Only include paths with the maximum length (the longest paths)
                        longest_len = len(raw_paths[0])
                        for path in raw_paths:
                            if len(path) < longest_len:
                                break  # Sorted descending, so stop when shorter
                            path_str = [
                                f"{node_data.get(p, {}).get('project_name', p)}@"
                                f"{node_data.get(p, {}).get('version', '')}"
                                for p in path
                            ]
                            paths.append(path_str)
                    else:
                        # Include up to 50 paths (longest first)
                        for path in raw_paths[:50]:
                            path_str = [
                                f"{node_data.get(p, {}).get('project_name', p)}@"
                                f"{node_data.get(p, {}).get('version', '')}"
                                for p in path
                            ]
                            paths.append(path_str)
            except nx.NetworkXError:
                pass

            dependants_list.append(
                {
                    "id": node_id,
                    "project_name": data.get("project_name", ""),
                    "version": data.get("version", ""),
                    "partition": partition,
                    "max_path_edges": max_path_edges,
                    "labels": data.get("labels", []),
                    "paths": paths,
                    "path_count": len(paths),
                }
            )

        # Sort by partition, then project name
        dependants_list.sort(key=lambda x: (x["partition"], x["project_name"], x["version"]))

        # Get target info
        root_data = node_data.get(root_id, {})

        return {
            "target": {
                "project_name": project_name,
                "version": version_name,
                "labels": root_data.get("labels", []),
            },
            "stats": {
                "total_dependants": len(dependants_list),
                "max_partition": max_partition,
                "unique_projects": len(unique_projects),
            },
            "dependants": dependants_list,
        }

    def find_cycles(self, max_cycle_length: int = 5) -> list[list[dict[str, Any]]]:
        """Find dependency cycles in the graph.

        Cycles are problematic as they can cause infinite loops in traversal
        and indicate potential issues in the dependency structure.

        Args:
            max_cycle_length: Maximum cycle length to search for (default 5)
                Longer cycles are computationally expensive to find.

        Returns:
            List of cycles, where each cycle is a list of node dicts
            representing the cycle path.
        """
        cycles: list[list[dict[str, Any]]] = []

        # Find cycles up to max_cycle_length
        for length in range(2, max_cycle_length + 1):
            # Use a bounded variable-length path that returns to the start
            path_pattern = f"[*{length}]"
            query = f"""
                MATCH path = (start:Version)-{path_pattern}->(start)
                WITH start, nodes(path) as cycle_nodes
                WHERE ALL(i IN range(0, size(cycle_nodes)-2) WHERE
                    cycle_nodes[i].project_name < cycle_nodes[i+1].project_name OR
                    (cycle_nodes[i].project_name = cycle_nodes[i+1].project_name AND
                     cycle_nodes[i].name <= cycle_nodes[i+1].name))
                RETURN [n IN cycle_nodes | {{
                    project_name: n.project_name,
                    version: n.name
                }}] as cycle
                LIMIT 100
            """

            try:
                result = self.execute_query(query, {})
                for row in result:
                    cycle_path = row[0]
                    if cycle_path:
                        cycles.append(cycle_path)
            except (TimeoutError, ConnectionError, RuntimeError):
                # If query times out, we may have too many cycles or long ones
                continue

        return cycles

    def find_direct_cycles(self) -> list[dict[str, Any]]:
        """Find direct cycles (A -> B -> A) in the graph.

        These are the most common type of problematic cycles.

        Returns:
            List of dicts containing cycle information.
        """
        query = """
            MATCH (a:Version)-[r1]->(b:Version)-[r2]->(a)
            WHERE a.project_name < b.project_name OR
                  (a.project_name = b.project_name AND a.name < b.name)
            RETURN DISTINCT
                a.project_name as project_a,
                a.name as version_a,
                b.project_name as project_b,
                b.name as version_b,
                type(r1) as rel_a_to_b,
                type(r2) as rel_b_to_a
            ORDER BY a.project_name, a.name
            LIMIT 1000
        """
        result = self.execute_query(query, {})
        return [
            {
                "project_a": row[0],
                "version_a": row[1],
                "project_b": row[2],
                "version_b": row[3],
                "rel_a_to_b": row[4],
                "rel_b_to_a": row[5],
            }
            for row in result
        ]

    def find_snapshot_dependencies(self, internal_only: bool = False) -> list[dict[str, Any]]:
        """Find all applications with SNAPSHOT dependencies.

        Args:
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of dicts with application and dependency information
        """
        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (app:{node_label})-[r]->(dep:{node_label})
            WHERE dep.name CONTAINS 'SNAPSHOT'
            RETURN app.project_name as application,
                   app.name as app_version,
                   dep.project_name as dependency,
                   dep.name as dep_version
            ORDER BY app.project_name, app.name
        """
        result = self.execute_query(query, {})
        return [
            {
                "application": row[0],
                "app_version": row[1],
                "dependency": row[2],
                "dep_version": row[3],
            }
            for row in result
        ]

    def find_self_dependencies(self, internal_only: bool = False) -> list[dict[str, Any]]:
        """Find nodes that depend on themselves.

        Args:
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of dicts with self-dependency information
        """
        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{node_label})-[r]->(v)
            RETURN v.project_name as project_name,
                   v.name as version,
                   type(r) as relationship_type
            ORDER BY v.project_name, v.name
        """
        result = self.execute_query(query, {})
        return [
            {
                "project_name": row[0],
                "version": row[1],
                "relationship_type": row[2],
            }
            for row in result
        ]

    def find_non_semver_versions(self, internal_only: bool = False) -> list[dict[str, Any]]:
        """Find all versions that don't follow SemVer naming convention.

        SemVer format: MAJOR.MINOR.PATCH with optional pre-release and build
        metadata (e.g., 1.0.0, 1.2.3-alpha, 1.2.3+build, v2.0.0).

        Common non-SemVer patterns include:
        - SNAPSHOT versions (e.g., 1.0.0-SNAPSHOT)
        - Date-based versions (e.g., 20230101)
        - Branch-based versions (e.g., feature-branch-1234)
        - Hash-based versions (e.g., abc123def)

        Args:
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of dicts with project_name, version, and reason
        """
        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{node_label})
            RETURN v.project_name as project_name,
                   v.name as version,
                   labels(v) as labels
            ORDER BY v.project_name, v.name
        """
        result = self.execute_query(query, {})

        non_semver_versions = []
        for row in result:
            project_name = row[0]
            version = row[1]
            labels = row[2]

            if version and not SEMVER_PATTERN.match(version):
                # Categorize the type of non-SemVer version
                reason = self._categorize_non_semver_version(version)
                non_semver_versions.append(
                    {
                        "project_name": project_name,
                        "version": version,
                        "reason": reason,
                        "labels": labels,
                    }
                )

        return non_semver_versions

    def _categorize_non_semver_version(self, version: str) -> str:
        """Categorize why a version doesn't follow SemVer.

        Args:
            version: The version string to categorize

        Returns:
            A description of the version pattern
        """
        version_lower = version.lower()

        # Note: SNAPSHOT and release qualifier suffixes (.RELEASE, .Final, .GA) are now
        # considered valid in SEMVER_PATTERN, so versions with those suffixes and a valid
        # SemVer base won't reach this function. If they do reach here, the issue is with
        # the base version, not the suffix.

        if "rc" in version_lower or "release-candidate" in version_lower:
            return "Release candidate"
        if "beta" in version_lower:
            return "Beta version"
        if "alpha" in version_lower:
            return "Alpha version"
        if version_lower.startswith("dev") or "-dev" in version_lower:
            return "Development version"
        if re.match(r"^\d{8}$", version):
            return "Date-based version (YYYYMMDD)"
        if re.match(r"^\d{6}$", version):
            return "Date-based version (YYMMDD)"
        if re.match(r"^[a-f0-9]{7,40}$", version_lower):
            return "Git commit hash"
        if re.match(r"^(main|master|develop|feature|release|hotfix)[-_]", version_lower):
            return "Branch-based version"
        if re.match(r"^\d+$", version):
            return "Single number version"
        if not re.search(r"\d", version):
            return "No numeric component"

        return "Non-standard format"

    def get_applications_by_scan_ids(self, scan_ids: list[str]) -> list[dict[str, Any]]:
        """Find Application nodes by their scan_id property.

        Args:
            scan_ids: List of scan IDs to search for

        Returns:
            List of dicts with application information
        """
        if not scan_ids:
            return []

        query = """
            MATCH (app:Application)
            WHERE app.scan_id IN $scan_ids
            RETURN app.project_name as project_name,
                   app.name as version,
                   app.scan_id as scan_id
            ORDER BY app.project_name, app.name
        """
        result = self.execute_query(query, {"scan_ids": scan_ids})
        return [
            {
                "project_name": row[0],
                "version": row[1],
                "scan_id": row[2],
            }
            for row in result
        ]

    def find_multi_version_dependency_sources(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Find dependencies with multiple versions and trace their sources.

        For a given project version, this method:
        1. Gets all transitive dependencies
        2. Identifies dependencies that have multiple versions
        3. For each multi-version dependency, finds which applications
           contributed each version by intersecting scan_ids

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse (defaults to DEFAULT_MAX_DEPTH)
            internal_only: Only include internal-labeled nodes

        Returns:
            Dict with:
                - target: The target project info
                - multi_version_dependencies: List of dependencies with multiple
                  versions and their contributing applications
        """
        # Get the target project's scan_ids
        root = self.find_version(project_name, version_name)
        if not root:
            return {
                "target": None,
                "multi_version_dependencies": [],
            }

        root_properties = root["properties"]
        target_scan_ids = set(root_properties.get("scan_ids", []))

        # Get all transitive dependencies using the standard method which applies
        # proper scan_id filtering (ANY for library nodes, single for Application nodes)
        # This ensures all returned dependencies share at least one scan_id with the root
        nodes, _ = self.get_transitive_dependencies(
            project_name, version_name, max_depth, internal_only
        )

        # Group dependencies by project_name
        deps_by_project: dict[str, list[dict[str, Any]]] = {}
        for node in nodes:
            dep_project: str = node.get("project_name", "unknown")
            # Skip the root node itself
            if dep_project == project_name and node.get("version") == version_name:
                continue
            if dep_project not in deps_by_project:
                deps_by_project[dep_project] = []
            deps_by_project[dep_project].append(node)

        # Find dependencies with multiple versions
        multi_version_deps: list[dict[str, Any]] = []
        for dep_project, versions in deps_by_project.items():
            if len(versions) > 1:
                # Multiple versions of this dependency
                version_sources: list[dict[str, Any]] = []
                for ver_node in versions:
                    dep_scan_ids = set(ver_node.get("properties", {}).get("scan_ids", []))
                    # Find intersection with target's scan_ids
                    common_scan_ids = list(target_scan_ids & dep_scan_ids)

                    # Get applications that have these scan_ids
                    contributing_apps = self.get_applications_by_scan_ids(common_scan_ids)

                    version_sources.append(
                        {
                            "version": ver_node.get("version", ""),
                            "scan_ids_intersection": common_scan_ids,
                            "contributing_applications": contributing_apps,
                        }
                    )

                # Sort versions
                version_sources.sort(key=lambda x: str(x.get("version", "")))

                multi_version_deps.append(
                    {
                        "dependency_project": dep_project,
                        "version_count": len(versions),
                        "versions": version_sources,
                    }
                )

        # Sort by dependency project name
        multi_version_deps.sort(key=lambda x: str(x.get("dependency_project", "")))

        return {
            "target": {
                "project_name": project_name,
                "version": version_name,
                "scan_ids_count": len(target_scan_ids),
            },
            "multi_version_dependencies": multi_version_deps,
        }

    def get_library_version_usage(
        self,
        project_name: str,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Get usage statistics for all versions of a library across the org.

        This method answers the question: "Who uses what version of this library?"
        For a given library (project_name), it finds all versions and lists which
        applications/projects depend on each version.

        Use case: Understanding library adoption patterns, identifying which teams
        need to upgrade when a vulnerability is found in a specific version.

        Args:
            project_name: The library/project name to analyze
            internal_only: Only include internal-labeled dependants

        Returns:
            Dict with:
                - library: The library being analyzed
                - total_versions: Number of distinct versions found
                - total_dependants: Total count of direct dependants across all versions
                - versions: List of version info with dependants for each
        """
        internal_label = self.config.internal_label

        # Build the internal filter clause
        internal_filter = ""
        if internal_only:
            internal_filter = f" AND '{internal_label}' IN labels(dependant)"

        # Query to find all versions and their direct dependants
        query = f"""
            MATCH (v:Version {{project_name: $project_name}})
            OPTIONAL MATCH (dependant:Version)-[:DEPENDENCY_VERSION]->(v)
            WHERE dependant IS NULL OR dependant.project_name <> $project_name
            {internal_filter}
            WITH v, collect(DISTINCT dependant) as dependants
            RETURN v.name as version,
                   v.project_group as project_group,
                   labels(v) as labels,
                   size(dependants) as dependant_count,
                   [d IN dependants WHERE d IS NOT NULL |
                    {{project_name: d.project_name,
                      version: d.name,
                      project_group: d.project_group,
                      labels: labels(d)}}] as dependants
            ORDER BY v.name DESC
        """

        result = self.graph.query(query, {"project_name": project_name})

        versions: list[dict[str, Any]] = []
        total_dependants = 0

        for row in result.result_set:
            version_name = row[0]
            project_group = row[1]
            labels = row[2] if row[2] else []
            dependant_count = row[3]
            dependants_raw = row[4] if row[4] else []

            is_internal = internal_label in labels

            # Process dependants
            dependants_list: list[dict[str, Any]] = []
            for dep in dependants_raw:
                if dep:
                    dep_labels = dep.get("labels", [])
                    dependants_list.append({
                        "project_name": dep.get("project_name", ""),
                        "version": dep.get("version", ""),
                        "project_group": dep.get("project_group", ""),
                        "is_internal": internal_label in dep_labels,
                    })

            # Sort dependants by project name
            dependants_list.sort(key=lambda x: (x["project_name"], x["version"]))

            versions.append({
                "version": version_name,
                "project_group": project_group,
                "is_internal": is_internal,
                "dependant_count": dependant_count,
                "dependants": dependants_list,
            })

            total_dependants += dependant_count

        return {
            "library": {
                "project_name": project_name,
                "total_versions": len(versions),
            },
            "total_dependants": total_dependants,
            "versions": versions,
        }

    def _get_transitive_dependencies_unfiltered(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Get transitive dependencies without scan_id filtering.

        This is similar to get_transitive_dependencies but never filters by
        scan_id, allowing us to see all dependencies from all contributing scans.

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse (defaults to DEFAULT_MAX_DEPTH)
            internal_only: Only include internal-labeled nodes

        Returns:
            Tuple of (nodes list, edges list)
        """
        effective_max_depth = max_depth if max_depth is not None else DEFAULT_MAX_DEPTH
        node_label = self.get_node_label(internal_only)

        # Track visited nodes to handle cycles
        visited_ids: set[str] = set()
        nodes_dict: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str]] = set()

        # Start with the root node
        root_id = f"{project_name}:{version_name}"
        current_frontier: set[str] = {root_id}
        visited_ids.add(root_id)

        # Fetch root node data
        root = self.find_version(project_name, version_name)
        root_properties = root["properties"] if root else {}
        root_labels = root["labels"] if root else []

        if root:
            nodes_dict[root_id] = {
                "id": root_id,
                "project_name": project_name,
                "version": version_name,
                "labels": root_labels,
                "properties": root_properties,
            }

        # Iterative BFS - query one depth level at a time
        for _ in range(effective_max_depth):
            if not current_frontier:
                break

            # Safety check: prevent memory exhaustion
            if len(nodes_dict) >= MAX_TRANSITIVE_NODES:
                break

            next_frontier: set[str] = set()

            # Process frontier in batches to avoid query size limits
            frontier_list = list(current_frontier)
            batch_size = 100

            for batch_start in range(0, len(frontier_list), batch_size):
                batch = frontier_list[batch_start : batch_start + batch_size]

                # Parse batch IDs back to project_name/version pairs
                batch_conditions = []
                batch_params: dict[str, Any] = {}
                for i, node_id in enumerate(batch):
                    parts = node_id.rsplit(":", 1)
                    if len(parts) == 2:
                        proj, ver = parts
                        batch_params[f"proj_{i}"] = proj
                        batch_params[f"ver_{i}"] = ver
                        batch_conditions.append(
                            f"(src.project_name = $proj_{i} AND src.name = $ver_{i})"
                        )

                if not batch_conditions:
                    continue

                where_clause = " OR ".join(batch_conditions)

                # Query for direct dependencies only (depth 1) - no scan_id filter
                query = f"""
                    MATCH (src:{node_label})-[r]->(tgt:{node_label})
                    WHERE {where_clause}
                    RETURN DISTINCT src, tgt, type(r) as rel_type
                """

                try:
                    result = self.execute_query(query, batch_params)
                except (TimeoutError, ConnectionError, RuntimeError):
                    continue

                for row in result:
                    src_node, tgt_node, rel_type = row

                    src_id = self._get_node_id(src_node)
                    tgt_id = self._get_node_id(tgt_node)

                    # Add source node if not already present
                    if src_id not in nodes_dict:
                        nodes_dict[src_id] = self._node_to_dict(src_node)

                    # Add target node if not already present
                    if tgt_id not in nodes_dict:
                        nodes_dict[tgt_id] = self._node_to_dict(tgt_node)

                    # Add edge if not duplicate
                    edge_key = (src_id, tgt_id)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append(
                            {
                                "source": src_id,
                                "target": tgt_id,
                                "type": rel_type,
                            }
                        )

                    # Add to next frontier if not yet visited
                    if tgt_id not in visited_ids:
                        visited_ids.add(tgt_id)
                        next_frontier.add(tgt_id)

            current_frontier = next_frontier

        return list(nodes_dict.values()), edges

    def get_all_vulnerabilities(
        self, internal_only: bool = False
    ) -> list[dict[str, Any]]:
        """Get all vulnerabilities with their affected versions.

        Args:
            internal_only: If True, only include vulnerabilities affecting
                          internal-labeled nodes

        Returns:
            List of vulnerability dicts with severity, affected versions, etc.
        """
        # Query all defects with their affected versions
        if internal_only:
            query = f"""
                MATCH (v:{self.internal_label})-[:VERSION_DEFECT]->(d:Defect)
                RETURN DISTINCT d.defect_id as defect_id,
                       d.title as title,
                       d.description as description,
                       d.severity as severity,
                       d.cvss_score as cvss_score,
                       d.cwe_id as cwe_id,
                       d.published_date as published_date,
                       collect(DISTINCT {{
                           project_name: v.project_name,
                           version: v.name,
                           project_group: v.project_group
                       }}) as affected_versions
                ORDER BY
                    CASE d.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    d.cvss_score DESC
            """
        else:
            query = """
                MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect)
                RETURN DISTINCT d.defect_id as defect_id,
                       d.title as title,
                       d.description as description,
                       d.severity as severity,
                       d.cvss_score as cvss_score,
                       d.cwe_id as cwe_id,
                       d.published_date as published_date,
                       collect(DISTINCT {
                           project_name: v.project_name,
                           version: v.name,
                           project_group: v.project_group
                       }) as affected_versions
                ORDER BY
                    CASE d.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    d.cvss_score DESC
            """

        result = self.execute_query(query, {})

        vulnerabilities = []
        for row in result:
            vulnerabilities.append({
                "defect_id": row[0],
                "title": row[1],
                "description": row[2],
                "severity": row[3],
                "cvss_score": row[4],
                "cwe_id": row[5],
                "published_date": row[6],
                "affected_versions": row[7] if row[7] else [],
            })

        return vulnerabilities

    def get_vulnerability_by_id(
        self, defect_id: str, internal_only: bool = False
    ) -> dict[str, Any] | None:
        """Get a specific vulnerability by its ID.

        Args:
            defect_id: The vulnerability ID (e.g., CVE-2021-44228)
            internal_only: If True, only include internal-labeled affected versions

        Returns:
            Vulnerability dict or None if not found
        """
        if internal_only:
            query = f"""
                MATCH (d:Defect {{defect_id: $defect_id}})
                OPTIONAL MATCH (v:{self.internal_label})-[:VERSION_DEFECT]->(d)
                RETURN d.defect_id as defect_id,
                       d.title as title,
                       d.description as description,
                       d.severity as severity,
                       d.cvss_score as cvss_score,
                       d.cwe_id as cwe_id,
                       d.published_date as published_date,
                       collect(DISTINCT {{
                           project_name: v.project_name,
                           version: v.name,
                           project_group: v.project_group
                       }}) as affected_versions
            """
        else:
            query = """
                MATCH (d:Defect {defect_id: $defect_id})
                OPTIONAL MATCH (v:Version)-[:VERSION_DEFECT]->(d)
                RETURN d.defect_id as defect_id,
                       d.title as title,
                       d.description as description,
                       d.severity as severity,
                       d.cvss_score as cvss_score,
                       d.cwe_id as cwe_id,
                       d.published_date as published_date,
                       collect(DISTINCT {
                           project_name: v.project_name,
                           version: v.name,
                           project_group: v.project_group
                       }) as affected_versions
            """

        result = self.execute_query(query, {"defect_id": defect_id})

        if not result:
            return None

        row = result[0]
        # Filter out None entries from affected_versions
        affected = [v for v in (row[7] or []) if v.get("project_name")]

        return {
            "defect_id": row[0],
            "title": row[1],
            "description": row[2],
            "severity": row[3],
            "cvss_score": row[4],
            "cwe_id": row[5],
            "published_date": row[6],
            "affected_versions": affected,
        }

    def get_vulnerability_dependants(
        self,
        defect_id: str,
        max_depth: int | None = None,
        internal_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get all dependants affected by a vulnerability.

        For each version directly affected by the vulnerability, finds all
        transitive dependants and returns them ordered by partition (distance
        from the vulnerable library).

        Args:
            defect_id: The vulnerability ID
            max_depth: Maximum traversal depth
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of dependant dicts with partition info, ordered by partition ASC
        """
        # First, get the vulnerability and its directly affected versions
        vuln = self.get_vulnerability_by_id(defect_id, internal_only=False)
        if not vuln:
            return []

        affected_versions = vuln.get("affected_versions", [])
        if not affected_versions:
            return []

        # Collect all dependants from all affected versions
        all_dependants: dict[str, dict[str, Any]] = {}

        for affected in affected_versions:
            project_name = affected.get("project_name")
            version = affected.get("version")

            if not project_name or not version:
                continue

            # Get dependants with partition info for this affected version
            result = self.get_dependants_with_partitions_and_paths(
                project_name=project_name,
                version_name=version,
                max_depth=max_depth,
                internal_only=internal_only,
                longest_only=True,
            )

            dependants = result.get("dependants", [])

            for dep in dependants:
                dep_id = f"{dep['project_name']}:{dep['version']}"
                partition = dep.get("partition", 0)

                if dep_id not in all_dependants:
                    # Check if internal by looking at labels
                    labels = dep.get("labels", [])
                    is_internal = self.internal_label in labels

                    all_dependants[dep_id] = {
                        "project_name": dep["project_name"],
                        "version": dep["version"],
                        "partition": partition,
                        "is_internal": is_internal,
                        "affected_by": [{
                            "project_name": project_name,
                            "version": version,
                        }],
                    }
                else:
                    # Update partition to minimum (closest path)
                    if partition < all_dependants[dep_id]["partition"]:
                        all_dependants[dep_id]["partition"] = partition
                    # Track all affected versions this dependant is exposed to
                    existing_affected = all_dependants[dep_id]["affected_by"]
                    new_affected = {"project_name": project_name, "version": version}
                    if new_affected not in existing_affected:
                        existing_affected.append(new_affected)

        # Sort by partition ascending (closest to vulnerability first)
        sorted_dependants = sorted(
            all_dependants.values(),
            key=lambda x: (x["partition"], x["project_name"], x["version"]),
        )

        return sorted_dependants

    def get_internal_centrality(
        self,
        sort_by: str = "inDegree",
        sort_order: str = "desc",
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Get centrality metrics for internal libraries.

        Returns inDegree and outDegree for all internal nodes, suitable for
        analyzing which libraries are most depended upon (high inDegree) or
        have the most dependencies (high outDegree).

        Args:
            sort_by: Field to sort by - "inDegree" or "outDegree" (default: inDegree)
            sort_order: Sort direction - "asc" or "desc" (default: desc)
            limit: Maximum number of results (default: 1000)

        Returns:
            List of dicts with project_group, project_name, version_name,
            inDegree, and outDegree
        """
        # Validate sort_by
        valid_sort_fields = {"inDegree", "outDegree", "project_name", "version_name"}
        if sort_by not in valid_sort_fields:
            sort_by = "inDegree"

        # Validate sort_order
        sort_direction = "DESC" if sort_order.lower() == "desc" else "ASC"

        # Map sort_by to the actual property name in the query
        sort_field_map = {
            "inDegree": "v.inDegree",
            "outDegree": "v.outDegree",
            "project_name": "v.project_name",
            "version_name": "v.name",
        }
        sort_field = sort_field_map.get(sort_by, "v.inDegree")

        query = f"""
            MATCH (v:Version:{self.internal_label})
            WHERE v.inDegree IS NOT NULL OR v.outDegree IS NOT NULL
            RETURN
                v.project_group AS project_group,
                v.project_name AS project_name,
                v.name AS version_name,
                COALESCE(v.inDegree, 0) AS inDegree,
                COALESCE(v.outDegree, 0) AS outDegree
            ORDER BY {sort_field} {sort_direction}, v.project_name ASC, v.name ASC
            LIMIT $limit
        """

        result = self.execute_query(query, {"limit": limit})

        centrality_data = []
        for row in result:
            centrality_data.append({
                "project_group": row[0] or "",
                "project_name": row[1] or "",
                "version_name": row[2] or "",
                "inDegree": row[3] or 0,
                "outDegree": row[4] or 0,
            })

        return centrality_data


# Global service instance
_service: FalkorDBService | None = None


def get_falkordb_service() -> FalkorDBService:
    """Get the FalkorDB service singleton."""
    global _service
    if _service is None:
        _service = FalkorDBService()
    return _service


def reset_service() -> None:
    """Reset the service singleton (useful for testing)."""
    global _service
    _service = None
