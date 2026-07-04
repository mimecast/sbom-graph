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

import fnmatch
import re
import ssl
import uuid
from collections import deque
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import networkx as nx
from falkordb import FalkorDB, Graph
from redis.exceptions import ResponseError
from sbom_graph_model import LicenseRiskCategory

from sbom_graph_api.config import FalkorDBConfig, get_config
from sbom_graph_api.utils.validation import (
    defect_id_match_prefix_for_starts_with,
    defect_id_match_uses_glob,
)

# FalkorDB returns this error when a read query targets a graph key that does
# not yet exist in Redis.  An empty graph is a valid initial state for a fresh
# deployment, so callers must treat it as an empty result set rather than a
# server error.  Match on a substring to be resilient to FalkorDB version
# wording changes (the canonical message is "Invalid graph operation on empty
# key").
_EMPTY_GRAPH_ERROR_FRAGMENT = "empty key"

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

# Default page size used when streaming a full result set page-by-page.
DB_STREAM_CHUNK = 1000


def _split_semver(version: str) -> tuple[int, int, int, str]:
    """Split a (loosely) SemVer string into (major, minor, patch, prerelease).

    Strips an optional ``v`` prefix and Maven suffixes (``.RELEASE``, ``.Final``,
    ``.GA``, ``.SNAPSHOT``) and build metadata. ``prerelease`` is the raw
    pre-release string (``""`` when absent). Missing numeric components default
    to ``0``.
    """
    v = version.lstrip("vV")
    v = re.sub(r"[.\-](?:RELEASE|FINAL|GA|SNAPSHOT)$", "", v, flags=re.IGNORECASE)
    parts = v.split("-", 1)
    version_part = parts[0].split("+")[0]
    prerelease = parts[1] if len(parts) > 1 else ""
    nums = version_part.split(".")

    def _int(index: int) -> int:
        try:
            return int(nums[index]) if len(nums) > index else 0
        except ValueError:
            return 0

    return _int(0), _int(1), _int(2), prerelease


def parse_semver(version: str) -> tuple[int, int, int, str]:
    """Parse a SemVer string into a sort-comparable tuple.

    Pre-release versions sort *below* their release (an empty pre-release maps to
    ``"~"``, which sorts after any alphanumeric pre-release identifier).
    """
    major, minor, patch, prerelease = _split_semver(version)
    return major, minor, patch, prerelease if prerelease else "~"


def iterate_pages(
    fetch_page: Callable[[int, int], list[Any]],
    chunk: int = DB_STREAM_CHUNK,
) -> Iterator[list[Any]]:
    """Yield successive pages from any offset-aware fetcher until exhausted.

    Holds at most one ``chunk`` in memory at a time, so a full export streams
    page-by-page rather than materialising the entire result set (PERF-001 /
    SEC-003). ``fetch_page(offset, limit)`` must return at most ``limit`` rows;
    a short (or empty) page signals the end.
    """
    offset = 0
    while True:
        page = fetch_page(offset, chunk)
        if not page:
            return
        yield page
        if len(page) < chunk:
            return
        offset += chunk


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
            if self.config.ssl:
                connection_kwargs["ssl"] = True
                connection_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
                if self.config.ssl_ca_certs:
                    connection_kwargs["ssl_ca_certs"] = self.config.ssl_ca_certs
                if self.config.ssl_certfile:
                    connection_kwargs["ssl_certfile"] = self.config.ssl_certfile
                if self.config.ssl_keyfile:
                    connection_kwargs["ssl_keyfile"] = self.config.ssl_keyfile
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

    @staticmethod
    def _page_clause(limit: int | None, offset: int = 0) -> tuple[str, dict[str, Any]]:
        """Build a parameterised ``SKIP/LIMIT`` clause for paginated list queries.

        Returns ``("", {})`` when ``limit`` is ``None`` (caller wants all rows),
        keeping back-compat for non-paginated callers. ``offset``/``limit`` are
        always passed as query parameters (never interpolated) — SEC-004.
        """
        if limit is None:
            return "", {}
        return "SKIP $offset LIMIT $limit", {"offset": int(offset), "limit": int(limit)}

    @contextmanager
    def get_graph(self) -> Generator[Graph, None, None]:
        """Context manager for graph operations."""
        yield self.graph

    def execute_query(self, query: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Execute a read-only query and return results.

        An empty graph (no nodes ever written) is treated as a valid empty
        result set rather than a server error -- a freshly-deployed instance
        with no SBOMs ingested yet must not return 500s on read endpoints.

        Args:
            query: Cypher query string
            params: Query parameters

        Returns:
            List of result rows.  Returns ``[]`` when the target graph key
            does not yet exist in FalkorDB.

        Raises:
            redis.exceptions.ResponseError: For any FalkorDB error other than
                the "empty graph key" condition (e.g. syntax errors, auth
                failures, server-side faults).
        """
        try:
            result = self.graph.ro_query(query, params or {})
        except ResponseError as exc:
            if _EMPTY_GRAPH_ERROR_FRAGMENT in str(exc).lower():
                return []
            raise
        return result.result_set

    def execute_write(self, query: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Execute a write query (MERGE, CREATE, DELETE, SET) and return results.

        ``CREATE`` / ``MERGE`` against an empty graph implicitly create the
        graph key, but pure ``MATCH ... DELETE`` / ``MATCH ... SET`` queries
        will surface the same "empty graph key" error as reads do.  Treat
        that as a no-op (nothing matched, nothing changed).

        Args:
            query: Cypher query string
            params: Query parameters

        Returns:
            List of result rows.  Returns ``[]`` when the target graph key
            does not yet exist in FalkorDB.

        Raises:
            redis.exceptions.ResponseError: For any FalkorDB error other than
                the "empty graph key" condition.
        """
        try:
            result = self.graph.query(query, params or {})
        except ResponseError as exc:
            if _EMPTY_GRAPH_ERROR_FRAGMENT in str(exc).lower():
                return []
            raise
        return result.result_set if hasattr(result, "result_set") else []

    def find_version(
        self,
        project_name: str,
        version_name: str,
        project_group: str | None = None,
    ) -> dict[str, Any] | None:
        """Find a specific version node.

        Args:
            project_name: The project name
            version_name: The version string
            project_group: Optional group for disambiguation

        Returns:
            Dict with 'properties' and 'labels' keys, or None if not found
        """
        params: dict[str, Any] = {
            "project_name": project_name,
            "version_name": version_name,
        }
        group_clause = ""
        if project_group:
            params["project_group"] = project_group
            group_clause = ", project_group: $project_group"

        query = f"""
            MATCH (v:Version {{project_name: $project_name, name: $version_name{group_clause}}})
            RETURN v
        """
        result = self.execute_query(query, params)
        if result:
            node = result[0][0]
            return {
                "properties": node.properties,
                "labels": list(node.labels),
            }
        return None

    def find_version_by_purl(self, purl: str) -> dict[str, Any] | None:
        """Resolve a purl to project_name, version_name, and project_group.

        Args:
            purl: The package URL to look up

        Returns:
            Dict with project_name, version_name, project_group, or None
        """
        query = """
            MATCH (v:Version {package_url: $purl})
            RETURN v.project_name, v.name, v.project_group
            LIMIT 1
        """
        result = self.execute_query(query, {"purl": purl})
        if result:
            return {
                "project_name": result[0][0],
                "version_name": result[0][1],
                "project_group": result[0][2],
            }
        return None

    def find_project_by_purl_prefix(self, purl_prefix: str) -> dict[str, Any] | None:
        """Resolve a versionless purl prefix to a project_name and group.

        Matches any Version node whose ``package_url`` starts with the given
        prefix.  Useful for routes that only need project-level identity.

        Args:
            purl_prefix: Purl without version, e.g. ``pkg:maven/com.acme/foo``

        Returns:
            Dict with project_name and project_group, or None
        """
        query = """
            MATCH (v:Version)
            WHERE v.package_url STARTS WITH $prefix
            RETURN DISTINCT v.project_name, v.project_group
            LIMIT 1
        """
        result = self.execute_query(query, {"prefix": purl_prefix})
        if result:
            return {
                "project_name": result[0][0],
                "project_group": result[0][1],
            }
        return None

    @staticmethod
    def _name_predicate(node_var: str, name: str | None, params: dict[str, Any]) -> str:
        """Build a case-insensitive ``project_name`` substring predicate (no keyword).

        Adds the bound ``$name`` parameter when *name* is set; returns ``""``
        otherwise. Only the hardcoded *node_var* is interpolated — the search
        term is passed as a query parameter (no injection). Use this for queries
        that already carry a ``WHERE`` (combine with ``AND``); see
        :meth:`_name_filter` for the standalone ``WHERE`` form.
        """
        if not name:
            return ""
        params["name"] = name
        return f"toLower({node_var}.project_name) CONTAINS toLower($name)"

    @staticmethod
    def _name_filter(node_var: str, name: str | None, params: dict[str, Any]) -> str:
        """Build a standalone case-insensitive ``project_name`` substring ``WHERE`` clause.

        Returns ``""`` when *name* is unset. For queries that already have a
        ``WHERE``, use :meth:`_name_predicate` and combine the result with ``AND``.
        """
        predicate = FalkorDBService._name_predicate(node_var, name, params)
        return f"WHERE {predicate}" if predicate else ""

    def count_all_projects(self, internal_only: bool = False, name: str | None = None) -> int:
        """Count Version nodes for the projects report (same filter as the page query)."""
        node_label = self.get_node_label(internal_only)
        params: dict[str, Any] = {}
        name_clause = self._name_filter("v", name, params)
        result = self.execute_query(
            f"MATCH (v:{node_label}) {name_clause} RETURN count(v) AS n", params
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def count_unique_projects(self, internal_only: bool = False, name: str | None = None) -> int:
        """Count distinct project names (same filter as the page query)."""
        node_label = self.get_node_label(internal_only)
        params: dict[str, Any] = {}
        name_clause = self._name_filter("v", name, params)
        result = self.execute_query(
            f"MATCH (v:{node_label}) {name_clause} RETURN count(DISTINCT v.project_name) AS n",
            params,
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def get_all_projects(
        self,
        limit: int = 1000,
        internal_only: bool = False,
        offset: int = 0,
        name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get all projects with their versions and licence info.

        Args:
            limit: Maximum number of results
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of project/version dicts with optional spdx_id and
            risk_category (aggregated from linked License nodes)
        """
        # Local import avoids a circular import with utils.purl, which imports
        # get_falkordb_service from this module at load time.
        from sbom_graph_api.utils.purl import purl_ecosystem

        node_label = self.get_node_label(internal_only)
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        name_clause = self._name_filter("v", name, params)
        query = f"""
            MATCH (v:{node_label})
            {name_clause}
            OPTIONAL MATCH (v)-[:HAS_LICENSE]->(l:License)
            OPTIONAL MATCH (v)-[:HAS_SOURCE]->(r:SourceRepository)
            OPTIONAL MATCH (v)-[:HAS_TRUST_SCORE]->(t:TrustScore)
            WITH v.project_name AS project_name,
                 v.name AS version,
                 v.package_url AS package_url,
                 v.project_group AS project_group,
                 collect(DISTINCT l.spdx_id) AS spdx_ids,
                 collect(DISTINCT l.risk_category) AS risk_categories,
                 head(collect(DISTINCT r.url)) AS source_repo_url,
                 head(collect(t.direct_score)) AS direct_score,
                 head(collect(t.effective_score)) AS effective_score,
                 head(collect(t.confidence)) AS confidence
            RETURN project_name, version, package_url, spdx_ids,
                   risk_categories, source_repo_url,
                   direct_score, effective_score, confidence, project_group
            ORDER BY project_name, version
            SKIP $offset LIMIT $limit
        """
        result = self.execute_query(query, params)
        rows: list[dict[str, Any]] = []
        for row in result:
            spdx_ids = [x for x in (row[3] or []) if x]
            risk_cats = [x for x in (row[4] or []) if x]
            spdx_id = ", ".join(sorted(set(spdx_ids))) if spdx_ids else ""
            risk_category = self._worst_license_risk(risk_cats) if risk_cats else ""
            direct_score = row[6]
            effective_score = row[7]
            confidence = row[8]
            if isinstance(direct_score, list):
                direct_score = direct_score[0] if direct_score else None
            if isinstance(effective_score, list):
                effective_score = effective_score[0] if effective_score else None
            if isinstance(confidence, list):
                confidence = confidence[0] if confidence else None
            rows.append(
                {
                    "project_name": row[0],
                    "version": row[1],
                    "package_url": row[2],
                    "project_group": row[9],
                    "language": purl_ecosystem(row[2]),
                    "spdx_id": spdx_id,
                    "risk_category": risk_category,
                    "source_repo_url": row[5] if row[5] else None,
                    "direct_score": direct_score,
                    "effective_score": effective_score,
                    "confidence": confidence,
                }
            )
        return rows

    def _application_label(self, internal_only: bool) -> str:
        """Single source of the Application label filter (page + count parity)."""
        return f"Application:{self.internal_label}" if internal_only else "Application"

    def count_all_applications(
        self, internal_only: bool = False, latest_only: bool = False, name: str | None = None
    ) -> int:
        """Count Application nodes (or distinct apps when latest_only) — same filter as page."""
        label_filter = self._application_label(internal_only)
        params: dict[str, Any] = {}
        name_clause = self._name_filter("app", name, params)
        if latest_only:
            query = (
                f"MATCH (app:{label_filter}) {name_clause} "
                "RETURN count(DISTINCT app.project_name) AS n"
            )
        else:
            query = f"MATCH (app:{label_filter}) {name_clause} RETURN count(app) AS n"
        result = self.execute_query(query, params)
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def count_unique_applications(
        self, internal_only: bool = False, name: str | None = None
    ) -> int:
        """Count distinct application project names (same filter as the page query)."""
        label_filter = self._application_label(internal_only)
        params: dict[str, Any] = {}
        name_clause = self._name_filter("app", name, params)
        result = self.execute_query(
            f"MATCH (app:{label_filter}) {name_clause} "
            "RETURN count(DISTINCT app.project_name) AS n",
            params,
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def get_all_applications(
        self,
        limit: int = 1000,
        internal_only: bool = False,
        latest_only: bool = False,
        offset: int = 0,
        name: str | None = None,
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
        # Local import avoids a circular import with utils.purl, which imports
        # get_falkordb_service from this module at load time.
        from sbom_graph_api.utils.purl import purl_ecosystem

        # Build label filter
        if internal_only:
            label_filter = f"Application:{self.internal_label}"
        else:
            label_filter = "Application"

        params: dict[str, Any] = {"limit": limit, "offset": offset}
        name_clause = self._name_filter("app", name, params)
        query = f"""
            MATCH (app:{label_filter})
            {name_clause}
            OPTIONAL MATCH (app)-[:HAS_LICENSE]->(l:License)
            OPTIONAL MATCH (app)-[:HAS_TRUST_SCORE]->(t:TrustScore)
            WITH app.project_name AS project_name,
                 app.name AS version,
                 app.scan_id AS scan_id,
                 app.app_id AS app_id,
                 app.public_id AS public_id,
                 app.repo_url AS repo_url,
                 app.project_group AS project_group,
                 app.package_url AS package_url,
                 labels(app) AS labels,
                 collect(DISTINCT l.spdx_id) AS spdx_ids,
                 collect(DISTINCT l.risk_category) AS risk_categories,
                 head(collect(t.direct_score)) AS direct_score,
                 head(collect(t.effective_score)) AS effective_score,
                 head(collect(t.confidence)) AS confidence
            RETURN project_name, version, scan_id, app_id, public_id,
                   repo_url, labels, spdx_ids, risk_categories,
                   direct_score, effective_score, confidence,
                   project_group, package_url
            ORDER BY project_name, version
            SKIP $offset LIMIT $limit
        """
        result = self.execute_query(query, params)

        applications = []
        for row in result:
            spdx_ids = [x for x in (row[7] or []) if x]
            risk_cats = [x for x in (row[8] or []) if x]
            spdx_id = ", ".join(sorted(set(spdx_ids))) if spdx_ids else ""
            risk_category = self._worst_license_risk(risk_cats) if risk_cats else ""
            direct_score = row[9]
            effective_score = row[10]
            confidence = row[11]
            if isinstance(direct_score, list):
                direct_score = direct_score[0] if direct_score else None
            if isinstance(effective_score, list):
                effective_score = effective_score[0] if effective_score else None
            if isinstance(confidence, list):
                confidence = confidence[0] if confidence else None
            applications.append(
                {
                    "project_name": row[0],
                    "version": row[1],
                    "scan_id": row[2],
                    "app_id": row[3],
                    "public_id": row[4],
                    "repo_url": row[5],
                    "labels": row[6] if row[6] else [],
                    "is_internal": self.internal_label in (row[6] or []),
                    "project_group": row[12],
                    "package_url": row[13],
                    "language": purl_ecosystem(row[13]),
                    "spdx_id": spdx_id,
                    "risk_category": risk_category,
                    "direct_score": direct_score,
                    "effective_score": effective_score,
                    "confidence": confidence,
                }
            )

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
                latest_version = self.get_latest_semver_version(project_name, internal_only)

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
                MATCH (dep:{dep_label})-[r]->(v:{target_label}
                    {{project_name: $project_name, name: $version_name}})
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
        self,
        project_name: str,
        internal_only: bool = False,
        project_group: str | None = None,
    ) -> list[str]:
        """Get all versions of a project.

        Args:
            project_name: The project name
            internal_only: If True, only include internal-labeled nodes
            project_group: Optional group for disambiguation

        Returns:
            List of version strings
        """
        node_label = self.get_node_label(internal_only)
        params: dict[str, Any] = {"project_name": project_name}
        group_clause = ""
        if project_group:
            params["project_group"] = project_group
            group_clause = ", project_group: $project_group"

        query = f"""
            MATCH (v:{node_label} {{project_name: $project_name{group_clause}}})
            RETURN v.name as version
            ORDER BY v.name
        """
        result = self.execute_query(query, params)
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

        try:
            sorted_versions = sorted(versions, key=parse_semver, reverse=True)
            return sorted_versions[0] if sorted_versions else None
        except (ValueError, IndexError):
            # If parsing fails, return None
            return None

    @staticmethod
    def _latest_and_prev(versions: list[str]) -> tuple[str | None, str | None]:
        """Rank version strings and return ``(latest, latest-1)``.

        Uses semver-aware ordering when every version is SemVer-compliant;
        otherwise falls back to descending string order, in which case the
        classification is only approximate. Empty/blank entries are ignored.

        Returns ``(None, None)`` when there are no versions; the second element
        is ``None`` when there is only one.
        """
        vs = [v for v in versions if v]
        if not vs:
            return None, None

        if all(SEMVER_PATTERN.match(v) for v in vs):
            try:
                ordered = sorted(vs, key=parse_semver, reverse=True)
            except (ValueError, IndexError):
                ordered = sorted(vs, reverse=True)
        else:
            ordered = sorted(vs, reverse=True)

        return ordered[0], (ordered[1] if len(ordered) > 1 else None)

    def get_target_version_recency(
        self, project_name: str, internal_only: bool = False
    ) -> tuple[str | None, str | None]:
        """Return the latest and previous (latest-1) versions of a project.

        Uses semver-aware ordering when every version is SemVer-compliant;
        otherwise falls back to descending string order, in which case the
        latest / latest-1 classification is only approximate.

        Args:
            project_name: The project whose versions are ranked.
            internal_only: If True, only include internal-labeled nodes.

        Returns:
            Tuple ``(latest, prev)``; either element may be ``None`` when there
            are too few versions.
        """
        return self._latest_and_prev(
            self.get_all_versions_of_project(project_name, internal_only)
        )

    def get_transitive_dependencies_for_report(
        self,
        project_name: str,
        version_name: str,
        max_depth: int | None = None,
        internal_only: bool = False,
        project_group: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get transitive dependencies in a flat list format suitable for reports.

        Uses the same BFS traversal as get_transitive_dependencies but returns
        a flat list with depth information instead of nodes/edges.

        Args:
            project_name: The project name
            version_name: The version string
            max_depth: Maximum depth to traverse (defaults to DEFAULT_MAX_DEPTH)
            internal_only: Only include internal-labeled nodes
            project_group: Optional group for root node disambiguation

        Returns:
            List of dicts with dependency_project, dependency_version, depth
        """
        # Use the existing transitive dependencies method
        nodes, edges = self.get_transitive_dependencies(
            project_name,
            version_name,
            max_depth,
            internal_only,
            project_group=project_group,
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

    def get_transitive_dependency_purls(self, purl: str, max_depth: int | None = None) -> list[str]:
        """Get transitive dependency purls for a package identified by purl.

        Resolves purl to project/version, runs BFS, returns list of dependency
        purls (excluding the root). Returns empty list if purl not found.

        Args:
            purl: Package URL of the root package
            max_depth: Maximum traversal depth (defaults to DEFAULT_MAX_DEPTH)

        Returns:
            List of dependency purls
        """
        resolved = self.find_version_by_purl(purl)
        if not resolved:
            return []
        nodes, _ = self.get_transitive_dependencies(
            resolved["project_name"],
            resolved["version_name"],
            max_depth=max_depth,
            project_group=resolved.get("project_group"),
        )
        root_id = f"{resolved['project_name']}:{resolved['version_name']}"
        purls: list[str] = []
        for node in nodes:
            if node["id"] == root_id:
                continue
            p = node.get("properties", {}).get("package_url")
            if p and p not in purls:
                purls.append(p)
        return purls

    def get_transitive_dependant_purls(self, purl: str, max_depth: int | None = None) -> list[str]:
        """Get transitive dependant purls (packages that depend on this one).

        Resolves purl to project/version, runs reverse BFS, returns list of
        dependant purls (excluding the root). Returns empty list if purl not found.

        Args:
            purl: Package URL of the root package
            max_depth: Maximum traversal depth (defaults to DEFAULT_MAX_DEPTH)

        Returns:
            List of dependant purls
        """
        resolved = self.find_version_by_purl(purl)
        if not resolved:
            return []
        nodes, _ = self.get_transitive_dependants(
            resolved["project_name"],
            resolved["version_name"],
            max_depth=max_depth,
            skip_scan_filter=True,
            project_group=resolved.get("project_group"),
        )
        root_id = f"{resolved['project_name']}:{resolved['version_name']}"
        purls: list[str] = []
        for node in nodes:
            if node["id"] == root_id:
                continue
            p = node.get("properties", {}).get("package_url")
            if p and p not in purls:
                purls.append(p)
        return purls

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
        if filter_mode == "any":
            # Library node: filter by ANY of the scan_ids
            # Include dependants that share at least one scan_id with root
            return f"""
                MATCH (src:{node_label})-[r]->(tgt:{node_label})
                WHERE ({where_clause})
                AND ANY(sid IN $scan_ids WHERE sid IN src.scan_ids)
                RETURN src, tgt, type(r) as rel_type
                LIMIT $query_limit
            """
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
        project_group: str | None = None,
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
            project_group: Optional group for root node disambiguation

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
        root = self.find_version(project_name, version_name, project_group)
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
        project_group: str | None = None,
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
            project_group: Optional group for root node disambiguation

        Returns:
            Tuple of (nodes list, edges list)
        """
        effective_max_depth = max_depth if max_depth is not None else DEFAULT_MAX_DEPTH

        # Initialize traversal state (includes scan_id filtering info)
        state = self._init_dependants_traversal_state(
            project_name, version_name, internal_only, skip_scan_filter, project_group
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
        project_group: str | None = None,
    ) -> dict[str, Any]:
        """Initialize the traversal state for dependants BFS.

        Args:
            project_name: The root project name
            version_name: The root version string
            internal_only: If True, only include internal-labeled nodes
            skip_scan_filter: If True, use "none" filter mode regardless of scan data
            project_group: Optional group for root node disambiguation

        Returns:
            Dictionary containing all traversal state including scan_id filter info
        """
        root_id = f"{project_name}:{version_name}"
        visited_ids: set[str] = set[str]()
        nodes_dict: dict[str, dict[str, Any]] = {}

        # Fetch and add root node
        root = self.find_version(project_name, version_name, project_group)
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
        project_group: str | None = None,
        name: str | None = None,
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
            project_group: Optional group for root node disambiguation
            name: Optional case-insensitive substring filter on the dependant's
                project_name. Applied to the listed dependants (and the derived
                stats); the full graph is still traversed for path analysis.

        Returns:
            Dict with target info, stats, and dependants list
        """
        name_lower = name.lower() if name else None
        # Get transitive dependants
        nodes, edges = self.get_transitive_dependants(
            project_name,
            version_name,
            max_depth,
            internal_only,
            project_group=project_group,
        )

        root_id = f"{project_name}:{version_name}"

        # Build NetworkX graph for path analysis
        graph: nx.DiGraph = nx.DiGraph()
        node_data = {n["id"]: n for n in nodes}

        for node in node_data.values():
            graph.add_node(node["id"])

        # Add edges (dependant -> target direction)
        for edge in edges:
            graph.add_edge(edge["source"], edge["target"])

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
            self_loops = list(nx.selfloop_edges(graph))
            graph.remove_edges_from(self_loops)
            # Then remove back-edges to break cycles
            remove_cycles_dfs(graph)
        except nx.NetworkXError:
            pass  # Graph error, continue with what we have

        # Calculate partitions using LONGEST path from root to each dependant
        # Use proper DAG longest path algorithm (topological sort based)
        # Since graph has edges dependant -> target, we work on the reversed graph
        graph_reversed = graph.reverse(copy=True)

        # For DAG longest path: use topological sort and dynamic programming
        # Initialize distances from root
        partitions = dict.fromkeys(graph_reversed.nodes(), -1)
        partitions[root_id] = 0

        # Get topological order starting from root (BFS-based for nodes reachable from root)
        # Process in BFS order to ensure we process shorter paths before longer ones
        # Use BFS to get nodes in level order, then process
        visited_order: list[str] = []
        queue = deque([root_id])
        visited_for_order = {root_id}

        while queue:
            current_node = queue.popleft()
            visited_order.append(current_node)
            for successor in graph_reversed.successors(current_node):
                if successor not in visited_for_order:
                    visited_for_order.add(successor)
                    queue.append(successor)

        # Now do longest path: process each node and update successors
        # Repeat until no changes (handles the DAG properly)
        changed = True
        iterations = 0
        max_iterations = len(graph_reversed.nodes()) + 1

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for current_node in visited_order:
                if partitions[current_node] < 0:
                    continue
                for successor in graph_reversed.successors(current_node):
                    new_dist = partitions[current_node] + 1
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

            if name_lower and name_lower not in data.get("project_name", "").lower():
                continue  # Doesn't match the name filter

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
                all_paths = nx.all_simple_paths(graph, node_id, root_id, cutoff=path_cutoff)
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

    def find_snapshot_dependencies(
        self, internal_only: bool = False, limit: int | None = None, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Find all applications with SNAPSHOT dependencies.

        Args:
            internal_only: If True, only include internal-labeled nodes
            limit: Page size for paginated reads (``None`` returns all rows)
            offset: Number of rows to skip (paginated reads)

        Returns:
            List of dicts with application and dependency information
        """
        node_label = self.get_node_label(internal_only)
        page_clause, params = self._page_clause(limit, offset)
        query = f"""
            MATCH (app:{node_label})-[r]->(dep:{node_label})
            WHERE dep.name CONTAINS 'SNAPSHOT'
            RETURN app.project_name as application,
                   app.name as app_version,
                   dep.project_name as dependency,
                   dep.name as dep_version
            ORDER BY app.project_name, app.name
            {page_clause}
        """
        result = self.execute_query(query, params)
        return [
            {
                "application": row[0],
                "app_version": row[1],
                "dependency": row[2],
                "dep_version": row[3],
            }
            for row in result
        ]

    def count_snapshot_dependencies(self, internal_only: bool = False) -> int:
        """Count SNAPSHOT dependency edges (same filter as the page query)."""
        node_label = self.get_node_label(internal_only)
        result = self.execute_query(
            f"""
            MATCH (app:{node_label})-[r]->(dep:{node_label})
            WHERE dep.name CONTAINS 'SNAPSHOT'
            RETURN count(r) AS n
            """,
            {},
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def find_self_dependencies(
        self, internal_only: bool = False, limit: int | None = None, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Find nodes that depend on themselves.

        Args:
            internal_only: If True, only include internal-labeled nodes
            limit: Page size for paginated reads (``None`` returns all rows)
            offset: Number of rows to skip (paginated reads)

        Returns:
            List of dicts with self-dependency information
        """
        node_label = self.get_node_label(internal_only)
        page_clause, params = self._page_clause(limit, offset)
        query = f"""
            MATCH (v:{node_label})-[r]->(v)
            RETURN v.project_name as project_name,
                   v.name as version,
                   type(r) as relationship_type
            ORDER BY v.project_name, v.name
            {page_clause}
        """
        result = self.execute_query(query, params)
        return [
            {
                "project_name": row[0],
                "version": row[1],
                "relationship_type": row[2],
            }
            for row in result
        ]

    def count_snapshot_applications(self, internal_only: bool = False) -> int:
        """Count distinct applications that have SNAPSHOT dependencies."""
        node_label = self.get_node_label(internal_only)
        result = self.execute_query(
            f"""
            MATCH (app:{node_label})-[r]->(dep:{node_label})
            WHERE dep.name CONTAINS 'SNAPSHOT'
            RETURN count(DISTINCT app.project_name) AS n
            """,
            {},
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def count_snapshot_dependency_versions(self, internal_only: bool = False) -> int:
        """Count distinct SNAPSHOT dependency project names."""
        node_label = self.get_node_label(internal_only)
        result = self.execute_query(
            f"""
            MATCH (app:{node_label})-[r]->(dep:{node_label})
            WHERE dep.name CONTAINS 'SNAPSHOT'
            RETURN count(DISTINCT dep.project_name) AS n
            """,
            {},
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def count_self_dependencies(self, internal_only: bool = False) -> int:
        """Count self-dependency edges (same filter as the page query)."""
        node_label = self.get_node_label(internal_only)
        result = self.execute_query(
            f"MATCH (v:{node_label})-[r]->(v) RETURN count(r) AS n", {}
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def count_self_dependency_projects(self, internal_only: bool = False) -> int:
        """Count distinct projects that depend on themselves."""
        node_label = self.get_node_label(internal_only)
        result = self.execute_query(
            f"MATCH (v:{node_label})-[r]->(v) RETURN count(DISTINCT v.project_name) AS n", {}
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def _classify_version_release(
        self, version: str, base_counts: dict[tuple[int, int, int], int]
    ) -> dict[str, Any]:
        """Classify a version's SemVer compliance and release status.

        Args:
            version: The version string to classify.
            base_counts: Map of ``(major, minor, patch)`` base → number of
                pre-release versions of the same project sharing that base. Used
                to flag suspected branch-name versioning.

        Returns:
            Dict with ``semver_compliant`` (bool), ``released`` (bool) and a
            human-readable ``reason`` (``""`` for a clean released version).
        """
        semver_compliant = bool(SEMVER_PATTERN.match(version))
        is_snapshot = "snapshot" in version.lower()

        prerelease = ""
        base: tuple[int, int, int] | None = None
        if semver_compliant:
            major, minor, patch, prerelease = _split_semver(version)
            base = (major, minor, patch)
        has_prerelease = bool(prerelease)

        # A clean release is SemVer-compliant with no pre-release/SNAPSHOT marker.
        released = semver_compliant and not (is_snapshot or has_prerelease)

        if not semver_compliant:
            reason = self._categorize_non_semver_version(version)
        elif is_snapshot:
            reason = "SNAPSHOT build (unreleased)"
        elif has_prerelease:
            if base is not None and base_counts.get(base, 0) >= 2:
                reason = "Suspected branch-name versioning"
            else:
                reason = "Pre-release (unreleased)"
        else:
            reason = ""

        return {
            "semver_compliant": semver_compliant,
            "released": released,
            "reason": reason,
        }

    def find_non_semver_versions(self, internal_only: bool = False) -> list[dict[str, Any]]:
        """Find versions that are non-SemVer *or* SemVer-but-suspect.

        Returns versions that either fail ``SEMVER_PATTERN`` or, while technically
        SemVer-compliant, are unreleased (pre-release / SNAPSHOT) or exhibit
        suspected branch-name versioning. Clean released versions are omitted.

        Common non-SemVer patterns include:
        - SNAPSHOT versions (e.g., 1.0.0-SNAPSHOT)
        - Date-based versions (e.g., 20230101)
        - Branch-based versions (e.g., feature-branch-1234)
        - Hash-based versions (e.g., abc123def)

        Args:
            internal_only: If True, only include internal-labeled nodes

        Returns:
            List of dicts with project_name, version, reason, semver_compliant,
            released, and labels.
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

        # Materialise rows and per-project pre-release base counts (for branch-
        # name detection) in a single pass over the result set.
        rows: list[tuple[Any, str, Any]] = []
        base_counts_by_project: dict[str, dict[tuple[int, int, int], int]] = {}
        for row in result:
            project_name, version, labels = row[0], row[1], row[2]
            if not version:
                continue
            rows.append((project_name, version, labels))
            if SEMVER_PATTERN.match(version):
                major, minor, patch, prerelease = _split_semver(version)
                if prerelease:
                    counts = base_counts_by_project.setdefault(project_name, {})
                    base = (major, minor, patch)
                    counts[base] = counts.get(base, 0) + 1

        suspect_versions = []
        for project_name, version, labels in rows:
            classification = self._classify_version_release(
                version, base_counts_by_project.get(project_name, {})
            )
            # Clean released SemVer versions are not suspect — skip them.
            if classification["semver_compliant"] and classification["released"]:
                continue
            suspect_versions.append(
                {
                    "project_name": project_name,
                    "version": version,
                    "reason": classification["reason"],
                    "semver_compliant": classification["semver_compliant"],
                    "released": classification["released"],
                    "labels": labels,
                }
            )

        return suspect_versions

    def count_duplicate_version_nodes(self) -> int:
        """Count (project_name, name) groups with duplicate or split nodes.

        A group qualifies when it spans more than one distinct
        (project_group, package_url) coordinate (a provenance split) or when any
        single coordinate is backed by more than one node (a genuine duplicate).

        Returns:
            The number of qualifying groups (same filter as the page query).
        """
        query = """
            MATCH (v:Version)
            WITH v.project_name AS project_name, v.name AS version,
                 v.project_group AS project_group, v.package_url AS package_url,
                 count(*) AS node_count
            WITH project_name, version,
                 count(*) AS distinct_coordinates,
                 max(node_count) AS max_combo_count
            WHERE distinct_coordinates > 1 OR max_combo_count > 1
            RETURN count(*) AS n
        """
        result = self.execute_query(query, {})
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def get_duplicate_node_stats(self) -> dict[str, int]:
        """Return duplicate/provenance-split KPI counters in one aggregation.

        Promotes the Phase 3b diagnostic to a trendable data-quality KPI: the
        total number of flagged ``(project_name, version)`` groups plus the
        breakdown by kind. ``provenance_splits`` and ``genuine_duplicates``
        overlap by design — a group that is both is counted in each.

        Returns:
            Dict with ``affected_groups``, ``provenance_splits`` and
            ``genuine_duplicates`` counts (all ``0`` on an empty graph).
        """
        query = """
            MATCH (v:Version)
            WITH v.project_name AS project_name, v.name AS version,
                 v.project_group AS project_group, v.package_url AS package_url,
                 count(*) AS node_count
            WITH project_name, version,
                 count(*) AS distinct_coordinates,
                 max(node_count) AS max_combo_count
            WHERE distinct_coordinates > 1 OR max_combo_count > 1
            RETURN count(*) AS affected_groups,
                   sum(CASE WHEN distinct_coordinates > 1 THEN 1 ELSE 0 END)
                       AS provenance_splits,
                   sum(CASE WHEN max_combo_count > 1 THEN 1 ELSE 0 END)
                       AS genuine_duplicates
        """
        result = self.execute_query(query, {})
        if not result or result[0] is None or result[0][0] is None:
            return {"affected_groups": 0, "provenance_splits": 0, "genuine_duplicates": 0}
        row = result[0]
        return {
            "affected_groups": int(row[0]),
            "provenance_splits": int(row[1]) if row[1] is not None else 0,
            "genuine_duplicates": int(row[2]) if row[2] is not None else 0,
        }

    def find_duplicate_version_nodes(
        self, limit: int = 1000, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Find Version nodes that duplicate or split on provenance.

        Groups Version nodes by ``(project_name, name)`` and surfaces groups
        that either:

        - span multiple distinct ``(project_group, package_url)`` coordinates
          (**provenance splits** — expected once purl is part of node identity,
          but worth monitoring), or
        - have more than one node for a single coordinate (**genuine
          duplicates** — same project_name/name/project_group/package_url with
          ``count > 1``, which should not happen).

        Args:
            limit: Maximum number of groups to return.
            offset: Number of groups to skip (pagination).

        Returns:
            List of group dicts with coordinate/duplicate diagnostics.
        """
        query = """
            MATCH (v:Version)
            WITH v.project_name AS project_name, v.name AS version,
                 v.project_group AS project_group, v.package_url AS package_url,
                 count(*) AS node_count
            WITH project_name, version,
                 collect({
                     project_group: project_group,
                     package_url: package_url,
                     node_count: node_count
                 }) AS combos,
                 sum(node_count) AS total_nodes,
                 max(node_count) AS max_combo_count
            WHERE size(combos) > 1 OR max_combo_count > 1
            RETURN project_name, version, combos, total_nodes,
                   size(combos) AS distinct_coordinates, max_combo_count
            ORDER BY project_name, version
            SKIP $offset LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit, "offset": offset})

        rows: list[dict[str, Any]] = []
        for row in result:
            combos = row[2] or []
            groups = sorted({(c.get("project_group") or "") for c in combos})
            purls = sorted({(c.get("package_url") or "") for c in combos})
            distinct_coordinates = int(row[4]) if row[4] is not None else len(combos)
            max_combo_count = int(row[5]) if row[5] is not None else 1
            is_genuine_duplicate = max_combo_count > 1
            is_provenance_split = distinct_coordinates > 1
            if is_genuine_duplicate and is_provenance_split:
                classification = "Duplicate + provenance split"
            elif is_genuine_duplicate:
                classification = "Genuine duplicate"
            else:
                classification = "Provenance split"
            rows.append(
                {
                    "project_name": row[0],
                    "version": row[1],
                    "distinct_coordinates": distinct_coordinates,
                    "total_nodes": int(row[3]) if row[3] is not None else 0,
                    "max_node_count": max_combo_count,
                    "is_genuine_duplicate": is_genuine_duplicate,
                    "is_provenance_split": is_provenance_split,
                    "classification": classification,
                    "project_groups": groups,
                    "package_urls": purls,
                }
            )
        return rows

    # ------------------------------------------------------------------
    # Phase 7 reporting-gap reports
    # ------------------------------------------------------------------

    def get_purl_coverage(self, internal_only: bool = False) -> dict[str, int]:
        """Return purl-identity coverage counters over Version nodes.

        Reports how many Version nodes carry a non-empty ``package_url`` (and
        therefore participate in the Phase 3a purl node identity) versus the
        total — the fraction still sitting in the name/project_name/
        project_group fallback bucket is ``total - with_purl``.

        Args:
            internal_only: If True, only count internal-labeled nodes.

        Returns:
            Dict with ``total``, ``with_purl`` and ``without_purl`` counts.
        """
        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{node_label})
            RETURN count(v) AS total,
                   sum(CASE WHEN v.package_url IS NOT NULL AND v.package_url <> ''
                            THEN 1 ELSE 0 END) AS with_purl
        """
        result = self.execute_query(query, {})
        if not result or result[0] is None or result[0][0] is None:
            return {"total": 0, "with_purl": 0, "without_purl": 0}
        total = int(result[0][0])
        with_purl = int(result[0][1]) if result[0][1] is not None else 0
        return {
            "total": total,
            "with_purl": with_purl,
            "without_purl": total - with_purl,
        }

    def get_ecosystem_breakdown(
        self, internal_only: bool = False, limit: int | None = None, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Aggregate Version nodes per purl ecosystem (package type).

        The package type is extracted from ``package_url`` in-query (a grouped
        aggregation, so raw rows are never materialised) and mapped to a
        language/ecosystem label in Python. Nodes with no/invalid purl fall into
        an ``(none)`` bucket labelled ``Unknown``.

        Args:
            internal_only: If True, only include internal-labeled nodes.
            limit: Max rows to return (``None`` = all); ecosystems are few.
            offset: Rows to skip (pagination).

        Returns:
            List of dicts: ``ecosystem`` (purl type), ``language`` (label),
            ``components``, ``projects``, ``pct`` (share of components).
        """
        # Local import: purl.py imports get_falkordb_service at module top, so a
        # top-level import here would be circular (mirrors get_all_projects).
        from sbom_graph_api.utils.purl import ecosystem_label

        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{node_label})
            WITH CASE
                     WHEN v.package_url IS NOT NULL AND v.package_url STARTS WITH 'pkg:'
                     THEN toLower(split(split(v.package_url, 'pkg:')[1], '/')[0])
                     ELSE ''
                 END AS ptype, v
            WITH ptype, count(v) AS components, count(DISTINCT v.project_name) AS projects
            RETURN ptype, components, projects
        """
        result = self.execute_query(query, {})

        raw: list[tuple[str, int, int]] = []
        total_components = 0
        for row in result:
            ptype = row[0] or ""
            components = int(row[1]) if row[1] is not None else 0
            projects = int(row[2]) if row[2] is not None else 0
            raw.append((ptype, components, projects))
            total_components += components

        rows: list[dict[str, Any]] = []
        for ptype, components, projects in raw:
            pct = round(components / total_components * 100, 1) if total_components else 0.0
            rows.append(
                {
                    "ecosystem": ptype or "(none)",
                    "language": ecosystem_label(ptype) or "Unknown",
                    "components": components,
                    "projects": projects,
                    "pct": pct,
                }
            )
        rows.sort(key=lambda r: (-r["components"], r["language"]))

        if limit is not None:
            return rows[offset : offset + limit]
        return rows

    def count_ecosystems(self, internal_only: bool = False) -> int:
        """Count distinct purl ecosystems (see :meth:`get_ecosystem_breakdown`)."""
        return len(self.get_ecosystem_breakdown(internal_only=internal_only))

    def get_unreleased_in_production(
        self, internal_only: bool = False, limit: int | None = None, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Find applications depending on unreleased dependency versions.

        Joins the Phase 4 ``released = False`` classification (SNAPSHOT /
        pre-release / branch-name / non-SemVer) back to the dependants that
        consume those versions, so the result is consumer-centric: which apps
        ship against a version that is not a clean release.

        Args:
            internal_only: If True, only include internal-labeled nodes.
            limit: Max rows to return (``None`` = all); ``offset`` to skip.
            offset: Rows to skip (pagination).

        Returns:
            List of dicts: ``application``, ``application_version``,
            ``dependency``, ``dependency_version``, ``reason``.
        """
        suspects = [
            s
            for s in self.find_non_semver_versions(internal_only)
            if not s.get("released", True)
        ]
        if not suspects:
            return []

        reason_by_key = {(s["project_name"], s["version"]): s["reason"] for s in suspects}
        target_projects = sorted({s["project_name"] for s in suspects})

        node_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (dep:{node_label})-[r]->(v:{node_label})
            WHERE v.project_name IN $projects
            RETURN DISTINCT dep.project_name AS application,
                   dep.name AS application_version,
                   v.project_name AS dependency,
                   v.name AS dependency_version
            ORDER BY dep.project_name, dep.name, v.project_name, v.name
        """
        result = self.execute_query(query, {"projects": target_projects})

        rows: list[dict[str, Any]] = []
        for row in result:
            key = (row[2], row[3])
            reason = reason_by_key.get(key)
            if reason is None:
                # Edge points at a released version of a project that also has
                # unreleased versions — not the one we're flagging.
                continue
            rows.append(
                {
                    "application": row[0],
                    "application_version": row[1],
                    "dependency": row[2],
                    "dependency_version": row[3],
                    "reason": reason,
                }
            )

        if limit is not None:
            return rows[offset : offset + limit]
        return rows

    def count_unreleased_in_production(self, internal_only: bool = False) -> int:
        """Count application→unreleased-dependency edges (see sibling method)."""
        return len(self.get_unreleased_in_production(internal_only=internal_only))

    def get_dependency_freshness(
        self, internal_only: bool = False, limit: int | None = None, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Fleet-wide dependency-freshness: consumers on latest / latest-1 / stale.

        For every dependency library with at least one consumer, rank its
        versions (semver-aware) to find latest / latest-1, then classify each
        consuming edge and aggregate. Ordered by fan-in (consumer count) so the
        highest-impact upgrade targets sort first. Libraries with no consumers
        are omitted (nothing to upgrade).

        Args:
            internal_only: If True, only include internal-labeled nodes.
            limit: Max rows to return (``None`` = all); ``offset`` to skip.
            offset: Rows to skip (pagination).

        Returns:
            List of dicts: ``target_project``, ``latest``, ``prev``,
            ``consumers``, ``on_latest``, ``on_latest_or_prev``, ``stale``,
            ``pct_stale``.
        """
        node_label = self.get_node_label(internal_only)

        # All versions per library, to establish the true latest / latest-1
        # (the latest version may itself have zero consumers).
        versions_by_lib: dict[str, list[str]] = {}
        for row in self.execute_query(
            f"""
            MATCH (v:{node_label})
            WITH v.project_name AS lib, collect(DISTINCT v.name) AS versions
            RETURN lib, versions
            """,
            {},
        ):
            versions_by_lib[row[0]] = [v for v in (row[1] or []) if v]

        # Consumer (fan-in) counts per (library, target version).
        consumer_rows = self.execute_query(
            f"""
            MATCH (dep:{node_label})-[r]->(v:{node_label})
            WITH v.project_name AS lib, v.name AS target_version,
                 count(DISTINCT dep) AS consumers
            RETURN lib, target_version, consumers
            """,
            {},
        )

        by_lib: dict[str, list[tuple[str, int]]] = {}
        for row in consumer_rows:
            lib, target_version = row[0], row[1]
            consumers = int(row[2]) if row[2] is not None else 0
            by_lib.setdefault(lib, []).append((target_version, consumers))

        rows: list[dict[str, Any]] = []
        for lib, edges in by_lib.items():
            latest, prev = self._latest_and_prev(versions_by_lib.get(lib, []))
            total_consumers = sum(c for _, c in edges)
            on_latest = sum(c for tv, c in edges if latest is not None and tv == latest)
            on_prev = sum(c for tv, c in edges if prev is not None and tv == prev)
            on_latest_or_prev = on_latest + on_prev
            stale = total_consumers - on_latest_or_prev
            pct_stale = (
                round(stale / total_consumers * 100, 1) if total_consumers else 0.0
            )
            rows.append(
                {
                    "target_project": lib,
                    "latest": latest or "",
                    "prev": prev or "",
                    "consumers": total_consumers,
                    "on_latest": on_latest,
                    "on_latest_or_prev": on_latest_or_prev,
                    "stale": stale,
                    "pct_stale": pct_stale,
                }
            )

        rows.sort(key=lambda r: (-r["consumers"], -r["pct_stale"], r["target_project"]))

        if limit is not None:
            return rows[offset : offset + limit]
        return rows

    def count_dependency_freshness(self, internal_only: bool = False) -> int:
        """Count libraries with at least one consumer (see sibling method)."""
        return len(self.get_dependency_freshness(internal_only=internal_only))

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
        project_group: str | None = None,
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
            project_group: Optional group for root node disambiguation

        Returns:
            Dict with:
                - target: The target project info
                - multi_version_dependencies: List of dependencies with multiple
                  versions and their contributing applications
        """
        # Get the target project's scan_ids
        root = self.find_version(project_name, version_name, project_group)
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
            project_name,
            version_name,
            max_depth,
            internal_only,
            project_group=project_group,
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
        name: str | None = None,
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
            name: Optional case-insensitive substring filter on the dependant's
                project_name. Versions with no matching dependant are dropped and
                per-version / total counts are recomputed from the matches.

        Returns:
            Dict with:
                - library: The library being analyzed
                - total_versions: Number of distinct versions found
                - total_dependants: Total count of direct dependants across all versions
                - versions: List of version info with dependants for each
        """
        internal_label = self.config.internal_label
        name_lower = name.lower() if name else None

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
                    dependants_list.append(
                        {
                            "project_name": dep.get("project_name", ""),
                            "version": dep.get("version", ""),
                            "project_group": dep.get("project_group", ""),
                            "is_internal": internal_label in dep_labels,
                        }
                    )

            # Sort dependants by project name
            dependants_list.sort(key=lambda x: (x["project_name"], x["version"]))

            if name_lower is not None:
                dependants_list = [
                    d for d in dependants_list if name_lower in d["project_name"].lower()
                ]
                if not dependants_list:
                    continue  # No dependant matches the name filter
                dependant_count = len(dependants_list)

            versions.append(
                {
                    "version": version_name,
                    "project_group": project_group,
                    "is_internal": is_internal,
                    "dependant_count": dependant_count,
                    "dependants": dependants_list,
                }
            )

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

    @staticmethod
    def _filter_vulnerabilities_defect_glob(
        items: list[dict[str, Any]],
        pattern: str,
    ) -> list[dict[str, Any]]:
        """Case-insensitive fnmatch on ``defect_id`` (FalkorDB has no ``=~``)."""
        pat = pattern.strip().lower()
        return [
            v
            for v in items
            if fnmatch.fnmatch((v.get("defect_id") or "").strip().lower(), pat)
        ]

    def get_all_vulnerabilities(
        self,
        internal_only: bool = False,
        defect_id_match: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get all vulnerabilities with their affected versions and VEX status.

        Includes vex_status (most recent VEX statement status, or null) per
        vulnerability via OPTIONAL MATCH to VexStatement nodes.

        Args:
            internal_only: If True, only include vulnerabilities affecting
                          internal-labeled nodes
            defect_id_match: Optional validated prefix or ``*``-glob filter
                (matched case-insensitively against defect id / primary id).

        Returns:
            List of vulnerability dicts with severity, affected versions,
            vex_status, etc.
        """
        where_prefix = ""
        query_params: dict[str, Any] = {}
        use_glob_postfilter = False
        if defect_id_match:
            use_glob_postfilter = defect_id_match_uses_glob(defect_id_match)
            if not use_glob_postfilter:
                where_prefix = """
                WHERE toLower(toString(COALESCE(d.defect_id, d.id, ''))) STARTS WITH $defect_id_prefix
"""
                query_params["defect_id_prefix"] = (
                    defect_id_match_prefix_for_starts_with(defect_id_match)
                )

        version_label = self.get_node_label(internal_only)
        if internal_only:
            query = f"""
                MATCH (v:{version_label})-[:VERSION_DEFECT]->(d:Defect)
                OPTIONAL MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
                WITH d,
                     collect(DISTINCT {{
                         project_name: v.project_name,
                         version: v.name,
                         project_group: v.project_group
                     }}) AS affected_versions,
                     collect(DISTINCT {{
                         status: s.status,
                         timestamp: s.timestamp
                     }}) AS vex_statements
{where_prefix}                RETURN COALESCE(d.defect_id, d.id) AS defect_id,
                       COALESCE(d.title, d.description) AS title,
                       d.description AS description,
                       d.severity AS severity,
                       COALESCE(d.cvss_score, d.cvss) AS cvss_score,
                       d.cwe_id AS cwe_id,
                       d.published_date AS published_date,
                       d.last_enriched_at AS last_enriched_at,
                       d.aliases AS aliases,
                       d.enrichment_source AS enrichment_source,
                       affected_versions,
                       vex_statements
                ORDER BY
                    CASE d.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'critical' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'high' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'medium' THEN 3
                        WHEN 'LOW' THEN 4
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    COALESCE(d.cvss_score, d.cvss) DESC
            """
        else:
            query = f"""
                MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect)
                OPTIONAL MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
                WITH d,
                     collect(DISTINCT {{
                         project_name: v.project_name,
                         version: v.name,
                         project_group: v.project_group
                     }}) AS affected_versions,
                     collect(DISTINCT {{
                         status: s.status,
                         timestamp: s.timestamp
                     }}) AS vex_statements
{where_prefix}                RETURN COALESCE(d.defect_id, d.id) AS defect_id,
                       COALESCE(d.title, d.description) AS title,
                       d.description AS description,
                       d.severity AS severity,
                       COALESCE(d.cvss_score, d.cvss) AS cvss_score,
                       d.cwe_id AS cwe_id,
                       d.published_date AS published_date,
                       d.last_enriched_at AS last_enriched_at,
                       d.aliases AS aliases,
                       d.enrichment_source AS enrichment_source,
                       affected_versions,
                       vex_statements
                ORDER BY
                    CASE d.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'critical' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'high' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'medium' THEN 3
                        WHEN 'LOW' THEN 4
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    COALESCE(d.cvss_score, d.cvss) DESC
            """

        result = self.execute_query(query, query_params)

        vulnerabilities = []
        for row in result:
            vex_statements = row[11] or []
            vex_status = self._latest_vex_status(vex_statements)

            vulnerabilities.append(
                {
                    "defect_id": row[0],
                    "title": row[1],
                    "description": row[2],
                    "severity": row[3],
                    "cvss_score": row[4],
                    "cwe_id": row[5],
                    "published_date": row[6],
                    "last_enriched_at": row[7],
                    "aliases": row[8] or [],
                    "enrichment_source": row[9],
                    "affected_versions": row[10] if row[10] else [],
                    "vex_status": vex_status,
                }
            )

        if defect_id_match and use_glob_postfilter:
            vulnerabilities = self._filter_vulnerabilities_defect_glob(
                vulnerabilities,
                defect_id_match,
            )

        return vulnerabilities

    def get_vulnerability_summary_stats(
        self,
        internal_only: bool = False,
        defect_id_match: str | None = None,
    ) -> dict[str, Any]:
        """Return aggregate stats (severity counts, VEX coverage) in a single query.

        Used to build the stats block on the paginated HTML report without
        fetching all row data (PERF-001).
        """
        where_clause = ""
        query_params: dict[str, Any] = {}

        if defect_id_match and not defect_id_match_uses_glob(defect_id_match):
            where_clause = (
                "                WHERE toLower(toString(COALESCE(d.defect_id, d.id, '')))"
                " STARTS WITH $defect_id_prefix\n"
            )
            query_params["defect_id_prefix"] = defect_id_match_prefix_for_starts_with(
                defect_id_match
            )

        version_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{version_label})-[:VERSION_DEFECT]->(d:Defect)
            OPTIONAL MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
            WITH d,
                 collect(DISTINCT {{version: v.name}}) AS affected_versions,
                 collect(DISTINCT s.status) AS statuses
{where_clause}            RETURN d.severity AS severity,
                   size(affected_versions) AS affected_count,
                   size([x IN statuses WHERE x IS NOT NULL]) AS vex_count
        """
        result = self.execute_query(query, query_params)

        severity_counts: dict[str, int] = {}
        total_affected = 0
        total_with_vex = 0

        for row in result:
            sev = (row[0] or "UNKNOWN").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_affected += row[1] or 0
            if row[2]:
                total_with_vex += 1

        if defect_id_match and defect_id_match_uses_glob(defect_id_match):
            # glob: must fall back to the full list for accurate counts
            all_vulns = self.get_all_vulnerabilities(internal_only, defect_id_match)
            severity_counts = {}
            total_affected = 0
            total_with_vex = 0
            for v in all_vulns:
                sev = (v.get("severity") or "UNKNOWN").upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                total_affected += len(v.get("affected_versions", []))
                if v.get("vex_status"):
                    total_with_vex += 1

        total = sum(severity_counts.values())
        return {
            "total": total,
            "with_vex": total_with_vex,
            "severity_counts": severity_counts,
            "total_affected": total_affected,
        }

    def get_all_vulnerabilities_paged(
        self,
        internal_only: bool = False,
        defect_id_match: str | None = None,
        vex_filter: str | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Paged fetch of vulnerabilities with optional VEX/defect_id filters (PERF-001/SEC-003)."""
        where_prefix = ""
        query_params: dict[str, Any] = {}
        use_glob_postfilter = False

        if defect_id_match:
            use_glob_postfilter = defect_id_match_uses_glob(defect_id_match)
            if not use_glob_postfilter:
                where_prefix = (
                    "                WHERE toLower(toString(COALESCE(d.defect_id, d.id, '')))"
                    " STARTS WITH $defect_id_prefix\n"
                )
                query_params["defect_id_prefix"] = defect_id_match_prefix_for_starts_with(
                    defect_id_match
                )

        page_clause, page_params = self._page_clause(limit, offset)
        query_params.update(page_params)

        version_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{version_label})-[:VERSION_DEFECT]->(d:Defect)
            OPTIONAL MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
            WITH d,
                 collect(DISTINCT {{
                     project_name: v.project_name,
                     version: v.name,
                     project_group: v.project_group
                 }}) AS affected_versions,
                 collect(DISTINCT {{
                     status: s.status,
                     timestamp: s.timestamp
                 }}) AS vex_statements
{where_prefix}            RETURN COALESCE(d.defect_id, d.id) AS defect_id,
                   COALESCE(d.title, d.description) AS title,
                   d.description AS description,
                   d.severity AS severity,
                   COALESCE(d.cvss_score, d.cvss) AS cvss_score,
                   d.cwe_id AS cwe_id,
                   d.published_date AS published_date,
                   d.last_enriched_at AS last_enriched_at,
                   d.aliases AS aliases,
                   d.enrichment_source AS enrichment_source,
                   affected_versions,
                   vex_statements
            ORDER BY
                CASE d.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'critical' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'high' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'medium' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                COALESCE(d.cvss_score, d.cvss) DESC
            {page_clause}
        """

        result = self.execute_query(query, query_params)

        vulnerabilities: list[dict[str, Any]] = []
        for row in result:
            vex_statements = row[11] or []
            vex_status = self._latest_vex_status(vex_statements)
            vulnerabilities.append({
                "defect_id": row[0],
                "title": row[1],
                "description": row[2],
                "severity": row[3],
                "cvss_score": row[4],
                "cwe_id": row[5],
                "published_date": row[6],
                "last_enriched_at": row[7],
                "aliases": row[8] or [],
                "enrichment_source": row[9],
                "affected_versions": row[10] if row[10] else [],
                "vex_status": vex_status,
            })

        if defect_id_match and use_glob_postfilter:
            vulnerabilities = self._filter_vulnerabilities_defect_glob(
                vulnerabilities, defect_id_match
            )

        if vex_filter == "hide_not_affected":
            vulnerabilities = [v for v in vulnerabilities if v.get("vex_status") != "not_affected"]
        elif vex_filter == "under_investigation":
            vulnerabilities = [
                v for v in vulnerabilities if v.get("vex_status") == "under_investigation"
            ]

        return vulnerabilities

    def count_all_vulnerabilities(
        self,
        internal_only: bool = False,
        defect_id_match: str | None = None,
        vex_filter: str | None = None,
    ) -> int:
        """Count vulnerabilities matching filters (PERF-001 — backs pagination)."""
        if vex_filter and vex_filter != "all":
            all_vulns = self.get_all_vulnerabilities(internal_only, defect_id_match)
            if vex_filter == "hide_not_affected":
                return sum(1 for v in all_vulns if v.get("vex_status") != "not_affected")
            if vex_filter == "under_investigation":
                return sum(1 for v in all_vulns if v.get("vex_status") == "under_investigation")
            return len(all_vulns)

        where_clause = ""
        query_params: dict[str, Any] = {}

        if defect_id_match and not defect_id_match_uses_glob(defect_id_match):
            where_clause = (
                "                WHERE toLower(toString(COALESCE(d.defect_id, d.id, '')))"
                " STARTS WITH $defect_id_prefix\n"
            )
            query_params["defect_id_prefix"] = defect_id_match_prefix_for_starts_with(
                defect_id_match
            )

        version_label = self.get_node_label(internal_only)
        query = f"""
            MATCH (v:{version_label})-[:VERSION_DEFECT]->(d:Defect)
            WITH d
{where_clause}            RETURN COUNT(DISTINCT d) AS total
        """
        result = self.execute_query(query, query_params)
        raw = result[0][0] if result else 0

        if defect_id_match and defect_id_match_uses_glob(defect_id_match):
            all_vulns = self.get_all_vulnerabilities(internal_only, defect_id_match)
            return len(all_vulns)

        return int(raw) if raw is not None else 0

    def _latest_vex_status(
        self,
        vex_statements: list[dict[str, Any]],
    ) -> str | None:
        """Extract status from the most recent VEX statement.

        Args:
            vex_statements: List of dicts with status and timestamp keys

        Returns:
            Status string or None if no valid statements
        """
        valid = [
            s for s in vex_statements if s and s.get("status") and isinstance(s.get("status"), str)
        ]
        if not valid:
            return None

        # Sort by timestamp descending; null timestamps go last
        def _sort_key(s: dict[str, Any]) -> tuple[int, str]:
            ts = s.get("timestamp")
            return (0 if ts else 1, str(ts) if ts else "")

        sorted_stmts = sorted(valid, key=_sort_key, reverse=True)
        return sorted_stmts[0].get("status")

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
        version_label = self.get_node_label(internal_only)
        query = f"""
                MATCH (d:Defect)
                WHERE d.defect_id = $defect_id OR d.id = $defect_id
                OPTIONAL MATCH (v:{version_label})-[:VERSION_DEFECT]->(d)
                RETURN COALESCE(d.defect_id, d.id) as defect_id,
                       d.title as title,
                       d.description as description,
                       d.severity as severity,
                       COALESCE(d.cvss_score, d.cvss) as cvss_score,
                       d.cwe_id as cwe_id,
                       d.published_date as published_date,
                       collect(DISTINCT {{
                           project_name: v.project_name,
                           version: v.name,
                           project_group: v.project_group
                       }}) as affected_versions
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
                        "labels": labels,
                        "affected_by": [
                            {
                                "project_name": project_name,
                                "version": version,
                            }
                        ],
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

        Returns inDegree and outDegree for all internal ``Version`` nodes,
        suitable for analyzing which libraries are most depended upon (high
        inDegree) or have the most dependencies (high outDegree). Counts are
        derived from live relationship patterns (``size``), so they do not
        rely on precomputed ``inDegree`` / ``outDegree`` node properties.

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

        # Map sort_by to aliases / properties (degrees computed per query)
        sort_field_map = {
            "inDegree": "inDegree",
            "outDegree": "outDegree",
            "project_name": "v.project_name",
            "version_name": "v.name",
        }
        sort_field = sort_field_map.get(sort_by, "inDegree")

        version_label = self.get_node_label(True)
        query = f"""
            MATCH (v:{version_label})
            WITH v, size((v)<--()) AS inDegree, size((v)-->()) AS outDegree
            RETURN
                v.project_group AS project_group,
                v.project_name AS project_name,
                v.name AS version_name,
                inDegree,
                outDegree
            ORDER BY {sort_field} {sort_direction}, v.project_name ASC, v.name ASC
            LIMIT $limit
        """

        result = self.execute_query(query, {"limit": limit})

        centrality_data = []
        for row in result:
            centrality_data.append(
                {
                    "project_group": row[0] or "",
                    "project_name": row[1] or "",
                    "version_name": row[2] or "",
                    "inDegree": row[3] or 0,
                    "outDegree": row[4] or 0,
                }
            )

        return centrality_data

    # ---- License queries ----

    @staticmethod
    def _worst_license_risk(categories: list[str]) -> str:
        """Return the highest-risk category from a list.

        Order (worst first): strong_copyleft > weak_copyleft > proprietary
        > permissive > unknown.
        """
        order = {
            "strong_copyleft": 0,
            "weak_copyleft": 1,
            "proprietary": 2,
            "permissive": 3,
            "unknown": 4,
        }
        worst = "unknown"
        worst_rank = 5
        for cat in categories:
            c = (cat or "").lower().strip()
            rank = order.get(c, 5)
            if rank < worst_rank:
                worst_rank = rank
                worst = c or "unknown"
        return worst

    def get_all_licenses(
        self,
        internal_only: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return all licenses with their usage counts.

        Args:
            internal_only: If True, only count versions labelled INTERNAL.
            limit: Maximum rows to return (None = all).
            offset: Row offset for pagination.

        Returns:
            List of dicts: ``{spdx_id, name, risk_category, usage_count}``.
        """
        label = f":{self.internal_label}" if internal_only else ""
        page_clause, page_params = self._page_clause(limit, offset)
        query = f"""
            MATCH (v:Version{label})-[:HAS_LICENSE]->(l:License)
            RETURN
                l.spdx_id AS spdx_id,
                l.name AS name,
                l.risk_category AS risk_category,
                COUNT(DISTINCT v) AS usage_count
            ORDER BY usage_count DESC
            {page_clause}
        """
        result = self.execute_query(query, page_params)
        return [
            {
                "spdx_id": row[0] or "",
                "name": row[1] or "",
                "risk_category": LicenseRiskCategory.from_str(row[2]),
                "usage_count": row[3] or 0,
            }
            for row in result
        ]

    def count_all_licenses(self, internal_only: bool = True) -> int:
        """Return total count of distinct licenses matching the filter."""
        label = f":{self.internal_label}" if internal_only else ""
        query = f"""
            MATCH (v:Version{label})-[:HAS_LICENSE]->(l:License)
            RETURN COUNT(DISTINCT l) AS total
        """
        result = self.execute_query(query)
        return int(result[0][0]) if result else 0

    def get_license_summary(
        self,
        project_name: str,
        version_name: str,
        project_group: str | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> list[dict[str, Any]]:
        """Return the license BOM for a specific project version.

        Uses iterative BFS (bounded by *max_depth*) to traverse the
        dependency tree safely, avoiding FalkorDB's entity-match limit
        and infinite loops from cyclic graphs.

        Args:
            project_name: The project name.
            version_name: The version string.
            project_group: Optional project group.
            max_depth: Maximum BFS depth for transitive dependencies.

        Returns:
            List of dicts with license and package info.
        """
        if project_group:
            root_match = (
                "MATCH (root:Version {project_name: $project_name,"
                " name: $version_name, project_group: $project_group})"
            )
            params: dict[str, Any] = {
                "project_name": project_name,
                "version_name": version_name,
                "project_group": project_group,
            }
        else:
            root_match = "MATCH (root:Version {project_name: $project_name, name: $version_name})"
            params = {
                "project_name": project_name,
                "version_name": version_name,
            }

        root_query = f"""
            {root_match}
            OPTIONAL MATCH (root)-[:HAS_LICENSE]->(l:License)
            RETURN
                root.project_group AS project_group,
                root.project_name AS dep_project_name,
                root.name AS dep_version,
                root.package_url AS purl,
                l.spdx_id AS spdx_id,
                l.name AS license_name,
                l.risk_category AS risk_category
        """
        results: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        root_result = self.execute_query(root_query, params)
        frontier_purls: set[str] = set()

        for row in root_result:
            purl = row[3] or ""
            if purl:
                frontier_purls.add(purl)
            spdx = row[4]
            if spdx:
                key = f"{purl}|{spdx}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        {
                            "project_group": row[0] or "",
                            "project_name": row[1] or "",
                            "version": row[2] or "",
                            "purl": purl,
                            "spdx_id": spdx or "",
                            "license_name": row[5] or "",
                            "risk_category": LicenseRiskCategory.from_str(row[6]),
                        }
                    )

        visited: set[str] = set(frontier_purls)
        for _depth in range(max_depth):
            if not frontier_purls or len(results) >= MAX_TRANSITIVE_NODES:
                break
            dep_query = """
                MATCH (parent:Version)-[:DEPENDENCY_VERSION]->(child:Version)
                WHERE parent.package_url IN $purls
                OPTIONAL MATCH (child)-[:HAS_LICENSE]->(l:License)
                RETURN
                    child.project_group AS project_group,
                    child.project_name AS dep_project_name,
                    child.name AS dep_version,
                    child.package_url AS purl,
                    l.spdx_id AS spdx_id,
                    l.name AS license_name,
                    l.risk_category AS risk_category
            """
            dep_result = self.execute_query(dep_query, {"purls": list(frontier_purls)})
            next_frontier: set[str] = set()
            for row in dep_result:
                child_purl = row[3] or ""
                if child_purl and child_purl not in visited:
                    visited.add(child_purl)
                    next_frontier.add(child_purl)
                spdx = row[4]
                if spdx:
                    key = f"{child_purl}|{spdx}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        results.append(
                            {
                                "project_group": row[0] or "",
                                "project_name": row[1] or "",
                                "version": row[2] or "",
                                "purl": child_purl,
                                "spdx_id": spdx or "",
                                "license_name": row[5] or "",
                                "risk_category": LicenseRiskCategory.from_str(row[6]),
                            }
                        )
            frontier_purls = next_frontier

        results.sort(key=lambda r: (r["risk_category"], r["project_name"]))
        return results

    def get_license_conflicts(
        self,
        internal_only: bool = True,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> list[dict[str, Any]]:
        """Find projects that mix strong-copyleft with permissive licenses.

        Performs a single combined BFS from *all* application purls to build
        an in-memory adjacency list and license map, then detects per-app
        conflicts via in-memory traversal.  This reduces database queries
        from ``N_apps * depth`` to ``depth + 2`` regardless of application
        count.

        Args:
            internal_only: If True, only check INTERNAL applications.
            max_depth: Maximum BFS depth for transitive dependencies.

        Returns:
            List of dicts describing conflicting license combinations.
        """
        label = f":{self.internal_label}" if internal_only else ""
        apps_query = f"""
            MATCH (app:Version:Application{label})
            RETURN app.project_group AS pg, app.project_name AS pn,
                   app.name AS vn, app.package_url AS purl
        """
        apps_result = self.execute_query(apps_query)

        app_infos: list[dict[str, str]] = []
        seed_purls: set[str] = set()
        for row in apps_result:
            purl = row[3]
            if not purl:
                continue
            app_infos.append(
                {
                    "pg": row[0] or "",
                    "pn": row[1] or "",
                    "vn": row[2] or "",
                    "purl": purl,
                }
            )
            seed_purls.add(purl)

        if not app_infos:
            return []

        # In-memory graph built by the combined BFS
        adj: dict[str, set[str]] = {}
        # purl -> set of (spdx_id, risk_category) tuples
        lic_map: dict[str, set[tuple[str, str]]] = {}

        frontier = set(seed_purls)
        visited = set(seed_purls)

        # Collect licenses on the seed nodes
        lic_query = """
            MATCH (v:Version)-[:HAS_LICENSE]->(l:License)
            WHERE v.package_url IN $purls
            RETURN v.package_url AS vpurl, l.spdx_id AS sid, l.risk_category AS rc
        """
        for row in self.execute_query(lic_query, {"purls": list(frontier)}):
            vpurl = row[0]
            if vpurl and row[1]:
                lic_map.setdefault(vpurl, set()).add((row[1], LicenseRiskCategory.from_str(row[2])))

        # Combined BFS: one query per depth level across all apps
        for _depth in range(max_depth):
            if not frontier:
                break

            dep_query = """
                MATCH (p:Version)-[:DEPENDENCY_VERSION]->(c:Version)
                WHERE p.package_url IN $purls
                OPTIONAL MATCH (c)-[:HAS_LICENSE]->(l:License)
                RETURN p.package_url AS ppurl, c.package_url AS cpurl,
                       l.spdx_id AS sid, l.risk_category AS rc
            """
            dep_result = self.execute_query(dep_query, {"purls": list(frontier)})

            next_frontier: set[str] = set()
            for row in dep_result:
                ppurl, cpurl = row[0], row[1]
                if ppurl and cpurl:
                    adj.setdefault(ppurl, set()).add(cpurl)
                if cpurl and row[2]:
                    lic_map.setdefault(cpurl, set()).add(
                        (row[2], LicenseRiskCategory.from_str(row[3]))
                    )
                if cpurl and cpurl not in visited:
                    visited.add(cpurl)
                    next_frontier.add(cpurl)

            frontier = next_frontier

            if len(visited) >= MAX_TRANSITIVE_NODES:
                break

        # Per-app in-memory traversal (zero DB calls)
        conflicts: list[dict[str, Any]] = []
        for app in app_infos:
            app_licenses: set[str] = set()
            app_categories: set[str] = set()

            stack = [app["purl"]]
            app_visited: set[str] = set()
            while stack:
                current = stack.pop()
                if current in app_visited:
                    continue
                app_visited.add(current)

                for sid, rc in lic_map.get(current, ()):
                    app_licenses.add(sid)
                    if rc:
                        app_categories.add(rc)

                for child in adj.get(current, ()):
                    if child not in app_visited:
                        stack.append(child)

            has_copyleft = LicenseRiskCategory.STRONG_COPYLEFT in app_categories
            has_permissive = LicenseRiskCategory.PERMISSIVE in app_categories
            if has_copyleft and has_permissive:
                conflicts.append(
                    {
                        "project_group": app["pg"],
                        "project_name": app["pn"],
                        "version_name": app["vn"],
                        "licenses": sorted(app_licenses),
                        "risk_categories": sorted(app_categories),
                    }
                )

        conflicts.sort(key=lambda c: c["project_name"])
        return conflicts

    # Worst-risk-category selector, expressed in Cypher over a ``cats`` list of
    # (trimmed, lower-cased) risk categories. MUST stay in sync with the
    # priority order in :meth:`_worst_license_risk`
    # (strong_copyleft > weak_copyleft > proprietary > permissive > unknown).
    _WORST_LICENSE_RISK_CASE = (
        "CASE "
        "WHEN 'strong_copyleft' IN cats THEN 'strong_copyleft' "
        "WHEN 'weak_copyleft' IN cats THEN 'weak_copyleft' "
        "WHEN 'proprietary' IN cats THEN 'proprietary' "
        "WHEN 'permissive' IN cats THEN 'permissive' "
        "ELSE 'unknown' END"
    )

    #: Risk categories in the fixed display/priority order (worst last-but-one;
    #: ``unknown`` always last). Used to seed count dicts deterministically.
    LICENSE_RISK_CATEGORIES = (
        "permissive",
        "weak_copyleft",
        "strong_copyleft",
        "proprietary",
        "unknown",
    )

    def get_license_risk_stats(self, internal_only: bool = False) -> dict[str, Any]:
        """Return licence-risk category counts/percentages without row buffering.

        Computes each package's worst risk category *in-query* and returns only
        the per-category counts and percentages (a tiny fixed-size result),
        never the package rows — so memory stays flat regardless of graph size
        (PERF: aggregate-materialization ceiling). Percentages are derived in
        Python from the small counts dict.

        Args:
            internal_only: If True, only include internal-labeled nodes.

        Returns:
            Dict with ``total_packages`` and ``categories`` (each
            ``{count, pct}``).
        """
        label = f":{self.internal_label}" if internal_only else ""
        query = f"""
            MATCH (v:Version{label})
            WHERE v.package_url IS NOT NULL
            OPTIONAL MATCH (v)-[:HAS_LICENSE]->(l:License)
            WITH v.project_name AS project_name, v.name AS version_name,
                 v.package_url AS purl,
                 collect(DISTINCT trim(toLower(l.risk_category))) AS cats
            WITH {self._WORST_LICENSE_RISK_CASE} AS worst
            RETURN worst, count(*) AS cnt
        """
        result = self.execute_query(query, {})

        counts: dict[str, int] = dict.fromkeys(self.LICENSE_RISK_CATEGORIES, 0)
        for row in result:
            key = row[0] if row[0] in counts else "unknown"
            counts[key] += int(row[1]) if row[1] is not None else 0

        total = sum(counts.values())
        categories = {
            cat: {
                "count": cnt,
                "pct": round(cnt / total * 100, 1) if total else 0.0,
            }
            for cat, cnt in counts.items()
        }
        return {"total_packages": total, "categories": categories}

    def get_license_risk_rows(
        self,
        internal_only: bool = False,
        limit: int | None = None,
        offset: int = 0,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return licence-dashboard package rows, paged and streamable.

        Each row is one package (``project_name``/``version``/``purl`` combo)
        tagged with its worst risk ``category``. Callers stream the full set
        page-by-page via :func:`iterate_pages` (JSON/Excel) or request a bounded
        per-``category`` sample (HTML drill-down) — the aggregate is never held
        in memory in one piece.

        Args:
            internal_only: If True, only include internal-labeled nodes.
            limit: Max rows to return (``None`` = all); ``offset`` to skip.
            offset: Rows to skip (pagination).
            category: Optional worst-category filter (e.g. ``strong_copyleft``).

        Returns:
            List of dicts: ``category``, ``purl``, ``project_name``,
            ``version_name``, ``spdx_id``, ``license_name``.
        """
        label = f":{self.internal_label}" if internal_only else ""
        page_clause, params = self._page_clause(limit, offset)
        where_worst = ""
        if category:
            where_worst = "WHERE worst = $category"
            params = {**params, "category": category}
        query = f"""
            MATCH (v:Version{label})
            WHERE v.package_url IS NOT NULL
            OPTIONAL MATCH (v)-[:HAS_LICENSE]->(l:License)
            WITH v.project_name AS project_name, v.name AS version_name,
                 v.package_url AS purl,
                 collect(DISTINCT l.spdx_id) AS spdx_ids,
                 collect(DISTINCT l.name) AS license_names,
                 collect(DISTINCT trim(toLower(l.risk_category))) AS cats
            WITH project_name, version_name, purl, spdx_ids, license_names,
                 {self._WORST_LICENSE_RISK_CASE} AS worst
            {where_worst}
            RETURN project_name, version_name, purl, spdx_ids, license_names, worst
            ORDER BY project_name, version_name, purl
            {page_clause}
        """
        result = self.execute_query(query, params)

        rows: list[dict[str, Any]] = []
        for row in result:
            spdx_ids = [x for x in (row[3] or []) if x]
            license_names = [x for x in (row[4] or []) if x]
            rows.append(
                {
                    "category": row[5] or "unknown",
                    "purl": row[2] or "",
                    "project_name": row[0] or "",
                    "version_name": row[1] or "",
                    "spdx_id": ", ".join(sorted(set(spdx_ids))) if spdx_ids else "",
                    "license_name": (
                        ", ".join(sorted(set(license_names))) if license_names else ""
                    ),
                }
            )
        return rows

    def count_license_risk_rows(self, internal_only: bool = False) -> int:
        """Count distinct licence-dashboard package rows (matches stats total)."""
        label = f":{self.internal_label}" if internal_only else ""
        query = f"""
            MATCH (v:Version{label})
            WHERE v.package_url IS NOT NULL
            WITH DISTINCT v.project_name AS p, v.name AS n, v.package_url AS u
            RETURN count(*) AS total
        """
        result = self.execute_query(query, {})
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def get_package_licenses(self, purl: str) -> list[dict[str, Any]]:
        """Return licenses for a specific package by purl.

        Args:
            purl: The package URL.

        Returns:
            List of license dicts.
        """
        query = """
            MATCH (v:Version {package_url: $purl})-[:HAS_LICENSE]->(l:License)
            RETURN
                l.spdx_id AS spdx_id,
                l.name AS name,
                l.risk_category AS risk_category,
                l.url AS url
        """
        result = self.execute_query(query, {"purl": purl})
        return [
            {
                "spdx_id": row[0] or "",
                "name": row[1] or "",
                "risk_category": LicenseRiskCategory.from_str(row[2]),
                "url": row[3] or "",
            }
            for row in result
        ]

    def get_vulnerability_freshness(
        self,
        internal_only: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return packages with enrichment freshness status.

        Each row contains the package purl, project info, and the most recent
        ``last_enriched_at`` timestamp from linked defect nodes (or null if
        never enriched).
        """
        label = f":{self.get_node_label(internal_only)}"
        page_clause, page_params = self._page_clause(limit, offset)
        query = f"""
            MATCH (v{label})
            WHERE v.package_url IS NOT NULL
            OPTIONAL MATCH (v)-[:VERSION_DEFECT]->(d:Defect)
            WITH v,
                 max(d.last_enriched_at) AS latest_enrichment
            RETURN v.project_group AS project_group,
                   v.project_name AS project_name,
                   v.name AS version_name,
                   v.package_url AS purl,
                   latest_enrichment
            ORDER BY latest_enrichment ASC
            {page_clause}
        """
        result = self.execute_query(query, page_params)
        rows = []
        for row in result:
            rows.append(
                {
                    "project_group": row[0] or "",
                    "project_name": row[1] or "",
                    "version_name": row[2] or "",
                    "purl": row[3] or "",
                    "last_enriched_at": row[4],
                }
            )
        return rows

    def count_vulnerability_freshness(self, internal_only: bool = False) -> int:
        """Return total count of packages with enrichment freshness data."""
        label = f":{self.get_node_label(internal_only)}"
        query = f"""
            MATCH (v{label})
            WHERE v.package_url IS NOT NULL
            RETURN COUNT(v) AS total
        """
        result = self.execute_query(query, {})
        return int(result[0][0]) if result else 0

    def get_enrichment_coverage(
        self,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Return enrichment coverage statistics for all packages.

        Categorizes packages by enrichment freshness:
        - recent: last_enriched_at within 7 days
        - stale: last_enriched_at more than 7 days ago
        - never: no enrichment date

        Args:
            internal_only: If True, only include internal-labeled nodes.

        Returns:
            Dict with total, recent, stale, never counts and percentages,
            plus a packages list with per-package details.
        """
        label = f":{self.get_node_label(internal_only)}"
        query = f"""
            MATCH (v{label})
            WHERE v.package_url IS NOT NULL
            OPTIONAL MATCH (v)-[:VERSION_DEFECT]->(d:Defect)
            WITH v,
                 max(d.last_enriched_at) AS latest_enrichment
            RETURN v.project_group AS project_group,
                   v.project_name AS project_name,
                   v.name AS version_name,
                   v.package_url AS purl,
                   latest_enrichment
            ORDER BY v.project_name, v.name
        """
        result = self.execute_query(query, {})
        cutoff = datetime.now(UTC) - timedelta(days=7)
        packages: list[dict[str, Any]] = []
        recent_count = 0
        stale_count = 0
        never_count = 0

        for row in result:
            project_group = row[0] or ""
            project_name = row[1] or ""
            version_name = row[2] or ""
            purl = row[3] or ""
            last_enriched_at = row[4]

            if last_enriched_at is None:
                status = "never"
                never_count += 1
            else:
                try:
                    if isinstance(last_enriched_at, str):
                        enriched_dt = datetime.fromisoformat(
                            last_enriched_at.replace("Z", "+00:00"),
                        )
                    else:
                        enriched_dt = last_enriched_at
                    if enriched_dt >= cutoff:
                        status = "recent"
                        recent_count += 1
                    else:
                        status = "stale"
                        stale_count += 1
                except (ValueError, TypeError):
                    status = "stale"
                    stale_count += 1

            last_str = str(last_enriched_at) if last_enriched_at is not None else None
            packages.append(
                {
                    "purl": purl,
                    "project_name": project_name,
                    "version_name": version_name,
                    "project_group": project_group,
                    "last_enriched_at": last_str,
                    "status": status,
                }
            )

        total = len(packages)
        recent_pct = (recent_count / total * 100) if total > 0 else 0.0
        stale_pct = (stale_count / total * 100) if total > 0 else 0.0
        never_pct = (never_count / total * 100) if total > 0 else 0.0

        return {
            "total": total,
            "recent": recent_count,
            "stale": stale_count,
            "never": never_count,
            "recent_pct": round(recent_pct, 1),
            "stale_pct": round(stale_pct, 1),
            "never_pct": round(never_pct, 1),
            "packages": packages,
        }

    def get_vulnerability_severities_for_versions(
        self,
        purls: list[str],
    ) -> dict[str, str]:
        """Return highest severity per purl for packages with vulnerabilities.

        For each Version node with the given purl, finds related Defect nodes
        via VERSION_DEFECT and returns the highest severity.

        Args:
            purls: List of package URLs to look up.

        Returns:
            Dict mapping purl -> highest severity (CRITICAL, HIGH, MEDIUM, LOW).
        """
        if not purls:
            return {}

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        result_map: dict[str, str] = {}

        batch_size = 500
        for i in range(0, len(purls), batch_size):
            batch = purls[i : i + batch_size]
            query = """
                MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect)
                WHERE v.package_url IN $purls AND d.severity IS NOT NULL
                RETURN v.package_url AS purl,
                       d.severity AS severity
            """
            rows = self.execute_query(query, {"purls": batch})
            for row in rows:
                purl = row[0]
                severity = (row[1] or "").upper()
                if not purl or not severity:
                    continue
                if severity not in severity_order:
                    continue
                current = result_map.get(purl)
                if current is None or severity_order[severity] < severity_order[current]:
                    result_map[purl] = severity

        return result_map

    def get_vex_statuses_for_versions(
        self,
        purls: list[str],
    ) -> dict[str, str]:
        """Return VEX status per purl for the highest-severity linked vulnerability.

        For each Version with the given purl, finds Defects via VERSION_DEFECT
        and VexStatements via HAS_VEX/REFERS_TO. Returns the VEX status of the
        highest-severity vulnerability that has a VEX statement.

        Args:
            purls: List of package URLs to look up.

        Returns:
            Dict mapping purl -> VEX status (not_affected, affected, fixed,
            under_investigation) or empty dict if no VEX for that purl.
        """
        if not purls:
            return {}

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        result_map: dict[str, str] = {}

        batch_size = 500
        for i in range(0, len(purls), batch_size):
            batch = purls[i : i + batch_size]
            query = """
                MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect)
                WHERE v.package_url IN $purls
                MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
                WHERE s.status IS NOT NULL
                RETURN v.package_url AS purl,
                       d.severity AS severity,
                       s.status AS vex_status,
                       s.timestamp AS vex_timestamp
            """
            rows = self.execute_query(query, {"purls": batch})

            purl_candidates: dict[str, list[tuple[int, str, str | None]]] = {}
            for row in rows:
                purl = row[0]
                severity = (row[1] or "").upper()
                vex_status = row[2]
                vex_timestamp = row[3]
                if not purl or not vex_status or severity not in severity_order:
                    continue
                sev_ord = severity_order[severity]
                if purl not in purl_candidates:
                    purl_candidates[purl] = []
                purl_candidates[purl].append((sev_ord, vex_status, vex_timestamp))

            for purl, candidates in purl_candidates.items():
                # Sort by severity (critical first), then by timestamp (recent first)
                best = sorted(
                    candidates,
                    key=lambda x: (
                        x[0],
                        (1 if x[2] is None else 0),
                        str(x[2]) if x[2] else "",
                    ),
                    reverse=False,
                )[0]
                result_map[purl] = best[1]

        return result_map

    def get_license_risks_for_versions(self, purls: list[str]) -> dict[str, str]:
        """Return licence risk category per purl for packages with licenses.

        For each Version node with the given purl, finds linked License
        nodes and returns the worst risk category.

        Args:
            purls: List of package URLs to look up.

        Returns:
            Dict mapping purl -> risk_category (permissive, weak_copyleft,
            strong_copyleft, proprietary, unknown).
        """
        if not purls:
            return {}

        result_map: dict[str, str] = {}
        batch_size = 500
        for i in range(0, len(purls), batch_size):
            batch = purls[i : i + batch_size]
            query = """
                MATCH (v:Version)-[:HAS_LICENSE]->(l:License)
                WHERE v.package_url IN $purls
                RETURN v.package_url AS purl,
                       collect(DISTINCT l.risk_category) AS risk_categories
            """
            rows = self.execute_query(query, {"purls": batch})
            for row in rows:
                purl = row[0]
                risk_cats = [x for x in (row[1] or []) if x]
                if not purl:
                    continue
                risk_category = self._worst_license_risk(risk_cats) if risk_cats else "unknown"
                result_map[purl] = risk_category

        return result_map

    def get_package_vulnerabilities(
        self,
        purl: str,
        include_dependencies: bool = False,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> dict[str, Any]:
        """Return vulnerabilities for a package, optionally including transitive deps.

        Args:
            purl: The package URL.
            include_dependencies: If True, also return transitive dependency vulns.
            max_depth: Maximum traversal depth for transitive dependencies.

        Returns:
            Dict with ``package``, ``vulnerabilities``, and optionally
            ``transitive_vulnerabilities`` keys.
        """
        direct_query = """
            MATCH (v:Version {package_url: $purl})-[:VERSION_DEFECT]->(d:Defect)
            RETURN COALESCE(d.id, d.defect_id) AS id,
                   d.severity AS severity,
                   d.cvss AS cvss,
                   d.cvss_string AS cvss_vector,
                   d.description AS description,
                   d.aliases AS aliases,
                   d.enrichment_source AS source,
                   d.last_enriched_at AS last_enriched_at
        """
        direct_result = self.execute_query(direct_query, {"purl": purl})
        direct_vulns = []
        for row in direct_result:
            direct_vulns.append(
                {
                    "id": row[0],
                    "severity": row[1],
                    "cvss": row[2],
                    "cvss_vector": row[3],
                    "description": row[4],
                    "aliases": row[5] or [],
                    "source": row[6],
                    "last_enriched_at": row[7],
                }
            )

        result: dict[str, Any] = {
            "package": purl,
            "vulnerabilities": direct_vulns,
            "count": len(direct_vulns),
        }

        if include_dependencies:
            dep_purls: set[str] = set()
            frontier = {purl}
            visited = {purl}

            for _depth in range(max_depth):
                if not frontier:
                    break
                dep_query = """
                    MATCH (p:Version)-[:DEPENDENCY_VERSION]->(c:Version)
                    WHERE p.package_url IN $purls AND c.package_url IS NOT NULL
                    RETURN DISTINCT c.package_url AS cpurl
                """
                dep_result = self.execute_query(dep_query, {"purls": list(frontier)})
                next_frontier: set[str] = set()
                for dep_row in dep_result:
                    cpurl = dep_row[0]
                    if cpurl and cpurl not in visited:
                        visited.add(cpurl)
                        next_frontier.add(cpurl)
                        dep_purls.add(cpurl)
                frontier = next_frontier
                if len(visited) >= MAX_TRANSITIVE_NODES:
                    break

            trans_vulns: list[dict[str, Any]] = []
            if dep_purls:
                batch_size = 500
                dep_purl_list = list(dep_purls)
                for i in range(0, len(dep_purl_list), batch_size):
                    batch = dep_purl_list[i : i + batch_size]
                    tv_query = """
                        MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect)
                        WHERE v.package_url IN $purls
                        RETURN v.package_url AS purl,
                               COALESCE(d.id, d.defect_id) AS id,
                               d.severity AS severity,
                               d.description AS description,
                               d.aliases AS aliases,
                               d.enrichment_source AS source
                    """
                    tv_result = self.execute_query(tv_query, {"purls": batch})
                    for tv_row in tv_result:
                        trans_vulns.append(
                            {
                                "package": tv_row[0],
                                "id": tv_row[1],
                                "severity": tv_row[2],
                                "description": tv_row[3],
                                "aliases": tv_row[4] or [],
                                "source": tv_row[5],
                            }
                        )

            result["transitive_vulnerabilities"] = trans_vulns
            result["transitive_count"] = len(trans_vulns)

        return result

    def get_policy_annotations(
        self,
        search: str | None = None,
        type_filter: str | None = None,
        internal_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return all policy annotations, optionally filtered by search and type.

        Args:
            search: Optional substring to filter by PURL or justification.
            type_filter: Optional policy type ("bad", "good", "hold").
            internal_only: If True, only return annotations on internal packages.

        Returns:
            List of dicts with purl, annotation_type (bad/good/hold),
            justification, created_by, created_at, annotation_id, etc.
        """
        label = f":{self.get_node_label(internal_only)}"
        params: dict[str, Any] = {}

        type_clause = ""
        if type_filter:
            type_clause = "AND a.type = $type_filter"
            params["type_filter"] = type_filter

        search_clause = ""
        if search and search.strip():
            search_clause = (
                "AND (v.package_url CONTAINS $search OR a.justification CONTAINS $search)"
            )
            params["search"] = search.strip()

        query = f"""
            MATCH (v{label})-[:HAS_POLICY]->(a:PolicyAnnotation)
            WHERE v.package_url IS NOT NULL {type_clause} {search_clause}
            RETURN a.annotation_id AS annotation_id,
                   a.type AS type,
                   a.justification AS justification,
                   a.created_by AS created_by,
                   a.created_at AS created_at,
                   a.expires_at AS expires_at,
                   v.package_url AS purl,
                   v.project_name AS project_name,
                   v.name AS version_name,
                   v.project_group AS project_group
            ORDER BY a.created_at DESC
        """
        result = self.execute_query(query, params)
        annotations: list[dict[str, Any]] = []
        for row in result:
            annotations.append(
                {
                    "annotation_id": row[0],
                    "type": row[1],
                    "justification": row[2],
                    "created_by": row[3],
                    "created_at": row[4],
                    "expires_at": row[5],
                    "purl": row[6],
                    "project_name": row[7] or "",
                    "version_name": row[8] or "",
                    "project_group": row[9] or "",
                }
            )
        return annotations

    def get_policy_violations(
        self,
        internal_only: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return all 'bad' policy annotations that are still in use.

        For each bad-annotated package, returns the count of dependant
        applications that transitively depend on it.
        """
        label = f":{self.get_node_label(internal_only)}"
        page_clause, page_params = self._page_clause(limit, offset)
        query = f"""
            MATCH (v{label})-[:HAS_POLICY]->(a:PolicyAnnotation {{type: 'bad'}})
            WHERE v.package_url IS NOT NULL
            OPTIONAL MATCH (app:Application)-[:DEPENDENCY_VERSION*1..5]->(v)
            WITH a, v, count(DISTINCT app) AS dependant_count
            RETURN a.annotation_id AS annotation_id,
                   a.justification AS justification,
                   a.created_by AS created_by,
                   a.created_at AS created_at,
                   a.expires_at AS expires_at,
                   v.package_url AS purl,
                   v.project_name AS project_name,
                   v.name AS version_name,
                   dependant_count
            ORDER BY dependant_count DESC
            {page_clause}
        """
        result = self.execute_query(query, page_params)
        violations: list[dict[str, Any]] = []
        for row in result:
            violations.append(
                {
                    "annotation_id": row[0],
                    "justification": row[1],
                    "created_by": row[2],
                    "created_at": row[3],
                    "expires_at": row[4],
                    "purl": row[5],
                    "project_name": row[6] or "",
                    "version_name": row[7] or "",
                    "dependant_count": row[8] or 0,
                }
            )
        return violations

    def count_policy_violations(self, internal_only: bool = False) -> int:
        """Return total count of 'bad' policy violation packages."""
        label = f":{self.get_node_label(internal_only)}"
        query = f"""
            MATCH (v{label})-[:HAS_POLICY]->(a:PolicyAnnotation {{type: 'bad'}})
            WHERE v.package_url IS NOT NULL
            RETURN COUNT(DISTINCT v) AS total
        """
        result = self.execute_query(query, {})
        return int(result[0][0]) if result else 0

    def get_policy_violations_total_dependants(self, internal_only: bool = False) -> int:
        """Return SUM of dependant_count over ALL policy violations (full set)."""
        label = f":{self.get_node_label(internal_only)}"
        query = f"""
            MATCH (v{label})-[:HAS_POLICY]->(a:PolicyAnnotation {{type: 'bad'}})
            WHERE v.package_url IS NOT NULL
            WITH DISTINCT v
            OPTIONAL MATCH (app:Application)-[:DEPENDENCY_VERSION*1..5]->(v)
            WITH count(DISTINCT app) AS dependant_count
            RETURN sum(dependant_count) AS total_dependants
        """
        result = self.execute_query(query, {})
        return int(result[0][0]) if result else 0

    def add_policy_annotation(
        self,
        purl: str,
        annotation_type: str,
        justification: str,
        created_by: str,
    ) -> dict[str, Any] | None:
        """Add a policy annotation to a package version.

        The Version node must exist. Creates a PolicyAnnotation and links
        it via HAS_POLICY.

        Args:
            purl: Package URL.
            annotation_type: One of "bad", "good", "hold".
            justification: Reason for the annotation.
            created_by: Username of the creator.

        Returns:
            Dict with purl, annotation_id, type, created_at, or None if
            the package was not found in the graph.
        """
        version_exists = self.execute_query(
            "MATCH (v:Version {package_url: $purl}) RETURN 1 LIMIT 1",
            {"purl": purl},
        )
        if not version_exists:
            return None

        annotation_id = str(uuid4())
        created_at = datetime.now(UTC).isoformat()

        self.execute_write(
            """
            MERGE (a:PolicyAnnotation {annotation_id: $annotation_id})
            ON CREATE SET
                a.type = $annotation_type,
                a.justification = $justification,
                a.created_by = $created_by,
                a.created_at = $created_at
            ON MATCH SET
                a.type = $annotation_type,
                a.justification = $justification
            """,
            {
                "annotation_id": annotation_id,
                "annotation_type": annotation_type,
                "justification": justification,
                "created_by": created_by,
                "created_at": created_at,
            },
        )

        self.execute_write(
            """
            MATCH (v:Version {package_url: $purl})
            MATCH (a:PolicyAnnotation {annotation_id: $annotation_id})
            MERGE (v)-[:HAS_POLICY]->(a)
            """,
            {"purl": purl, "annotation_id": annotation_id},
        )

        return {
            "purl": purl,
            "annotation_id": annotation_id,
            "type": annotation_type,
            "created_at": created_at,
        }

    def remove_policy_annotation(self, purl: str) -> bool:
        """Remove all policy annotations from a package version.

        Args:
            purl: Package URL.

        Returns:
            True if at least one annotation was removed, False otherwise.
        """
        result = self.execute_write(
            """
            MATCH (v:Version {package_url: $purl})-[:HAS_POLICY]->(a:PolicyAnnotation)
            WITH count(a) AS to_delete
            MATCH (v2:Version {package_url: $purl})-[:HAS_POLICY]->(a2:PolicyAnnotation)
            DETACH DELETE a2
            RETURN to_delete AS deleted
            """,
            {"purl": purl},
        )
        deleted = result[0][0] if result else 0
        return deleted > 0

    def get_policy_annotations_for_purls(
        self,
        purls: list[str],
    ) -> dict[str, str]:
        """Return mapping of purl -> annotation type for packages with annotations.

        For packages with multiple annotations, returns the most recent
        (by created_at). For packages with multiple types, "bad" takes
        precedence over "hold" over "good".

        Args:
            purls: List of package URLs to check.

        Returns:
            Dict mapping purl to type ("bad", "good", "hold").
        """
        if not purls:
            return {}

        query = """
            UNWIND $purls AS purl
            MATCH (v:Version {package_url: purl})-[:HAS_POLICY]->(a:PolicyAnnotation)
            WITH purl, a
            ORDER BY a.created_at DESC
            WITH purl, collect(a.type) AS types
            RETURN purl,
                   CASE WHEN 'bad' IN types THEN 'bad'
                        WHEN 'hold' IN types THEN 'hold'
                        ELSE 'good' END AS type
        """
        result = self.execute_query(query, {"purls": purls})
        return {row[0]: row[1] for row in result}

    def check_policy(self, purl: str) -> dict[str, Any]:
        """Check the policy status for a package URL (CI/CD gate).

        Returns pass/fail/hold with all applicable annotations.

        Args:
            purl: The package URL to check.

        Returns:
            Dict with ``status`` ("pass", "fail", "hold") and ``annotations`` list.
        """
        query = """
            MATCH (v:Version {package_url: $purl})-[:HAS_POLICY]->(a:PolicyAnnotation)
            RETURN a.annotation_id AS annotation_id,
                   a.type AS type,
                   a.justification AS justification,
                   a.created_by AS created_by,
                   a.created_at AS created_at,
                   a.expires_at AS expires_at
            ORDER BY a.created_at DESC
        """
        result = self.execute_query(query, {"purl": purl})
        annotations = []
        for row in result:
            annotations.append(
                {
                    "annotation_id": row[0],
                    "type": row[1],
                    "justification": row[2],
                    "created_by": row[3],
                    "created_at": row[4],
                    "expires_at": row[5],
                }
            )

        if any(a["type"] == "bad" for a in annotations):
            status = "fail"
        elif any(a["type"] == "hold" for a in annotations):
            status = "hold"
        else:
            status = "pass"

        return {
            "purl": purl,
            "status": status,
            "annotations": annotations,
        }

    def compute_patch_plan(
        self,
        defect_id: str,
        max_depth: int = 10,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Compute a frontier-level patch plan for a vulnerability.

        Starts from the Defect node, traverses VERSION_DEFECT to get
        affected versions (frontier level 0), then BFS outward via
        reverse DEPENDENCY_VERSION edges to compute frontier levels 1..N.
        At each level, collects affected projects and associated PointOfContact nodes.

        Args:
            defect_id: The vulnerability ID (e.g. CVE-2024-xxx).
            max_depth: Maximum BFS depth.
            internal_only: If True, only include INTERNAL-labelled nodes.

        Returns:
            Dict with defect info, frontiers, total_affected, and contacts.
        """
        defect_query = """
            MATCH (d:Defect)
            WHERE d.id = $defect_id OR d.defect_id = $defect_id
            RETURN d.id AS id, COALESCE(d.id, d.defect_id) AS defect_id,
                   d.severity AS severity, d.aliases AS aliases,
                   d.description AS description
            LIMIT 1
        """
        defect_result = self.execute_query(defect_query, {"defect_id": defect_id})
        if not defect_result:
            return {"defect": None, "frontiers": [], "total_affected": 0, "contacts": []}

        defect_row = defect_result[0]
        defect_info = {
            "id": defect_row[0] or defect_row[1],
            "severity": defect_row[2],
            "aliases": defect_row[3] or [],
            "description": defect_row[4],
        }

        label = f":{self.get_node_label(internal_only)}"
        level0_query = f"""
            MATCH (v{label})-[:VERSION_DEFECT]->(d:Defect)
            WHERE d.id = $defect_id OR d.defect_id = $defect_id
            RETURN v.project_name AS project_name, v.name AS version,
                   v.package_url AS purl, v.project_group AS project_group
        """
        level0_result = self.execute_query(level0_query, {"defect_id": defect_id})

        frontiers: list[dict[str, Any]] = []
        all_contacts: list[dict[str, Any]] = []
        visited_purls: set[str] = set()
        current_purls: set[str] = set()

        level0_packages: list[dict[str, Any]] = []
        for row in level0_result:
            purl = row[2]
            pkg: dict[str, Any] = {
                "project_name": row[0] or "",
                "version": row[1] or "",
                "purl": purl or "",
                "project_group": row[3] or "",
                "contacts": [],
            }
            if purl:
                contacts = self._get_contacts_for_purl(purl)
                pkg["contacts"] = contacts
                all_contacts.extend(contacts)
                visited_purls.add(purl)
                current_purls.add(purl)
            level0_packages.append(pkg)

        if level0_packages:
            frontiers.append({"level": 0, "packages": level0_packages})

        for level in range(1, max_depth + 1):
            if not current_purls:
                break

            dep_query = f"""
                MATCH (parent{label})-[:DEPENDENCY_VERSION]->(child:Version)
                WHERE child.package_url IN $purls
                  AND parent.package_url IS NOT NULL
                RETURN DISTINCT parent.project_name AS project_name,
                       parent.name AS version,
                       parent.package_url AS purl,
                       parent.project_group AS project_group
            """
            dep_result = self.execute_query(dep_query, {"purls": list(current_purls)})

            next_purls: set[str] = set()
            level_packages: list[dict[str, Any]] = []

            for row in dep_result:
                purl = row[2]
                if purl and purl not in visited_purls:
                    visited_purls.add(purl)
                    next_purls.add(purl)
                    contacts = self._get_contacts_for_purl(purl)
                    all_contacts.extend(contacts)
                    level_packages.append(
                        {
                            "project_name": row[0] or "",
                            "version": row[1] or "",
                            "purl": purl,
                            "project_group": row[3] or "",
                            "contacts": contacts,
                        }
                    )

            if level_packages:
                frontiers.append({"level": level, "packages": level_packages})

            current_purls = next_purls

            if len(visited_purls) >= MAX_TRANSITIVE_NODES:
                break

        seen_emails: set[str] = set()
        unique_contacts: list[dict[str, Any]] = []
        for c in all_contacts:
            if c["email"] not in seen_emails:
                seen_emails.add(c["email"])
                unique_contacts.append(c)

        total = sum(len(f["packages"]) for f in frontiers)

        return {
            "defect": defect_info,
            "frontiers": frontiers,
            "total_affected": total,
            "contacts": unique_contacts,
        }

    def _get_contacts_for_purl(self, purl: str) -> list[dict[str, Any]]:
        """Get PointOfContact nodes linked to a package version."""
        result = self.execute_query(
            """
            MATCH (c:PointOfContact)-[:CONTACT_FOR]->(v:Version {package_url: $purl})
            RETURN c.email AS email, c.team AS team, c.slack_channel AS slack_channel
            """,
            {"purl": purl},
        )
        return [
            {"email": row[0] or "", "team": row[1] or "", "slack_channel": row[2] or ""}
            for row in result
        ]

    def compute_blast_radius(
        self,
        purl: str,
        max_depth: int = 10,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Compute blast radius from a specific package outward through dependants.

        Args:
            purl: The package URL to analyze.
            max_depth: Maximum BFS depth.
            internal_only: If True, only include INTERNAL-labelled nodes.

        Returns:
            Dict with package info, affected dependants by depth, and total count.
        """
        label = f":{self.get_node_label(internal_only)}"
        frontiers: list[dict[str, Any]] = []
        visited: set[str] = {purl}
        current: set[str] = {purl}

        for depth in range(1, max_depth + 1):
            if not current:
                break

            query = f"""
                MATCH (parent{label})-[:DEPENDENCY_VERSION]->(child:Version)
                WHERE child.package_url IN $purls
                  AND parent.package_url IS NOT NULL
                RETURN DISTINCT parent.project_name AS project_name,
                       parent.name AS version,
                       parent.package_url AS purl,
                       parent.project_group AS project_group
            """
            result = self.execute_query(query, {"purls": list(current)})

            next_frontier: set[str] = set()
            level_packages: list[dict[str, Any]] = []

            for row in result:
                p = row[2]
                if p and p not in visited:
                    visited.add(p)
                    next_frontier.add(p)
                    level_packages.append(
                        {
                            "project_name": row[0] or "",
                            "version": row[1] or "",
                            "purl": p,
                            "project_group": row[3] or "",
                        }
                    )

            if level_packages:
                frontiers.append({"depth": depth, "packages": level_packages})

            current = next_frontier

            if len(visited) >= MAX_TRANSITIVE_NODES:
                break

        total = sum(len(f["packages"]) for f in frontiers)

        return {
            "package": purl,
            "frontiers": frontiers,
            "total_affected": total,
        }

    def get_blast_radius(
        self,
        defect_id: str,
        max_depth: int = 50,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Get blast radius for a vulnerability (defect_id).

        Returns affected versions, affected applications, graph data for
        visualization, and max partition depth.

        Args:
            defect_id: The vulnerability ID (e.g. CVE-2024-xxx).
            max_depth: Maximum traversal depth.
            internal_only: If True, restrict to internal-labeled nodes.

        Returns:
            Dict with affected_versions, affected_applications,
            graph_nodes, graph_edges, and max_partition.
        """
        vuln = self.get_vulnerability_by_id(defect_id, internal_only=False)
        if not vuln:
            return {
                "affected_versions": [],
                "affected_applications": [],
                "graph_nodes": [],
                "graph_edges": [],
                "max_partition": 0,
            }

        affected_versions = vuln.get("affected_versions", [])
        deps = self.get_vulnerability_dependants(
            defect_id=defect_id,
            max_depth=max_depth,
            internal_only=internal_only,
        )

        max_partition = max((d.get("partition", 0) for d in deps), default=0)
        affected_apps = [
            {
                "project_name": d["project_name"],
                "version": d["version"],
                "purl": "",
                "id": f"{d['project_name']}:{d['version']}",
            }
            for d in deps
            if "Application" in d.get("labels", [])
        ]

        graph_nodes: list[dict[str, Any]] = []
        graph_edges: list[dict[str, Any]] = []

        defect_node_id = f"defect:{defect_id}"
        graph_nodes.append(
            {
                "id": defect_node_id,
                "label": defect_id,
                "type": "vulnerability",
            }
        )

        for av in affected_versions:
            nid = f"{av.get('project_name', '')}:{av.get('version', '')}"
            graph_nodes.append(
                {
                    "id": nid,
                    "label": f"{av.get('project_name', '')}:{av.get('version', '')}",
                    "type": "affected",
                    "partition": 0,
                }
            )
            graph_edges.append({"source": defect_node_id, "target": nid, "type": "VERSION_DEFECT"})

        for dep in deps:
            nid = f"{dep['project_name']}:{dep['version']}"
            if not any(n.get("id") == nid for n in graph_nodes):
                dtype = "application" if "Application" in dep.get("labels", []) else "transitive"
                graph_nodes.append(
                    {
                        "id": nid,
                        "label": f"{dep['project_name']}:{dep['version']}",
                        "type": dtype,
                        "partition": dep.get("partition", 0),
                    }
                )

        return {
            "affected_versions": affected_versions,
            "affected_applications": affected_apps,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
            "max_partition": max_partition,
        }

    def get_patch_plan(
        self,
        defect_id: str,
        internal_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get patch plan as list for a vulnerability.

        Flattens compute_patch_plan frontiers into a list of items with
        priority, project_name, version_name, purl, is_direct,
        dependant_count, recommended_action.

        Args:
            defect_id: The vulnerability ID.
            internal_only: If True, restrict to internal-labeled nodes.

        Returns:
            List of patch plan item dicts.
        """
        result = self.compute_patch_plan(
            defect_id=defect_id,
            max_depth=50,
            internal_only=internal_only,
        )
        frontiers = result.get("frontiers", [])
        items: list[dict[str, Any]] = []
        for f in frontiers:
            level = f.get("level", 0)
            is_direct = level == 0
            priority = "high" if level == 0 else ("medium" if level == 1 else "low")
            for pkg in f.get("packages", []):
                items.append(
                    {
                        "priority": priority,
                        "project_name": pkg.get("project_name", ""),
                        "version_name": pkg.get("version", ""),
                        "purl": pkg.get("purl", ""),
                        "is_direct": is_direct,
                        "dependant_count": 0,
                        "recommended_action": "upgrade",
                    }
                )
        return items

    def get_vex_for_package(self, purl: str) -> list[dict[str, Any]]:
        """Return VEX statements for a package.

        Args:
            purl: The package URL.

        Returns:
            List of VEX statement dicts with linked vulnerability info.
        """
        query = """
            MATCH (v:Version {package_url: $purl})-[:HAS_VEX]->(s:VexStatement)
            OPTIONAL MATCH (s)-[:REFERS_TO]->(d:Defect)
            RETURN s.statement_id AS statement_id,
                   s.status AS status,
                   s.justification AS justification,
                   s.impact_statement AS impact_statement,
                   s.action_statement AS action_statement,
                   s.source_document AS source_document,
                   s.timestamp AS timestamp,
                   COALESCE(d.id, d.defect_id) AS vulnerability_id,
                   d.severity AS vulnerability_severity
            ORDER BY s.timestamp DESC
        """
        result = self.execute_query(query, {"purl": purl})
        statements = []
        for row in result:
            statements.append(
                {
                    "statement_id": row[0],
                    "status": row[1],
                    "justification": row[2],
                    "impact_statement": row[3],
                    "action_statement": row[4],
                    "source_document": row[5],
                    "timestamp": row[6],
                    "vulnerability_id": row[7],
                    "vulnerability_severity": row[8],
                }
            )
        return statements

    def get_vex_coverage(
        self,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Return VEX coverage statistics.

        Counts vulnerabilities with and without VEX statements.
        """
        label = f":{self.get_node_label(internal_only)}"

        total_query = f"""
            MATCH (v{label})-[:VERSION_DEFECT]->(d:Defect)
            RETURN count(DISTINCT d) AS total_vulns
        """
        total_result = self.execute_query(total_query, {})
        total_vulns = total_result[0][0] if total_result else 0

        covered_query = f"""
            MATCH (v{label})-[:VERSION_DEFECT]->(d:Defect)
            MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
            RETURN count(DISTINCT d) AS covered_vulns
        """
        covered_result = self.execute_query(covered_query, {})
        covered_vulns = covered_result[0][0] if covered_result else 0

        uncovered = total_vulns - covered_vulns
        pct = round((covered_vulns / total_vulns * 100), 1) if total_vulns > 0 else 0.0

        return {
            "total_vulnerabilities": total_vulns,
            "with_vex": covered_vulns,
            "without_vex": uncovered,
            "coverage_percent": pct,
        }

    # Source repository queries

    def get_all_source_repos(
        self,
        internal_only: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return all source repositories with linked package counts.

        Args:
            internal_only: Restrict to INTERNAL-labeled versions.
            limit: Page size for paginated reads (``None`` returns all rows).
            offset: Number of rows to skip (paginated reads).

        Returns:
            List of dicts with url, vcs_type, namespace, name, and
            package_count.
        """
        label = f":{self.get_node_label(internal_only)}"
        page_clause, params = self._page_clause(limit, offset)

        query = f"""
            MATCH (v{label})-[:HAS_SOURCE]->(r:SourceRepository)
            RETURN r.url AS url,
                   r.vcs_type AS vcs_type,
                   r.namespace AS namespace,
                   r.name AS name,
                   count(DISTINCT v) AS package_count
            ORDER BY package_count DESC
            {page_clause}
        """
        result = self.execute_query(query, params)
        repos = []
        for row in result:
            repos.append(
                {
                    "url": row[0],
                    "vcs_type": row[1],
                    "namespace": row[2],
                    "name": row[3],
                    "package_count": row[4],
                }
            )
        return repos

    def count_source_repos(self, internal_only: bool = False) -> int:
        """Count distinct source repositories (same filter as the page query)."""
        label = f":{self.get_node_label(internal_only)}"
        result = self.execute_query(
            f"MATCH (v{label})-[:HAS_SOURCE]->(r:SourceRepository) "
            f"RETURN count(DISTINCT r) AS n",
            {},
        )
        return int(result[0][0]) if result and result[0] and result[0][0] is not None else 0

    def get_packages_by_source_repo(self, repo_url: str) -> list[dict[str, Any]]:
        """Return all packages sourced from a given repository.

        Args:
            repo_url: The canonical source repository URL.

        Returns:
            List of dicts with project_name, project_group, version,
            purl, and sbom_format.
        """
        query = """
            MATCH (v:Version)-[:HAS_SOURCE]->(r:SourceRepository {url: $repo_url})
            RETURN v.project_name AS project_name,
                   v.project_group AS project_group,
                   v.name AS version,
                   v.package_url AS purl,
                   v.sbom_format AS sbom_format
            ORDER BY v.project_name, v.name
        """
        result = self.execute_query(query, {"repo_url": repo_url})
        packages = []
        for row in result:
            packages.append(
                {
                    "project_name": row[0],
                    "project_group": row[1],
                    "version": row[2],
                    "purl": row[3],
                    "sbom_format": row[4],
                }
            )
        return packages

    def get_vulnerabilities_by_source_repo(self, repo_url: str) -> list[dict[str, Any]]:
        """Return all vulnerabilities in packages sourced from a repository.

        Args:
            repo_url: The canonical source repository URL.

        Returns:
            List of dicts with defect_id, severity, description,
            affected_project, and affected_version.
        """
        query = """
            MATCH (v:Version)-[:HAS_SOURCE]->(r:SourceRepository {url: $repo_url})
            MATCH (v)-[:VERSION_DEFECT]->(d:Defect)
            RETURN COALESCE(d.id, d.defect_id) AS defect_id,
                   d.severity AS severity,
                   COALESCE(d.description, d.title) AS description,
                   v.project_name AS affected_project,
                   v.name AS affected_version
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'critical' THEN 1
                    WHEN 'HIGH' THEN 2 WHEN 'high' THEN 2
                    WHEN 'MEDIUM' THEN 3 WHEN 'medium' THEN 3
                    WHEN 'LOW' THEN 4 WHEN 'low' THEN 4
                    ELSE 5
                END
        """
        result = self.execute_query(query, {"repo_url": repo_url})
        vulns = []
        for row in result:
            vulns.append(
                {
                    "defect_id": row[0],
                    "severity": row[1],
                    "description": row[2],
                    "affected_project": row[3],
                    "affected_version": row[4],
                }
            )
        return vulns

    def get_source_repo_impact(
        self,
        repo_url: str,
        max_depth: int = 50,
        internal_only: bool = False,
    ) -> dict[str, Any]:
        """Get the impact of a source repository on downstream consumers.

        Returns packages from this repo, their dependants (direct and
        transitive), affected applications, and graph data for visualization.

        Args:
            repo_url: The canonical source repository URL.
            max_depth: Maximum traversal depth for transitive dependants.
            internal_only: If True, restrict to internal-labeled nodes.

        Returns:
            Dict with packages, dependants, affected_applications,
            graph_nodes, graph_edges, and stats.
        """
        label = self.get_node_label(internal_only)
        app_label = f"Application:{self.internal_label}" if internal_only else "Application"

        # Use parameterised max_depth - FalkorDB requires literal in path
        depth_param = min(max_depth, 50)

        # Packages from this repo with direct and transitive dependant counts
        packages_query = f"""
            MATCH (v:{label})-[:HAS_SOURCE]->(r:SourceRepository {{url: $repo_url}})
            OPTIONAL MATCH (direct)-[:DEPENDENCY_VERSION]->(v)
            WHERE (direct:Version OR direct:Application)
            WITH v, count(DISTINCT direct) AS direct_count
            OPTIONAL MATCH (any_dep)-[:DEPENDENCY_VERSION*1..{depth_param}]->(v)
            WHERE (any_dep:Version OR any_dep:Application)
            WITH v, direct_count,
                 count(DISTINCT any_dep) AS total_count
            RETURN v.project_name AS project_name,
                   v.name AS version,
                   v.package_url AS purl,
                   direct_count,
                   total_count - direct_count AS transitive_count
            ORDER BY total_count DESC, v.project_name, v.name
        """
        result = self.execute_query(packages_query, {"repo_url": repo_url})

        packages = []
        for row in result:
            packages.append(
                {
                    "project_name": row[0],
                    "version": row[1],
                    "purl": row[2],
                    "direct_dependants": row[3] or 0,
                    "transitive_dependants": row[4] or 0,
                }
            )

        # Get distinct downstream consumer project/versions (dependants)
        dependants_query = f"""
            MATCH (v:{label})-[:HAS_SOURCE]->(r:SourceRepository {{url: $repo_url}})
            MATCH (dep)-[:DEPENDENCY_VERSION*1..{depth_param}]->(v)
            WHERE (dep:Version OR dep:Application)
            RETURN DISTINCT dep.project_name AS project_name,
                   dep.name AS version,
                   labels(dep)[0] AS node_type
            ORDER BY project_name, version
        """
        dep_result = self.execute_query(
            dependants_query,
            {"repo_url": repo_url},
        )
        dependants = [
            {
                "project_name": row[0],
                "version": row[1],
                "node_type": row[2] or "Version",
            }
            for row in dep_result
        ]

        # Affected applications
        app_query = f"""
            MATCH (v:{label})-[:HAS_SOURCE]->(r:SourceRepository {{url: $repo_url}})
            MATCH (app:{app_label})-[:DEPENDENCY_VERSION*1..{depth_param}]->(v)
            RETURN DISTINCT app.project_name AS project_name,
                   app.name AS version
            ORDER BY project_name, version
        """
        app_result = self.execute_query(
            app_query,
            {"repo_url": repo_url},
        )
        affected_apps = [{"project_name": row[0], "version": row[1]} for row in app_result]

        # Build graph_nodes and graph_edges for visualization
        node_ids: set[str] = set()
        graph_nodes: list[dict[str, Any]] = []
        graph_edges: list[dict[str, Any]] = []

        # Add source repo as root node
        repo_node_id = "repo:" + repo_url
        node_ids.add(repo_node_id)
        graph_nodes.append(
            {
                "id": repo_node_id,
                "label": "Source Repo",
                "type": "source_repo",
            }
        )

        # Add package nodes and edges from repo to packages
        for pkg in packages:
            nid = f"{pkg['project_name']}:{pkg['version']}"
            if nid not in node_ids:
                node_ids.add(nid)
                graph_nodes.append(
                    {
                        "id": nid,
                        "label": f"{pkg['project_name']}@{pkg['version']}",
                        "type": "package",
                    }
                )
            graph_edges.append({"source": repo_node_id, "target": nid, "type": "HAS_SOURCE"})

        # Add dependant nodes and edges (limit to avoid huge graphs)
        seen_edges: set[tuple[str, str]] = set()
        for dep in dependants[:200]:  # Cap for visualization
            nid = f"{dep['project_name']}:{dep['version']}"
            if nid not in node_ids:
                node_ids.add(nid)
                dtype = "application" if dep["node_type"] == "Application" else "dependant"
                graph_nodes.append(
                    {
                        "id": nid,
                        "label": f"{dep['project_name']}@{dep['version']}",
                        "type": dtype,
                    }
                )

        # Edges: dependant -> package (dependency direction)
        graph_query = f"""
            MATCH (v:{label})-[:HAS_SOURCE]->(r:SourceRepository {{url: $repo_url}})
            MATCH (dep)-[e:DEPENDENCY_VERSION*1..1]->(v)
            RETURN DISTINCT dep.project_name AS dproj, dep.name AS dver,
                   v.project_name AS vproj, v.name AS vver
            LIMIT 300
        """
        edge_result = self.execute_query(
            graph_query,
            {"repo_url": repo_url},
        )
        for row in edge_result:
            snid = f"{row[0]}:{row[1]}"
            tnid = f"{row[2]}:{row[3]}"
            if (snid, tnid) not in seen_edges and snid in node_ids and tnid in node_ids:
                seen_edges.add((snid, tnid))
                graph_edges.append({"source": snid, "target": tnid, "type": "DEPENDS_ON"})

        return {
            "packages": packages,
            "dependants": dependants,
            "affected_applications": affected_apps,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
            "stats": {
                "packages_from_repo": len(packages),
                "total_downstream_consumers": len(dependants),
                "affected_applications": len(affected_apps),
            },
        }

    def get_vulnerabilities_with_vex(
        self,
        internal_only: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return all vulnerabilities with their latest VEX status.

        Each vulnerability includes its latest VEX status (if any).
        """
        label = f":{self.get_node_label(internal_only)}"
        page_clause, page_params = self._page_clause(limit, offset)

        query = f"""
            MATCH (v{label})-[:VERSION_DEFECT]->(d:Defect)
            OPTIONAL MATCH (v)-[:HAS_VEX]->(s:VexStatement)-[:REFERS_TO]->(d)
            WITH d, collect(DISTINCT s) AS statements,
                 collect(DISTINCT {{
                     project_name: v.project_name,
                     version: v.name,
                     project_group: v.project_group
                 }}) AS affected
            RETURN COALESCE(d.id, d.defect_id) AS defect_id,
                   d.severity AS severity,
                   d.description AS description,
                   CASE WHEN size(statements) > 0
                        THEN head(statements).status
                        ELSE null END AS vex_status,
                   size(statements) AS vex_count,
                   affected
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'critical' THEN 1
                    WHEN 'HIGH' THEN 2 WHEN 'high' THEN 2
                    WHEN 'MEDIUM' THEN 3 WHEN 'medium' THEN 3
                    WHEN 'LOW' THEN 4 WHEN 'low' THEN 4
                    ELSE 5
                END
            {page_clause}
        """
        result = self.execute_query(query, page_params)
        vulns = []
        for row in result:
            vulns.append(
                {
                    "defect_id": row[0],
                    "severity": row[1],
                    "description": row[2],
                    "vex_status": row[3],
                    "vex_count": row[4],
                    "affected_versions": row[5] or [],
                }
            )
        return vulns

    def count_vulnerabilities_with_vex(self, internal_only: bool = False) -> int:
        """Return total count of distinct defects reachable from versions."""
        label = f":{self.get_node_label(internal_only)}"
        query = f"""
            MATCH (v{label})-[:VERSION_DEFECT]->(d:Defect)
            RETURN COUNT(DISTINCT d) AS total
        """
        result = self.execute_query(query, {})
        return int(result[0][0]) if result else 0

    # Trust Score methods

    def get_trust_score_for_purl(self, purl: str) -> dict[str, Any] | None:
        """Return the full trust score breakdown for a single package.

        Args:
            purl: Package URL.

        Returns:
            Dict with all trust score fields, or None if no score exists.
        """
        query = """
            MATCH (t:TrustScore {purl: $purl})
            RETURN t.purl AS purl,
                   t.direct_score AS direct_score,
                   t.effective_score AS effective_score,
                   t.inherited_score AS inherited_score,
                   t.min_path_score AS min_path_score,
                   t.confidence AS confidence,
                   t.dep_count AS dep_count,
                   t.security_practices_score AS security_practices_score,
                   t.vulnerability_profile_score AS vulnerability_profile_score,
                   t.maintenance_health_score AS maintenance_health_score,
                   t.supply_chain_hygiene_score AS supply_chain_hygiene_score,
                   t.sources_used AS sources_used,
                   t.scored_at AS scored_at
        """
        result = self.execute_query(query, {"purl": purl})
        if not result:
            return None
        row = result[0]
        return {
            "purl": row[0],
            "direct_score": row[1],
            "effective_score": row[2],
            "inherited_score": row[3],
            "min_path_score": row[4],
            "confidence": row[5],
            "dep_count": row[6],
            "security_practices_score": row[7],
            "vulnerability_profile_score": row[8],
            "maintenance_health_score": row[9],
            "supply_chain_hygiene_score": row[10],
            "sources_used": row[11],
            "scored_at": row[12],
        }

    def get_trust_score_risk_path(self, purl: str, limit: int = 10) -> list[dict[str, Any]]:
        """Return the dependency risk path from a package, sorted by score impact.

        Uses BFS to traverse DEPENDENCY_VERSION edges downward, collecting
        trust scores for each dependency.

        Args:
            purl: Starting package URL.
            limit: Maximum dependencies to return.

        Returns:
            List of dicts with purl, direct_score, effective_score, depth.
        """
        query = """
            MATCH path = (v:Version {package_url: $purl})-[:DEPENDENCY_VERSION*1..5]->(dep:Version)
            WHERE dep.package_url IS NOT NULL
            WITH dep, length(path) AS depth
            OPTIONAL MATCH (dep)-[:HAS_TRUST_SCORE]->(t:TrustScore)
            RETURN DISTINCT dep.package_url AS purl,
                   t.direct_score AS direct_score,
                   t.effective_score AS effective_score,
                   t.min_path_score AS min_path_score,
                   depth
            ORDER BY t.direct_score ASC
            LIMIT $limit
        """
        result = self.execute_query(query, {"purl": purl, "limit": limit})
        paths = []
        for row in result:
            paths.append(
                {
                    "purl": row[0],
                    "direct_score": row[1],
                    "effective_score": row[2],
                    "min_path_score": row[3],
                    "depth": row[4],
                }
            )
        return paths

    def get_application_supply_chain_risk(self, purl: str) -> dict[str, Any]:
        """Return aggregate supply-chain risk for an application package.

        Args:
            purl: Application package URL.

        Returns:
            Dict with effective_score, min_path_score, dep_count,
            risk_distribution, and weakest_links.
        """
        score = self.get_trust_score_for_purl(purl)
        if not score:
            return {"purl": purl, "error": "No trust score found"}

        weakest = self.get_trust_score_risk_path(purl, limit=5)

        return {
            "purl": purl,
            "effective_score": score.get("effective_score"),
            "direct_score": score.get("direct_score"),
            "inherited_score": score.get("inherited_score"),
            "min_path_score": score.get("min_path_score"),
            "dep_count": score.get("dep_count"),
            "confidence": score.get("confidence"),
            "weakest_links": weakest,
        }

    def get_trust_score_distribution(self) -> dict[str, int]:
        """Return a histogram of effective trust scores across all packages.

        Returns:
            Dict mapping score bucket labels to counts.
        """
        query = """
            MATCH (t:TrustScore)
            WHERE t.effective_score IS NOT NULL
            RETURN
                CASE
                    WHEN t.effective_score >= 9 THEN 'excellent'
                    WHEN t.effective_score >= 7 THEN 'good'
                    WHEN t.effective_score >= 5 THEN 'moderate'
                    WHEN t.effective_score >= 3 THEN 'poor'
                    ELSE 'critical'
                END AS bucket,
                count(t) AS count
            ORDER BY
                CASE bucket
                    WHEN 'critical' THEN 1
                    WHEN 'poor' THEN 2
                    WHEN 'moderate' THEN 3
                    WHEN 'good' THEN 4
                    WHEN 'excellent' THEN 5
                END
        """
        result = self.execute_query(query, {})
        distribution = {}
        for row in result:
            distribution[row[0]] = row[1]
        return distribution

    def get_most_depended_packages(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return packages with the most dependants (highest fan-in).

        Args:
            limit: Maximum packages to return.

        Returns:
            List of dicts with purl and fan_in (number of dependants).
        """
        query = """
            MATCH (v:Version)<-[:DEPENDENCY_VERSION]-(d:Version)
            WHERE v.package_url IS NOT NULL
            WITH v.package_url AS purl, count(DISTINCT d) AS fan_in
            RETURN purl, fan_in ORDER BY fan_in DESC LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})
        return [{"purl": row[0] or "", "fan_in": row[1] or 0} for row in result]

    def get_remediation_priorities(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return packages ranked by remediation priority.

        Packages with the lowest effective_score that are depended on by the
        most other packages are the highest priority for remediation.

        Args:
            limit: Maximum packages to return.

        Returns:
            List of dicts with purl, effective_score, direct_score,
            min_path_score, and dependents_count.
        """
        query = """
            MATCH (t:TrustScore)
            WHERE t.effective_score IS NOT NULL
            OPTIONAL MATCH (parent:Version)-[:DEPENDENCY_VERSION]->(v:Version {package_url: t.purl})
            WITH t, count(DISTINCT parent) AS dependents_count
            RETURN t.purl AS purl,
                   t.effective_score AS effective_score,
                   t.direct_score AS direct_score,
                   t.min_path_score AS min_path_score,
                   t.confidence AS confidence,
                   dependents_count
            ORDER BY t.effective_score ASC, dependents_count DESC
            LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})
        priorities = []
        for row in result:
            priorities.append(
                {
                    "purl": row[0],
                    "effective_score": row[1],
                    "direct_score": row[2],
                    "min_path_score": row[3],
                    "confidence": row[4],
                    "dependents_count": row[5],
                }
            )
        return priorities

    def get_trust_score_gaps(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return packages with low confidence, sorted by dependency frequency.

        These are packages where more data sources are needed to improve
        scoring accuracy.

        Args:
            limit: Maximum packages to return.

        Returns:
            List of dicts with purl, project_name, version, confidence,
            sources_used, direct_score, dependents_count.
        """
        query = """
            MATCH (t:TrustScore)
            WHERE t.confidence < 0.75
            OPTIONAL MATCH (v:Version {package_url: t.purl})
            OPTIONAL MATCH (parent:Version)-[:DEPENDENCY_VERSION]->
                (v2:Version {package_url: t.purl})
            WITH t,
                 head(collect(DISTINCT v.project_name)) AS project_name,
                 head(collect(DISTINCT v.name)) AS version,
                 count(DISTINCT parent) AS dependents_count
            RETURN t.purl AS purl,
                   project_name,
                   version,
                   t.confidence AS confidence,
                   t.sources_used AS sources_used,
                   t.direct_score AS direct_score,
                   dependents_count
            ORDER BY dependents_count DESC, t.confidence ASC
            LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})
        gaps = []
        for row in result:
            project_name = row[1]
            version = row[2]
            if isinstance(project_name, list):
                project_name = project_name[0] if project_name else None
            if isinstance(version, list):
                version = version[0] if version else None
            gaps.append(
                {
                    "purl": row[0],
                    "project_name": project_name,
                    "version": version,
                    "confidence": row[3],
                    "sources_used": row[4],
                    "direct_score": row[5],
                    "dependents_count": row[6],
                }
            )
        return gaps

    def get_all_trust_scores_for_report(
        self,
        internal_only: bool = False,
        min_score: float = 0.0,
        sort_by: str = "effective_score",
        limit: int | None = None,
        offset: int = 0,
        name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all packages with trust scores for report listing.

        Args:
            internal_only: If True, restrict to INTERNAL-labeled versions.
            min_score: Minimum effective_score (or direct_score) filter.
            sort_by: Sort key - "effective_score" or "direct_score".
            limit: Maximum rows to return (None = all).
            offset: Row offset for pagination.
            name: Optional case-insensitive project_name substring filter.

        Returns:
            List of dicts with purl, project_name, direct_score, effective_score,
            confidence, sources_used.
        """
        label_filter = f":{self.internal_label}" if internal_only else ""
        sort_field = "effective_score" if sort_by == "effective_score" else "direct_score"
        page_clause, page_params = self._page_clause(limit, offset)
        params: dict[str, Any] = {"min_score": min_score, **page_params}
        name_pred = self._name_predicate("v", name, params)
        name_clause = f"AND {name_pred}" if name_pred else ""
        query = f"""
            MATCH (v:Version{label_filter})-[:HAS_TRUST_SCORE]->(t:TrustScore)
            WHERE t.{sort_field} IS NOT NULL AND t.{sort_field} >= $min_score {name_clause}
            RETURN t.purl AS purl,
                   v.project_name AS project_name,
                   v.name AS version,
                   t.direct_score AS direct_score,
                   t.effective_score AS effective_score,
                   t.confidence AS confidence,
                   t.sources_used AS sources_used
            ORDER BY t.{sort_field} ASC
            {page_clause}
        """
        result = self.execute_query(query, params)
        return [
            {
                "purl": row[0],
                "project_name": row[1],
                "version": row[2],
                "direct_score": row[3],
                "effective_score": row[4],
                "confidence": row[5],
                "sources_used": row[6] or [],
            }
            for row in result
        ]

    def count_all_trust_scores_for_report(
        self,
        internal_only: bool = False,
        min_score: float = 0.0,
        sort_by: str = "effective_score",
        name: str | None = None,
    ) -> int:
        """Return total count of packages with trust scores matching the filter."""
        label_filter = f":{self.internal_label}" if internal_only else ""
        sort_field = "effective_score" if sort_by == "effective_score" else "direct_score"
        params: dict[str, Any] = {"min_score": min_score}
        name_pred = self._name_predicate("v", name, params)
        name_clause = f"AND {name_pred}" if name_pred else ""
        query = f"""
            MATCH (v:Version{label_filter})-[:HAS_TRUST_SCORE]->(t:TrustScore)
            WHERE t.{sort_field} IS NOT NULL AND t.{sort_field} >= $min_score {name_clause}
            RETURN COUNT(DISTINCT t) AS total
        """
        result = self.execute_query(query, params)
        return int(result[0][0]) if result else 0

    def get_trust_scores_summary(
        self,
        internal_only: bool = False,
        min_score: float = 0.0,
        sort_by: str = "effective_score",
        name: str | None = None,
    ) -> dict[str, Any]:
        """Return aggregate stats for trust scores report (FULL SET, no pagination).

        Honors the same internal_only / min_score / name filter as the paginated
        query. Returns total, avg_direct, avg_effective, low/medium/high counts.
        """
        label_filter = f":{self.internal_label}" if internal_only else ""
        sort_field = "effective_score" if sort_by == "effective_score" else "direct_score"
        params: dict[str, Any] = {"min_score": min_score}
        name_pred = self._name_predicate("v", name, params)
        name_clause = f"AND {name_pred}" if name_pred else ""
        query = f"""
            MATCH (v:Version{label_filter})-[:HAS_TRUST_SCORE]->(t:TrustScore)
            WHERE t.{sort_field} IS NOT NULL AND t.{sort_field} >= $min_score {name_clause}
            RETURN
                count(t) AS total,
                avg(t.direct_score) AS avg_direct,
                avg(t.effective_score) AS avg_effective,
                sum(CASE WHEN t.effective_score < 4 THEN 1 ELSE 0 END) AS low,
                sum(CASE WHEN t.effective_score >= 4 AND t.effective_score < 7 THEN 1 ELSE 0 END) AS medium,
                sum(CASE WHEN t.effective_score >= 7 THEN 1 ELSE 0 END) AS high
        """
        result = self.execute_query(query, params)
        if not result:
            return {"total": 0, "avg_direct": None, "avg_effective": None, "low": 0, "medium": 0, "high": 0}
        row = result[0]
        return {
            "total": int(row[0]) if row[0] is not None else 0,
            "avg_direct": float(row[1]) if row[1] is not None else None,
            "avg_effective": float(row[2]) if row[2] is not None else None,
            "low": int(row[3]) if row[3] is not None else 0,
            "medium": int(row[4]) if row[4] is not None else 0,
            "high": int(row[5]) if row[5] is not None else 0,
        }

    def get_trust_scores_heatmap(
        self,
        internal_only: bool = False,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return trust scores with category breakdowns for heatmap visualization.

        Args:
            internal_only: If True, restrict to INTERNAL-labeled versions.
            limit: Maximum packages to return.

        Returns:
            List of dicts with purl, project_name, version, effective_score,
            security_practices_score, vulnerability_profile_score,
            maintenance_health_score, supply_chain_hygiene_score.
        """
        label_filter = f":{self.internal_label}" if internal_only else ""
        query = f"""
            MATCH (v:Version{label_filter})-[:HAS_TRUST_SCORE]->(t:TrustScore)
            WHERE t.effective_score IS NOT NULL
            RETURN t.purl AS purl,
                   v.project_name AS project_name,
                   v.name AS version,
                   t.effective_score AS effective_score,
                   t.security_practices_score AS security_practices_score,
                   t.vulnerability_profile_score AS vulnerability_profile_score,
                   t.maintenance_health_score AS maintenance_health_score,
                   t.supply_chain_hygiene_score AS supply_chain_hygiene_score
            ORDER BY t.effective_score ASC
            LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})
        return [
            {
                "purl": row[0],
                "project_name": row[1],
                "version": row[2],
                "effective_score": row[3],
                "security_practices_score": row[4],
                "vulnerability_profile_score": row[5],
                "maintenance_health_score": row[6],
                "supply_chain_hygiene_score": row[7],
            }
            for row in result
        ]

    def get_application_risk_dashboard(
        self,
        internal_only: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return applications with aggregate supply-chain risk for dashboard.

        Args:
            internal_only: If True, restrict to INTERNAL-labeled applications.
            limit: Maximum applications to return.

        Returns:
            List of dicts with purl, project_name, version, effective_score,
            direct_dep_count, transitive_dep_count (from dep_count).
        """
        label_filter = f":{self.internal_label}" if internal_only else ""
        query = f"""
            MATCH (app:Application{label_filter})
            OPTIONAL MATCH (app)-[:HAS_TRUST_SCORE]->(t:TrustScore)
            OPTIONAL MATCH (app)-[:DEPENDENCY_VERSION]->(direct:Version)
            WITH app, t,
                 t.effective_score AS effective_score,
                 t.dep_count AS dep_count,
                 t.purl AS t_purl,
                 count(DISTINCT direct) AS direct_count
            WHERE app.package_url IS NOT NULL OR t_purl IS NOT NULL
            RETURN coalesce(t_purl, app.package_url) AS purl,
                   app.project_name AS project_name,
                   app.name AS version,
                   effective_score,
                   direct_count AS direct_dep_count,
                   coalesce(dep_count, direct_count) AS transitive_dep_count
            ORDER BY coalesce(effective_score, 10) ASC
            LIMIT $limit
        """
        result = self.execute_query(query, {"limit": limit})
        return [
            {
                "purl": row[0],
                "project_name": row[1],
                "version": row[2],
                "effective_score": row[3],
                "direct_dep_count": row[4] or 0,
                "transitive_dep_count": row[5] or row[4] or 0,
            }
            for row in result
        ]

    def get_risk_outliers(
        self,
        min_dependents: int = 3,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return packages with low effective_score and high fan-in (risk outliers).

        Packages with effective_score < 4 that are dependencies of >= min_dependents
        applications/packages.

        Args:
            min_dependents: Minimum number of dependants (default 3).
            limit: Maximum packages to return.

        Returns:
            List of dicts with purl, project_name, version, effective_score,
            dependents_count.
        """
        query = """
            MATCH (t:TrustScore)
            WHERE t.effective_score IS NOT NULL AND t.effective_score < 4
            OPTIONAL MATCH (parent:Version)-[:DEPENDENCY_VERSION]->(v:Version)
            WHERE v.package_url = t.purl
            WITH t, count(DISTINCT parent) AS dependents_count
            WHERE dependents_count >= $min_dependents
            OPTIONAL MATCH (v2:Version {package_url: t.purl})
            WITH t, dependents_count,
                 head(collect(DISTINCT v2.project_name)) AS project_name,
                 head(collect(DISTINCT v2.name)) AS version
            RETURN t.purl AS purl,
                   project_name,
                   version,
                   t.effective_score AS effective_score,
                   dependents_count
            ORDER BY t.effective_score ASC, dependents_count DESC
            LIMIT $limit
        """
        result = self.execute_query(query, {"min_dependents": min_dependents, "limit": limit})
        return [
            {
                "purl": row[0],
                "project_name": row[1] or "",
                "version": row[2] or "",
                "effective_score": row[3],
                "dependents_count": row[4],
            }
            for row in result
        ]

    def get_sbom_inventory(
        self,
        search: str | None = None,
        tool: str | None = None,
        sbom_format: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all SBOMRecord nodes with metadata and linked version count.

        Args:
            search: Optional substring filter for record_id, tool_name, format.
            tool: Optional exact match for tool_name.
            sbom_format: Optional format filter (CycloneDX or SPDX).
            date_from: Optional start date (YYYY-MM-DD) for ingested_at.
            date_to: Optional end date (YYYY-MM-DD) for ingested_at.

        Returns:
            List of dicts with record_id, format, ingested_at, source,
            optional tool fields, and version_count.
        """
        search_val = (search or "").strip()
        tool_val = (tool or "").strip()
        format_val = (sbom_format or "").strip()
        date_from_val = (date_from or "").strip()
        date_to_val = (date_to or "").strip()

        params: dict[str, Any] = {
            "search": search_val,
            "tool": tool_val,
            "format_filter": format_val,
            "date_from": date_from_val + "T00:00:00Z" if date_from_val else "",
            "date_to": date_to_val + "T23:59:59Z" if date_to_val else "",
        }

        query = """
            MATCH (s:SBOMRecord)
            WHERE ($search = "" OR coalesce(s.record_id, "") CONTAINS $search
                   OR coalesce(s.tool_name, "") CONTAINS $search
                   OR toLower(toString(coalesce(s.format, ""))) CONTAINS toLower($search))
              AND ($tool = "" OR s.tool_name = $tool)
              AND ($format_filter = "" OR toLower(toString(s.format)) = toLower($format_filter))
              AND ($date_from = "" OR s.ingested_at >= $date_from)
              AND ($date_to = "" OR s.ingested_at <= $date_to)
            OPTIONAL MATCH (v:Version)-[:PRODUCED_BY_SBOM]->(s)
            WITH s, count(v) AS version_count
            RETURN s.record_id AS record_id,
                    s.format AS format,
                    s.ingested_at AS ingested_at,
                    s.source AS source,
                    s.tool_name AS tool_name,
                    s.tool_version AS tool_version,
                    s.serial_number AS serial_number,
                    s.document_hash AS document_hash,
                    version_count
        """
        result = self.execute_query(query, params)
        return [
            {
                "record_id": row[0],
                "format": row[1],
                "ingested_at": row[2],
                "source": row[3],
                "tool_name": row[4],
                "tool_version": row[5],
                "serial_number": row[6],
                "document_hash": row[7],
                "version_count": row[8] or 0,
            }
            for row in result
        ]

    def _sbom_inventory_params(
        self,
        search: str | None,
        tool: str | None,
        sbom_format: str | None,
        date_from: str | None,
        date_to: str | None,
    ) -> dict[str, Any]:
        """Build shared query params for SBOM inventory queries."""
        search_val = (search or "").strip()
        tool_val = (tool or "").strip()
        format_val = (sbom_format or "").strip()
        date_from_val = (date_from or "").strip()
        date_to_val = (date_to or "").strip()
        return {
            "search": search_val,
            "tool": tool_val,
            "format_filter": format_val,
            "date_from": date_from_val + "T00:00:00Z" if date_from_val else "",
            "date_to": date_to_val + "T23:59:59Z" if date_to_val else "",
        }

    def get_sbom_inventory_paged(
        self,
        search: str | None = None,
        tool: str | None = None,
        sbom_format: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Paged version of get_sbom_inventory (PERF-001/SEC-003)."""
        params = self._sbom_inventory_params(search, tool, sbom_format, date_from, date_to)
        page_clause, page_params = self._page_clause(limit, offset)
        params.update(page_params)
        query = f"""
            MATCH (s:SBOMRecord)
            WHERE ($search = "" OR coalesce(s.record_id, "") CONTAINS $search
                   OR coalesce(s.tool_name, "") CONTAINS $search
                   OR toLower(toString(coalesce(s.format, ""))) CONTAINS toLower($search))
              AND ($tool = "" OR s.tool_name = $tool)
              AND ($format_filter = "" OR toLower(toString(s.format)) = toLower($format_filter))
              AND ($date_from = "" OR s.ingested_at >= $date_from)
              AND ($date_to = "" OR s.ingested_at <= $date_to)
            OPTIONAL MATCH (v:Version)-[:PRODUCED_BY_SBOM]->(s)
            WITH s, count(v) AS version_count
            RETURN s.record_id AS record_id,
                    s.format AS format,
                    s.ingested_at AS ingested_at,
                    s.source AS source,
                    s.tool_name AS tool_name,
                    s.tool_version AS tool_version,
                    s.serial_number AS serial_number,
                    s.document_hash AS document_hash,
                    version_count
            ORDER BY s.ingested_at DESC
            {page_clause}
        """
        result = self.execute_query(query, params)
        return [
            {
                "record_id": row[0],
                "format": row[1],
                "ingested_at": row[2],
                "source": row[3],
                "tool_name": row[4],
                "tool_version": row[5],
                "serial_number": row[6],
                "document_hash": row[7],
                "version_count": row[8] or 0,
            }
            for row in result
        ]

    def count_sbom_inventory(
        self,
        search: str | None = None,
        tool: str | None = None,
        sbom_format: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> int:
        """Count SBOMRecord nodes matching filters (backs pagination, PERF-001)."""
        params = self._sbom_inventory_params(search, tool, sbom_format, date_from, date_to)
        query = """
            MATCH (s:SBOMRecord)
            WHERE ($search = "" OR coalesce(s.record_id, "") CONTAINS $search
                   OR coalesce(s.tool_name, "") CONTAINS $search
                   OR toLower(toString(coalesce(s.format, ""))) CONTAINS toLower($search))
              AND ($tool = "" OR s.tool_name = $tool)
              AND ($format_filter = "" OR toLower(toString(s.format)) = toLower($format_filter))
              AND ($date_from = "" OR s.ingested_at >= $date_from)
              AND ($date_to = "" OR s.ingested_at <= $date_to)
            RETURN COUNT(s) AS total
        """
        result = self.execute_query(query, params)
        return int(result[0][0]) if result else 0

    def get_sbom_inventory_tools(
        self,
        search: str | None = None,
        tool: str | None = None,
        sbom_format: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[str]:
        """Return distinct tool names for the SBOM inventory filter UI."""
        params = self._sbom_inventory_params(search, tool, sbom_format, date_from, date_to)
        query = """
            MATCH (s:SBOMRecord)
            WHERE ($search = "" OR coalesce(s.record_id, "") CONTAINS $search
                   OR coalesce(s.tool_name, "") CONTAINS $search
                   OR toLower(toString(coalesce(s.format, ""))) CONTAINS toLower($search))
              AND ($tool = "" OR s.tool_name = $tool)
              AND ($format_filter = "" OR toLower(toString(s.format)) = toLower($format_filter))
              AND ($date_from = "" OR s.ingested_at >= $date_from)
              AND ($date_to = "" OR s.ingested_at <= $date_to)
            WITH s.tool_name AS tn WHERE tn IS NOT NULL
            RETURN DISTINCT tn ORDER BY tn
        """
        result = self.execute_query(query, params)
        return [row[0] for row in result if row[0]]

    def get_sbom_inventory_summary(
        self,
        search: str | None = None,
        tool: str | None = None,
        sbom_format: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> dict[str, Any]:
        """Return aggregate stats for SBOM inventory report (FULL SET, no pagination).

        Returns total, by_format dict, by_source dict — honoring the same filters
        as the paged query.
        """
        params = self._sbom_inventory_params(search, tool, sbom_format, date_from, date_to)
        query = """
            MATCH (s:SBOMRecord)
            WHERE ($search = "" OR coalesce(s.record_id, "") CONTAINS $search
                   OR coalesce(s.tool_name, "") CONTAINS $search
                   OR toLower(toString(coalesce(s.format, ""))) CONTAINS toLower($search))
              AND ($tool = "" OR s.tool_name = $tool)
              AND ($format_filter = "" OR toLower(toString(s.format)) = toLower($format_filter))
              AND ($date_from = "" OR s.ingested_at >= $date_from)
              AND ($date_to = "" OR s.ingested_at <= $date_to)
            RETURN
                coalesce(toString(s.format), "Unknown") AS fmt,
                coalesce(s.source, "Unknown") AS src,
                count(s) AS cnt
        """
        result = self.execute_query(query, params)
        total = 0
        by_format: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for row in result:
            fmt = str(row[0]) if row[0] is not None else "Unknown"
            src = str(row[1]) if row[1] is not None else "Unknown"
            cnt = int(row[2]) if row[2] is not None else 0
            by_format[fmt] = by_format.get(fmt, 0) + cnt
            by_source[src] = by_source.get(src, 0) + cnt
            total += cnt
        return {"total": total, "by_format": by_format, "by_source": by_source}

    def get_sbom_coverage(self, recent_days: int = 30) -> dict[str, int]:
        """Return SBOM coverage statistics for projects.

        Args:
            recent_days: Days within which an SBOM is considered recent.

        Returns:
            Dict with total_projects, with_recent_sbom, with_stale_sbom,
            with_no_sbom.
        """
        cutoff = (datetime.now(UTC) - timedelta(days=recent_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        total_result = self.execute_query(
            """
            MATCH (v:Version)
            WHERE v.project_name IS NOT NULL
            WITH DISTINCT v.project_name, v.project_group
            RETURN count(*) AS total
            """,
            {},
        )
        total = total_result[0][0] if total_result else 0

        recent_result = self.execute_query(
            """
            MATCH (v:Version)-[:PRODUCED_BY_SBOM]->(s:SBOMRecord)
            WHERE v.project_name IS NOT NULL AND s.ingested_at >= $cutoff
            WITH DISTINCT v.project_name, v.project_group
            RETURN count(*) AS cnt
            """,
            {"cutoff": cutoff},
        )
        with_recent = recent_result[0][0] if recent_result else 0

        with_any_result = self.execute_query(
            """
            MATCH (v:Version)-[:PRODUCED_BY_SBOM]->(s:SBOMRecord)
            WHERE v.project_name IS NOT NULL
            WITH DISTINCT v.project_name, v.project_group
            RETURN count(*) AS cnt
            """,
            {},
        )
        with_any = with_any_result[0][0] if with_any_result else 0

        with_stale = with_any - with_recent
        with_no_sbom = total - with_any

        return {
            "total_projects": total,
            "with_recent_sbom": with_recent,
            "with_stale_sbom": with_stale,
            "with_no_sbom": with_no_sbom,
        }

    def get_sbom_coverage_for_dashboard(
        self,
        internal_only: bool = False,
        recent_days: int = 30,
    ) -> dict[str, Any]:
        """Return SBOM coverage stats and per-version details for dashboard.

        Args:
            internal_only: If True, restrict to INTERNAL-labeled versions.
            recent_days: Days within which an SBOM is considered fresh.

        Returns:
            Dict with stats (total_projects, fresh, stale, never, percentages)
            and projects list (project_name, version_name, project_group,
            status, last_ingested, tool_name).
        """
        cutoff = (datetime.now(UTC) - timedelta(days=recent_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        node_label = self.get_node_label(internal_only)

        query = f"""
            MATCH (v:{node_label})
            WHERE v.project_name IS NOT NULL
            OPTIONAL MATCH (v)-[:PRODUCED_BY_SBOM]->(s:SBOMRecord)
            RETURN v.project_name AS project_name,
                   v.name AS version_name,
                   v.project_group AS project_group,
                   s.ingested_at AS ingested_at,
                   s.tool_name AS tool_name
        """
        result = self.execute_query(query, {})

        # Collapse to latest SBOM per version (same version may have multiple)
        version_to_latest: dict[tuple[str, str, str | None], dict[str, Any]] = {}
        for row in result:
            proj, ver, grp, ingested, tool = row[0], row[1], row[2], row[3], row[4]
            key = (proj or "", ver or "", grp)
            existing = version_to_latest.get(key)
            if existing is None or (
                ingested and (not existing["ingested_at"] or ingested > existing["ingested_at"])
            ):
                version_to_latest[key] = {
                    "project_name": proj,
                    "version_name": ver,
                    "project_group": grp or "",
                    "ingested_at": ingested,
                    "tool_name": tool or "-",
                }

        projects: list[dict[str, Any]] = []
        for entry in version_to_latest.values():
            ingested = entry["ingested_at"]
            if ingested is None:
                status = "never"
            elif ingested >= cutoff:
                status = "fresh"
            else:
                status = "stale"
            entry["status"] = status
            entry["last_ingested"] = ingested or "-"
            projects.append(entry)

        # Project-level stats: each project gets status of its "best" version
        project_status: dict[tuple[str, str], str] = {}
        for p in projects:
            pname = str(p.get("project_name", "") or "")
            pgrp = str(p.get("project_group", "") or "")
            pkey = (pname, pgrp)
            current = project_status.get(pkey, "never")
            if p["status"] == "fresh" or current == "fresh":
                project_status[pkey] = "fresh"
            elif p["status"] == "stale" or current == "stale":
                project_status[pkey] = "stale"
            else:
                project_status[pkey] = "never"

        fresh_count = sum(1 for s in project_status.values() if s == "fresh")
        stale_count = sum(1 for s in project_status.values() if s == "stale")
        never_count = sum(1 for s in project_status.values() if s == "never")
        total_projects = len(project_status)
        fresh_pct = (fresh_count / total_projects * 100) if total_projects else 0
        stale_pct = (stale_count / total_projects * 100) if total_projects else 0
        never_pct = (never_count / total_projects * 100) if total_projects else 0

        return {
            "stats": {
                "total_projects": total_projects,
                "fresh": fresh_count,
                "stale": stale_count,
                "never": never_count,
                "fresh_pct": round(fresh_pct, 1),
                "stale_pct": round(stale_pct, 1),
                "never_pct": round(never_pct, 1),
            },
            "projects": sorted(
                projects,
                key=lambda p: (
                    p["project_name"],
                    p["version_name"],
                    p["project_group"],
                ),
            ),
            "recent_days": recent_days,
        }

    def get_sbom_record_by_id(self, record_id: str) -> dict[str, Any] | None:
        """Return a single SBOMRecord by record_id with linked version purls.

        Args:
            record_id: The SBOM record identifier.

        Returns:
            Dict with record metadata and purls list, or None if not found.
        """
        query = """
            MATCH (s:SBOMRecord {record_id: $record_id})
            OPTIONAL MATCH (v:Version)-[:PRODUCED_BY_SBOM]->(s)
            WITH s, collect(DISTINCT v.package_url) AS purl_list
            RETURN s.record_id AS record_id,
                    s.format AS format,
                    s.ingested_at AS ingested_at,
                    s.source AS source,
                    s.tool_name AS tool_name,
                    s.tool_version AS tool_version,
                    s.serial_number AS serial_number,
                    s.document_hash AS document_hash,
                    purl_list
        """
        result = self.execute_query(query, {"record_id": record_id})
        if not result:
            return None

        row = result[0]
        purl_list = row[8] or []
        purls = [p for p in purl_list if p is not None]
        return {
            "record_id": row[0],
            "format": row[1],
            "ingested_at": row[2],
            "source": row[3],
            "tool_name": row[4],
            "tool_version": row[5],
            "serial_number": row[6],
            "document_hash": row[7],
            "purls": purls,
        }

    def simulate_risk_propagation(self, purl: str, simulated_score: float) -> list[dict[str, Any]]:
        """What-if: if package X drops to score Y, what applications are impacted?

        Args:
            purl: Package URL to simulate score change for.
            simulated_score: Simulated trust score (0-10).

        Returns:
            List of dicts with purl, current_effective, simulated_effective,
            impact for each transitive dependant.
        """
        current = self.get_trust_score_for_purl(purl)
        if not current:
            return []

        query = """
            MATCH (v:Version {package_url: $purl})
            MATCH (dep:Version)-[:DEPENDENCY_VERSION*1..20]->(v)
            WHERE dep.package_url IS NOT NULL
            WITH DISTINCT dep.package_url AS dep_purl
            LIMIT 500
            MATCH (dep2:Version {package_url: dep_purl})
            OPTIONAL MATCH (dep2)-[:HAS_TRUST_SCORE]->(t:TrustScore)
            RETURN dep_purl AS purl,
                   t.effective_score AS current_effective,
                   t.direct_score AS direct_score
        """
        result = self.execute_query(query, {"purl": purl})

        impacts = []
        for row in result:
            dep_purl = row[0]
            current_eff = row[1] or row[2] or 0.0
            simulated_eff = min(current_eff, simulated_score)
            impact = current_eff - simulated_eff
            impacts.append(
                {
                    "purl": dep_purl,
                    "current_effective": current_eff,
                    "simulated_effective": simulated_eff,
                    "impact": round(impact, 2),
                }
            )

        return sorted(impacts, key=lambda x: x["impact"], reverse=True)

    def evaluate_patch_plan(
        self,
        purl: str,
        current_version: str,
        target_version: str,
    ) -> dict[str, Any]:
        """Compare vulnerabilities between current and target version.

        Args:
            purl: Package URL prefix (without version).
            current_version: Current version in use.
            target_version: Target version to upgrade to.

        Returns:
            Dict with current_vulns, target_vulns, resolved, added, purl.
        """
        purl_prefix = purl.rsplit("@", 1)[0] + "@" if "@" in purl else purl.rstrip("/") + "@"
        current_purl = purl_prefix + current_version
        target_purl = purl_prefix + target_version

        current_vulns_query = """
            MATCH (v:Version {package_url: $purl})-[:VERSION_DEFECT]->(d:Defect)
            RETURN collect(d.id) AS vulns
        """
        target_vulns_query = """
            MATCH (v:Version {package_url: $purl})-[:VERSION_DEFECT]->(d:Defect)
            RETURN collect(d.id) AS vulns
        """

        current_res = self.execute_query(current_vulns_query, {"purl": current_purl})
        target_res = self.execute_query(target_vulns_query, {"purl": target_purl})

        current_vulns = set(current_res[0][0] or []) if current_res else set()
        target_vulns = set(target_res[0][0] or []) if target_res else set()

        resolved = list(current_vulns - target_vulns)
        added = list(target_vulns - current_vulns)

        return {
            "purl": purl_prefix,
            "current_version": current_version,
            "target_version": target_version,
            "current_vulns": list(current_vulns),
            "target_vulns": list(target_vulns),
            "resolved": resolved,
            "added": added,
        }

    def generate_vex_auto_stubs(
        self, purl: str, justification: str | None = None
    ) -> list[dict[str, Any]]:
        """Create VEX not_affected stubs for packages with vulns but no VEX.

        Args:
            purl: Package URL.
            justification: Optional justification for not_affected status.

        Returns:
            List of created stubs with statement_id, defect_id, status.
        """
        query = """
            MATCH (v:Version {package_url: $purl})-[:VERSION_DEFECT]->(d:Defect)
            WHERE NOT (v)-[:HAS_VEX]->(:VexStatement)-[:REFERS_TO]->(d)
            RETURN d.id AS defect_id
        """
        result = self.execute_query(query, {"purl": purl})
        if not result:
            return []

        defect_ids = [row[0] for row in result]
        created = []
        justification_val = justification or "Auto-generated not_affected stub"
        timestamp = datetime.now(UTC).isoformat()

        for defect_id in defect_ids:
            statement_id = str(uuid.uuid4())
            self.execute_write(
                """
                MERGE (s:VexStatement {statement_id: $statement_id})
                SET s.status = 'not_affected',
                    s.justification = $justification,
                    s.timestamp = $timestamp
                """,
                {
                    "statement_id": statement_id,
                    "justification": justification_val,
                    "timestamp": timestamp,
                },
            )
            self.execute_write(
                """
                MATCH (v:Version {package_url: $purl})
                MATCH (s:VexStatement {statement_id: $statement_id})
                MATCH (d:Defect {id: $defect_id})
                MERGE (v)-[:HAS_VEX]->(s)
                MERGE (s)-[:REFERS_TO]->(d)
                """,
                {
                    "purl": purl,
                    "statement_id": statement_id,
                    "defect_id": defect_id,
                },
            )
            created.append(
                {
                    "statement_id": statement_id,
                    "defect_id": defect_id,
                    "status": "not_affected",
                }
            )

        return created


# Global service instance
_service: FalkorDBService | None = None


def get_falkordb_service() -> FalkorDBService:
    """Get the FalkorDB service singleton."""
    global _service  # pylint: disable=global-statement
    if _service is None:
        _service = FalkorDBService()
    return _service


def reset_service() -> None:
    """Reset the service singleton (useful for testing)."""
    global _service  # pylint: disable=global-statement
    _service = None
