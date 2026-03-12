"""Dependencies graph visualization with spring layout.

This module creates visualizations of the dependency graph for a specific
project version using a force-directed (spring) layout. It properly handles
cyclic dependencies using the visitor pattern during both data extraction
and visualization generation.

The spring layout is ideal for visualizing graphs with cycles because it
doesn't require a hierarchical structure and naturally spreads nodes apart
based on their connectivity.
"""

from collections.abc import Callable

import networkx as nx
from markupsafe import escape
from pyvis.network import Network

from sbom_graph_api.services.falkordb_service import (
    FalkorDBService,
    get_falkordb_service,
)
from sbom_graph_api.visualizations.kpartite import (
    format_properties_for_tooltip,
    get_license_risk_color,
    get_partition_color,
    get_severity_color,
)


class DependencyVisitor:
    """Visitor pattern implementation for traversing dependency graphs with cycles.

    This class handles cycle detection during graph traversal using DFS-based
    back-edge detection. It tracks visited nodes and nodes currently in the
    recursion stack to identify cycles without infinite loops.
    """

    def __init__(self) -> None:
        """Initialize the visitor with empty tracking sets."""
        self.visited: set[str] = set()
        self.rec_stack: set[str] = set()
        self.cycle_edges: list[tuple[str, str]] = []

    def visit(
        self,
        graph: nx.DiGraph,
        node: str,
        on_visit: Callable[[str], None] | None = None,
    ) -> None:
        """Visit a node and its successors, detecting cycles.

        Uses DFS traversal with recursion stack tracking to detect back-edges
        that create cycles. Cycles are recorded but traversal continues.

        Args:
            graph: The NetworkX DiGraph to traverse
            node: The current node ID to visit
            on_visit: Optional callback function called for each visited node
        """
        self.visited.add(node)
        self.rec_stack.add(node)

        if on_visit:
            on_visit(node)

        for successor in graph.successors(node):
            if successor not in self.visited:
                self.visit(graph, successor, on_visit)
            elif successor in self.rec_stack:
                # Back-edge found - this creates a cycle
                self.cycle_edges.append((node, successor))

        self.rec_stack.remove(node)

    def traverse_all(
        self,
        graph: nx.DiGraph,
        start_node: str | None = None,
        on_visit: Callable[[str], None] | None = None,
    ) -> None:
        """Traverse all nodes in the graph, starting from a specific node if provided.

        Args:
            graph: The NetworkX DiGraph to traverse
            start_node: Optional starting node (traversed first if provided)
            on_visit: Optional callback function called for each visited node
        """
        # Start from specified node if provided
        if start_node and start_node not in self.visited:
            self.visit(graph, start_node, on_visit)

        # Visit any remaining disconnected nodes
        for node in graph.nodes():
            if node not in self.visited:
                self.visit(graph, node, on_visit)

    def get_cycle_edges(self) -> list[tuple[str, str]]:
        """Return the list of edges that create cycles."""
        return self.cycle_edges

    def has_cycles(self) -> bool:
        """Return True if any cycles were detected."""
        return len(self.cycle_edges) > 0


def calculate_depths_with_cycles(
    graph: nx.DiGraph,
    root_id: str,
) -> dict[str, int]:
    """Calculate node depths handling cycles gracefully.

    Uses BFS to calculate the shortest path depth from root to each node.
    Cycles are handled by only updating depths when a shorter path is found.

    Args:
        graph: NetworkX DiGraph with dependency relationships
        root_id: The node ID of the root element

    Returns:
        Dictionary mapping node_id -> depth from root
    """
    depths: dict[str, int] = {root_id: 0}
    queue: list[tuple[str, int]] = [(root_id, 0)]
    visited_in_bfs: set[str] = {root_id}

    while queue:
        current, depth = queue.pop(0)

        for successor in graph.successors(current):
            if successor not in visited_in_bfs:
                visited_in_bfs.add(successor)
                depths[successor] = depth + 1
                queue.append((successor, depth + 1))

    return depths


_VEX_SHIELD = "\U0001f6e1"
_POLICY_BANNED = "\U0001f6ab"
_POLICY_APPROVED = "\u2705"
_POLICY_DEPRECATED = "\u26a0\ufe0f"
_POLICY_LABELS = {
    "bad": "Banned",
    "good": "Approved",
    "hold": "Deprecated",
}

_SPRING_LAYOUT_OPTIONS = """
{
    "physics": {
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {
            "gravitationalConstant": -50,
            "centralGravity": 0.01,
            "springLength": 150,
            "springConstant": 0.08,
            "damping": 0.4,
            "avoidOverlap": 0.5
        },
        "stabilization": {
            "enabled": true,
            "iterations": 200,
            "updateInterval": 25
        }
    },
    "nodes": {
        "font": {"size": 12},
        "shape": "box",
        "borderWidth": 2
    },
    "edges": {
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.8}},
        "smooth": {
            "enabled": true,
            "type": "continuous",
            "roundness": 0.5
        }
    },
    "interaction": {
        "hover": true,
        "navigationButtons": true,
        "keyboard": true
    }
}
"""


class _EnrichmentMaps:  # pylint: disable=too-few-public-methods
    """Aggregates per-purl enrichment maps queried from the service."""

    __slots__ = (
        "severity",
        "license_risk",
        "vex_status",
        "policy",
    )

    def __init__(
        self,
        service: FalkorDBService,
        node_data: dict[str, dict],
    ) -> None:
        self.severity: dict[str, str] = {}
        self.license_risk: dict[str, str] = {}
        self.vex_status: dict[str, str] = {}
        self.policy: dict[str, str] = {}

        purls = [
            d.get("properties", {}).get("package_url")
            for d in node_data.values()
            if d.get("properties", {}).get("package_url")
        ]
        if purls:
            self.severity = (
                service.get_vulnerability_severities_for_versions(
                    purls
                )
            )
            self.license_risk = (
                service.get_license_risks_for_versions(purls)
            )
            self.vex_status = (
                service.get_vex_statuses_for_versions(purls)
            )
            self.policy = (
                service.get_policy_annotations_for_purls(purls)
            )


def _build_node_label(
    safe_project: str,
    safe_version: str,
    vex_status: str | None,
    policy_type: str | None,
) -> str:
    """Build the display label for a graph node."""
    label = f"{safe_project}\n{safe_version}"
    if vex_status == "not_affected":
        label += f" {_VEX_SHIELD}"
    if policy_type == "bad":
        label += f" {_POLICY_BANNED}"
    elif policy_type == "good":
        label += f" {_POLICY_APPROVED}"
    elif policy_type == "hold":
        label += f" {_POLICY_DEPRECATED}"
    return label


def _build_node_tooltip(
    safe_project: str,
    safe_version: str,
    depth: int,
    data: dict,
    severity: str | None,
    risk_category: str | None,
    vex_status: str | None,
    policy_type: str | None,
    is_in_cycle: bool,
) -> str:
    """Build the hover tooltip for a graph node."""
    labels_str = escape(
        ", ".join(data.get("labels", []))
    )
    parts = [
        f"{safe_project}\n",
        f"Version: {safe_version}\n",
        f"Depth from root: {depth}\n",
        f"Labels: {labels_str}\n",
    ]
    if severity:
        parts.append(
            f"Highest vulnerability severity: {severity}\n"
        )
    if risk_category:
        parts.append(
            f"License risk: "
            f"{escape(risk_category.replace('_', ' '))}\n"
        )
    if vex_status:
        parts.append(
            f"VEX status: "
            f"{escape(vex_status.replace('_', ' '))}\n"
        )
    if policy_type:
        policy_label = _POLICY_LABELS.get(
            policy_type, policy_type
        )
        parts.append(f"Policy: {escape(policy_label)}\n")
    if is_in_cycle:
        parts.append("** HAS CYCLIC DEPENDENCY **\n")

    properties = data.get("properties", {})
    if properties:
        parts.append("=======================\n")
        parts.append("All Properties:\n")
        parts.append(
            format_properties_for_tooltip(properties)
        )
    return "\n".join(parts)


def _add_nodes_to_network(
    net: Network,
    node_data: dict[str, dict],
    depths: dict[str, int],
    enrichment: _EnrichmentMaps,
    cycle_edges_set: set[tuple[str, str]],
    self_loops: set[tuple[str, str]],
) -> None:
    """Populate the PyVis network with styled nodes."""
    all_cycle_members = cycle_edges_set | self_loops
    for node_id, data in node_data.items():
        depth = depths.get(node_id, 0)
        purl = data.get("properties", {}).get("package_url")

        severity = enrichment.severity.get(purl) if purl else None
        risk_cat = enrichment.license_risk.get(purl) if purl else None
        vex_status = enrichment.vex_status.get(purl) if purl else None
        policy_type = enrichment.policy.get(purl) if purl else None

        color = _resolve_node_color(
            severity, risk_cat, depth
        )
        is_in_cycle = any(
            node_id in (e[0], e[1])
            for e in all_cycle_members
        )

        safe_project = escape(data["project_name"])
        safe_version = escape(data["version"])

        label = _build_node_label(
            safe_project, safe_version,
            vex_status, policy_type,
        )
        title = _build_node_tooltip(
            safe_project, safe_version, depth, data,
            severity, risk_cat, vex_status, policy_type,
            is_in_cycle,
        )

        border_width = 4 if is_in_cycle else 2
        border_color = "#ff0000" if is_in_cycle else color
        node_color: dict[str, str] = {
            "background": color,
            "border": border_color,
        }
        net.add_node(
            node_id,
            label=label,
            title=title,
            color=node_color,  # type: ignore[arg-type]
            borderWidth=border_width,
            group=depth,
        )


def _resolve_node_color(
    severity: str | None,
    risk_category: str | None,
    depth: int,
) -> str:
    """Choose the node colour based on severity, licence risk, or depth."""
    if severity:
        sev_color = get_severity_color(severity)
        if sev_color:
            return sev_color
    if risk_category:
        lic_color = get_license_risk_color(risk_category)
        if lic_color:
            return lic_color
    return get_partition_color(depth)


def _add_edges_to_network(
    net: Network,
    edges: list[dict],
    cycle_edges_set: set[tuple[str, str]],
) -> None:
    """Add dependency edges to the PyVis network."""
    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        is_cycle = (
            (source, target) in cycle_edges_set
            or source == target
        )
        if is_cycle:
            net.add_edge(
                source, target,
                title=f"{edge['type']} (CYCLE)",
                arrows="to",
                color="#ff0000",
                dashes=True,
                width=3,
            )
        else:
            net.add_edge(
                source, target,
                title=edge["type"],
                arrows="to",
            )


def create_dependencies_graph_visualization(
    project_name: str,
    version_name: str,
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
) -> str | None:
    """Create a spring-layout visualization of the dependency graph.

    Shows the dependency tree for a project version using a force-directed
    layout that naturally handles cyclic dependencies. Cycle edges are
    highlighted in red with dashed lines.

    Args:
        project_name: The project name to visualize
        version_name: The version string
        max_depth: Maximum depth to traverse (None for unlimited)
        internal_only: If True, only include internal-labeled nodes
        height: Height of the visualization (validated CSS dimension)
        width: Width of the visualization (validated CSS dimension)
        service: FalkorDB service instance
        project_group: Optional group for root node disambiguation

    Returns:
        HTML string of the visualization, or None if project not found
    """
    if service is None:
        service = get_falkordb_service()

    root = service.find_version(
        project_name, version_name, project_group
    )
    if not root:
        return None

    nodes, edges = service.get_transitive_dependencies(
        project_name, version_name,
        max_depth, internal_only,
        project_group=project_group,
    )

    root_id = f"{project_name}:{version_name}"
    node_data = {n["id"]: n for n in nodes}
    if root_id not in node_data:
        node_data[root_id] = {
            "id": root_id,
            "project_name": project_name,
            "version": version_name,
            "labels": root["labels"],
            "properties": root["properties"],
        }

    graph: nx.DiGraph = nx.DiGraph()
    for node in node_data.values():
        graph.add_node(node["id"])
    for edge in edges:
        graph.add_edge(edge["source"], edge["target"])

    visitor = DependencyVisitor()
    visitor.traverse_all(graph, start_node=root_id)
    cycle_edges_set = set(visitor.get_cycle_edges())
    self_loops = set(nx.selfloop_edges(graph))

    depths = calculate_depths_with_cycles(graph, root_id)
    enrichment = _EnrichmentMaps(service, node_data)

    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )
    net.set_options(_SPRING_LAYOUT_OPTIONS)

    _add_nodes_to_network(
        net, node_data, depths,
        enrichment, cycle_edges_set, self_loops,
    )
    _add_edges_to_network(
        net, edges, cycle_edges_set,
    )

    return net.generate_html()
