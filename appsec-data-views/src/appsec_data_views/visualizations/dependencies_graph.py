"""Dependencies graph visualization with spring layout.

This module creates visualizations of the dependency graph for a specific
project version using a force-directed (spring) layout. It properly handles
cyclic dependencies using the visitor pattern during both data extraction
and visualization generation.

The spring layout is ideal for visualizing graphs with cycles because it
doesn't require a hierarchical structure and naturally spreads nodes apart
based on their connectivity.
"""

import networkx as nx
from markupsafe import escape
from pyvis.network import Network

from appsec_data_views.services.falkordb_service import (
    FalkorDBService,
    get_falkordb_service,
)
from appsec_data_views.visualizations.kpartite import (
    format_properties_for_tooltip,
    get_partition_color,
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
        on_visit: callable | None = None,
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
        on_visit: callable | None = None,
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


def create_dependencies_graph_visualization(
    project_name: str,
    version_name: str,
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
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

    Returns:
        HTML string of the visualization, or None if project not found
    """
    if service is None:
        service = get_falkordb_service()

    # Verify root node exists
    root = service.find_version(project_name, version_name)
    if not root:
        return None

    root_properties = root["properties"]
    root_labels = root["labels"]

    # Get dependency graph
    nodes, edges = service.get_transitive_dependencies(
        project_name, version_name, max_depth, internal_only
    )

    root_id = f"{project_name}:{version_name}"

    # Build node data dictionary
    node_data = {n["id"]: n for n in nodes}

    # Ensure root is in node_data
    if root_id not in node_data:
        node_data[root_id] = {
            "id": root_id,
            "project_name": project_name,
            "version": version_name,
            "labels": root_labels,
            "properties": root_properties,
        }

    # Build NetworkX graph
    G = nx.DiGraph()

    for node in node_data.values():
        G.add_node(node["id"])

    for edge in edges:
        G.add_edge(edge["source"], edge["target"])

    # Use visitor pattern to detect cycles
    visitor = DependencyVisitor()
    visitor.traverse_all(G, start_node=root_id)

    cycle_edges_set = set(visitor.get_cycle_edges())

    # Also detect self-loops (simple cycles)
    self_loops = set(nx.selfloop_edges(G))

    # Calculate depths for coloring (using BFS for shortest path)
    depths = calculate_depths_with_cycles(G, root_id)

    # Create PyVis network with spring layout
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )

    # Configure spring layout (force-directed physics)
    # This layout works well with cyclic graphs as it doesn't require hierarchy
    net.set_options(
        """
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
    )

    # Add nodes
    for node_id, data in node_data.items():
        depth = depths.get(node_id, 0)
        color = get_partition_color(depth)

        # Check if this node has any cycle edges (self-loop or back-edge)
        is_in_cycle = any(
            node_id == e[0] or node_id == e[1]
            for e in cycle_edges_set | self_loops
        )

        # Escape all user-controlled data to prevent XSS
        safe_project = escape(data['project_name'])
        safe_version = escape(data['version'])
        label = f"{safe_project}\n{safe_version}"

        labels_str = escape(", ".join(data.get("labels", [])))
        properties = data.get("properties", {})

        title_parts = [
            f"{safe_project}\n",
            f"Version: {safe_version}\n",
            f"Depth from root: {depth}\n",
            f"Labels: {labels_str}\n",
        ]

        if is_in_cycle:
            title_parts.append("** HAS CYCLIC DEPENDENCY **\n")

        if properties:
            title_parts.append("=======================\n")
            title_parts.append("All Properties:\n")
            title_parts.append(format_properties_for_tooltip(properties))

        title = "\n".join(title_parts)

        # Highlight nodes involved in cycles with a thick border
        border_width = 4 if is_in_cycle else 2
        border_color = "#ff0000" if is_in_cycle else None

        net.add_node(
            node_id,
            label=label,
            title=title,
            color={
                "background": color,
                "border": border_color if border_color else color,
            },
            borderWidth=border_width,
            group=depth,
        )

    # Add edges with special styling for cycle edges
    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        edge_key = (source, target)

        is_cycle_edge = edge_key in cycle_edges_set
        is_self_loop = source == target

        if is_cycle_edge or is_self_loop:
            # Highlight cycle edges in red with dashed lines
            net.add_edge(
                source,
                target,
                title=f"{edge['type']} (CYCLE)",
                arrows="to",
                color="#ff0000",
                dashes=True,
                width=3,
            )
        else:
            net.add_edge(
                source,
                target,
                title=edge["type"],
                arrows="to",
            )

    return net.generate_html()
