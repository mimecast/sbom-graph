"""Multi-layout graph visualization module with cycle detection.

This module provides graph visualizations with multiple layout options and
cycle detection/highlighting. Supports both dependencies and dependants
graph directions.

Available Layouts:
- spring: Force-directed (ForceAtlas2) - good for cyclic graphs
- radial: Radial tree layout - nodes arranged in concentric circles
- shell: Shell layout - nodes in concentric shells by depth
- bfs: BFS tree layout - hierarchical breadth-first layout
- circular: Circular layout - nodes arranged in a circle

The visualization includes an interactive layout switcher that allows
users to change layouts without reloading the page.
"""

import json
from typing import Any

import networkx as nx
from markupsafe import escape
from pyvis.network import Network

from sbom_graph_api.services.falkordb_service import (
    FalkorDBService,
    get_falkordb_service,
)
from sbom_graph_api.visualizations.kpartite import (
    calculate_partitions_longest_path,
    format_properties_for_tooltip,
    get_partition_color,
)

# Available layout types
LAYOUT_TYPES = ["spring", "radial", "shell", "bfs", "circular"]

# Layout display names for UI
LAYOUT_DISPLAY_NAMES = {
    "spring": "Spring (Force-Directed)",
    "radial": "Radial Tree",
    "shell": "Shell",
    "bfs": "BFS Tree (Hierarchical)",
    "circular": "Circular",
}


class CycleDetector:
    """Detector for cycles in directed graphs using DFS traversal.

    This class uses a DFS-based approach to detect back-edges that
    create cycles in the graph. It tracks both visited nodes and
    nodes currently in the recursion stack.
    """

    def __init__(self) -> None:
        """Initialize the cycle detector."""
        self.visited: set[str] = set()
        self.rec_stack: set[str] = set()
        self.cycle_edges: list[tuple[str, str]] = []
        self.nodes_in_cycles: set[str] = set()

    def detect_cycles(self, graph: nx.DiGraph, start_node: str | None = None) -> None:
        """Detect all cycles in the graph.

        Args:
            graph: NetworkX DiGraph to analyze
            start_node: Optional starting node for traversal
        """
        if start_node and start_node not in self.visited:
            self._dfs(graph, start_node)

        # Visit any remaining nodes
        for node in graph.nodes():
            if node not in self.visited:
                self._dfs(graph, node)

    def _dfs(self, graph: nx.DiGraph, node: str) -> None:
        """DFS traversal to detect back-edges."""
        self.visited.add(node)
        self.rec_stack.add(node)

        for successor in graph.successors(node):
            if successor not in self.visited:
                self._dfs(graph, successor)
            elif successor in self.rec_stack:
                # Back-edge found - cycle detected
                self.cycle_edges.append((node, successor))
                self.nodes_in_cycles.add(node)
                self.nodes_in_cycles.add(successor)

        self.rec_stack.remove(node)

    def get_cycle_edges(self) -> list[tuple[str, str]]:
        """Return list of edges that create cycles."""
        return self.cycle_edges

    def get_nodes_in_cycles(self) -> set[str]:
        """Return set of nodes involved in cycles."""
        return self.nodes_in_cycles

    def has_cycles(self) -> bool:
        """Return True if cycles were detected."""
        return len(self.cycle_edges) > 0


def calculate_depths_bfs(graph: nx.DiGraph, root_id: str) -> dict[str, int]:
    """Calculate node depths using BFS from root.

    Args:
        graph: NetworkX DiGraph
        root_id: Starting node ID

    Returns:
        Dictionary mapping node_id -> depth
    """
    depths: dict[str, int] = {root_id: 0}
    queue: list[tuple[str, int]] = [(root_id, 0)]
    visited: set[str] = {root_id}

    while queue:
        current, depth = queue.pop(0)
        for successor in graph.successors(current):
            if successor not in visited:
                visited.add(successor)
                depths[successor] = depth + 1
                queue.append((successor, depth + 1))

    return depths


def get_layout_options(layout: str, direction: str = "LR") -> str:
    """Get PyVis options JSON for the specified layout.

    Args:
        layout: Layout type (spring, radial, shell, bfs, circular)
        direction: Layout direction for hierarchical layouts (LR, RL, UD, DU)

    Returns:
        JSON string of PyVis options
    """
    base_options: dict[str, Any] = {
        "nodes": {
            "font": {"size": 12},
            "shape": "box",
            "borderWidth": 2,
        },
        "edges": {
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
            "smooth": {"enabled": True, "type": "continuous", "roundness": 0.5},
        },
        "interaction": {
            "hover": True,
            "navigationButtons": True,
            "keyboard": True,
            "zoomView": True,
            "dragView": True,
        },
    }

    if layout == "spring":
        base_options["physics"] = {
            "enabled": True,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 150,
                "springConstant": 0.08,
                "damping": 0.4,
                "avoidOverlap": 0.5,
            },
            "stabilization": {
                "enabled": True,
                "iterations": 200,
                "updateInterval": 25,
            },
        }
    elif layout == "bfs":
        base_options["layout"] = {
            "hierarchical": {
                "enabled": True,
                "direction": direction,
                "sortMethod": "directed",
                "levelSeparation": 200,
                "nodeSpacing": 80,
            },
        }
        base_options["physics"] = {
            "hierarchicalRepulsion": {
                "centralGravity": 0.0,
                "springLength": 100,
                "springConstant": 0.01,
                "nodeDistance": 120,
            },
        }
        base_options["edges"]["smooth"] = {"type": "cubicBezier"}
    elif layout in ("radial", "shell", "circular"):
        # These layouts use pre-calculated positions, so disable physics
        base_options["physics"] = {"enabled": False}
        base_options["edges"]["smooth"] = {"enabled": True, "type": "continuous"}

    return json.dumps(base_options)


def calculate_layout_positions(
    graph: nx.DiGraph,
    layout: str,
    root_id: str | None = None,
    depths: dict[str, int] | None = None,
) -> dict[str, tuple[float, float]]:
    """Calculate node positions for the specified layout.

    Args:
        graph: NetworkX DiGraph
        layout: Layout type
        root_id: Root node ID (for radial/shell layouts)
        depths: Pre-calculated depths (optional)

    Returns:
        Dictionary mapping node_id -> (x, y) position
    """
    scale = 500  # Base scale for positions

    if layout == "spring":
        pos = nx.spring_layout(graph, k=2, iterations=50, scale=scale)
    elif layout == "radial":
        if root_id and root_id in graph:
            # Use BFS layers as rings
            pos = nx.shell_layout(
                graph,
                nlist=_get_depth_shells(graph, root_id, depths),
                scale=scale,
            )
        else:
            pos = nx.shell_layout(graph, scale=scale)
    elif layout == "shell":
        if depths:
            pos = nx.shell_layout(
                graph,
                nlist=_get_depth_shells(graph, root_id, depths),
                scale=scale,
            )
        else:
            pos = nx.shell_layout(graph, scale=scale)
    elif layout == "circular":
        pos = nx.circular_layout(graph, scale=scale)
    else:
        # Default to spring
        pos = nx.spring_layout(graph, k=2, iterations=50, scale=scale)

    # Convert numpy arrays to tuples
    return {node: (float(coord[0]), float(coord[1])) for node, coord in pos.items()}


def _get_depth_shells(
    graph: nx.DiGraph,
    root_id: str | None,
    depths: dict[str, int] | None,
) -> list[list[str]]:
    """Get nodes organized by depth for shell layout.

    Args:
        graph: NetworkX DiGraph
        root_id: Root node ID
        depths: Node depth mapping

    Returns:
        List of node lists, one per shell/ring
    """
    if not depths:
        if root_id:
            depths = calculate_depths_bfs(graph, root_id)
        else:
            return [list(graph.nodes())]

    max_depth = max(depths.values()) if depths else 0
    shells: list[list[str]] = [[] for _ in range(max_depth + 1)]

    for node, depth in depths.items():
        if node in graph:
            shells[depth].append(node)

    # Add any nodes not in depths dict to the last shell
    depth_nodes = set(depths.keys())
    for node in graph.nodes():
        if node not in depth_nodes:
            shells[-1].append(node)

    # Remove empty shells
    return [shell for shell in shells if shell]


def get_layout_switcher_html(
    current_layout: str,
    project_name: str,
    version: str,
    endpoint: str,
    internal_only: bool = False,
    max_depth: int | None = None,
) -> str:
    """Generate HTML for the layout switcher UI.

    Args:
        current_layout: Currently selected layout
        project_name: Project name for URL
        version: Version string for URL
        endpoint: Base endpoint (dependencies or dependants)
        internal_only: Internal-only filter state
        max_depth: Max depth parameter

    Returns:
        HTML string for the layout switcher
    """
    options = []
    for layout_id, display_name in LAYOUT_DISPLAY_NAMES.items():
        selected = 'selected="selected"' if layout_id == current_layout else ""
        safe_layout_id = escape(layout_id)
        safe_display_name = escape(display_name)
        options.append(f'<option value="{safe_layout_id}" {selected}>{safe_display_name}</option>')

    options_html = "\n".join(options)

    # Build base URL params
    params = []
    if internal_only:
        params.append("internal_only=true")
    if max_depth:
        params.append(f"max_depth={max_depth}")

    # Prefix with '&' when concatenated to '?layout=' query
    raw_param_str = "&" + "&".join(params) if params else ""

    # Prepare safe JavaScript string literals
    safe_endpoint_js = json.dumps(str(endpoint))
    safe_project_js = json.dumps(str(project_name))
    safe_version_js = json.dumps(str(version))
    safe_param_js = json.dumps(raw_param_str)

    return f"""
    <div id="layout-switcher" style="
        position: fixed;
        top: 10px;
        right: 10px;
        z-index: 1000;
        background: rgba(255, 255, 255, 0.95);
        padding: 10px 15px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        font-family: Arial, sans-serif;
    ">
        <label for="layout-select" style="
            font-size: 12px;
            font-weight: bold;
            display: block;
            margin-bottom: 5px;
            color: #333;
        ">Layout:</label>
        <select id="layout-select" onchange="switchLayout(this.value)" style="
            padding: 5px 10px;
            border-radius: 4px;
            border: 1px solid #ccc;
            font-size: 12px;
            cursor: pointer;
            min-width: 150px;
        ">
            {options_html}
        </select>
    </div>
    <script>
        function switchLayout(layout) {{
            var baseUrl = '/visualizations/' + {safe_endpoint_js}
                + '/' + {safe_project_js} + '/' + {safe_version_js};
            var url = baseUrl + '?layout=' + encodeURIComponent(layout) + {safe_param_js};
            window.location.href = url;
        }}
    </script>
    """


def create_multi_layout_visualization(
    graph_data: tuple[list[dict[str, Any]], list[dict[str, Any]]],
    root_id: str,
    root_properties: dict[str, Any],
    root_labels: list[str],
    layout: str = "spring",
    height: str = "100vh",
    width: str = "100vw",
    direction: str = "dependants",
    project_name: str = "",
    version_name: str = "",
    internal_only: bool = False,
    max_depth: int | None = None,
) -> str:
    """Create a graph visualization with the specified layout.

    Args:
        graph_data: Tuple of (nodes, edges) from FalkorDB
        root_id: ID of the root node
        root_properties: Properties of the root node
        root_labels: Labels of the root node
        layout: Layout type (spring, radial, shell, bfs, circular)
        height: Visualization height
        width: Visualization width
        direction: Graph direction (dependencies or dependants)
        project_name: Project name for layout switcher
        version_name: Version string for layout switcher
        internal_only: Internal-only filter
        max_depth: Maximum depth

    Returns:
        HTML string of the visualization
    """
    nodes, edges = graph_data

    # Build node data dictionary
    node_data = {n["id"]: n for n in nodes}

    # Ensure root is in node_data
    if root_id not in node_data:
        project, version = root_id.split(":", 1)
        node_data[root_id] = {
            "id": root_id,
            "project_name": project,
            "version": version,
            "labels": root_labels,
            "properties": root_properties,
        }

    # Build NetworkX graph
    graph: nx.DiGraph = nx.DiGraph()

    for node in node_data.values():
        graph.add_node(node["id"])

    for edge in edges:
        if direction == "dependants":
            # Reverse edges for dependants view (flow from leaves to root)
            graph.add_edge(edge["target"], edge["source"])
        else:
            graph.add_edge(edge["source"], edge["target"])

    # Detect cycles
    detector = CycleDetector()
    detector.detect_cycles(graph, root_id)
    cycle_edges = set(detector.get_cycle_edges())
    nodes_in_cycles = detector.get_nodes_in_cycles()

    # Also detect self-loops
    self_loops = set(nx.selfloop_edges(graph))
    for u, _ in self_loops:
        nodes_in_cycles.add(u)

    # Always remove cycles for depth/partition calculation.
    # calculate_partitions_longest_path has no visited tracking and will loop
    # infinitely on cyclic graphs. Cycle information is already captured in
    # cycle_edges/nodes_in_cycles above and used for edge/node styling.
    graph_acyclic = graph.copy()
    graph_acyclic.remove_edges_from(self_loops)
    graph_acyclic.remove_edges_from(cycle_edges)

    # Calculate depths
    if direction == "dependants":
        depths = calculate_partitions_longest_path(graph_acyclic, root_id)
    else:
        depths = calculate_depths_bfs(graph_acyclic, root_id)

    # Calculate positions for non-physics layouts
    positions = None
    if layout in ("radial", "shell", "circular"):
        positions = calculate_layout_positions(graph_acyclic, layout, root_id, depths)

    # Create PyVis network
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )

    # Set layout options
    layout_dir = "RL" if direction == "dependants" else "LR"
    net.set_options(get_layout_options(layout, layout_dir))

    # Add nodes
    for node_id, data in node_data.items():
        depth = depths.get(node_id, 0)
        color = get_partition_color(depth)
        is_in_cycle = node_id in nodes_in_cycles

        # Escape all user-controlled data to prevent XSS
        safe_project = escape(data["project_name"])
        safe_version = escape(data["version"])
        label = f"{safe_project}\n{safe_version}"
        labels_str = escape(", ".join(data.get("labels", [])))
        properties = data.get("properties", {})

        title_parts = [
            f"{safe_project}\n",
            f"Version: {safe_version}\n",
            f"Distance from root: {depth}\n",
            f"Labels: {labels_str}\n",
        ]

        if is_in_cycle:
            title_parts.append("** HAS CYCLIC DEPENDENCY **\n")

        if properties:
            title_parts.append("=======================\n")
            title_parts.append("All Properties:\n")
            title_parts.append(format_properties_for_tooltip(properties))

        title = "\n".join(title_parts)

        # Node styling
        border_width = 4 if is_in_cycle else 2
        border_color = "#ff0000" if is_in_cycle else color

        node_kwargs: dict[str, Any] = {
            "label": label,
            "title": title,
            "color": {"background": color, "border": border_color},
            "borderWidth": border_width,
            "group": depth,
        }

        # Add position for non-physics layouts
        if positions and node_id in positions:
            x, y = positions[node_id]
            node_kwargs["x"] = x
            node_kwargs["y"] = y
            node_kwargs["physics"] = False

        # Add level for hierarchical layout
        if layout == "bfs":
            node_kwargs["level"] = depth

        net.add_node(node_id, **node_kwargs)

    # Add edges with cycle highlighting
    for edge in edges:
        source = edge["source"]
        target = edge["target"]

        # For dependants, we reversed the graph direction
        if direction == "dependants":
            edge_key = (target, source)
        else:
            edge_key = (source, target)

        is_cycle_edge = edge_key in cycle_edges
        is_self_loop = source == target

        if is_cycle_edge or is_self_loop:
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
            net.add_edge(source, target, title=edge["type"], arrows="to")

    # Generate HTML and inject layout switcher
    html = net.generate_html()

    # Add layout switcher
    endpoint = "dependants-multi" if direction == "dependants" else "dependencies"
    switcher_html = get_layout_switcher_html(
        layout, project_name, version_name, endpoint, internal_only, max_depth
    )

    # Inject switcher before closing body tag
    html = html.replace("</body>", f"{switcher_html}</body>")

    return html


def create_dependants_multi_layout_visualization(
    project_name: str,
    version_name: str,
    layout: str = "spring",
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
) -> str | None:
    """Create a dependants visualization with multiple layout options.

    Args:
        project_name: Project name to visualize
        version_name: Version string
        layout: Layout type (spring, radial, shell, bfs, circular)
        max_depth: Maximum depth to traverse
        internal_only: If True, only include internal nodes
        height: Visualization height
        width: Visualization width
        service: FalkorDB service instance
        project_group: Optional group for root node disambiguation

    Returns:
        HTML string or None if project not found
    """
    if service is None:
        service = get_falkordb_service()

    # Validate layout
    if layout not in LAYOUT_TYPES:
        layout = "spring"

    # Verify root node exists
    root = service.find_version(project_name, version_name, project_group)
    if not root:
        return None

    root_id = f"{project_name}:{version_name}"

    # Get dependants graph data
    # Use skip_scan_filter=True to show raw graph structure in visualization
    nodes, edges = service.get_transitive_dependants(
        project_name,
        version_name,
        max_depth,
        internal_only,
        skip_scan_filter=True,
        project_group=project_group,
    )

    return create_multi_layout_visualization(
        graph_data=(nodes, edges),
        root_id=root_id,
        root_properties=root["properties"],
        root_labels=root["labels"],
        layout=layout,
        height=height,
        width=width,
        direction="dependants",
        project_name=project_name,
        version_name=version_name,
        internal_only=internal_only,
        max_depth=max_depth,
    )


def create_dependencies_multi_layout_visualization(
    project_name: str,
    version_name: str,
    layout: str = "spring",
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
) -> str | None:
    """Create a dependencies visualization with multiple layout options.

    Args:
        project_name: Project name to visualize
        version_name: Version string
        layout: Layout type (spring, radial, shell, bfs, circular)
        max_depth: Maximum depth to traverse
        internal_only: If True, only include internal nodes
        height: Visualization height
        width: Visualization width
        service: FalkorDB service instance
        project_group: Optional group for root node disambiguation

    Returns:
        HTML string or None if project not found
    """
    if service is None:
        service = get_falkordb_service()

    # Validate layout
    if layout not in LAYOUT_TYPES:
        layout = "spring"

    # Verify root node exists
    root = service.find_version(project_name, version_name, project_group)
    if not root:
        return None

    root_id = f"{project_name}:{version_name}"

    # Get dependencies graph data
    nodes, edges = service.get_transitive_dependencies(
        project_name,
        version_name,
        max_depth,
        internal_only,
        project_group=project_group,
    )

    return create_multi_layout_visualization(
        graph_data=(nodes, edges),
        root_id=root_id,
        root_properties=root["properties"],
        root_labels=root["labels"],
        layout=layout,
        height=height,
        width=width,
        direction="dependencies",
        project_name=project_name,
        version_name=version_name,
        internal_only=internal_only,
        max_depth=max_depth,
    )
