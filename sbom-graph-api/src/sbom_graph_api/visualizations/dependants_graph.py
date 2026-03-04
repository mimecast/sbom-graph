"""Full dependants graph visualization showing all dependants to leaf nodes.

This module creates visualizations showing all dependants of a library
traversing back to the leaf nodes (applications that have no dependants).
"""

import networkx as nx
from markupsafe import escape
from pyvis.network import Network

from sbom_graph_api.services.falkordb_service import FalkorDBService, get_falkordb_service
from sbom_graph_api.visualizations.kpartite import (
    calculate_partitions_longest_path,
    format_properties_for_tooltip,
    get_partition_color,
)


def create_dependants_graph_visualization(
    project_name: str,
    version_name: str,
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
) -> str | None:
    """Create a visualization of all dependants back to leaf nodes.

    Shows the reverse dependency tree - all projects that depend on the
    given project, and their dependants, back to the leaf applications.

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

    # Verify root node exists
    root = service.find_version(project_name, version_name, project_group)
    if not root:
        return None

    root_properties = root["properties"]
    root_labels = root["labels"]

    # Get reverse dependency graph (dependants)
    # Use skip_scan_filter=True to show raw graph structure in visualization
    nodes, edges = service.get_transitive_dependants(
        project_name, version_name, max_depth, internal_only, skip_scan_filter=True,
        project_group=project_group,
    )

    root_id = f"{project_name}:{version_name}"

    # Build NetworkX graph for layout calculation
    # Note: We reverse the edges for partition calculation since we want
    # the root on the right and leaf nodes on the left
    G = nx.DiGraph()
    node_data = {n["id"]: n for n in nodes}

    if root_id not in node_data:
        node_data[root_id] = {
            "id": root_id,
            "project_name": project_name,
            "version": version_name,
            "labels": root_labels,
            "properties": root_properties,
        }

    for node in node_data.values():
        G.add_node(node["id"])

    # Reverse edges for visualization (dependants point to dependencies)
    for edge in edges:
        # In the original graph: source depends on target
        # For dependants view: we reverse to show flow from leaf to root
        G.add_edge(edge["target"], edge["source"])

    # Remove cycles to allow hierarchical layout
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
        # Remove self-loops first
        self_loops = list(nx.selfloop_edges(G))
        G.remove_edges_from(self_loops)
        # Then remove back-edges to break cycles
        remove_cycles_dfs(G)
    except nx.NetworkXError:
        pass  # Graph error, continue with what we have

    # Calculate partitions (root at level 0, dependants at higher levels)
    partitions = calculate_partitions_longest_path(G, root_id)

    # Create PyVis network
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )

    # Configure hierarchical layout (RL - root on right, leaves on left)
    net.set_options(
        """
    {
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "RL",
                "sortMethod": "directed",
                "levelSeparation": 200,
                "nodeSpacing": 80
            }
        },
        "physics": {
            "hierarchicalRepulsion": {
                "centralGravity": 0.0,
                "springLength": 100,
                "springConstant": 0.01,
                "nodeDistance": 120
            }
        },
        "nodes": {
            "font": {"size": 12},
            "shape": "box"
        },
        "edges": {
            "arrows": {"to": {"enabled": true}},
            "smooth": {"type": "cubicBezier"}
        }
    }
    """
    )

    # Add nodes
    for node_id, data in node_data.items():
        partition = partitions.get(node_id, 0)
        color = get_partition_color(partition)

        # Escape all user-controlled data to prevent XSS
        safe_project = escape(data['project_name'])
        safe_version = escape(data['version'])
        label = f"{safe_project}\n{safe_version}"

        labels_str = escape(", ".join(data.get("labels", [])))
        properties = data.get("properties", {})

        title_parts = [
            f"{safe_project}\n",
            f"Version: {safe_version}\n",
            f"Distance from target: {partition}\n",
            f"Labels: {labels_str}\n",
        ]

        if properties:
            title_parts.append("=======================\n")
            title_parts.append("All Properties:\n")
            title_parts.append(format_properties_for_tooltip(properties))

        title = "\n".join(title_parts)

        net.add_node(
            node_id,
            label=label,
            title=title,
            color=color,
            level=partition,
            group=partition,
        )

    # Add edges (original direction: dependant -> dependency)
    for edge in edges:
        net.add_edge(edge["source"], edge["target"], title=edge["type"], arrows="to")

    return net.generate_html()
