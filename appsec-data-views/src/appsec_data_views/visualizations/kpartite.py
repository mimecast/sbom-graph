"""K-Partite dependency visualization module.

This module provides functions to create k-partite visualizations of transitive
dependencies from FalkorDB graph database.

A k-partite graph visualization organizes nodes into k distinct layers (partitions)
based on their longest path distance from a root node:

- Partition 0 (Red): The root node on the left (the project you're analyzing)
- Partition 1 (Blue): Direct dependencies (one hop from root)
- Partition 2 (Green): Nodes whose longest path from root is 2 hops
- Partition 3+: Deeper transitive dependencies (positioned further right)
"""

import json

import networkx as nx
from markupsafe import escape
from pyvis.network import Network

from appsec_data_views.services.falkordb_service import FalkorDBService, get_falkordb_service

# Color palette for partition levels (expandable)
PARTITION_COLORS = [
    "#e41a1c",  # Red - Root (partition 0)
    "#377eb8",  # Blue - Direct dependencies (partition 1)
    "#4daf4a",  # Green - 2nd level
    "#984ea3",  # Purple - 3rd level
    "#ff7f00",  # Orange - 4th level
    "#ffff33",  # Yellow - 5th level
    "#a65628",  # Brown - 6th level
    "#f781bf",  # Pink - 7th level
    "#999999",  # Gray - 8th+ level
]


def get_partition_color(partition: int) -> str:
    """Get color for a partition level, cycling through palette if needed."""
    if partition < len(PARTITION_COLORS):
        return PARTITION_COLORS[partition]
    return PARTITION_COLORS[-1]


def calculate_partitions_longest_path(G: nx.DiGraph, root_id: str) -> dict[str, int]:
    """Calculate partition levels based on the LONGEST path from root to each node.

    Uses DFS to find all paths from root to each node and assigns the partition
    based on the maximum path length (deepest dependency chain).

    Args:
        G: NetworkX DiGraph with dependency relationships
        root_id: The node ID of the root element

    Returns:
        Dictionary mapping node_id -> partition level (longest path from root)
    """
    partitions = {root_id: 0}
    stack = [(root_id, 0)]

    while stack:
        current, depth = stack.pop()

        for successor in G.successors(current):
            new_depth = depth + 1

            if successor not in partitions or new_depth > partitions[successor]:
                partitions[successor] = new_depth
                stack.append((successor, new_depth))

    return partitions


def format_properties_for_tooltip(properties: dict) -> str:
    """Format node properties as a tooltip with all key-value pairs."""
    if not properties:
        return ""

    lines = []
    for key, value in sorted(properties.items()):
        if isinstance(value, (list, tuple)):
            value_str = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            value_str = json.dumps(value, indent=2)
        else:
            value_str = str(value)

        lines.append(f"{key}: {value_str}")

    return "\n".join(lines)


def create_kpartite_visualization(
    project_name: str,
    version_name: str,
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
) -> str | None:
    """Create a k-partite visualization of transitive dependencies.

    The root node (specified by project_name and version_name) is at partition 0.
    Direct dependencies are at partition 1, their dependencies at partition 2, etc.

    Args:
        project_name: The project_name property of the root node
        version_name: The name property (version) of the root node
        max_depth: Maximum depth to traverse (None for unlimited)
        internal_only: If True, only include internal-labeled nodes
        height: Height of the visualization
        width: Width of the visualization
        service: FalkorDB service instance (uses singleton if not provided)

    Returns:
        HTML string of the visualization, or None if root node not found
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

    if not nodes:
        # Only root node
        nodes = [
            {
                "id": f"{project_name}:{version_name}",
                "project_name": project_name,
                "version": version_name,
                "labels": root_labels,
                "properties": root_properties,
            }
        ]

    # Build NetworkX graph for partition calculation
    G = nx.DiGraph()
    root_id = f"{project_name}:{version_name}"

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

    for node in node_data.values():
        G.add_node(node["id"])

    for edge in edges:
        G.add_edge(edge["source"], edge["target"])

    # Calculate partitions using longest path
    partitions = calculate_partitions_longest_path(G, root_id)

    # Create PyVis network
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )

    # Configure hierarchical layout
    net.set_options(
        """
    {
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "LR",
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

    # Add nodes to PyVis
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
            f"Partition Level: {partition}\n",
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

    # Add edges
    for edge in edges:
        net.add_edge(edge["source"], edge["target"], title=edge["type"], arrows="to")

    # Generate HTML
    return net.generate_html()
