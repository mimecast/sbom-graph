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
import logging

import networkx as nx
from markupsafe import escape
from pyvis.network import Network

from sbom_graph_api.services.falkordb_service import FalkorDBService, get_falkordb_service
from sbom_graph_api.visualizations._bounded import bound_nodes_edges, inject_truncation_banner

logger = logging.getLogger(__name__)

MAX_VIZ_NODES = 2000
MAX_VIZ_EDGES = 5000

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


def get_severity_color(severity: str) -> str | None:
    """Return hex colour for vulnerability severity, or None if unknown.

    Args:
        severity: CRITICAL, HIGH, MEDIUM, or LOW (case-insensitive).

    Returns:
        Hex colour string, or None if severity is not recognised.
    """
    mapping = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#f57c00",
        "MEDIUM": "#fbc02d",
        "LOW": "#377eb8",
    }
    return mapping.get((severity or "").upper())


def get_license_risk_color(risk_category: str) -> str | None:
    """Return hex colour for licence risk category, or None if unknown.

    Colour priority in visualizations: severity > licence risk > partition.

    Args:
        risk_category: permissive, weak_copyleft, strong_copyleft,
            proprietary, or unknown (case-insensitive).

    Returns:
        Hex colour string, or None if risk_category is not recognised.
    """
    mapping = {
        "permissive": "#388e3c",
        "weak_copyleft": "#fbc02d",
        "strong_copyleft": "#d32f2f",
        "proprietary": "#7b1fa2",
        "unknown": "#757575",
    }
    return mapping.get((risk_category or "").lower())


def calculate_partitions_longest_path(graph: nx.DiGraph, root_id: str) -> dict[str, int]:
    """Calculate partition levels based on the LONGEST path from root to each node.

    Uses DFS to find all paths from root to each node and assigns the partition
    based on the maximum path length (deepest dependency chain).

    Args:
        graph: NetworkX DiGraph with dependency relationships
        root_id: The node ID of the root element

    Returns:
        Dictionary mapping node_id -> partition level (longest path from root)
    """
    partitions = {root_id: 0}
    stack = [(root_id, 0)]

    while stack:
        current, depth = stack.pop()

        for successor in graph.successors(current):
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

        # Node properties originate from ingested (untrusted) SBOMs and this
        # string is rendered as HTML in the PyVis ``title=`` tooltip — escape
        # both key and value to prevent stored XSS (CWE-79).
        lines.append(f"{escape(key)}: {escape(value_str)}")

    return "\n".join(lines)


def create_kpartite_visualization(
    project_name: str,
    version_name: str,
    max_depth: int | None = None,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
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
        project_group: Optional group for root node disambiguation

    Returns:
        HTML string of the visualization, or None if root node not found
    """
    if service is None:
        service = get_falkordb_service()

    # Verify root node exists
    root = service.find_version(project_name, version_name, project_group)
    if not root:
        return None

    root_properties = root["properties"]
    root_labels = root["labels"]

    # Get dependency graph
    nodes, edges = service.get_transitive_dependencies(
        project_name,
        version_name,
        max_depth,
        internal_only,
        project_group=project_group,
    )

    root_id = f"{project_name}:{version_name}"
    nodes, edges, _truncated, _dropped = bound_nodes_edges(
        nodes, edges, MAX_VIZ_NODES, MAX_VIZ_EDGES, root_id=root_id
    )
    if _truncated:
        logger.warning(
            "K-partite graph for %s@%s truncated at %d nodes (%d dropped)",
            project_name, version_name, MAX_VIZ_NODES, _dropped,
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
    graph: nx.DiGraph = nx.DiGraph()
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
        graph.add_node(node["id"])

    for edge in edges:
        graph.add_edge(edge["source"], edge["target"])

    # Calculate partitions using longest path
    partitions = calculate_partitions_longest_path(graph, root_id)

    # Query vulnerability severities, licence risks, and VEX status for nodes
    purls = [
        d.get("properties", {}).get("package_url")
        for d in node_data.values()
        if d.get("properties", {}).get("package_url")
    ]
    severity_map: dict[str, str] = {}
    license_risk_map: dict[str, str] = {}
    vex_status_map: dict[str, str] = {}
    if purls:
        severity_map = service.get_vulnerability_severities_for_versions(purls)
        license_risk_map = service.get_license_risks_for_versions(purls)
        vex_status_map = service.get_vex_statuses_for_versions(purls)

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

    # Unicode shield for not_affected VEX status (U+1F6E1)
    _vex_shield = "\U0001f6e1"

    # Add nodes to PyVis
    for node_id, data in node_data.items():
        partition = partitions.get(node_id, 0)
        purl = data.get("properties", {}).get("package_url")
        severity = severity_map.get(purl) if purl else None
        risk_category = license_risk_map.get(purl) if purl else None
        vex_status = vex_status_map.get(purl) if purl else None
        severity_color = get_severity_color(severity) if severity else None
        license_color = get_license_risk_color(risk_category) if risk_category else None
        color = (
            severity_color
            if severity_color
            else (license_color if license_color else get_partition_color(partition))
        )

        # Escape all user-controlled data to prevent XSS
        safe_project = escape(data["project_name"])
        safe_version = escape(data["version"])
        label = f"{safe_project}\n{safe_version}"
        if vex_status == "not_affected":
            label += f" {_vex_shield}"

        labels_str = escape(", ".join(data.get("labels", [])))
        properties = data.get("properties", {})

        title_parts = [
            f"{safe_project}\n",
            f"Version: {safe_version}\n",
            f"Partition Level: {partition}\n",
            f"Labels: {labels_str}\n",
        ]
        if severity:
            title_parts.append(f"Highest vulnerability severity: {severity}\n")
        if risk_category:
            title_parts.append(f"License risk: {escape(risk_category.replace('_', ' '))}\n")
        if vex_status:
            title_parts.append(f"VEX status: {escape(vex_status.replace('_', ' '))}\n")

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
    html = net.generate_html()
    if _truncated:
        html = inject_truncation_banner(html, MAX_VIZ_NODES, _dropped)
    return html
