"""Blast radius graph visualization for incident response.

Renders the dependency graph from a vulnerability out to affected
applications, with nodes colour-coded by type:
- Red: vulnerability
- Orange: directly affected packages
- Yellow: transitively affected
- Blue: applications
"""

from markupsafe import escape
from pyvis.network import Network

# Node type -> colour (hex)
NODE_COLORS = {
    "vulnerability": "#d32f2f",
    "affected": "#f57c00",
    "transitive": "#fbc02d",
    "application": "#377eb8",
}


def create_blast_radius_graph(
    graph_nodes: list[dict],
    graph_edges: list[dict],
    height: str = "600px",
    width: str = "100%",
) -> str:
    """Create a PyVis HTML visualization of the blast radius graph.

    Args:
        graph_nodes: List of dicts with id, label, type, optional partition
        graph_edges: List of dicts with source, target, type
        height: CSS height for the visualization
        width: CSS width for the visualization

    Returns:
        HTML string (self-contained) for embedding
    """
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )

    net.set_options(
        """
    {
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "LR",
                "sortMethod": "directed",
                "levelSeparation": 150,
                "nodeSpacing": 100
            }
        },
        "physics": {
            "hierarchicalRepulsion": {
                "springLength": 120,
                "springConstant": 0.01,
                "nodeDistance": 100
            }
        },
        "nodes": {
            "font": {"size": 11},
            "shape": "box"
        },
        "edges": {
            "arrows": {"to": {"enabled": true}},
            "smooth": {"type": "cubicBezier"}
        }
    }
    """
    )

    for node in graph_nodes:
        nid = node.get("id", "")
        label = escape(node.get("label", nid))
        ntype = node.get("type", "transitive")
        color = NODE_COLORS.get(ntype, "#999999")
        partition = node.get("partition", 0) if ntype != "vulnerability" else -1
        level = 0 if ntype == "vulnerability" else partition + 1

        title = (
            f"{label}\nType: {ntype}\nDistance: {partition}"
            if partition >= 0
            else f"{label}\nType: {ntype}"
        )
        net.add_node(
            nid,
            label=label,
            title=title,
            color=color,
            level=level,
        )

    for edge in graph_edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src and tgt:
            net.add_edge(src, tgt, arrows="to")

    return net.generate_html()
