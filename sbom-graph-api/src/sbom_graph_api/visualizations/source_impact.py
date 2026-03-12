"""Source impact graph visualization.

Renders the dependency graph from a source repository to its packages
and downstream consumers, with nodes colour-coded by type:
- Purple: source repo
- Orange: packages from repo
- Yellow: dependant packages
- Blue: applications
"""

from markupsafe import escape
from pyvis.network import Network

# Node type -> colour (hex)
NODE_COLORS = {
    "source_repo": "#7b1fa2",
    "package": "#f57c00",
    "dependant": "#fbc02d",
    "application": "#377eb8",
}


def create_source_impact_graph(
    graph_nodes: list[dict],
    graph_edges: list[dict],
    height: str = "600px",
    width: str = "100%",
) -> str:
    """Create a PyVis HTML visualization of the source impact graph.

    Args:
        graph_nodes: List of dicts with id, label, type
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
        ntype = node.get("type", "dependant")
        color = NODE_COLORS.get(ntype, "#999999")
        level = 0 if ntype == "source_repo" else 1
        if ntype == "package":
            level = 1
        elif ntype in ("dependant", "application"):
            level = 2

        title = f"{label}\nType: {ntype}"
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
