"""Bi-partite graph visualization for project versions and their dependants.

This module creates bi-partite visualizations showing a project with all its
versions on the left side and all direct dependants on the right side.

Phase 1: the network is bounded by a node/edge cap (``build_bounded_network``)
so a high-fan-in project cannot exhaust memory or stall rendering; when the cap
is exceeded a visible truncation notice is injected and the drop is logged.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from markupsafe import escape
from pyvis.network import Network

from sbom_graph_api.services.falkordb_service import FalkorDBService, get_falkordb_service
from sbom_graph_api.visualizations._bounded import inject_truncation_banner

logger = logging.getLogger(__name__)

# Bounds on the rendered graph (SEC-005). Beyond these the graph is truncated.
MAX_GRAPH_NODES = 2000
MAX_GRAPH_EDGES = 5000

_TARGET_COLOR = "#e41a1c"  # Red for the target project
_DEPENDANT_COLOR = "#377eb8"  # Blue for dependants

_LAYOUT_OPTIONS = """
{
    "layout": {
        "hierarchical": {
            "enabled": true,
            "direction": "LR",
            "sortMethod": "directed",
            "levelSeparation": 400,
            "nodeSpacing": 50
        }
    },
    "physics": {"enabled": false},
    "nodes": {"font": {"size": 11}, "shape": "box"},
    "edges": {
        "arrows": {"to": {"enabled": true}},
        "smooth": {"type": "cubicBezier"}
    }
}
"""


def build_bounded_network(
    edges_iter: Iterable[dict[str, Any]],
    *,
    max_nodes: int = MAX_GRAPH_NODES,
    max_edges: int = MAX_GRAPH_EDGES,
    seed_targets: Iterable[tuple[str, str]] | None = None,
    height: str = "100vh",
    width: str = "100vw",
) -> tuple[Network, bool, int]:
    """Build a bounded bi-partite PyVis network from dependant edges.

    ``edges_iter`` yields dicts with ``target_project``/``target_version`` and
    ``dependant_project``/``dependant_version``. Nodes are capped at ``max_nodes``
    and edges at ``max_edges``; anything beyond is dropped.

    Returns ``(network, truncated, dropped)``.
    """
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )
    net.set_options(_LAYOUT_OPTIONS)

    added: set[str] = set()
    truncated = False
    dropped = 0
    edge_count = 0

    def _add_node(node_id: str, project: str, version: str, color: str, level: int) -> bool:
        """Add a node if under the cap. Returns False if the cap blocks it."""
        if node_id in added:
            return True
        if len(added) >= max_nodes:
            return False
        safe = f"{escape(project)}\n{escape(version)}"
        net.add_node(node_id, label=safe, title=safe, color=color, level=level)
        added.add(node_id)
        return True

    # Seed the target project's versions first so the project always renders.
    for project, version in seed_targets or []:
        if not _add_node(f"target:{project}:{version}", project, version, _TARGET_COLOR, 0):
            truncated = True
            dropped += 1

    for edge in edges_iter:
        target_id = f"target:{edge['target_project']}:{edge['target_version']}"
        dep_id = f"dependant:{edge['dependant_project']}:{edge['dependant_version']}"
        # Would adding this edge breach a cap?
        prospective_new = sum(1 for n in (target_id, dep_id) if n not in added)
        if edge_count >= max_edges or len(added) + prospective_new > max_nodes:
            truncated = True
            dropped += 1
            continue
        _add_node(target_id, edge["target_project"], edge["target_version"], _TARGET_COLOR, 0)
        _add_node(
            dep_id, edge["dependant_project"], edge["dependant_version"], _DEPENDANT_COLOR, 1
        )
        net.add_edge(dep_id, target_id, title="depends_on", arrows="to")
        edge_count += 1

    return net, truncated, dropped


def create_bipartite_visualization(
    project_name: str,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
) -> str | None:
    """Create a bounded bi-partite visualization of project versions and dependants.

    Returns the HTML string, or ``None`` if the project has no versions.
    """
    if service is None:
        service = get_falkordb_service()

    versions = service.get_all_versions_of_project(
        project_name, internal_only, project_group=project_group
    )
    if not versions:
        return None

    dependants = service.get_direct_dependants(project_name, internal_only=internal_only)

    net, truncated, dropped = build_bounded_network(
        dependants,
        seed_targets=[(project_name, v) for v in versions],
        height=height,
        width=width,
    )

    html = net.generate_html()
    if truncated:
        logger.warning(
            "Bipartite graph for %s truncated at %d nodes (%d dropped)",
            project_name,
            MAX_GRAPH_NODES,
            dropped,
        )
        html = inject_truncation_banner(html, MAX_GRAPH_NODES, dropped)
    return html
