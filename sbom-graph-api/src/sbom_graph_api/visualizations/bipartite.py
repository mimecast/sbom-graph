"""Bi-partite graph visualization for project versions and their dependants.

This module creates bi-partite visualizations showing a project with all its
versions on the left side and all direct dependants on the right side.
"""

from markupsafe import escape
from pyvis.network import Network

from sbom_graph_api.services.falkordb_service import FalkorDBService, get_falkordb_service


def create_bipartite_visualization(
    project_name: str,
    internal_only: bool = False,
    height: str = "100vh",
    width: str = "100vw",
    service: FalkorDBService | None = None,
    project_group: str | None = None,
) -> str | None:
    """Create a bi-partite visualization of project versions and dependants.

    Shows all versions of the target project on the left and all direct
    dependants (with their versions) on the right.

    Args:
        project_name: The project name to visualize
        internal_only: If True, only include internal-labeled nodes
        height: Height of the visualization (validated CSS dimension)
        width: Width of the visualization (validated CSS dimension)
        service: FalkorDB service instance
        project_group: Optional group for disambiguation

    Returns:
        HTML string of the visualization, or None if project not found
    """
    if service is None:
        service = get_falkordb_service()

    # Get all versions of the project
    versions = service.get_all_versions_of_project(
        project_name, internal_only, project_group=project_group
    )
    if not versions:
        return None

    # Get all direct dependants for the project (all versions)
    dependants = service.get_direct_dependants(project_name, internal_only=internal_only)

    # Create PyVis network
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        directed=True,
        height=height,
        width=width,
    )

    # Configure layout for bi-partite visualization
    net.set_options(
        """
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
        "physics": {
            "enabled": false
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

    # Add target project versions (left side - level 1)
    target_color = "#e41a1c"  # Red for target project
    # Escape project_name once for use in all target nodes
    safe_project_name = escape(project_name)
    for version in versions:
        safe_version = escape(version)
        node_id = f"target:{project_name}:{version}"
        label = f"{safe_project_name}\n{safe_version}"
        net.add_node(
            node_id,
            label=label,
            title=f"Target: {safe_project_name} @ {safe_version}",
            color=target_color,
            level=0,
        )

    # Add dependant versions (right side - level 0)
    dependant_color = "#377eb8"  # Blue for dependants
    added_dependants = set()

    for dep in dependants:
        dep_id = f"dependant:{dep['dependant_project']}:{dep['dependant_version']}"
        target_id = f"target:{dep['target_project']}:{dep['target_version']}"

        if dep_id not in added_dependants:
            # Escape all user-controlled data to prevent XSS
            safe_dep_project = escape(dep['dependant_project'])
            safe_dep_version = escape(dep['dependant_version'])
            label = f"{safe_dep_project}\n{safe_dep_version}"
            net.add_node(
                dep_id,
                label=label,
                title=f"Dependant: {safe_dep_project} @ {safe_dep_version}",
                color=dependant_color,
                level=1,
            )
            added_dependants.add(dep_id)

        # Add edge from dependant to target (direction: dependant depends on target)
        net.add_edge(dep_id, target_id, title="depends_on", arrows="to")

    return net.generate_html()
