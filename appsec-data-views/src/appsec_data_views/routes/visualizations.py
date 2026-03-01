"""Flask routes for graph data visualizations."""

from flask import Blueprint, Response, request
from markupsafe import escape

from appsec_data_views.routes.auth import auth_required
from appsec_data_views.utils.validation import (
    validate_boolean,
    validate_css_dimension,
    validate_layout,
    validate_max_depth,
    validate_project_name,
    validate_version_name,
)
from appsec_data_views.visualizations.bipartite import create_bipartite_visualization
from appsec_data_views.visualizations.dependants_graph import (
    create_dependants_graph_visualization,
)
from appsec_data_views.visualizations.dependencies_graph import (
    create_dependencies_graph_visualization,
)
from appsec_data_views.visualizations.kpartite import create_kpartite_visualization
from appsec_data_views.visualizations.multi_layout import (
    LAYOUT_DISPLAY_NAMES,
    create_dependants_multi_layout_visualization,
    create_dependencies_multi_layout_visualization,
)

bp = Blueprint("visualizations", __name__, url_prefix="/visualizations")


@bp.route("/kpartite/<project_name>/<version>")
@auth_required
def kpartite_dependencies(project_name: str, version: str) -> Response | tuple[str, int]:
    """Endpoint 1: K-partite visualization of transitive dependencies.

    Shows dependencies in a hierarchical layout with partitions based on
    the longest path from the root node.

    Args:
        project_name: The project name
        version: The version string

    Query Parameters:
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes (optional)
        height: Visualization height (default: 100vh, validated CSS dimension)
        width: Visualization width (default: 100vw, validated CSS dimension)

    Returns:
        HTML visualization or error message
    """
    # Validate path parameters to prevent XSS and injection
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)
    if not validated_project or not validated_version:
        return "Invalid project name or version format", 400

    # Validate query parameters
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_kpartite_visualization(
        project_name=validated_project,
        version_name=validated_version,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
    )

    if html is None:
        return f"Project not found: {escape(validated_project)} @ {escape(validated_version)}", 404

    # Security Review: XSS false positive - input validated via validate_project_name/
    # validate_version_name (strict regex), used only for DB query. HTML content from
    # visualization module uses markupsafe.escape() on all database values.
    return Response(html, mimetype="text/html")


@bp.route("/bipartite/<project_name>")
@auth_required
def bipartite_dependants(project_name: str) -> Response | tuple[str, int]:
    """Endpoint 2: Bi-partite visualization of project versions and dependants.

    Shows all versions of a project on the left and all direct dependants
    on the right.

    Args:
        project_name: The project name

    Query Parameters:
        internal_only: Set to 'true' to show only internal-labeled nodes (optional)
        height: Visualization height (default: 100vh, validated CSS dimension)
        width: Visualization width (default: 100vw, validated CSS dimension)

    Returns:
        HTML visualization or error message
    """
    # Validate path parameters to prevent XSS and injection
    validated_project = validate_project_name(project_name)
    if not validated_project:
        return "Invalid project name format", 400

    # Validate query parameters
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_bipartite_visualization(
        project_name=validated_project,
        internal_only=internal_only,
        height=height,
        width=width,
    )

    if html is None:
        return f"Project not found: {escape(validated_project)}", 404

    # Security Review: XSS false positive - input validated via validate_project_name
    # (strict regex), used only for DB query. HTML content from visualization module
    # uses markupsafe.escape() on all database values.
    return Response(html, mimetype="text/html")


@bp.route("/dependants/<project_name>/<version>")
@auth_required
def full_dependants_graph(project_name: str, version: str) -> Response | tuple[str, int]:
    """Endpoint 4: Full dependants graph to leaf nodes.

    Shows all dependants of a library back to the leaf nodes (applications
    that have no dependants).

    Args:
        project_name: The project name
        version: The version string

    Query Parameters:
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes (optional)
        height: Visualization height (default: 100vh, validated CSS dimension)
        width: Visualization width (default: 100vw, validated CSS dimension)

    Returns:
        HTML visualization or error message
    """
    # Validate path parameters to prevent XSS and injection
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)
    if not validated_project or not validated_version:
        return "Invalid project name or version format", 400

    # Validate query parameters
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_dependants_graph_visualization(
        project_name=validated_project,
        version_name=validated_version,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
    )

    if html is None:
        return f"Project not found: {escape(validated_project)} @ {escape(validated_version)}", 404

    # Security Review: XSS false positive - input validated via validate_project_name/
    # validate_version_name (strict regex), used only for DB query. HTML content from
    # visualization module uses markupsafe.escape() on all database values.
    return Response(html, mimetype="text/html")


@bp.route("/dependencies/<project_name>/<version>")
@auth_required
def dependencies_graph(project_name: str, version: str) -> Response | tuple[str, int]:
    """Endpoint 5: Dependencies graph with multiple layout options.

    Shows all dependencies of a project version with cycle detection and
    highlighting. Supports multiple layout algorithms with in-visualization
    switching.

    Available Layouts:
        - spring: Force-directed (ForceAtlas2) - default, ideal for cyclic graphs
        - radial: Radial tree layout - nodes in concentric circles
        - shell: Shell layout - nodes grouped by depth
        - bfs: BFS tree (hierarchical) - traditional tree layout
        - circular: Circular layout - nodes arranged in a circle

    Cycle edges are highlighted in red with dashed lines.
    Nodes involved in cycles have red borders.

    Path Parameters:
        project_name: The project name
        version: The version string

    Query Parameters:
        layout: Layout algorithm (spring, radial, shell, bfs, circular) - default: spring
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes (optional)
        height: Visualization height (default: 100vh, validated CSS dimension)
        width: Visualization width (default: 100vw, validated CSS dimension)

    Returns:
        HTML visualization or error message

    Example URLs:
        /visualizations/dependencies/extensible-platform/1.0.0
        /visualizations/dependencies/acme-kafka/2.0.0?layout=radial
    """
    # Validate all inputs
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)

    if validated_project is None:
        return "Invalid project_name parameter", 400
    if validated_version is None:
        return "Invalid version parameter", 400

    layout = validate_layout(request.args.get("layout"), "spring")
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_dependencies_multi_layout_visualization(
        project_name=validated_project,
        version_name=validated_version,
        layout=layout,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
    )

    if html is None:
        return (
            f"Project not found: {escape(validated_project)} @ {escape(validated_version)}",
            404,
        )

    # Security Review: XSS false positive - input validated via validate_project_name/
    # validate_version_name (strict regex), used only for DB query. HTML content from
    # visualization module uses markupsafe.escape() on all database values.
    return Response(html, mimetype="text/html")


@bp.route("/dependants-multi/<project_name>/<version>")
@auth_required
def dependants_multi_layout(project_name: str, version: str) -> Response | tuple[str, int]:
    """Endpoint 6: Dependants graph with multiple layout options.

    Shows all dependants of a library with cycle detection and highlighting.
    Supports multiple layout algorithms with in-visualization switching.
    This is ideal for viewing graphs with circular references.

    Available Layouts:
        - spring: Force-directed (ForceAtlas2) - good for cyclic graphs
        - radial: Radial tree layout - default, nodes in concentric circles
        - shell: Shell layout - nodes grouped by depth
        - bfs: BFS tree (hierarchical) - traditional tree layout
        - circular: Circular layout - nodes arranged in a circle

    Cycle edges are highlighted in red with dashed lines.
    Nodes involved in cycles have red borders.

    Path Parameters:
        project_name: The project name
        version: The version string

    Query Parameters:
        layout: Layout algorithm (spring, radial, shell, bfs, circular) - default: radial
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes (optional)
        height: Visualization height (default: 100vh, validated CSS dimension)
        width: Visualization width (default: 100vw, validated CSS dimension)

    Returns:
        HTML visualization or error message

    Example URLs:
        /visualizations/dependants-multi/acme-common/2.0.0
        /visualizations/dependants-multi/acme-config/2.0.0?layout=spring
    """
    # Validate all inputs
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)

    if validated_project is None:
        return "Invalid project_name parameter", 400
    if validated_version is None:
        return "Invalid version parameter", 400

    # Default layout is radial for dependants
    layout = validate_layout(request.args.get("layout"), "radial")
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_dependants_multi_layout_visualization(
        project_name=validated_project,
        version_name=validated_version,
        layout=layout,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
    )

    if html is None:
        return (
            f"Project not found: {escape(validated_project)} @ {escape(validated_version)}",
            404,
        )

    # Security Review: XSS false positive - input validated via validate_project_name/
    # validate_version_name (strict regex), used only for DB query. HTML content from
    # visualization module uses markupsafe.escape() on all database values.
    return Response(html, mimetype="text/html")
