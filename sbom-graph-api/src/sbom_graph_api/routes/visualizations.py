"""Flask routes for graph data visualizations."""

from flask import Blueprint, Response, request
from markupsafe import escape

from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.utils.purl import resolve_purl, resolve_purl_project
from sbom_graph_api.utils.validation import (
    validate_boolean,
    validate_css_dimension,
    validate_layout,
    validate_max_depth,
    validate_project_group,
    validate_project_name,
    validate_version_name,
)
from sbom_graph_api.visualizations.bipartite import create_bipartite_visualization
from sbom_graph_api.visualizations.dependants_graph import (
    create_dependants_graph_visualization,
)
from sbom_graph_api.visualizations.kpartite import create_kpartite_visualization
from sbom_graph_api.visualizations.multi_layout import (
    create_dependants_multi_layout_visualization,
    create_dependencies_multi_layout_visualization,
)

bp = Blueprint("visualizations", __name__, url_prefix="/visualizations")


def _kpartite_impl(
    project_name: str,
    version: str,
    project_group: str | None = None,
) -> Response | tuple[str, int]:
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_kpartite_visualization(
        project_name=project_name,
        version_name=version,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
        project_group=project_group,
    )

    if html is None:
        return f"Project not found: {escape(project_name)} @ {escape(version)}", 404

    return Response(html, mimetype="text/html")


@bp.route("/kpartite/<project_name>/<version>")
@auth_required
def kpartite_dependencies(project_name: str, version: str) -> Response | tuple[str, int]:
    """K-partite visualization of transitive dependencies.

    Query Parameters:
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes
        project_group: Optional group for disambiguation
        height: Visualization height (default: 100vh)
        width: Visualization width (default: 100vw)
    """
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)
    if not validated_project or not validated_version:
        return "Invalid project name or version format", 400

    group = validate_project_group(request.args.get("project_group"))
    return _kpartite_impl(validated_project, validated_version, group)


@bp.route("/kpartite/purl/<path:purl>")
@auth_required
def kpartite_dependencies_by_purl(purl: str) -> Response | tuple[str, int]:
    """K-partite visualization resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _kpartite_impl(
        coords["project_name"], coords["version_name"], coords.get("project_group")
    )


def _bipartite_impl(
    project_name: str,
    project_group: str | None = None,
) -> Response | tuple[str, int]:
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_bipartite_visualization(
        project_name=project_name,
        internal_only=internal_only,
        height=height,
        width=width,
        project_group=project_group,
    )

    if html is None:
        return f"Project not found: {escape(project_name)}", 404

    return Response(html, mimetype="text/html")


@bp.route("/bipartite/<project_name>")
@auth_required
def bipartite_dependants(project_name: str) -> Response | tuple[str, int]:
    """Bi-partite visualization of project versions and dependants.

    Query Parameters:
        internal_only: Set to 'true' to show only internal-labeled nodes
        project_group: Optional group for disambiguation
        height: Visualization height (default: 100vh)
        width: Visualization width (default: 100vw)
    """
    validated_project = validate_project_name(project_name)
    if not validated_project:
        return "Invalid project name format", 400

    group = validate_project_group(request.args.get("project_group"))
    return _bipartite_impl(validated_project, group)


@bp.route("/bipartite/purl/<path:purl>")
@auth_required
def bipartite_dependants_by_purl(purl: str) -> Response | tuple[str, int]:
    """Bi-partite visualization resolved via package URL."""
    coords = resolve_purl_project(purl)
    if isinstance(coords, tuple):
        return coords
    return _bipartite_impl(coords["project_name"], coords.get("project_group"))


def _dependants_impl(
    project_name: str,
    version: str,
    project_group: str | None = None,
) -> Response | tuple[str, int]:
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_dependants_graph_visualization(
        project_name=project_name,
        version_name=version,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
        project_group=project_group,
    )

    if html is None:
        return f"Project not found: {escape(project_name)} @ {escape(version)}", 404

    return Response(html, mimetype="text/html")


@bp.route("/dependants/<project_name>/<version>")
@auth_required
def full_dependants_graph(project_name: str, version: str) -> Response | tuple[str, int]:
    """Full dependants graph to leaf nodes.

    Query Parameters:
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes
        project_group: Optional group for disambiguation
        height: Visualization height (default: 100vh)
        width: Visualization width (default: 100vw)
    """
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)
    if not validated_project or not validated_version:
        return "Invalid project name or version format", 400

    group = validate_project_group(request.args.get("project_group"))
    return _dependants_impl(validated_project, validated_version, group)


@bp.route("/dependants/purl/<path:purl>")
@auth_required
def full_dependants_graph_by_purl(purl: str) -> Response | tuple[str, int]:
    """Full dependants graph resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _dependants_impl(
        coords["project_name"], coords["version_name"], coords.get("project_group")
    )


def _dependencies_impl(
    project_name: str,
    version: str,
    project_group: str | None = None,
) -> Response | tuple[str, int]:
    layout = validate_layout(request.args.get("layout"), "spring")
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_dependencies_multi_layout_visualization(
        project_name=project_name,
        version_name=version,
        layout=layout,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
        project_group=project_group,
    )

    if html is None:
        return (
            f"Project not found: {escape(project_name)} @ {escape(version)}",
            404,
        )

    return Response(html, mimetype="text/html")


@bp.route("/dependencies/<project_name>/<version>")
@auth_required
def dependencies_graph(project_name: str, version: str) -> Response | tuple[str, int]:
    """Dependencies graph with multiple layout options.

    Query Parameters:
        layout: Layout algorithm (spring, radial, shell, bfs, circular)
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes
        project_group: Optional group for disambiguation
        height: Visualization height (default: 100vh)
        width: Visualization width (default: 100vw)
    """
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)

    if validated_project is None:
        return "Invalid project_name parameter", 400
    if validated_version is None:
        return "Invalid version parameter", 400

    group = validate_project_group(request.args.get("project_group"))
    return _dependencies_impl(validated_project, validated_version, group)


@bp.route("/dependencies/purl/<path:purl>")
@auth_required
def dependencies_graph_by_purl(purl: str) -> Response | tuple[str, int]:
    """Dependencies graph resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _dependencies_impl(
        coords["project_name"], coords["version_name"], coords.get("project_group")
    )


def _dependants_multi_impl(
    project_name: str,
    version: str,
    project_group: str | None = None,
) -> Response | tuple[str, int]:
    layout = validate_layout(request.args.get("layout"), "radial")
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    height = validate_css_dimension(request.args.get("height", "100vh"), "100vh")
    width = validate_css_dimension(request.args.get("width", "100vw"), "100vw")

    html = create_dependants_multi_layout_visualization(
        project_name=project_name,
        version_name=version,
        layout=layout,
        max_depth=max_depth,
        internal_only=internal_only,
        height=height,
        width=width,
        project_group=project_group,
    )

    if html is None:
        return (
            f"Project not found: {escape(project_name)} @ {escape(version)}",
            404,
        )

    return Response(html, mimetype="text/html")


@bp.route("/dependants-multi/<project_name>/<version>")
@auth_required
def dependants_multi_layout(project_name: str, version: str) -> Response | tuple[str, int]:
    """Dependants graph with multiple layout options.

    Query Parameters:
        layout: Layout algorithm (spring, radial, shell, bfs, circular)
        max_depth: Maximum depth to traverse (optional, 1-100)
        internal_only: Set to 'true' to show only internal-labeled nodes
        project_group: Optional group for disambiguation
        height: Visualization height (default: 100vh)
        width: Visualization width (default: 100vw)
    """
    validated_project = validate_project_name(project_name)
    validated_version = validate_version_name(version)

    if validated_project is None:
        return "Invalid project_name parameter", 400
    if validated_version is None:
        return "Invalid version parameter", 400

    group = validate_project_group(request.args.get("project_group"))
    return _dependants_multi_impl(validated_project, validated_version, group)


@bp.route("/dependants-multi/purl/<path:purl>")
@auth_required
def dependants_multi_layout_by_purl(purl: str) -> Response | tuple[str, int]:
    """Dependants multi-layout resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _dependants_multi_impl(
        coords["project_name"], coords["version_name"], coords.get("project_group")
    )
