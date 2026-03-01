"""Flask routes for reports (HTML tables, Excel exports, JSON)."""

from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, Response, jsonify, render_template, request

from appsec_data_views.exports.excel import (
    create_all_projects_excel,
    create_applications_excel,
    create_dependants_report_excel,
    create_multi_version_dependency_report_excel,
    create_multi_version_deps_excel,
    create_non_semver_report_excel,
    create_self_dependency_report_excel,
    create_snapshot_report_excel,
    create_vulnerabilities_excel,
    create_vulnerability_dependants_excel,
)
from appsec_data_views.routes.auth import auth_required
from appsec_data_views.services.falkordb_service import get_falkordb_service
from appsec_data_views.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_defect_id,
    validate_format,
    validate_limit,
    validate_max_depth,
    validate_project_name,
    validate_version_name,
)

bp = Blueprint("reports", __name__, url_prefix="/reports")


def _get_internal_title(base_title: str, internal_only: bool) -> str:
    """Get the title with internal filter label based on config.

    Args:
        base_title: The base title (e.g., "Projects")
        internal_only: Whether internal-only filter is active

    Returns:
        Title string with or without internal label
    """
    if internal_only:
        return f"Internal {base_title}"
    return f"All {base_title}"


def _get_current_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat()


def _build_json_response(data: dict[str, Any], filename: str) -> Response:
    """Build a JSON response with proper headers.

    Args:
        data: The data to serialize as JSON
        filename: Suggested filename for download

    Returns:
        Flask Response with JSON content
    """
    response = jsonify(data)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


# Template name for table views
TABLE_TEMPLATE = "table.html"


@bp.route("/projects")
@auth_required
def all_projects() -> Response:
    """Endpoint 5: Table view of all projects with versions.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        limit: Maximum number of results (default: 10000, max: 100000)
        internal_only: Set to 'true' to show only internal-labeled nodes (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    limit = validate_limit(request.args.get("limit", type=int), 10000)
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    projects = service.get_all_projects(limit, internal_only)
    unique_projects = len({p["project_name"] for p in projects})

    if output_format == "excel":
        filename = "internal_projects.xlsx" if internal_only else "all_projects.xlsx"
        buffer = create_all_projects_excel(service, limit, internal_only)
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        filename = "internal_projects.json" if internal_only else "all_projects.json"
        data = {
            "report_type": "projects",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "stats": {
                "total_project_versions": len(projects),
                "unique_projects": unique_projects,
            },
            "data": projects,
        }
        return _build_json_response(data, filename)

    # HTML table
    title = _get_internal_title("Projects", internal_only)
    base_url = "/reports/projects"

    html = render_template(
        TABLE_TEMPLATE,
        title=title,
        internal_only=internal_only,
        headers=["Project Name", "Version"],
        data=[[p["project_name"], p["version"]] for p in projects],
        stats={
            "Total Project Versions": len(projects),
            "Unique Projects": unique_projects,
        },
        excel_url=build_url_with_params(
            base_url, format="excel", limit=limit, internal_only=internal_only
        ),
        json_url=build_url_with_params(
            base_url, format="json", limit=limit, internal_only=internal_only
        ),
        schema_url="/schemas/projects",
    )

    return Response(html, mimetype="text/html")


@bp.route("/applications")
@auth_required
def all_applications() -> Response:
    """Report of all applications with their versions.

    Applications are nodes with the 'Application' label in the graph.
    This report shows all applications with their metadata including
    scan IDs, app IDs, and repository URLs.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        limit: Maximum number of results (default: 10000, max: 100000)
        internal_only: Set to 'true' to show only internal-labeled nodes (default: false)
        latest_only: Set to 'true' to show only the latest version per application (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    limit = validate_limit(request.args.get("limit", type=int), 10000)
    internal_only = validate_boolean(request.args.get("internal_only"))
    latest_only = validate_boolean(request.args.get("latest_only"))

    service = get_falkordb_service()
    applications = service.get_all_applications(limit, internal_only, latest_only)
    unique_apps = len({a["project_name"] for a in applications})

    if output_format == "excel":
        parts = []
        if internal_only:
            parts.append("internal")
        if latest_only:
            parts.append("latest")
        parts.append("applications.xlsx")
        filename = "_".join(parts) if len(parts) > 1 else "applications.xlsx"

        buffer = create_applications_excel(service, limit, internal_only, latest_only)
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        parts = []
        if internal_only:
            parts.append("internal")
        if latest_only:
            parts.append("latest")
        parts.append("applications.json")
        filename = "_".join(parts) if len(parts) > 1 else "applications.json"

        data = {
            "report_type": "applications",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "version_mode": "latest_only" if latest_only else "all_versions",
            "stats": {
                "total_application_versions": len(applications),
                "unique_applications": unique_apps,
            },
            "data": applications,
        }
        return _build_json_response(data, filename)

    # HTML table
    title_parts = []
    if internal_only:
        title_parts.append("Internal")
    if latest_only:
        title_parts.append("Latest")
    title_parts.append("Applications")
    title = " ".join(title_parts)

    base_url = "/reports/applications"

    # Prepare table data
    table_data = []
    for app in applications:
        table_data.append([
            app["project_name"],
            app["version"],
            app.get("scan_id") or "",
            app.get("public_id") or "",
            app.get("repo_url") or "",
            "Yes" if app.get("is_internal") else "No",
        ])

    html = render_template(
        TABLE_TEMPLATE,
        title=title,
        internal_only=internal_only,
        headers=[
            "Project Name",
            "Version",
            "Scan ID",
            "Public ID",
            "Repo URL",
            "Is Internal",
        ],
        data=table_data,
        stats={
            "Total Application Versions": len(applications),
            "Unique Applications": unique_apps,
            "Version Mode": "Latest Only" if latest_only else "All Versions",
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            limit=limit,
            internal_only=internal_only,
            latest_only=latest_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            limit=limit,
            internal_only=internal_only,
            latest_only=latest_only,
        ),
        schema_url="/schemas/applications",
        extra_toggles=[
            {
                "name": "latest_only",
                "label": "Latest Only",
                "checked": latest_only,
                "url": build_url_with_params(
                    base_url,
                    limit=limit,
                    internal_only=internal_only,
                    latest_only=not latest_only,
                ),
            }
        ],
    )

    return Response(html, mimetype="text/html")


@bp.route("/snapshots")
@auth_required
def snapshot_dependencies() -> Response:
    """Endpoint 6: Report of applications with SNAPSHOT dependencies.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    data = service.find_snapshot_dependencies(internal_only)

    unique_apps = len({r["application"] for r in data})
    unique_deps = len({r["dependency"] for r in data})

    if output_format == "excel":
        buffer = create_snapshot_report_excel(data)
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=snapshot_dependencies.xlsx"},
        )

    if output_format == "json":
        json_data = {
            "report_type": "snapshots",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "stats": {
                "total_snapshot_dependencies": len(data),
                "affected_applications": unique_apps,
                "unique_snapshot_dependencies": unique_deps,
            },
            "data": data,
        }
        return _build_json_response(json_data, "snapshot_dependencies.json")

    # HTML table
    base_url = "/reports/snapshots"
    html = render_template(
        TABLE_TEMPLATE,
        title="SNAPSHOT Dependencies Report",
        internal_only=internal_only,
        headers=["Application", "App Version", "Dependency", "Dependency Version"],
        data=[
            [r["application"], r["app_version"], r["dependency"], r["dep_version"]] for r in data
        ],
        stats={
            "Total SNAPSHOT Dependencies": len(data),
            "Affected Applications": unique_apps,
            "Unique SNAPSHOT Dependencies": unique_deps,
        },
        excel_url=build_url_with_params(base_url, format="excel", internal_only=internal_only),
        json_url=build_url_with_params(base_url, format="json", internal_only=internal_only),
        schema_url="/schemas/snapshots",
    )

    return Response(html, mimetype="text/html")


@bp.route("/self-dependencies")
@auth_required
def self_dependencies() -> Response:
    """Endpoint 7: Report of nodes that depend on themselves.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    data = service.find_self_dependencies(internal_only)

    unique_projects = len({r["project_name"] for r in data})

    if output_format == "excel":
        buffer = create_self_dependency_report_excel(data)
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=self_dependencies.xlsx"},
        )

    if output_format == "json":
        json_data = {
            "report_type": "self-dependencies",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "stats": {
                "total_self_dependencies": len(data),
                "affected_projects": unique_projects,
            },
            "data": data,
        }
        return _build_json_response(json_data, "self_dependencies.json")

    # HTML table
    base_url = "/reports/self-dependencies"
    html = render_template(
        TABLE_TEMPLATE,
        title="Self Dependencies Report",
        internal_only=internal_only,
        headers=["Project Name", "Version", "Relationship Type"],
        data=[[r["project_name"], r["version"], r["relationship_type"]] for r in data],
        stats={
            "Total Self Dependencies": len(data),
            "Affected Projects": unique_projects,
        },
        excel_url=build_url_with_params(base_url, format="excel", internal_only=internal_only),
        json_url=build_url_with_params(base_url, format="json", internal_only=internal_only),
        schema_url="/schemas/self-dependencies",
    )

    return Response(html, mimetype="text/html")


@bp.route("/multi-version-deps/<project_name>")
@auth_required
def multi_version_deps(project_name: str) -> Response | tuple[Response, int]:
    """Report showing all versions of a library and who uses each version.

    This endpoint answers: "Who uses what version of this library?"
    For a given library (project_name), it finds all versions and lists which
    applications/projects depend on each version.

    Use case: Understanding library adoption patterns, identifying which teams
    need to upgrade when a vulnerability is found in a specific version.

    Differs from /multi-version-sources which analyzes a specific project's
    dependency tree for version conflicts (diamond dependencies).

    URL Parameters:
        project_name: The library/project name to analyze

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled dependants

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(project_name):
        return jsonify({"error": "Invalid project name"}), 400

    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    data = service.get_library_version_usage(project_name, internal_only)

    library_info = data.get("library", {})
    versions = data.get("versions", [])
    total_dependants = data.get("total_dependants", 0)

    if not versions:
        if output_format == "json":
            return jsonify({
                "error": "Library not found",
                "project_name": project_name,
            }), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=f"Version Usage: {project_name}",
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": "Library not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(html, mimetype="text/html", status=404)

    base_url = f"/reports/multi-version-deps/{project_name}"

    if output_format == "excel":
        buffer = create_multi_version_deps_excel(data)
        safe_name = project_name.replace("/", "_").replace(":", "_")
        filename = f"version_usage_{safe_name}.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        safe_name = project_name.replace("/", "_").replace(":", "_")
        filename = f"version_usage_{safe_name}.json"
        json_data = {
            "report_type": "multi-version-deps",
            "generated_at": _get_current_timestamp(),
            "library": library_info,
            "stats": {
                "total_versions": library_info.get("total_versions", 0),
                "total_dependants": total_dependants,
            },
            "versions": versions,
        }
        return _build_json_response(json_data, filename)

    # HTML table - flatten data for display
    table_data = []
    for ver_info in versions:
        version = ver_info.get("version", "")
        dependant_count = ver_info.get("dependant_count", 0)
        dependants = ver_info.get("dependants", [])

        if dependants:
            for dep in dependants:
                internal_marker = " [INTERNAL]" if dep.get("is_internal") else ""
                table_data.append([
                    version,
                    dependant_count,
                    f"{dep.get('project_name', '')}{internal_marker}",
                    dep.get("version", ""),
                    dep.get("project_group", ""),
                ])
        else:
            table_data.append([
                version,
                dependant_count,
                "(no direct dependants)",
                "-",
                "-",
            ])

    html = render_template(
        TABLE_TEMPLATE,
        title=f"Version Usage: {project_name}",
        internal_only=internal_only,
        headers=[
            "Library Version",
            "Dependant Count",
            "Dependant Project",
            "Dependant Version",
            "Project Group",
        ],
        data=table_data,
        stats={
            "Library": project_name,
            "Total Versions": library_info.get("total_versions", 0),
            "Total Dependants": total_dependants,
        },
        excel_url=build_url_with_params(
            base_url, format="excel", internal_only=internal_only
        ),
        json_url=build_url_with_params(
            base_url, format="json", internal_only=internal_only
        ),
        schema_url="/schemas/multi-version-deps",
    )

    return Response(html, mimetype="text/html")


@bp.route("/multi-version-sources/<project_name>/<version_name>")
@auth_required
def multi_version_dependency_sources(
    project_name: str, version_name: str
) -> Response | tuple[Response, int]:
    """Report showing where multiple dependency versions come from (diamond deps).

    For a given project version, identifies dependencies that have multiple
    versions in the transitive dependency graph and traces each version back
    to the applications that introduced it.

    URL Parameters:
        project_name: The project name to analyze
        version_name: The version string

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        max_depth: Maximum traversal depth (default: 15, max: 100)
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(project_name) or not validate_version_name(version_name):
        return jsonify({"error": "Invalid project name or version"}), 400

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    data = service.find_multi_version_dependency_sources(
        project_name, version_name, max_depth, internal_only
    )

    if data.get("target") is None:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Project/version not found",
                    "project_name": project_name,
                    "version_name": version_name,
                }
            ), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=f"Multi-Version Dependencies: {project_name}@{version_name}",
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": "Project/version not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(html, mimetype="text/html", status=404)

    # Calculate stats
    multi_deps = data.get("multi_version_dependencies", [])
    target = data.get("target", {})
    total_versions = sum(dep["version_count"] for dep in multi_deps)

    all_apps: set[str] = set()
    for dep in multi_deps:
        for version_info in dep["versions"]:
            for app in version_info["contributing_applications"]:
                all_apps.add(app["project_name"])

    if output_format == "excel":
        buffer = create_multi_version_dependency_report_excel(data)
        safe_name = project_name.replace("/", "_").replace(":", "_")
        safe_version = version_name.replace("/", "_").replace(":", "_")
        filename = f"multi_version_deps_{safe_name}_{safe_version}.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        safe_name = project_name.replace("/", "_").replace(":", "_")
        safe_version = version_name.replace("/", "_").replace(":", "_")
        filename = f"multi_version_deps_{safe_name}_{safe_version}.json"
        json_data = {
            "report_type": "multi-version-sources",
            "generated_at": _get_current_timestamp(),
            "target": target,
            "stats": {
                "dependencies_with_multiple_versions": len(multi_deps),
                "total_conflicting_versions": total_versions,
                "contributing_applications": len(all_apps),
            },
            "multi_version_dependencies": multi_deps,
        }
        return _build_json_response(json_data, filename)

    # HTML table - flatten data for display
    table_data = []
    for dep in multi_deps:
        dep_project = dep["dependency_project"]
        for version_info in dep["versions"]:
            dep_version = version_info["version"]
            apps = version_info["contributing_applications"]
            if apps:
                for app in apps:
                    table_data.append(
                        [
                            dep_project,
                            dep_version,
                            app["project_name"],
                            app["version"],
                        ]
                    )
            else:
                table_data.append(
                    [
                        dep_project,
                        dep_version,
                        "(unknown source)",
                        "-",
                    ]
                )

    base_url = f"/reports/multi-version-sources/{project_name}/{version_name}"

    html = render_template(
        TABLE_TEMPLATE,
        title=f"Multi-Version Dependencies: {project_name}@{version_name}",
        internal_only=internal_only,
        headers=[
            "Dependency Project",
            "Dependency Version",
            "Contributing Application",
            "Application Version",
        ],
        data=table_data,
        stats={
            "Dependencies with Multiple Versions": len(multi_deps),
            "Total Conflicting Versions": total_versions,
            "Contributing Applications": len(all_apps),
            "Scan IDs Analyzed": target.get("scan_ids_count", 0),
        },
        excel_url=build_url_with_params(
            base_url, format="excel", max_depth=max_depth, internal_only=internal_only
        ),
        json_url=build_url_with_params(
            base_url, format="json", max_depth=max_depth, internal_only=internal_only
        ),
        schema_url="/schemas/multi-version-sources",
    )

    return Response(html, mimetype="text/html")


@bp.route("/non-semver-versions")
@auth_required
def non_semver_versions() -> Response:
    """Endpoint 9: Report of versions not following SemVer naming convention.

    SemVer format: MAJOR.MINOR.PATCH with optional pre-release and build
    metadata (e.g., 1.0.0, 1.2.3-alpha, v2.0.0).

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    data = service.find_non_semver_versions(internal_only)

    unique_projects = len({r["project_name"] for r in data})

    # Count by reason for stats
    reason_counts: dict[str, int] = {}
    for record in data:
        reason = record["reason"]
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    if output_format == "excel":
        buffer = create_non_semver_report_excel(data)
        filename = "non_semver_internal.xlsx" if internal_only else "non_semver_versions.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        filename = "non_semver_internal.json" if internal_only else "non_semver_versions.json"
        json_data = {
            "report_type": "non-semver-versions",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "stats": {
                "total_non_semver_versions": len(data),
                "affected_projects": unique_projects,
                "reason_breakdown": reason_counts,
            },
            "data": data,
        }
        return _build_json_response(json_data, filename)

    # HTML table
    # Find top 3 reasons for display
    top_reasons = sorted(reason_counts.items(), key=lambda x: -x[1])[:3]
    top_reasons_str = ", ".join(f"{r[0]} ({r[1]})" for r in top_reasons)

    base_url = "/reports/non-semver-versions"
    html = render_template(
        TABLE_TEMPLATE,
        title="Non-SemVer Versions Report",
        internal_only=internal_only,
        headers=["Project Name", "Version", "Reason", "Labels"],
        data=[
            [
                r["project_name"],
                r["version"],
                r["reason"],
                ", ".join(r.get("labels", [])),
            ]
            for r in data
        ],
        stats={
            "Total Non-SemVer Versions": len(data),
            "Affected Projects": unique_projects,
            "Top Reasons": top_reasons_str if top_reasons_str else "N/A",
        },
        excel_url=build_url_with_params(base_url, format="excel", internal_only=internal_only),
        json_url=build_url_with_params(base_url, format="json", internal_only=internal_only),
        schema_url="/schemas/non-semver-versions",
    )

    return Response(html, mimetype="text/html")


@bp.route("/version-dependencies/<project_name>/<version_name>")
@auth_required
def version_dependencies_report(
    project_name: str, version_name: str
) -> Response | tuple[Response, int]:
    """Report of transitive dependencies for a project version.

    Shows what a version depends ON (its dependencies), including transitive dependencies.
    This mirrors the visualization but in tabular format.

    URL Parameters:
        project_name: The project name
        version_name: The version string, or 'latest' for latest SemVer version

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes
        max_depth: Maximum depth to traverse (default: 10)

    Special version values:
        'latest': Returns the latest SemVer-compliant version. Only available if
                  ALL versions of the project follow SemVer naming convention.

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(project_name) or not validate_version_name(version_name):
        return jsonify({"error": "Invalid project name or version"}), 400

    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    max_depth = request.args.get("max_depth", type=int, default=10)

    service = get_falkordb_service()

    # Check semver compliance and handle 'latest' version
    is_semver_compliant, non_compliant_versions = service.is_project_semver_compliant(
        project_name, internal_only
    )
    latest_version = None
    if is_semver_compliant:
        latest_version = service.get_latest_semver_version(project_name, internal_only)

    # Handle 'latest' version request
    resolved_version = version_name
    if version_name.lower() == "latest":
        if not is_semver_compliant:
            error_msg = (
                f"Cannot use 'latest' for {project_name}: project has non-SemVer versions. "
                f"Non-compliant: {', '.join(non_compliant_versions[:5])}"
                f"{'...' if len(non_compliant_versions) > 5 else ''}"
            )
            if output_format == "json":
                return jsonify(
                    {
                        "error": error_msg,
                        "project_name": project_name,
                        "non_compliant_versions": non_compliant_versions,
                    }
                ), 400

            html = render_template(
                TABLE_TEMPLATE,
                title=f"Version Dependencies: {project_name}@latest",
                internal_only=internal_only,
                headers=[],
                data=[],
                stats={"Error": error_msg},
                excel_url=None,
                json_url=None,
                schema_url=None,
            )
            return Response(html, mimetype="text/html", status=400)

        if latest_version is None:
            # Edge case: project is semver compliant but has no versions
            error_msg = f"No versions found for project {project_name}"
            if output_format == "json":
                return jsonify({"error": error_msg, "project_name": project_name}), 404
            html = render_template(
                TABLE_TEMPLATE,
                title=f"Version Dependencies: {project_name}@latest",
                internal_only=internal_only,
                headers=[],
                data=[],
                stats={"Error": error_msg},
                excel_url=None,
                json_url=None,
                schema_url=None,
            )
            return Response(html, mimetype="text/html", status=404)

        resolved_version = latest_version

    # Get versions to verify the version exists
    all_versions = service.get_all_versions_of_project(project_name, internal_only)
    if not all_versions:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Project not found",
                    "project_name": project_name,
                }
            ), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=f"Version Dependencies: {project_name}@{version_name}",
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": "Project not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(html, mimetype="text/html", status=404)

    # Check if specific version exists
    if resolved_version not in all_versions:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Version not found",
                    "project_name": project_name,
                    "version_name": resolved_version,
                    "available_versions": all_versions[:20],
                }
            ), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=f"Version Dependencies: {project_name}@{resolved_version}",
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": f"Version '{resolved_version}' not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(html, mimetype="text/html", status=404)

    # Get transitive dependencies
    dependencies = service.get_transitive_dependencies_for_report(
        project_name, resolved_version, max_depth, internal_only
    )

    # Build title
    title = f"Version Dependencies: {project_name}@{resolved_version}"
    if version_name.lower() == "latest":
        title = f"Version Dependencies: {project_name}@latest ({resolved_version})"

    # Calculate stats
    unique_dependencies = (
        len({(d["dependency_project"], d["dependency_version"]) for d in dependencies})
        if dependencies
        else 0
    )

    max_depth_reached = max(d["depth"] for d in dependencies) if dependencies else 0
    direct_deps = sum(1 for d in dependencies if d["depth"] == 1)

    # Build base URL for download links
    base_url = f"/reports/version-dependencies/{project_name}/{version_name}"

    # Excel output
    if output_format == "excel":
        from appsec_data_views.exports.excel import create_version_dependencies_report_excel

        buffer = create_version_dependencies_report_excel(
            project_name,
            resolved_version,
            dependencies,
            is_semver_compliant,
            latest_version,
            internal_only,
            max_depth,
        )
        safe_name = project_name.replace("/", "_").replace(":", "_")
        safe_version = resolved_version.replace("/", "_").replace(":", "_")
        filename = f"{safe_name}_{safe_version}_dependencies.xlsx"

        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # JSON output
    if output_format == "json":
        safe_name = project_name.replace("/", "_").replace(":", "_")
        safe_version = resolved_version.replace("/", "_").replace(":", "_")
        filename = f"{safe_name}_{safe_version}_dependencies.json"

        # Transform data for JSON
        data_rows = []
        if dependencies:
            for d in dependencies:
                data_rows.append(
                    {
                        "depth": d["depth"],
                        "dependency_project": d["dependency_project"],
                        "dependency_version": d["dependency_version"],
                        "is_internal": d.get("is_internal", False),
                    }
                )
        else:
            data_rows.append(
                {
                    "depth": 0,
                    "dependency_project": "(no dependencies)",
                    "dependency_version": "-",
                    "is_internal": False,
                }
            )

        json_data = {
            "report_type": "version-dependencies",
            "generated_at": _get_current_timestamp(),
            "project_name": project_name,
            "version": resolved_version,
            "filter": "internal_only" if internal_only else "all",
            "max_depth": max_depth,
            "semver_compliance": {
                "is_compliant": is_semver_compliant,
                "latest_version": latest_version,
                "non_compliant_count": len(non_compliant_versions)
                if not is_semver_compliant
                else 0,
            },
            "summary": {
                "total_dependencies": len(dependencies),
                "unique_dependencies": unique_dependencies,
                "direct_dependencies": direct_deps,
                "max_depth_reached": max_depth_reached,
            },
            "data": data_rows,
        }
        return _build_json_response(json_data, filename)

    # HTML output
    table_data = []
    if dependencies:
        for d in dependencies:
            table_data.append(
                [
                    d["depth"],
                    d["dependency_project"],
                    d["dependency_version"],
                    "Yes" if d.get("is_internal", False) else "No",
                ]
            )
    else:
        table_data.append(["-", "(no dependencies)", "-", "-"])

    # Build stats
    stats = {
        "Project": project_name,
        "Version": resolved_version,
        "Max Depth Setting": max_depth,
        "Total Dependencies": len(dependencies),
        "Unique Dependencies": unique_dependencies,
        "Direct Dependencies": direct_deps,
        "Max Depth Reached": max_depth_reached,
    }

    # Add semver info to stats if relevant
    if is_semver_compliant and latest_version:
        stats["Latest Version"] = latest_version
        stats["SemVer Compliant"] = "Yes"
    elif not is_semver_compliant:
        stats["SemVer Compliant"] = f"No ({len(non_compliant_versions)} non-compliant)"

    html = render_template(
        TABLE_TEMPLATE,
        title=title,
        internal_only=internal_only,
        headers=["Depth", "Dependency Project", "Dependency Version", "Is Internal"],
        data=table_data,
        stats=stats,
        excel_url=build_url_with_params(
            base_url, format="excel", internal_only=internal_only, max_depth=max_depth
        ),
        json_url=build_url_with_params(
            base_url, format="json", internal_only=internal_only, max_depth=max_depth
        ),
        schema_url="/schemas/version-dependencies",
    )

    return Response(html, mimetype="text/html")


@bp.route("/dependants/<project_name>/<version_name>")
@auth_required
def dependants_report(project_name: str, version_name: str) -> Response | tuple[Response, int]:
    """Endpoint 10: Report of dependants with partition and path information.

    For a given project version, shows all transitive dependants with:
    - Partition level (longest path from target)
    - Alternative paths to reach that dependant

    URL Parameters:
        project_name: The project name to analyze
        version_name: The version string

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        max_depth: Maximum traversal depth (default: 50, max: 100)
        internal_only: Set to 'true' to show only internal-labeled nodes
        longest_only: Set to 'false' to show all paths (default: true, shows only longest)

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(project_name) or not validate_version_name(version_name):
        return jsonify({"error": "Invalid project name or version"}), 400

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))
    # Default to true - show only longest paths for vulnerability prioritization
    longest_only_param = request.args.get("longest_only", "true").lower()
    longest_only = longest_only_param != "false"

    service = get_falkordb_service()

    # Check if project exists
    root = service.find_version(project_name, version_name)
    if root is None:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Project/version not found",
                    "project_name": project_name,
                    "version_name": version_name,
                }
            ), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=f"Dependants Report: {project_name}@{version_name}",
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": "Project/version not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(html, mimetype="text/html", status=404)

    # Get dependants with partition information
    report_data = service.get_dependants_with_partitions_and_paths(
        project_name, version_name, max_depth, internal_only, longest_only
    )

    dependants = report_data.get("dependants", [])
    target = report_data.get("target", {})

    if output_format == "excel":
        buffer = create_dependants_report_excel(report_data, longest_only)
        safe_name = project_name.replace("/", "_").replace(":", "_")
        safe_version = version_name.replace("/", "_").replace(":", "_")
        suffix = "_longest" if longest_only else "_all_paths"
        filename = f"dependants_{safe_name}_{safe_version}{suffix}.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        safe_name = project_name.replace("/", "_").replace(":", "_")
        safe_version = version_name.replace("/", "_").replace(":", "_")
        suffix = "_longest" if longest_only else "_all_paths"
        filename = f"dependants_{safe_name}_{safe_version}{suffix}.json"
        json_data = {
            "report_type": "dependants",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "longest_only": longest_only,
            "target": target,
            "stats": report_data.get("stats", {}),
            "dependants": dependants,
        }
        return _build_json_response(json_data, filename)

    # Build custom HTML for dependants with expandable paths
    base_url = f"/reports/dependants/{project_name}/{version_name}"
    stats = report_data.get("stats", {})

    html = render_template(
        "dependants.html",
        project_name=project_name,
        version_name=version_name,
        internal_only=internal_only,
        longest_only=longest_only,
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            max_depth=max_depth,
            internal_only=internal_only,
            longest_only=longest_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            max_depth=max_depth,
            internal_only=internal_only,
            longest_only=longest_only,
        ),
        total_dependants=stats.get("total_dependants", len(dependants)),
        max_partition=stats.get("max_partition", 0),
        unique_projects=stats.get("unique_projects", 0),
        dependants=dependants,
    )

    return Response(html, mimetype="text/html")


@bp.route("/vulnerabilities")
@auth_required
def all_vulnerabilities() -> Response:
    """Report of all vulnerabilities ordered by severity.

    Shows all vulnerabilities with their affected versions. Each affected
    version is clickable to view its dependants graph visualization.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    vulnerabilities = service.get_all_vulnerabilities(internal_only)

    # Count statistics
    severity_counts: dict[str, int] = {}
    total_affected = 0
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_affected += len(vuln.get("affected_versions", []))

    if output_format == "excel":
        buffer = create_vulnerabilities_excel(vulnerabilities, internal_only)
        filename = "vulnerabilities_internal.xlsx" if internal_only else "vulnerabilities.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        filename = "vulnerabilities_internal.json" if internal_only else "vulnerabilities.json"
        data = {
            "report_type": "vulnerabilities",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "stats": {
                "total_vulnerabilities": len(vulnerabilities),
                "total_affected_versions": total_affected,
                "by_severity": severity_counts,
            },
            "data": vulnerabilities,
        }
        return _build_json_response(data, filename)

    # HTML table with clickable links
    title = _get_internal_title("Vulnerabilities", internal_only)
    base_url = "/reports/vulnerabilities"

    html = render_template(
        "vulnerabilities.html",
        title=title,
        internal_only=internal_only,
        vulnerabilities=vulnerabilities,
        stats={
            "Total Vulnerabilities": len(vulnerabilities),
            "Total Affected Versions": total_affected,
            "Critical": severity_counts.get("CRITICAL", 0),
            "High": severity_counts.get("HIGH", 0),
            "Medium": severity_counts.get("MEDIUM", 0),
            "Low": severity_counts.get("LOW", 0),
        },
        excel_url=build_url_with_params(base_url, format="excel", internal_only=internal_only),
        json_url=build_url_with_params(base_url, format="json", internal_only=internal_only),
        schema_url="/schemas/vulnerabilities",
    )

    return Response(html, mimetype="text/html")


@bp.route("/vulnerability-dependants/<defect_id>")
@auth_required
def vulnerability_dependants(defect_id: str) -> Response:
    """Report of all dependants affected by a specific vulnerability.

    Shows all projects that transitively depend on versions affected by this
    vulnerability, ordered by partition (distance from the vulnerable library).
    Partition 1 means direct dependency on the vulnerable version.

    Path Parameters:
        defect_id: The vulnerability ID (e.g., CVE-2021-44228)

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        max_depth: Maximum traversal depth (default: 50)
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_defect_id(defect_id):
        return jsonify({"error": "Invalid defect ID"}), 400

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()

    # Get the vulnerability details
    vuln = service.get_vulnerability_by_id(defect_id, internal_only=False)
    if not vuln:
        from markupsafe import escape
        return Response(f"Vulnerability not found: {escape(defect_id)}", status=404)

    # Get all dependants
    dependants = service.get_vulnerability_dependants(
        defect_id=defect_id,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    # Calculate statistics
    max_partition = max((d.get("partition", 0) for d in dependants), default=0)
    unique_projects = len({d["project_name"] for d in dependants})
    partition_counts: dict[int, int] = {}
    for dep in dependants:
        p = dep.get("partition", 0)
        partition_counts[p] = partition_counts.get(p, 0) + 1

    if output_format == "excel":
        buffer = create_vulnerability_dependants_excel(vuln, dependants, internal_only)
        filename = f"vulnerability_dependants_{defect_id}.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        filename = f"vulnerability_dependants_{defect_id}.json"
        data = {
            "report_type": "vulnerability-dependants",
            "generated_at": _get_current_timestamp(),
            "filter": "internal_only" if internal_only else "all",
            "vulnerability": vuln,
            "stats": {
                "total_dependants": len(dependants),
                "max_partition": max_partition,
                "unique_projects": unique_projects,
                "by_partition": partition_counts,
            },
            "dependants": dependants,
        }
        return _build_json_response(data, filename)

    # HTML table
    title = f"Dependants Affected by {defect_id}"
    base_url = f"/reports/vulnerability-dependants/{defect_id}"

    html = render_template(
        "vulnerability_dependants.html",
        title=title,
        vulnerability=vuln,
        internal_only=internal_only,
        dependants=dependants,
        stats={
            "Total Dependants": len(dependants),
            "Max Partition": max_partition,
            "Unique Projects": unique_projects,
        },
        excel_url=build_url_with_params(
            base_url, format="excel", max_depth=max_depth, internal_only=internal_only
        ),
        json_url=build_url_with_params(
            base_url, format="json", max_depth=max_depth, internal_only=internal_only
        ),
        schema_url="/schemas/vulnerability-dependants",
    )

    return Response(html, mimetype="text/html")


@bp.route("/centrality")
@auth_required
def internal_centrality() -> Response:
    """Report of centrality metrics for internal libraries.

    Shows inDegree and outDegree for all internal nodes. inDegree represents
    how many projects depend on this library (popularity/importance).
    outDegree represents how many dependencies this library has (complexity).

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        sort_by: Field to sort by - 'inDegree' or 'outDegree' (default: inDegree)
        sort_order: Sort direction - 'asc' or 'desc' (default: desc)
        limit: Maximum number of results (default: 1000)

    Returns:
        HTML table with drill-down links, Excel download, or JSON

    Drill-down Links:
        - outDegree column has two links per row:
          1. Dependencies visualization (internal only)
          2. Dependencies visualization (all dependencies)
        - inDegree column links to dependants visualization (radial layout)
    """
    output_format = validate_format(request.args.get("format"))
    sort_by = request.args.get("sort_by", "inDegree")
    sort_order = request.args.get("sort_order", "desc")
    limit = validate_limit(request.args.get("limit", type=int), 1000)

    # Validate sort_by
    valid_sort_fields = {"inDegree", "outDegree", "project_name", "version_name"}
    if sort_by not in valid_sort_fields:
        sort_by = "inDegree"

    # Validate sort_order
    if sort_order.lower() not in ("asc", "desc"):
        sort_order = "desc"

    service = get_falkordb_service()
    centrality_data = service.get_internal_centrality(
        sort_by=sort_by,
        sort_order=sort_order,
        limit=limit,
    )

    # Calculate statistics
    total_libs = len(centrality_data)
    total_in_degree = sum(d.get("inDegree", 0) for d in centrality_data)
    total_out_degree = sum(d.get("outDegree", 0) for d in centrality_data)
    max_in_degree = max((d.get("inDegree", 0) for d in centrality_data), default=0)
    max_out_degree = max((d.get("outDegree", 0) for d in centrality_data), default=0)

    if output_format == "excel":
        from appsec_data_views.exports.excel import create_centrality_excel

        buffer = create_centrality_excel(centrality_data)
        filename = "internal_centrality.xlsx"
        return Response(
            buffer.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    if output_format == "json":
        filename = "internal_centrality.json"
        data = {
            "report_type": "centrality",
            "generated_at": _get_current_timestamp(),
            "stats": {
                "total_libraries": total_libs,
                "total_in_degree": total_in_degree,
                "total_out_degree": total_out_degree,
                "max_in_degree": max_in_degree,
                "max_out_degree": max_out_degree,
            },
            "data": centrality_data,
        }
        return _build_json_response(data, filename)

    # Build URL params for sort toggles
    base_url = "/reports/centrality"

    # Get opposite sort order for toggle
    opposite_order = "asc" if sort_order == "desc" else "desc"

    # URLs for column header sorting
    sort_urls = {
        "inDegree": f"{base_url}?sort_by=inDegree&sort_order={'desc' if sort_by != 'inDegree' else opposite_order}&limit={limit}",
        "outDegree": f"{base_url}?sort_by=outDegree&sort_order={'desc' if sort_by != 'outDegree' else opposite_order}&limit={limit}",
        "project_name": f"{base_url}?sort_by=project_name&sort_order={'asc' if sort_by != 'project_name' else opposite_order}&limit={limit}",
        "version_name": f"{base_url}?sort_by=version_name&sort_order={'asc' if sort_by != 'version_name' else opposite_order}&limit={limit}",
    }

    # Excel/JSON download URLs preserve current sort
    excel_url = f"{base_url}?format=excel&sort_by={sort_by}&sort_order={sort_order}&limit={limit}"
    json_url = f"{base_url}?format=json&sort_by={sort_by}&sort_order={sort_order}&limit={limit}"

    html = render_template(
        "centrality.html",
        title="Internal Library Centrality",
        centrality_data=centrality_data,
        stats={
            "Total Internal Libraries": total_libs,
            "Total Inward Connections": total_in_degree,
            "Total Outward Connections": total_out_degree,
            "Max inDegree": max_in_degree,
            "Max outDegree": max_out_degree,
        },
        sort_by=sort_by,
        sort_order=sort_order,
        sort_urls=sort_urls,
        excel_url=excel_url,
        json_url=json_url,
        schema_url="/schemas/centrality",
    )

    return Response(html, mimetype="text/html")
