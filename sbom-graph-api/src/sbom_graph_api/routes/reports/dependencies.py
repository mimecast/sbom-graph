"""Dependency-analysis reports and PURL redirect helpers."""

from typing import Any

from flask import (
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue

from sbom_graph_api.exports.excel import (
    create_dependants_report_excel,
    create_multi_version_dependency_report_excel,
    create_multi_version_deps_excel,
    create_non_semver_report_excel,
    create_self_dependency_report_excel,
    create_snapshot_report_excel,
    create_version_dependencies_report_excel,
    excel_response,
)
from sbom_graph_api.exports.json_format import (
    dependants_json,
    multi_version_deps_json,
    multi_version_sources_json,
    non_semver_json,
    self_dependencies_json,
    snapshots_json,
    version_dependencies_json,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    TABLE_TEMPLATE,
    build_json_response,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.purl import resolve_purl, resolve_purl_project
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_format,
    validate_max_depth,
    validate_project_group,
    validate_project_name,
    validate_version_name,
)

# ------------------------------------------------------------------
# Snapshot dependencies
# ------------------------------------------------------------------


@bp.route("/snapshots")
@auth_required
def snapshot_dependencies() -> ResponseReturnValue:
    """Endpoint 6: Report of applications with SNAPSHOT deps.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled
            nodes (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    data = service.find_snapshot_dependencies(internal_only)

    unique_apps = len({r["application"] for r in data})
    unique_deps = len({r["dependency"] for r in data})

    if output_format == "excel":
        buf = create_snapshot_report_excel(data)
        return excel_response(
            buf,
            "snapshot_dependencies.xlsx",
        )

    if output_format == "json":
        payload, fn = snapshots_json(
            data,
            internal_only,
            unique_apps,
            unique_deps,
        )
        return build_json_response(payload, fn)

    # HTML table
    base_url = "/reports/snapshots"
    html = render_template(
        TABLE_TEMPLATE,
        title="SNAPSHOT Dependencies Report",
        internal_only=internal_only,
        headers=[
            "Application",
            "App Version",
            "Dependency",
            "Dependency Version",
        ],
        data=[
            [
                r["application"],
                r["app_version"],
                r["dependency"],
                r["dep_version"],
            ]
            for r in data
        ],
        stats={
            "Total SNAPSHOT Dependencies": len(data),
            "Affected Applications": unique_apps,
            "Unique SNAPSHOT Dependencies": unique_deps,
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            internal_only=internal_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            internal_only=internal_only,
        ),
        schema_url="/schemas/snapshots",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Self dependencies
# ------------------------------------------------------------------


@bp.route("/self-dependencies")
@auth_required
def self_dependencies() -> ResponseReturnValue:
    """Endpoint 7: Report of nodes that depend on themselves.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled
            nodes (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    data = service.find_self_dependencies(internal_only)

    unique_projects = len(
        {r["project_name"] for r in data},
    )

    if output_format == "excel":
        buf = create_self_dependency_report_excel(data)
        return excel_response(
            buf,
            "self_dependencies.xlsx",
        )

    if output_format == "json":
        payload, fn = self_dependencies_json(
            data,
            internal_only,
            unique_projects,
        )
        return build_json_response(payload, fn)

    # HTML table
    base_url = "/reports/self-dependencies"
    html = render_template(
        TABLE_TEMPLATE,
        title="Self Dependencies Report",
        internal_only=internal_only,
        headers=[
            "Project Name",
            "Version",
            "Relationship Type",
        ],
        data=[
            [
                r["project_name"],
                r["version"],
                r["relationship_type"],
            ]
            for r in data
        ],
        stats={
            "Total Self Dependencies": len(data),
            "Affected Projects": unique_projects,
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            internal_only=internal_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            internal_only=internal_only,
        ),
        schema_url="/schemas/self-dependencies",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Multi-version dependency usage
# ------------------------------------------------------------------


@bp.route("/multi-version-deps/<project_name>")
@auth_required
def multi_version_deps(
    project_name: str,
) -> ResponseReturnValue:
    """Report showing all versions of a library and who uses each.

    This endpoint answers: "Who uses what version of this library?"
    For a given library (project_name), it finds all versions and
    lists which applications/projects depend on each version.

    Differs from ``/multi-version-sources`` which analyses a
    specific project's dependency tree for version conflicts
    (diamond dependencies).

    URL Parameters:
        project_name: The library/project name to analyse

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled
            dependants

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(project_name):
        return jsonify({"error": "Invalid project name"}), 400

    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    data = service.get_library_version_usage(
        project_name,
        internal_only,
    )

    library_info = data.get("library", {})
    versions = data.get("versions", [])
    total_dependants = data.get("total_dependants", 0)

    if not versions:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Library not found",
                    "project_name": project_name,
                },
            ), 404

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
        return Response(
            html,
            mimetype="text/html",
            status=404,
        )

    base_url = f"/reports/multi-version-deps/{project_name}"

    if output_format == "excel":
        buf = create_multi_version_deps_excel(data)
        safe = project_name.replace("/", "_").replace(
            ":",
            "_",
        )
        return excel_response(
            buf,
            f"version_usage_{safe}.xlsx",
        )

    if output_format == "json":
        payload, fn = multi_version_deps_json(
            library_info,
            total_dependants,
            versions,
            project_name,
        )
        return build_json_response(payload, fn)

    # HTML table — flatten data for display
    table_data = _flatten_multi_version_deps(versions)

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
            "Total Versions": library_info.get(
                "total_versions",
                0,
            ),
            "Total Dependants": total_dependants,
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            internal_only=internal_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            internal_only=internal_only,
        ),
        schema_url="/schemas/multi-version-deps",
    )

    return Response(html, mimetype="text/html")


def _flatten_multi_version_deps(
    versions: list[dict[str, Any]],
) -> list[list[Any]]:
    """Flatten nested version/dependant data into table rows."""
    rows: list[list[Any]] = []
    for ver_info in versions:
        version = ver_info.get("version", "")
        dependant_count = ver_info.get("dependant_count", 0)
        dependants = ver_info.get("dependants", [])

        if dependants:
            for dep in dependants:
                internal_marker = " [INTERNAL]" if dep.get("is_internal") else ""
                dep_name = dep.get("project_name", "")
                rows.append(
                    [
                        version,
                        dependant_count,
                        f"{dep_name}{internal_marker}",
                        dep.get("version", ""),
                        dep.get("project_group", ""),
                    ],
                )
        else:
            rows.append(
                [
                    version,
                    dependant_count,
                    "(no direct dependants)",
                    "-",
                    "-",
                ],
            )
    return rows


# ------------------------------------------------------------------
# Multi-version dependency sources (diamond dependency analysis)
# ------------------------------------------------------------------


@bp.route(
    "/multi-version-sources/<project_name>/<version_name>",
)
@auth_required
def multi_version_dependency_sources(
    project_name: str,
    version_name: str,
) -> ResponseReturnValue:
    """Report showing where multiple dependency versions come from.

    For a given project version, identifies dependencies that have
    multiple versions in the transitive dependency graph and traces
    each version back to the applications that introduced it.

    URL Parameters:
        project_name: The project name to analyse
        version_name: The version string

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        max_depth: Maximum traversal depth (default: 15,
            max: 100)
        internal_only: Set to 'true' to show only
            internal-labeled nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(
        project_name,
    ) or not validate_version_name(version_name):
        return (
            jsonify(
                {"error": "Invalid project name or version"},
            ),
            400,
        )

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(
        request.args.get("max_depth", type=int),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    project_group = validate_project_group(
        request.args.get("project_group"),
    )

    service = get_falkordb_service()
    data = service.find_multi_version_dependency_sources(
        project_name,
        version_name,
        max_depth,
        internal_only,
        project_group=project_group,
    )

    if data.get("target") is None:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Project/version not found",
                    "project_name": project_name,
                    "version_name": version_name,
                },
            ), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=(f"Multi-Version Dependencies: {project_name}@{version_name}"),
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": "Project/version not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(
            html,
            mimetype="text/html",
            status=404,
        )

    multi_deps = data.get(
        "multi_version_dependencies",
        [],
    )
    target = data.get("target", {})
    total_versions = sum(dep["version_count"] for dep in multi_deps)

    all_apps: set[str] = set()
    for dep in multi_deps:
        for vi in dep["versions"]:
            for app in vi["contributing_applications"]:
                all_apps.add(app["project_name"])

    if output_format == "excel":
        buf = create_multi_version_dependency_report_excel(
            data,
        )
        safe_n = project_name.replace("/", "_").replace(
            ":",
            "_",
        )
        safe_v = version_name.replace("/", "_").replace(
            ":",
            "_",
        )
        fn = f"multi_version_deps_{safe_n}_{safe_v}.xlsx"
        return excel_response(buf, fn)

    if output_format == "json":
        payload, fn = multi_version_sources_json(
            target,
            multi_deps,
            total_versions,
            len(all_apps),
            project_name,
            version_name,
        )
        return build_json_response(payload, fn)

    # HTML table — flatten data for display
    table_data = _flatten_multi_version_sources(multi_deps)

    base_url = f"/reports/multi-version-sources/{project_name}/{version_name}"

    html = render_template(
        TABLE_TEMPLATE,
        title=(f"Multi-Version Dependencies: {project_name}@{version_name}"),
        internal_only=internal_only,
        headers=[
            "Dependency Project",
            "Dependency Version",
            "Contributing Application",
            "Application Version",
        ],
        data=table_data,
        stats={
            "Dependencies with Multiple Versions": len(
                multi_deps,
            ),
            "Total Conflicting Versions": total_versions,
            "Contributing Applications": len(all_apps),
            "Scan IDs Analyzed": target.get(
                "scan_ids_count",
                0,
            ),
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            max_depth=max_depth,
            internal_only=internal_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            max_depth=max_depth,
            internal_only=internal_only,
        ),
        schema_url="/schemas/multi-version-sources",
    )

    return Response(html, mimetype="text/html")


def _flatten_multi_version_sources(
    multi_deps: list[dict[str, Any]],
) -> list[list[Any]]:
    """Flatten nested multi-version source data into rows."""
    rows: list[list[Any]] = []
    for dep in multi_deps:
        dep_project = dep["dependency_project"]
        for vi in dep["versions"]:
            dep_version = vi["version"]
            apps = vi["contributing_applications"]
            if apps:
                for app in apps:
                    rows.append(
                        [
                            dep_project,
                            dep_version,
                            app["project_name"],
                            app["version"],
                        ],
                    )
            else:
                rows.append(
                    [
                        dep_project,
                        dep_version,
                        "(unknown source)",
                        "-",
                    ],
                )
    return rows


# ------------------------------------------------------------------
# Non-SemVer versions
# ------------------------------------------------------------------


@bp.route("/non-semver-versions")
@auth_required
def non_semver_versions() -> ResponseReturnValue:
    """Endpoint 9: Report of versions not following SemVer.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled
            nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    data = service.find_non_semver_versions(internal_only)

    unique_projects = len(
        {r["project_name"] for r in data},
    )

    reason_counts: dict[str, int] = {}
    for record in data:
        reason = record["reason"]
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    if output_format == "excel":
        buf = create_non_semver_report_excel(data)
        filename = "non_semver_internal.xlsx" if internal_only else "non_semver_versions.xlsx"
        return excel_response(buf, filename)

    if output_format == "json":
        payload, fn = non_semver_json(
            data,
            internal_only,
            unique_projects,
            reason_counts,
        )
        return build_json_response(payload, fn)

    # HTML table
    top_reasons = sorted(
        reason_counts.items(),
        key=lambda x: -x[1],
    )[:3]
    top_reasons_str = ", ".join(f"{r[0]} ({r[1]})" for r in top_reasons)

    base_url = "/reports/non-semver-versions"
    html = render_template(
        TABLE_TEMPLATE,
        title="Non-SemVer Versions Report",
        internal_only=internal_only,
        headers=[
            "Project Name",
            "Version",
            "Reason",
            "Labels",
        ],
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
            "Top Reasons": (top_reasons_str if top_reasons_str else "N/A"),
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            internal_only=internal_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            internal_only=internal_only,
        ),
        schema_url="/schemas/non-semver-versions",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Version dependencies (transitive dep tree)
# ------------------------------------------------------------------


@bp.route(
    "/version-dependencies/<project_name>/<version_name>",
)
@auth_required
def version_dependencies_report(
    project_name: str,
    version_name: str,
) -> ResponseReturnValue:
    """Report of transitive dependencies for a project version.

    Shows what a version depends ON (its dependencies), including
    transitive dependencies.  This mirrors the visualisation but in
    tabular format.

    URL Parameters:
        project_name: The project name
        version_name: The version string, or 'latest' for latest
            SemVer version

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled
            nodes
        max_depth: Maximum depth to traverse (default: 10)

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(
        project_name,
    ) or not validate_version_name(version_name):
        return (
            jsonify(
                {"error": "Invalid project name or version"},
            ),
            400,
        )

    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    max_depth = (
        validate_max_depth(
            request.args.get("max_depth", type=int),
        )
        or 10
    )
    project_group = validate_project_group(
        request.args.get("project_group"),
    )

    service = get_falkordb_service()

    is_semver_compliant, non_compliant_versions = service.is_project_semver_compliant(
        project_name,
        internal_only,
    )
    latest_version = None
    if is_semver_compliant:
        latest_version = service.get_latest_semver_version(
            project_name,
            internal_only,
        )

    resolved_version = version_name
    if version_name.lower() == "latest":
        error_resp = _handle_latest_resolution(
            service,
            project_name,
            is_semver_compliant,
            non_compliant_versions,
            latest_version,
            output_format,
            internal_only,
        )
        if error_resp is not None:
            return error_resp
        assert latest_version is not None
        resolved_version = latest_version

    all_versions = service.get_all_versions_of_project(
        project_name,
        internal_only,
        project_group=project_group,
    )

    error_resp = _check_version_exists(
        all_versions,
        project_name,
        version_name,
        resolved_version,
        output_format,
        internal_only,
    )
    if error_resp is not None:
        return error_resp

    dependencies = service.get_transitive_dependencies_for_report(
        project_name,
        resolved_version,
        max_depth,
        internal_only,
        project_group=project_group,
    )

    return _render_version_deps(
        dependencies,
        project_name,
        version_name,
        resolved_version,
        internal_only,
        max_depth,
        output_format,
        is_semver_compliant,
        latest_version,
        non_compliant_versions,
    )


def _handle_latest_resolution(
    _service: Any,
    project_name: str,
    is_semver_compliant: bool,
    non_compliant_versions: list[str],
    latest_version: str | None,
    output_format: str | None,
    internal_only: bool,
) -> ResponseReturnValue | None:
    """Resolve 'latest' version; return error response or None."""
    if not is_semver_compliant:
        ncv = non_compliant_versions
        sample = ", ".join(ncv[:5])
        ellipsis = "..." if len(ncv) > 5 else ""
        error_msg = (
            f"Cannot use 'latest' for "
            f"{project_name}: project has "
            f"non-SemVer versions. "
            f"Non-compliant: {sample}{ellipsis}"
        )
        if output_format == "json":
            return jsonify(
                {
                    "error": error_msg,
                    "project_name": project_name,
                    "non_compliant_versions": ncv,
                },
            ), 400

        html = render_template(
            TABLE_TEMPLATE,
            title=(f"Version Dependencies: {project_name}@latest"),
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": error_msg},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(
            html,
            mimetype="text/html",
            status=400,
        )

    if latest_version is None:
        error_msg = f"No versions found for project {project_name}"
        if output_format == "json":
            return jsonify(
                {
                    "error": error_msg,
                    "project_name": project_name,
                },
            ), 404
        html = render_template(
            TABLE_TEMPLATE,
            title=(f"Version Dependencies: {project_name}@latest"),
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": error_msg},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(
            html,
            mimetype="text/html",
            status=404,
        )

    return None


def _check_version_exists(
    all_versions: list[str],
    project_name: str,
    version_name: str,
    resolved_version: str,
    output_format: str | None,
    internal_only: bool,
) -> ResponseReturnValue | None:
    """Return an error response if the version is not found."""
    if not all_versions:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Project not found",
                    "project_name": project_name,
                },
            ), 404
        html = render_template(
            TABLE_TEMPLATE,
            title=(f"Version Dependencies: {project_name}@{version_name}"),
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={"Error": "Project not found"},
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(
            html,
            mimetype="text/html",
            status=404,
        )

    if resolved_version not in all_versions:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Version not found",
                    "project_name": project_name,
                    "version_name": resolved_version,
                    "available_versions": all_versions[:20],
                },
            ), 404
        html = render_template(
            TABLE_TEMPLATE,
            title=(f"Version Dependencies: {project_name}@{resolved_version}"),
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={
                "Error": (f"Version '{resolved_version}' not found"),
            },
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(
            html,
            mimetype="text/html",
            status=404,
        )

    return None


def _render_version_deps(  # noqa: PLR0913
    dependencies: list[dict[str, Any]],
    project_name: str,
    version_name: str,
    resolved_version: str,
    internal_only: bool,
    max_depth: int,
    output_format: str | None,
    is_semver_compliant: bool,
    latest_version: str | None,
    non_compliant_versions: list[str],
) -> ResponseReturnValue:
    """Render version-dependencies in the requested format."""
    title = f"Version Dependencies: {project_name}@{resolved_version}"
    if version_name.lower() == "latest":
        title = f"Version Dependencies: {project_name}@latest ({resolved_version})"

    unique_dependencies = (
        len(
            {
                (
                    d["dependency_project"],
                    d["dependency_version"],
                )
                for d in dependencies
            },
        )
        if dependencies
        else 0
    )

    max_depth_reached = max(d["depth"] for d in dependencies) if dependencies else 0
    direct_deps = sum(1 for d in dependencies if d["depth"] == 1)

    base_url = f"/reports/version-dependencies/{project_name}/{version_name}"

    if output_format == "excel":
        buf = create_version_dependencies_report_excel(
            project_name,
            resolved_version,
            dependencies,
            is_semver_compliant,
            latest_version,
            internal_only,
            max_depth,
        )
        safe_n = project_name.replace("/", "_").replace(
            ":",
            "_",
        )
        safe_v = resolved_version.replace("/", "_").replace(
            ":",
            "_",
        )
        fn = f"{safe_n}_{safe_v}_dependencies.xlsx"
        return excel_response(buf, fn)

    if output_format == "json":
        payload, fn = version_dependencies_json(
            dependencies,
            project_name,
            resolved_version,
            internal_only,
            max_depth,
            is_semver_compliant,
            latest_version,
            len(non_compliant_versions),
            unique_dependencies,
            direct_deps,
            max_depth_reached,
        )
        return build_json_response(payload, fn)

    # HTML output
    table_data = []
    if dependencies:
        for d in dependencies:
            table_data.append(
                [
                    d["depth"],
                    d["dependency_project"],
                    d["dependency_version"],
                    ("Yes" if d.get("is_internal", False) else "No"),
                ],
            )
    else:
        table_data.append(
            ["-", "(no dependencies)", "-", "-"],
        )

    stats: dict[str, Any] = {
        "Project": project_name,
        "Version": resolved_version,
        "Max Depth Setting": max_depth,
        "Total Dependencies": len(dependencies),
        "Unique Dependencies": unique_dependencies,
        "Direct Dependencies": direct_deps,
        "Max Depth Reached": max_depth_reached,
    }

    if is_semver_compliant and latest_version:
        stats["Latest Version"] = latest_version
        stats["SemVer Compliant"] = "Yes"
    elif not is_semver_compliant:
        nc_count = len(non_compliant_versions)
        stats["SemVer Compliant"] = f"No ({nc_count} non-compliant)"

    html = render_template(
        TABLE_TEMPLATE,
        title=title,
        internal_only=internal_only,
        headers=[
            "Depth",
            "Dependency Project",
            "Dependency Version",
            "Is Internal",
        ],
        data=table_data,
        stats=stats,
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            internal_only=internal_only,
            max_depth=max_depth,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            internal_only=internal_only,
            max_depth=max_depth,
        ),
        schema_url="/schemas/version-dependencies",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Dependants report
# ------------------------------------------------------------------


@bp.route("/dependants/<project_name>/<version_name>")
@auth_required
def dependants_report(
    project_name: str,
    version_name: str,
) -> ResponseReturnValue:
    """Endpoint 10: Report of dependants with partition info.

    URL Parameters:
        project_name: The project name to analyse
        version_name: The version string

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        max_depth: Maximum traversal depth
            (default: 50, max: 100)
        internal_only: Set to 'true' to show only
            internal-labeled nodes
        longest_only: Set to 'false' to show all paths
            (default: true, shows only longest)

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_project_name(
        project_name,
    ) or not validate_version_name(version_name):
        return (
            jsonify(
                {"error": "Invalid project name or version"},
            ),
            400,
        )

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(
        request.args.get("max_depth", type=int),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    project_group = validate_project_group(
        request.args.get("project_group"),
    )
    longest_only = validate_boolean(
        request.args.get("longest_only"),
        default=True,
    )

    service = get_falkordb_service()

    root = service.find_version(
        project_name,
        version_name,
        project_group,
    )
    if root is None:
        if output_format == "json":
            return jsonify(
                {
                    "error": "Project/version not found",
                    "project_name": project_name,
                    "version_name": version_name,
                },
            ), 404

        html = render_template(
            TABLE_TEMPLATE,
            title=(f"Dependants Report: {project_name}@{version_name}"),
            internal_only=internal_only,
            headers=[],
            data=[],
            stats={
                "Error": "Project/version not found",
            },
            excel_url=None,
            json_url=None,
            schema_url=None,
        )
        return Response(
            html,
            mimetype="text/html",
            status=404,
        )

    report_data = service.get_dependants_with_partitions_and_paths(
        project_name,
        version_name,
        max_depth,
        internal_only,
        longest_only,
        project_group=project_group,
    )

    if output_format == "excel":
        buf = create_dependants_report_excel(
            report_data,
            longest_only,
        )
        safe_n = project_name.replace("/", "_").replace(
            ":",
            "_",
        )
        safe_v = version_name.replace("/", "_").replace(
            ":",
            "_",
        )
        suffix = "_longest" if longest_only else "_all_paths"
        fn = f"dependants_{safe_n}_{safe_v}{suffix}.xlsx"
        return excel_response(buf, fn)

    if output_format == "json":
        payload, fn = dependants_json(
            report_data,
            internal_only,
            longest_only,
            project_name,
            version_name,
        )
        return build_json_response(payload, fn)

    # HTML — custom dependants template
    base_url = f"/reports/dependants/{project_name}/{version_name}"
    dependants = report_data.get("dependants", [])
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
        total_dependants=stats.get(
            "total_dependants",
            len(dependants),
        ),
        max_partition=stats.get("max_partition", 0),
        unique_projects=stats.get("unique_projects", 0),
        dependants=dependants,
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# PURL route variants
# ------------------------------------------------------------------


def _purl_redirect(
    endpoint: str,
    coords: dict[str, Any],
    version_key: str | None = None,
) -> ResponseReturnValue:
    """Redirect to a named endpoint with purl-resolved coords.

    Preserves all existing query parameters and adds
    ``project_group`` if the purl resolved to one.
    """
    params: dict[str, str] = dict(request.args)
    if coords.get("project_group"):
        params["project_group"] = coords["project_group"]

    kwargs: dict[str, str] = {
        "project_name": coords["project_name"],
    }
    if version_key:
        kwargs[version_key] = coords["version_name"]

    target = url_for(endpoint, **kwargs)  # type: ignore[arg-type]
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        target = f"{target}?{qs}"

    return redirect(target, code=307)


@bp.route("/multi-version-deps/purl/<path:purl>")
@auth_required
def multi_version_deps_by_purl(
    purl: str,
) -> ResponseReturnValue:
    """Multi-version-deps report resolved via package URL."""
    coords = resolve_purl_project(purl)
    if isinstance(coords, tuple):
        return coords
    return _purl_redirect(
        "reports.multi_version_deps",
        coords,
    )


@bp.route("/multi-version-sources/purl/<path:purl>")
@auth_required
def multi_version_sources_by_purl(
    purl: str,
) -> ResponseReturnValue:
    """Multi-version-sources report resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _purl_redirect(
        "reports.multi_version_dependency_sources",
        coords,
        version_key="version_name",
    )


@bp.route("/version-dependencies/purl/<path:purl>")
@auth_required
def version_dependencies_by_purl(
    purl: str,
) -> ResponseReturnValue:
    """Version-dependencies report resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _purl_redirect(
        "reports.version_dependencies_report",
        coords,
        version_key="version_name",
    )


@bp.route("/dependants/purl/<path:purl>")
@auth_required
def dependants_report_by_purl(
    purl: str,
) -> ResponseReturnValue:
    """Dependants report resolved via package URL."""
    coords = resolve_purl(purl)
    if isinstance(coords, tuple):
        return coords
    return _purl_redirect(
        "reports.dependants_report",
        coords,
        version_key="version_name",
    )
