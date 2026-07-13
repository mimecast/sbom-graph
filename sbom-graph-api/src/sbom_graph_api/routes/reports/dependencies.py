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

from sbom_graph_api.exports.json_format import (
    dependants_json,
    multi_version_deps_json,
    multi_version_sources_json,
    non_semver_json,
    version_dependencies_json,
)
from sbom_graph_api.exports.streaming import (
    SheetSpec,
    stream_json_response,
    stream_multi_sheet_workbook_response,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    TABLE_TEMPLATE,
    _safe_int,
    get_internal_title,
    parse_pagination,
    render_paged_report,
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
    validate_search_term,
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
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination()
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.find_snapshot_dependencies(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def to_cells(r: dict) -> list:
        return [r["application"], r["app_version"], r["dependency"], r["dep_version"]]

    def _affected_apps() -> int:
        return _safe_int(service.count_snapshot_applications(internal_only), 0)

    def _unique_deps() -> int:
        return _safe_int(service.count_snapshot_dependency_versions(internal_only), 0)

    def stats_builder(total: int) -> dict:
        return {
            "Total SNAPSHOT Dependencies": total,
            "Affected Applications": _affected_apps(),
            "Unique SNAPSHOT Dependencies": _unique_deps(),
        }

    def json_stats_builder(total: int) -> dict:
        return {
            "total_snapshot_dependencies": total,
            "affected_applications": _affected_apps(),
            "unique_snapshot_dependencies": _unique_deps(),
        }

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_snapshot_dependencies(internal_only),
        headers=["Application", "App Version", "Dependency", "Dependency Version"],
        to_cells=to_cells,
        title="SNAPSHOT Dependencies Report",
        base_url="/reports/snapshots",
        params={"internal_only": internal_only},
        filename_stem="snapshot_dependencies",
        report_type="snapshots",
        schema_url="/schemas/snapshots",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        json_meta={"filter": "internal_only" if internal_only else "all"},
        internal_only=internal_only,
    )


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
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination()
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.find_self_dependencies(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def to_cells(r: dict) -> list:
        return [r["project_name"], r["version"], r["relationship_type"]]

    def _affected_projects() -> int:
        return _safe_int(service.count_self_dependency_projects(internal_only), 0)

    def stats_builder(total: int) -> dict:
        return {
            "Total Self Dependencies": total,
            "Affected Projects": _affected_projects(),
        }

    def json_stats_builder(total: int) -> dict:
        return {
            "total_self_dependencies": total,
            "affected_projects": _affected_projects(),
        }

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_self_dependencies(internal_only),
        headers=["Project Name", "Version", "Relationship Type"],
        to_cells=to_cells,
        title="Self Dependencies Report",
        base_url="/reports/self-dependencies",
        params={"internal_only": internal_only},
        filename_stem="self_dependencies",
        report_type="self-dependencies",
        schema_url="/schemas/self-dependencies",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        json_meta={"filter": "internal_only" if internal_only else "all"},
        internal_only=internal_only,
    )


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
    internal_only = validate_boolean(request.args.get("internal_only"))
    name = validate_search_term(request.args.get("name"))
    req = parse_pagination(request.args)

    service = get_falkordb_service()
    data = service.get_library_version_usage(project_name, internal_only, name=name)

    library_info = data.get("library", {})
    versions = data.get("versions", [])
    total_dependants = data.get("total_dependants", 0)

    # An active name filter that matches nothing is an empty result, not a
    # missing library — fall through so the (paged) view keeps its search box.
    if not versions and not name:
        if output_format == "json":
            return jsonify({"error": "Library not found", "project_name": project_name}), 404

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
        safe = project_name.replace("/", "_").replace(":", "_")
        usage_headers = [
            "Library Version",
            "Dependant Count",
            "Dependant Project",
            "Dependant Version",
            "Project Group",
            "Is Internal",
        ]

        def _usage_rows() -> list[list[Any]]:
            rows: list[list[Any]] = []
            for ver_info in versions:
                version = ver_info.get("version", "")
                dependant_count = ver_info.get("dependant_count", 0)
                dependants = ver_info.get("dependants", [])
                if dependants:
                    for dep in dependants:
                        rows.append(
                            [
                                version,
                                dependant_count,
                                dep.get("project_name", ""),
                                dep.get("version", ""),
                                dep.get("project_group", ""),
                                "Yes" if dep.get("is_internal") else "No",
                            ]
                        )
                else:
                    rows.append([version, 0, "(no direct dependants)", "-", "-", "-"])
            return rows

        summary_rows = [
            ["Library", library_info.get("project_name", "N/A")],
            ["Total Versions", library_info.get("total_versions", 0)],
            ["Total Dependants", total_dependants or 0],
        ]
        version_summary_rows = [
            [
                ver_info.get("version", ""),
                ver_info.get("dependant_count", 0),
                "Yes" if ver_info.get("is_internal") else "No",
            ]
            for ver_info in versions
        ]
        sheets = [
            SheetSpec(title="Version Usage", headers=usage_headers, rows=_usage_rows()),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
            SheetSpec(
                title="Version Summary",
                headers=["Version", "Dependant Count", "Is Internal"],
                rows=version_summary_rows,
            ),
        ]
        return stream_multi_sheet_workbook_response(sheets, f"version_usage_{safe}.xlsx")

    if output_format == "json":
        payload, fn = multi_version_deps_json(library_info, total_dependants, versions, project_name)
        meta = {k: v for k, v in payload.items() if k != "versions"}
        return stream_json_response(meta, iter(versions), fn, data_key="versions")

    # HTML: in-memory pagination over flattened rows
    flat_rows = _flatten_multi_version_deps(versions)
    total_rows = len(flat_rows)

    def fetch_page(offset: int, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "library_version": r[0],
                "dependant_count": r[1],
                "dependant_project": r[2],
                "dependant_version": r[3],
                "project_group": r[4],
            }
            for r in flat_rows[offset : offset + limit]
        ]

    return render_paged_report(
        req=req,
        output_format="html",
        fetch_page=fetch_page,
        count=lambda: total_rows,
        headers=[
            "Library Version",
            "Dependant Count",
            "Dependant Project",
            "Dependant Version",
            "Project Group",
        ],
        to_cells=lambda r: [
            r["library_version"],
            r["dependant_count"],
            r["dependant_project"],
            r["dependant_version"],
            r["project_group"],
        ],
        title=f"Version Usage: {project_name}",
        base_url=base_url,
        params={"internal_only": internal_only, "name": name},
        filename_stem=f"version_usage_{project_name.replace('/', '_').replace(':', '_')}",
        report_type="multi-version-deps",
        schema_url="/schemas/multi-version-deps",
        stats_builder=lambda _total: {
            "Library": project_name,
            "Total Versions": library_info.get("total_versions", 0),
            "Total Dependants": total_dependants,
        },
        internal_only=internal_only,
        extra_context={"show_name_search": True, "name_search": name},
    )


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
    req = parse_pagination(request.args)

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
        safe_n = project_name.replace("/", "_").replace(":", "_")
        safe_v = version_name.replace("/", "_").replace(":", "_")
        fn = f"multi_version_deps_{safe_n}_{safe_v}.xlsx"
        main_headers = [
            "Dependency Project",
            "Dependency Version",
            "Contributing Application",
            "Application Version",
        ]
        unique_apps: set[tuple[str, str]] = set()
        for dep in multi_deps:
            for vi in dep["versions"]:
                for app in vi["contributing_applications"]:
                    unique_apps.add((app["project_name"], app["version"]))
        summary_rows = [
            ["Target Project", target.get("project_name", "N/A")],
            ["Target Version", target.get("version", "N/A")],
            ["Scan IDs Contributing", target.get("scan_ids_count", 0)],
            ["Dependencies with Multiple Versions", len(multi_deps)],
            ["Total Conflicting Versions", total_versions],
            ["Unique Contributing Applications", len(unique_apps)],
        ]
        dep_summary_rows = [
            [
                dep["dependency_project"],
                dep["version_count"],
                ", ".join(v["version"] for v in dep["versions"]),
            ]
            for dep in multi_deps
        ]
        sheets = [
            SheetSpec(
                title="Multi-Version Dependencies",
                headers=main_headers,
                rows=_flatten_multi_version_sources(multi_deps),
            ),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
            SheetSpec(
                title="Dependency Summary",
                headers=["Dependency Project", "Version Count", "Versions"],
                rows=dep_summary_rows,
            ),
        ]
        return stream_multi_sheet_workbook_response(sheets, fn)

    if output_format == "json":
        payload, fn = multi_version_sources_json(
            target, multi_deps, total_versions, len(all_apps), project_name, version_name,
        )
        meta = {k: v for k, v in payload.items() if k != "multi_version_dependencies"}
        return stream_json_response(meta, iter(multi_deps), fn, data_key="multi_version_dependencies")

    # HTML: in-memory pagination over flattened rows
    flat_rows = _flatten_multi_version_sources(multi_deps)
    total_rows = len(flat_rows)
    base_url = f"/reports/multi-version-sources/{project_name}/{version_name}"

    def fetch_page(offset: int, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "dep_project": r[0],
                "dep_version": r[1],
                "app_name": r[2],
                "app_version": r[3],
            }
            for r in flat_rows[offset : offset + limit]
        ]

    return render_paged_report(
        req=req,
        output_format="html",
        fetch_page=fetch_page,
        count=lambda: total_rows,
        headers=[
            "Dependency Project",
            "Dependency Version",
            "Contributing Application",
            "Application Version",
        ],
        to_cells=lambda r: [r["dep_project"], r["dep_version"], r["app_name"], r["app_version"]],
        title=f"Multi-Version Dependencies: {project_name}@{version_name}",
        base_url=base_url,
        params={"internal_only": internal_only, "max_depth": max_depth},
        filename_stem=f"multi_version_deps_{project_name.replace('/', '_').replace(':', '_')}_{version_name.replace('/', '_').replace(':', '_')}",
        report_type="multi-version-sources",
        schema_url="/schemas/multi-version-sources",
        stats_builder=lambda _total: {
            "Dependencies with Multiple Versions": len(multi_deps),
            "Total Conflicting Versions": total_versions,
            "Contributing Applications": len(all_apps),
            "Scan IDs Analyzed": target.get("scan_ids_count", 0),
        },
        internal_only=internal_only,
    )


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
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination(request.args)

    service = get_falkordb_service()
    data = service.find_non_semver_versions(internal_only)

    unique_projects = len({r["project_name"] for r in data})
    reason_counts: dict[str, int] = {}
    for record in data:
        reason = record["reason"]
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    if output_format == "excel":
        filename = "non_semver_internal.xlsx" if internal_only else "non_semver_versions.xlsx"
        main_headers = [
            "Project Name", "Version", "SemVer Compliant", "Released", "Reason", "Labels",
        ]
        main_rows = [
            [
                r["project_name"],
                r["version"],
                "Yes" if r.get("semver_compliant") else "No",
                "Yes" if r.get("released") else "No",
                r["reason"],
                ", ".join(r.get("labels", [])),
            ]
            for r in data
        ]
        summary_rows: list[list[Any]] = [
            ["Total Non-SemVer Versions", len(data)],
            ["Affected Projects", unique_projects],
            ["Breakdown by Reason", ""],
        ]
        for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1]):
            summary_rows.append([reason, count])
        by_reason_rows = [
            [r["reason"], r["project_name"], r["version"]]
            for r in sorted(data, key=lambda x: (x["reason"], x["project_name"], x["version"]))
        ]
        sheets = [
            SheetSpec(title="Non-SemVer Versions", headers=main_headers, rows=main_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
            SheetSpec(
                title="By Reason",
                headers=["Reason", "Project Name", "Version"],
                rows=by_reason_rows,
            ),
        ]
        return stream_multi_sheet_workbook_response(sheets, filename)

    if output_format == "json":
        payload, fn = non_semver_json(data, internal_only, unique_projects, reason_counts)
        meta = {k: v for k, v in payload.items() if k != "data"}
        return stream_json_response(meta, iter(data), fn)

    # HTML: in-memory pagination — data already in memory
    total = len(data)
    top_reasons = sorted(reason_counts.items(), key=lambda x: -x[1])[:3]
    top_reasons_str = ", ".join(f"{r[0]} ({r[1]})" for r in top_reasons)

    def fetch_page(offset: int, limit: int) -> list[dict[str, Any]]:
        return data[offset : offset + limit]

    return render_paged_report(
        req=req,
        output_format="html",
        fetch_page=fetch_page,
        count=lambda: total,
        headers=[
            "Project Name", "Version", "SemVer Compliant", "Released", "Reason", "Labels",
        ],
        to_cells=lambda r: [
            r["project_name"],
            r["version"],
            "Yes" if r.get("semver_compliant") else "No",
            "Yes" if r.get("released") else "No",
            r["reason"],
            ", ".join(r.get("labels", [])),
        ],
        title="Non-SemVer Versions Report",
        base_url="/reports/non-semver-versions",
        params={"internal_only": internal_only},
        filename_stem="non_semver_internal" if internal_only else "non_semver_versions",
        report_type="non-semver-versions",
        schema_url="/schemas/non-semver-versions",
        stats_builder=lambda _total: {
            "Total Non-SemVer Versions": total,
            "Affected Projects": unique_projects,
            "Top Reasons": top_reasons_str if top_reasons_str else "N/A",
        },
        internal_only=internal_only,
    )


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
    name = validate_search_term(request.args.get("name"))
    req = parse_pagination(request.args)

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
        # _handle_latest_resolution returns an error response when latest_version
        # is None, so reaching here with None means that contract was violated.
        if latest_version is None:
            raise RuntimeError("Latest version could not be resolved")
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
        req=req,
        name=name,
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
    req: Any = None,
    name: str | None = None,
) -> ResponseReturnValue:
    """Render version-dependencies in the requested format."""

    if req is None:
        req = parse_pagination(request.args)

    # Optional case-insensitive filter on the dependency's project name. Applied
    # before the derived stats so counts/exports stay consistent with the view.
    if name:
        name_lower = name.lower()
        dependencies = [
            d for d in dependencies if name_lower in (d.get("dependency_project") or "").lower()
        ]

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
        safe_n = project_name.replace("/", "_").replace(":", "_")
        safe_v = resolved_version.replace("/", "_").replace(":", "_")
        fn = f"{safe_n}_{safe_v}_dependencies.xlsx"
        main_headers = ["Depth", "Dependency Project", "Dependency Version", "Is Internal"]
        if dependencies:
            main_rows = [
                [
                    d["depth"],
                    d["dependency_project"],
                    d["dependency_version"],
                    "Yes" if d.get("is_internal") else "No",
                ]
                for d in dependencies
            ]
        else:
            main_rows = [["-", "(no dependencies)", "-", "-"]]
        summary_rows: list[list[Any]] = [
            ["Project Name", project_name],
            ["Version", resolved_version],
            ["Filter Mode", "Internal Only" if internal_only else "All"],
            ["Max Depth Setting", max_depth],
            ["Total Dependencies", len(dependencies)],
            ["Unique Dependencies", unique_dependencies],
            ["Direct Dependencies", direct_deps],
            ["Max Depth Reached", max_depth_reached],
            ["SemVer Compliant", "Yes" if is_semver_compliant else "No"],
        ]
        if is_semver_compliant and latest_version:
            summary_rows.append(["Latest SemVer Version", latest_version])
        sheets = [
            SheetSpec(title="Version Dependencies", headers=main_headers, rows=main_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
        ]
        return stream_multi_sheet_workbook_response(sheets, fn)

    if output_format == "json":
        payload, fn = version_dependencies_json(
            dependencies, project_name, resolved_version, internal_only, max_depth,
            is_semver_compliant, latest_version, len(non_compliant_versions),
            unique_dependencies, direct_deps, max_depth_reached,
        )
        meta = {k: v for k, v in payload.items() if k != "data"}
        return stream_json_response(meta, iter(payload.get("data", [])), fn)

    # HTML: in-memory pagination — data already fetched; slice in Python
    total_deps = len(dependencies)

    def fetch_page(offset: int, limit: int) -> list[dict[str, Any]]:
        page = dependencies[offset : offset + limit]
        if not page and not dependencies:
            return [
                {
                    "depth": "-",
                    "dependency_project": "(no dependencies)",
                    "dependency_version": "-",
                    "is_internal": False,
                }
            ]
        return page

    stats_val: dict[str, Any] = {
        "Project": project_name,
        "Version": resolved_version,
        "Max Depth Setting": max_depth,
        "Total Dependencies": total_deps,
        "Unique Dependencies": unique_dependencies,
        "Direct Dependencies": direct_deps,
        "Max Depth Reached": max_depth_reached,
    }
    if is_semver_compliant and latest_version:
        stats_val["Latest Version"] = latest_version
        stats_val["SemVer Compliant"] = "Yes"
    elif not is_semver_compliant:
        stats_val["SemVer Compliant"] = f"No ({len(non_compliant_versions)} non-compliant)"

    return render_paged_report(
        req=req,
        output_format="html",
        fetch_page=fetch_page,
        count=lambda: total_deps,
        headers=["Depth", "Dependency Project", "Dependency Version", "Is Internal"],
        to_cells=lambda d: [
            d["depth"],
            d["dependency_project"],
            d["dependency_version"],
            "Yes" if d.get("is_internal", False) else "No",
        ],
        title=title,
        base_url=base_url,
        params={"internal_only": internal_only, "max_depth": max_depth, "name": name},
        filename_stem=f"{project_name}_{resolved_version}_dependencies",
        report_type="version-dependencies",
        schema_url="/schemas/version-dependencies",
        stats_builder=lambda _total: stats_val,
        internal_only=internal_only,
        extra_context={"show_name_search": True, "name_search": name},
    )


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
    name = validate_search_term(request.args.get("name"))

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
        name=name,
    )

    if output_format == "excel":
        safe_n = project_name.replace("/", "_").replace(":", "_")
        safe_v = version_name.replace("/", "_").replace(":", "_")
        suffix = "_longest" if longest_only else "_all_paths"
        fn = f"dependants_{safe_n}_{safe_v}{suffix}.xlsx"
        _deps = report_data.get("dependants", [])
        _target = report_data.get("target", {})
        _stats = report_data.get("stats", {})

        main_headers = [
            "Dependant Project",
            "Version",
            "Partition (Longest Path)",
            "Max Path Edges",
            "Path Count",
            "Labels",
        ]
        main_rows = [
            [
                d.get("project_name", ""),
                d.get("version", ""),
                d.get("partition", 0),
                d.get("max_path_edges", 0),
                d.get("path_count", 0),
                ", ".join(d.get("labels", [])),
            ]
            for d in _deps
        ]
        path_rows: list[list[Any]] = []
        for d in _deps:
            for path_num, path in enumerate(d.get("paths", []), start=1):
                path_rows.append(
                    [
                        d.get("project_name", ""),
                        d.get("version", ""),
                        path_num,
                        len(path),
                        " -> ".join(path),
                    ]
                )
        summary_rows = [
            ["Target Project", _target.get("project_name", "N/A")],
            ["Target Version", _target.get("version", "N/A")],
            ["Total Dependants", _stats.get("total_dependants", 0)],
            ["Max Partition (Longest Path)", _stats.get("max_partition", 0)],
            ["Unique Projects", _stats.get("unique_projects", 0)],
            ["Path Mode", "Longest only" if longest_only else "All paths"],
        ]
        sheets = [
            SheetSpec(title="Dependants", headers=main_headers, rows=main_rows),
            SheetSpec(
                title="Dependency Paths",
                headers=["Dependant", "Version", "Path #", "Path Length", "Path"],
                rows=path_rows,
            ),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
        ]
        return stream_multi_sheet_workbook_response(sheets, fn)

    if output_format == "json":
        payload, fn = dependants_json(report_data, internal_only, longest_only, project_name, version_name)
        meta = {k: v for k, v in payload.items() if k != "dependants"}
        return stream_json_response(meta, iter(report_data.get("dependants", [])), fn, data_key="dependants")

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
            name=name,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            max_depth=max_depth,
            internal_only=internal_only,
            longest_only=longest_only,
            name=name,
        ),
        total_dependants=stats.get(
            "total_dependants",
            len(dependants),
        ),
        max_partition=stats.get("max_partition", 0),
        unique_projects=stats.get("unique_projects", 0),
        dependants=dependants,
        show_name_search=True,
        name_search=name,
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


# ------------------------------------------------------------------
# Bipartite dependants report (latest / latest-1 classification, Phase 5)
# ------------------------------------------------------------------

_BIPARTITE_RECENCY = frozenset({"latest", "latest_or_prev", "not_latest_or_prev"})


def _bipartite_report_impl(
    project_name: str,
    project_group: str | None = None,
) -> ResponseReturnValue:
    """Tabular bipartite report: dependants vs. target-version recency."""
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    name = validate_search_term(request.args.get("name"))
    name_lower = name.lower() if name else None
    recency = request.args.get("recency")
    if recency not in _BIPARTITE_RECENCY:
        recency = None
    req = parse_pagination(request.args)
    service = get_falkordb_service()

    latest, prev = service.get_target_version_recency(project_name, internal_only)
    recent_set = {v for v in (latest, prev) if v}

    enriched: list[dict[str, Any]] = []
    for r in service.get_direct_dependants(project_name, internal_only=internal_only):
        dependant_project = r.get("dependant_project")
        if name_lower and name_lower not in (dependant_project or "").lower():
            continue
        target_version = r.get("target_version")
        is_latest = target_version is not None and target_version == latest
        is_latest_or_prev = target_version in recent_set if recent_set else False
        if recency == "latest" and not is_latest:
            continue
        if recency == "latest_or_prev" and not is_latest_or_prev:
            continue
        if recency == "not_latest_or_prev" and is_latest_or_prev:
            continue
        enriched.append(
            {
                "target_project": r.get("target_project"),
                "target_version": target_version,
                "is_latest": is_latest,
                "is_latest_or_prev": is_latest_or_prev,
                "dependant_project": r.get("dependant_project"),
                "dependant_version": r.get("dependant_version"),
            }
        )

    total = len(enriched)

    def fetch_page(offset: int, limit: int) -> list[dict[str, Any]]:
        return enriched[offset : offset + limit]

    def to_cells(r: dict[str, Any]) -> list[Any]:
        return [
            r["target_project"],
            r["target_version"],
            "Yes" if r["is_latest"] else "No",
            "Yes" if r["is_latest_or_prev"] else "No",
            r["dependant_project"],
            r["dependant_version"],
        ]

    base_url = f"/reports/bipartite/{project_name}"
    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: total,
        headers=[
            "Target Project", "Target Version", "Is Latest",
            "Is Latest-or-(Latest-1)", "Dependant Project", "Dependant Version",
        ],
        to_cells=to_cells,
        to_export_cells=to_cells,
        title=f"Bipartite Dependants: {project_name}",
        base_url=base_url,
        params={"internal_only": internal_only, "recency": recency, "name": name},
        filename_stem=f"bipartite_{project_name}",
        report_type="bipartite",
        schema_url="/schemas/bipartite",
        stats_builder=lambda t: {
            "Total Dependants": t,
            "Latest Version": latest or "N/A",
            "Previous Version": prev or "N/A",
        },
        json_stats_builder=lambda t: {
            "total_dependants": t,
            "latest_version": latest,
            "previous_version": prev,
        },
        json_meta={
            "project_name": project_name,
            "filter": "internal_only" if internal_only else "all",
        },
        internal_only=internal_only,
        extra_context={"show_name_search": True, "name_search": name},
    )


@bp.route("/bipartite/<project_name>")
@auth_required
def bipartite_report(project_name: str) -> ResponseReturnValue:
    """Bipartite dependants report with latest / latest-1 classification.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes
        project_group: Optional group for disambiguation
        recency: Filter rows — 'latest', 'latest_or_prev', or 'not_latest_or_prev'
        page / page_size: Pagination (page_size 1..1000, default 100)
    """
    validated_project = validate_project_name(project_name)
    if not validated_project:
        return "Invalid project name format", 400
    group = validate_project_group(request.args.get("project_group"))
    return _bipartite_report_impl(validated_project, group)


@bp.route("/bipartite/purl/<path:purl>")
@auth_required
def bipartite_report_by_purl(purl: str) -> ResponseReturnValue:
    """Bipartite dependants report resolved via package URL."""
    coords = resolve_purl_project(purl)
    if isinstance(coords, tuple):
        return coords
    return _purl_redirect("reports.bipartite_report", coords)


# ------------------------------------------------------------------
# Unreleased-in-production (Phase 7 gap #4)
# ------------------------------------------------------------------


@bp.route("/unreleased-in-prod")
@auth_required
def unreleased_in_prod() -> Response | tuple[Response, int]:
    """Applications depending on unreleased dependency versions.

    Joins the suspect/unreleased version classification (SNAPSHOT, pre-release,
    branch-name, non-SemVer) to the applications that consume those versions.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: 'true' to restrict to internal-labeled nodes
        page / page_size: Pagination (page_size 1..1000, default 100)
        all: 'true' to lift the total cap (exports stream the full set)

    Returns:
        Paged HTML table, streamed Excel download, or streamed JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination()
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.get_unreleased_in_production(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def to_cells(r: dict) -> list:
        return [
            r["application"],
            r["application_version"],
            r["dependency"],
            r["dependency_version"],
            r["reason"],
        ]

    def stats_builder(total: int) -> dict:
        return {"Unreleased Dependencies In Use": total}

    def json_stats_builder(total: int) -> dict:
        return {"unreleased_in_use": total}

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_unreleased_in_production(internal_only=internal_only),
        headers=[
            "Application", "Application Version", "Dependency",
            "Dependency Version", "Reason",
        ],
        to_cells=to_cells,
        title=get_internal_title("Unreleased Dependencies In Production", internal_only),
        base_url="/reports/unreleased-in-prod",
        params={"internal_only": "true"} if internal_only else {},
        filename_stem="unreleased_in_prod",
        report_type="unreleased-in-prod",
        schema_url="/schemas/unreleased-in-prod",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        internal_only=internal_only,
    )


# ------------------------------------------------------------------
# Dependency-freshness fleet report (Phase 7 gap #1)
# ------------------------------------------------------------------


@bp.route("/dependency-freshness")
@auth_required
def dependency_freshness() -> Response | tuple[Response, int]:
    """Fleet-wide dependency freshness ranked by fan-in.

    One row per dependency library: how many consumers are on the latest /
    latest-1 version versus stale, so upgrade campaigns can target the
    highest-impact stale libraries first.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: 'true' to restrict to internal-labeled nodes
        page / page_size: Pagination (page_size 1..1000, default 100)
        all: 'true' to lift the total cap (exports stream the full set)

    Returns:
        Paged HTML table, streamed Excel download, or streamed JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination()
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.get_dependency_freshness(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def to_cells(r: dict) -> list:
        return [
            r["target_project"],
            r["latest"],
            r["prev"],
            r["consumers"],
            r["on_latest"],
            r["on_latest_or_prev"],
            r["stale"],
            f"{r['pct_stale']}%",
        ]

    def stats_builder(total: int) -> dict:
        return {"Dependency Libraries": total}

    def json_stats_builder(total: int) -> dict:
        return {"libraries": total}

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_dependency_freshness(internal_only=internal_only),
        headers=[
            "Target Project", "Latest", "Latest-1", "Consumers",
            "On Latest", "On Latest-or-(Latest-1)", "Stale", "% Stale",
        ],
        to_cells=to_cells,
        title=get_internal_title("Dependency Freshness (Fleet)", internal_only),
        base_url="/reports/dependency-freshness",
        params={"internal_only": "true"} if internal_only else {},
        filename_stem="dependency_freshness",
        report_type="dependency-freshness",
        schema_url="/schemas/dependency-freshness",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        internal_only=internal_only,
    )
