"""License and policy compliance reports."""

from typing import Any

from flask import (
    Response,
    jsonify,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue

from sbom_graph_api.exports.json_format import (
    license_conflicts_json,
    license_summary_json,
)
from sbom_graph_api.exports.streaming import (
    SheetSpec,
    stream_json_response,
    stream_multi_sheet_workbook_response,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    TOTAL_COUNT_HEADER,
    build_page_view,
    get_internal_title,
    parse_pagination,
    render_paged_report,
    ts,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service, iterate_pages
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_format,
    validate_project_group,
    validate_project_name,
    validate_version_name,
)

# HTML dashboard shows exact counts/percentages plus a bounded sample of
# packages per risk category; the full list is available via JSON/Excel.
LICENSE_DASHBOARD_SAMPLE_PER_CATEGORY = 100

# ------------------------------------------------------------------
# Licenses
# ------------------------------------------------------------------


@bp.route("/licenses")
@auth_required
def licenses_report() -> ResponseReturnValue:
    """All licenses grouped by risk category.

    Supports ``format=json``, ``format=excel``, and
    ``format=html`` (default).
    """
    fmt = validate_format(request.args.get("format", "html"))
    internal_only = validate_boolean(request.args.get("internal_only", "true"))
    req = parse_pagination(request.args)
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list:
        return service.get_all_licenses(internal_only=internal_only, limit=limit, offset=offset)

    def count() -> int:
        return service.count_all_licenses(internal_only=internal_only)

    return render_paged_report(
        req=req,
        output_format=fmt,
        fetch_page=fetch_page,
        count=count,
        headers=["SPDX ID", "Name", "Risk Category", "Usage Count"],
        to_cells=lambda r: [r["spdx_id"], r["name"], r["risk_category"], r["usage_count"]],
        title=get_internal_title("Licenses", internal_only),
        base_url="/reports/licenses",
        params={"internal_only": internal_only},
        filename_stem="licenses",
        report_type="licenses",
        schema_url="/schemas/licenses",
        template="licenses.html",
        internal_only=internal_only,
    )


# ------------------------------------------------------------------
# License summary (per project version)
# ------------------------------------------------------------------


@bp.route("/license-summary")
@auth_required
def license_summary_report() -> ResponseReturnValue:
    """License BOM for a specific project version.

    Query params: ``project_name``, ``version_name``,
    ``project_group``.
    """
    project_name = validate_project_name(
        request.args.get("project_name", ""),
    )
    version_name = validate_version_name(
        request.args.get("version_name", ""),
    )
    project_group = validate_project_group(
        request.args.get("project_group"),
    )
    fmt = validate_format(
        request.args.get("format", "html"),
    )

    if not project_name or not version_name:
        return (
            jsonify(
                {
                    "error": ("project_name and version_name are required"),
                },
            ),
            400,
        )

    service = get_falkordb_service()
    summary = service.get_license_summary(
        project_name=project_name,
        version_name=version_name,
        project_group=project_group,
    )

    if fmt == "json":
        payload, fn = license_summary_json(summary, project_name, version_name)
        meta = {k: v for k, v in payload.items() if k != "licenses"}
        return stream_json_response(meta, iter(summary), fn, data_key="licenses")

    if fmt == "excel":
        _cols = ["project_group", "project_name", "version", "purl", "spdx_id", "license_name", "risk_category"]
        main_headers = ["Project Group", "Project Name", "Version", "PURL", "SPDX ID", "License Name", "Risk Category"]
        main_rows = [[r.get(c, "") for c in _cols] for r in summary]
        summary_rows: list[list[Any]] = [
            ["Project", project_name],
            ["Version", version_name],
            ["Total Licenses", len(summary)],
        ]
        sheets = [
            SheetSpec(title="License Summary", headers=main_headers, rows=main_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
        ]
        return stream_multi_sheet_workbook_response(sheets, "license-summary.xlsx")

    return render_template(
        "license_summary.html",
        title=(f"License Summary: {project_name} {version_name}"),
        project_name=project_name,
        version_name=version_name,
        summary=summary,
        generated_at=ts(),
        schema_url="/schemas/license-summary",
    )


# ------------------------------------------------------------------
# License dashboard
# ------------------------------------------------------------------


@bp.route("/license-dashboard")
@auth_required
def license_dashboard() -> ResponseReturnValue:
    """Licence compliance dashboard with counts by risk category.

    Query Parameters:
        format: 'html', 'json', or 'excel' (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        HTML dashboard, JSON, or Excel download.
    """
    fmt = validate_format(
        request.args.get("format", "html"),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    # Counts/percentages come from a fixed-size grouped aggregation; package
    # rows are streamed (JSON/Excel) or sampled (HTML) — the full set is never
    # materialised (PERF: aggregate-materialization ceiling).
    stats_data = service.get_license_risk_stats(internal_only=internal_only)
    categories = stats_data["categories"]

    def _row_page(offset: int, limit: int) -> list[dict]:
        return service.get_license_risk_rows(
            internal_only=internal_only, limit=limit, offset=offset
        )

    if fmt == "json":
        filename = "license_dashboard_internal.json" if internal_only else "license_dashboard.json"
        meta = {
            "report_type": "license-dashboard",
            "generated_at": ts(),
            "filter": "internal_only" if internal_only else "all",
        }
        stats = {
            "total_packages": stats_data["total_packages"],
            "categories": {
                k: {"count": v["count"], "pct": v["pct"]} for k, v in categories.items()
            },
        }
        # Stream package rows straight from the DB, page-by-page.
        dashboard_rows = (row for page in iterate_pages(_row_page) for row in page)
        resp = stream_json_response(meta, dashboard_rows, filename, stats=stats)
        resp.headers[TOTAL_COUNT_HEADER] = str(stats_data["total_packages"])
        return resp

    if fmt == "excel":
        main_headers = ["Risk Category", "PURL", "Project Name", "Version", "SPDX ID", "License Name"]
        filename = "license_dashboard_internal.xlsx" if internal_only else "license_dashboard.xlsx"
        main_rows = (
            [
                row["category"].replace("_", " "),
                row["purl"],
                row["project_name"],
                row["version_name"],
                row["spdx_id"],
                row["license_name"],
            ]
            for page in iterate_pages(_row_page)
            for row in page
        )
        summary_rows: list[list] = [
            ["Total Packages", stats_data["total_packages"]],
            ["Filter", "Internal Only" if internal_only else "All"],
        ]
        for cat_key, cat_data in categories.items():
            summary_rows.append(
                [cat_key.replace("_", " "), f"{cat_data['count']} ({cat_data['pct']}%)"]
            )
        sheets = [
            SheetSpec(title="License Dashboard", headers=main_headers, rows=main_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=iter(summary_rows)),
        ]
        resp = stream_multi_sheet_workbook_response(sheets, filename)
        resp.headers[TOTAL_COUNT_HEADER] = str(stats_data["total_packages"])
        return resp

    # HTML — exact counts/percentages from the aggregation plus a bounded
    # per-category sample of packages (the full list is only via JSON/Excel).
    categories_view: dict[str, dict] = {}
    for cat_key, cat_data in categories.items():
        sample = (
            service.get_license_risk_rows(
                internal_only=internal_only,
                limit=LICENSE_DASHBOARD_SAMPLE_PER_CATEGORY,
                offset=0,
                category=cat_key,
            )
            if cat_data["count"]
            else []
        )
        categories_view[cat_key] = {
            "count": cat_data["count"],
            "pct": cat_data["pct"],
            "packages": sample,
            "shown": len(sample),
            "truncated": cat_data["count"] > len(sample),
        }
    data = {
        "total_packages": stats_data["total_packages"],
        "categories": categories_view,
    }

    title = get_internal_title(
        "License Compliance Dashboard",
        internal_only,
    )
    base_url = "/reports/license-dashboard"

    return Response(
        render_template(
            "license_dashboard.html",
            title=title,
            internal_only=internal_only,
            data=data,
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
            schema_url="/schemas/license-dashboard",
        ),
        mimetype="text/html",
    )


# ------------------------------------------------------------------
# License conflicts
# ------------------------------------------------------------------


@bp.route("/license-conflicts")
@auth_required
def license_conflicts_report() -> ResponseReturnValue:
    """Projects mixing incompatible license categories."""
    fmt = validate_format(
        request.args.get("format", "html"),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only", "true"),
    )
    req = parse_pagination(request.args)
    service = get_falkordb_service()
    # Computed once via in-memory BFS (cannot be DB-paged); slice for HTML and
    # stream the SAME single computed list for JSON — no per-page recompute.
    conflicts = service.get_license_conflicts(
        internal_only=internal_only,
    )

    if fmt == "json":
        payload, fn = license_conflicts_json(conflicts, internal_only)
        meta = {k: v for k, v in payload.items() if k != "conflicts"}
        return stream_json_response(meta, iter(conflicts), fn, data_key="conflicts")

    total = len(conflicts)
    page = conflicts[req.offset : req.offset + req.page_size]
    pagination = build_page_view(
        req, total, "/reports/license-conflicts", {"internal_only": internal_only}
    )
    return render_template(
        "license_conflicts.html",
        title=get_internal_title(
            "License Conflicts",
            internal_only,
        ),
        conflicts=page,
        pagination=pagination,
        internal_only=internal_only,
        generated_at=ts(),
        schema_url="/schemas/license-conflicts",
    )


# ------------------------------------------------------------------
# Policy violations
# ------------------------------------------------------------------


@bp.route("/policy-violations")
@auth_required
def policy_violations() -> ResponseReturnValue:
    """Report showing all 'bad'-annotated packages still in use."""
    internal_only = validate_boolean(request.args.get("internal_only"))
    output_format = validate_format(request.args.get("format", "html"))
    req = parse_pagination(request.args)
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list:
        return service.get_policy_violations(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def count() -> int:
        return service.count_policy_violations(internal_only=internal_only)

    def to_cells(d: dict) -> list:
        return [
            d.get("purl", ""),
            d.get("project_name", ""),
            d.get("version_name", ""),
            d.get("justification", ""),
            d.get("created_by", ""),
            d.get("created_at") or "",
            d.get("dependant_count", 0),
        ]

    total_dependants = service.get_policy_violations_total_dependants(internal_only=internal_only)

    def stats_builder(total: int) -> dict:
        return {
            "Total Violations": total,
            "Total Affected Dependants": total_dependants,
        }

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=count,
        headers=[
            "PURL",
            "Project Name",
            "Version",
            "Justification",
            "Created By",
            "Created At",
            "Dependant Count",
        ],
        to_cells=to_cells,
        title=get_internal_title("Policy Violations", internal_only),
        base_url=url_for("reports.policy_violations"),
        params={"internal_only": internal_only},
        filename_stem="policy_violations",
        report_type="policy-violations",
        schema_url="/schemas/policy-violations",
        stats_builder=stats_builder,
        internal_only=internal_only,
        extra_context={"policy_admin_url": url_for("admin.policy_admin_page")},
    )
