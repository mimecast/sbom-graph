"""SBOM provenance reports: inventory, coverage."""

from urllib.parse import urlencode

from flask import Response, render_template, request

from sbom_graph_api.exports.streaming import (
    stream_json_response,
    stream_workbook_response,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    parse_pagination,
    render_paged_report,
    ts,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service, iterate_pages
from sbom_graph_api.utils.validation import (
    validate_boolean,
    validate_date_param,
    validate_format,
    validate_int_param,
    validate_sbom_format,
    validate_search_term,
)


def _build_sbom_inventory_url(base: str, **params) -> str:
    """Build URL with optional query params for SBOM inventory."""
    filtered = {k: v for k, v in params.items() if v is not None and v != ""}
    if not filtered:
        return base
    return f"{base}?{urlencode(filtered)}"


@bp.route("/sbom-inventory")
@auth_required
def sbom_inventory_report() -> Response | tuple[Response, int]:
    """List all ingested SBOM records with metadata.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        search: Substring filter for record_id, tool, or format
        tool: Exact tool name filter
        sbom_format: CycloneDX or SPDX
        date_from: Start date (YYYY-MM-DD)
        date_to: End date (YYYY-MM-DD)

    Returns:
        HTML table or JSON with record_id, format, ingested_at, source,
        tool_name, tool_version, serial_number, document_hash.
    """
    output_format = validate_format(request.args.get("format"))
    search = validate_search_term(request.args.get("search"))
    tool = validate_search_term(request.args.get("tool")) or None
    sbom_format = validate_sbom_format(request.args.get("sbom_format"))
    if sbom_format:
        sbom_format = "CycloneDX" if sbom_format == "cyclonedx" else "SPDX"
    date_from = validate_date_param(request.args.get("date_from"))
    date_to = validate_date_param(request.args.get("date_to"))

    service = get_falkordb_service()
    base = "/reports/sbom-inventory"
    url_params = {
        "search": search,
        "tool": tool,
        "sbom_format": sbom_format,
        "date_from": date_from,
        "date_to": date_to,
    }

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.get_sbom_inventory_paged(
            search=search,
            tool=tool,
            sbom_format=sbom_format,
            date_from=date_from,
            date_to=date_to,
            offset=offset,
            limit=limit,
        )

    def count() -> int:
        return service.count_sbom_inventory(
            search=search,
            tool=tool,
            sbom_format=sbom_format,
            date_from=date_from,
            date_to=date_to,
        )

    # Full-set aggregate for stats (one lightweight query, all formats need it).
    inv_summary = service.get_sbom_inventory_summary(
        search=search,
        tool=tool,
        sbom_format=sbom_format,
        date_from=date_from,
        date_to=date_to,
    )

    _export_headers = [
        "Record ID", "Format", "Tool", "Version",
        "Serial Number", "Ingested At", "Source", "Document Hash",
    ]

    def _to_export_row(r: dict) -> list:
        return [
            r.get("record_id", ""),
            r.get("format", ""),
            r.get("tool_name") or "-",
            r.get("tool_version") or "-",
            r.get("serial_number") or "-",
            r.get("ingested_at", ""),
            r.get("source", ""),
            r.get("document_hash") or "-",
        ]

    if output_format == "excel":
        rows = (
            _to_export_row(r)
            for page in iterate_pages(fetch_page)
            for r in page
        )
        return stream_workbook_response(
            _export_headers, rows, "sbom_inventory.xlsx", "SBOM Inventory"
        )

    if output_format == "json":
        meta = {
            "report_type": "sbom-inventory",
            "generated_at": ts(),
            "count": inv_summary["total"],
        }
        json_rows = (r for page in iterate_pages(fetch_page) for r in page)
        return stream_json_response(meta, json_rows, "sbom_inventory.json", data_key="inventory")

    # HTML — paginated
    req = parse_pagination()
    tools = service.get_sbom_inventory_tools(
        search=search,
        tool=tool,
        sbom_format=sbom_format,
        date_from=date_from,
        date_to=date_to,
    )
    excel_url = _build_sbom_inventory_url(base, format="excel", **url_params)
    json_url = _build_sbom_inventory_url(base, format="json", **url_params)

    def _inventory_stats_builder(total: int) -> dict:
        stats: dict = {"Total SBOMs": total}
        for fmt, cnt in sorted(inv_summary.get("by_format", {}).items()):
            stats[f"By Format ({fmt})"] = cnt
        for src, cnt in sorted(inv_summary.get("by_source", {}).items()):
            stats[f"By Source ({src})"] = cnt
        return stats

    return render_paged_report(
        req=req,
        output_format="html",
        fetch_page=fetch_page,
        count=count,
        headers=[],
        to_cells=lambda r: [],
        title="SBOM Inventory",
        base_url=base,
        params={k: v for k, v in url_params.items() if v},
        filename_stem="sbom_inventory",
        report_type="sbom-inventory",
        schema_url="/schemas/sbom-inventory",
        stats_builder=_inventory_stats_builder,
        template="sbom_inventory.html",
        page_context_fn=lambda page: {"rows": page},
        extra_context={
            "search": search,
            "tool": tool,
            "sbom_format": sbom_format,
            "date_from": date_from,
            "date_to": date_to,
            "tools": tools,
            "excel_url": excel_url,
            "json_url": json_url,
            "schema_url": "/schemas/sbom-inventory",
        },
    )


@bp.route("/coverage")
@auth_required
def sbom_coverage_report() -> Response:
    """Show SBOM coverage statistics and per-project details.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        recent_days: Days within which SBOM is considered fresh (default: 30)
        internal_only: 'true' to restrict to internal-labeled projects

    Returns:
        HTML dashboard or JSON with stats and per-version details.
    """
    output_format = validate_format(request.args.get("format"))
    recent_days = validate_int_param(
        request.args.get("recent_days"),
        default=30,
        min_val=1,
        max_val=365,
    )
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    data = service.get_sbom_coverage_for_dashboard(
        internal_only=internal_only,
        recent_days=recent_days,
    )

    base = "/reports/coverage"
    extra = {"internal_only": "true"} if internal_only else {}
    excel_params = {"format": "excel", "recent_days": recent_days, **extra}
    json_params = {"format": "json", "recent_days": recent_days, **extra}
    excel_url = _build_sbom_inventory_url(base, **excel_params)
    json_url = _build_sbom_inventory_url(base, **json_params)

    if output_format == "excel":
        headers = ["Project", "Version", "SBOM Status", "Last Ingested", "Tool"]
        filename = "sbom_coverage_internal.xlsx" if internal_only else "sbom_coverage.xlsx"

        def _rows():
            for p in data.get("projects", []):
                yield [
                    p.get("project_name", ""),
                    p.get("version_name", ""),
                    p.get("status", ""),
                    p.get("last_ingested", ""),
                    p.get("tool_name", ""),
                ]

        return stream_workbook_response(headers, _rows(), filename, "SBOM Coverage")

    if output_format == "json":
        meta = {
            "report_type": "sbom-coverage",
            "generated_at": ts(),
            "recent_days": recent_days,
            "internal_only": internal_only,
            "stats": data.get("stats", {}),
        }
        return stream_json_response(
            meta, iter(data.get("projects", [])), "sbom_coverage.json", data_key="projects"
        )

    title = "Internal SBOM Coverage" if internal_only else "SBOM Coverage"

    html = render_template(
        "sbom_coverage.html",
        title=title,
        data=data,
        internal_only=internal_only,
        excel_url=excel_url,
        json_url=json_url,
        schema_url="/schemas/sbom-coverage",
    )

    return Response(html, mimetype="text/html")
