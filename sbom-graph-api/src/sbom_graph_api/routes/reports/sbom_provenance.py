"""SBOM provenance reports: inventory, coverage."""

from datetime import UTC, datetime
from urllib.parse import urlencode

from flask import Response, render_template, request

from sbom_graph_api.exports.excel import create_generic_excel
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import build_json_response
from sbom_graph_api.services.falkordb_service import get_falkordb_service
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
def sbom_inventory_report() -> Response:
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
    rows = service.get_sbom_inventory(
        search=search,
        tool=tool,
        sbom_format=sbom_format,
        date_from=date_from,
        date_to=date_to,
    )

    base = "/reports/sbom-inventory"
    url_params = {
        "search": search,
        "tool": tool,
        "sbom_format": sbom_format,
        "date_from": date_from,
        "date_to": date_to,
    }

    if output_format == "excel":
        excel_data = [
            {
                "Record ID": r["record_id"],
                "Format": r["format"],
                "Tool": r["tool_name"] or "-",
                "Version": r["tool_version"] or "-",
                "Serial Number": r["serial_number"] or "-",
                "Ingested At": r["ingested_at"],
                "Source": r["source"],
                "Document Hash": r["document_hash"] or "-",
            }
            for r in rows
        ]
        return create_generic_excel(
            excel_data,
            columns=[
                "Record ID",
                "Format",
                "Tool",
                "Version",
                "Serial Number",
                "Ingested At",
                "Source",
                "Document Hash",
            ],
            sheet_name="SBOM Inventory",
            filename="sbom_inventory.xlsx",
        )

    if output_format == "json":
        data = {
            "report_type": "sbom-inventory",
            "generated_at": datetime.now(UTC).isoformat(),
            "inventory": rows,
            "count": len(rows),
        }
        return build_json_response(data, "sbom_inventory.json")

    # Stats: Total, By Format, By Source
    format_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for r in rows:
        fmt = r.get("format") or "Unknown"
        format_counts[fmt] = format_counts.get(fmt, 0) + 1
        src = r.get("source") or "Unknown"
        source_counts[src] = source_counts.get(src, 0) + 1

    stats = {"Total SBOMs": len(rows)}
    for fmt, cnt in sorted(format_counts.items()):
        stats[f"By Format ({fmt})"] = cnt
    for src, cnt in sorted(source_counts.items()):
        stats[f"By Source ({src})"] = cnt

    tools = sorted({r["tool_name"] for r in rows if r.get("tool_name")})

    excel_url = _build_sbom_inventory_url(
        base, format="excel", **url_params
    )
    json_url = _build_sbom_inventory_url(base, format="json", **url_params)

    html = render_template(
        "sbom_inventory.html",
        title="SBOM Inventory",
        rows=rows,
        stats=stats,
        tools=tools,
        search=search,
        tool=tool,
        sbom_format=sbom_format,
        date_from=date_from,
        date_to=date_to,
        excel_url=excel_url,
        json_url=json_url,
        schema_url="/schemas/sbom-inventory",
    )

    return Response(html, mimetype="text/html")


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
        excel_data = [
            {
                "Project": p["project_name"],
                "Version": p["version_name"],
                "SBOM Status": p["status"],
                "Last Ingested": p["last_ingested"],
                "Tool": p["tool_name"],
            }
            for p in data["projects"]
        ]
        filename = (
            "sbom_coverage_internal.xlsx"
            if internal_only
            else "sbom_coverage.xlsx"
        )
        return create_generic_excel(
            excel_data,
            columns=["Project", "Version", "SBOM Status", "Last Ingested", "Tool"],
            sheet_name="SBOM Coverage",
            filename=filename,
        )

    if output_format == "json":
        payload = {
            "report_type": "sbom-coverage",
            "generated_at": datetime.now(UTC).isoformat(),
            "coverage": data,
            "recent_days": recent_days,
            "internal_only": internal_only,
        }
        return build_json_response(payload, "sbom_coverage.json")

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
