"""Trust score reports: all trust scores, trust score gaps."""

from datetime import UTC, datetime

from flask import Response, render_template, request
from markupsafe import Markup

from sbom_graph_api.exports.excel import create_generic_excel
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import build_json_response, get_internal_title
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_float_param,
    validate_format,
    validate_int_param,
)


def _trust_score_cell(score: float | None) -> Markup | str:
    """Return HTML for a colour-coded trust score cell."""
    if score is None:
        return ""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s < 4:
        css = "trust-score-low"
    elif s < 7:
        css = "trust-score-medium"
    else:
        css = "trust-score-high"
    return Markup(f'<span class="trust-score {css}">{s:.1f}</span>')


def _confidence_badge(confidence: float | None) -> Markup | str:
    """Return HTML for a confidence percentage badge."""
    if confidence is None:
        return ""
    try:
        pct = float(confidence) * 100
    except (TypeError, ValueError):
        return ""
    return Markup(f'<span class="confidence-badge">{pct:.0f}%</span>')

# Map source IDs to human-readable missing factor labels
_SOURCE_LABELS: dict[str, str] = {
    "scorecard": "OpenSSF Scorecard",
    "osv": "Vulnerability scan (OSV)",
    "sonatype": "Sonatype OSS Index",
    "depsdev": "deps.dev",
}


def _missing_factors(sources_used: list[str] | None) -> list[str]:
    """Return human-readable labels for missing data sources."""
    if not sources_used:
        return [f"No {label}" for label in _SOURCE_LABELS.values()]
    used = frozenset(s.lower().strip() for s in sources_used)
    missing = []
    for sid, label in _SOURCE_LABELS.items():
        if sid not in used:
            missing.append(f"No {label}")
    return missing if missing else ["All sources present"]


def _recommendation(missing: list[str]) -> str:
    """Return a short recommendation based on missing factors."""
    if not missing or missing == ["All sources present"]:
        return "Data complete"
    if any("Vulnerability" in m or "OSV" in m for m in missing):
        return "Run vulnerability enrichment"
    if any("Scorecard" in m for m in missing):
        return "Link source repo for Scorecard"
    return "Add missing data sources"


@bp.route("/trust-scores")
@auth_required
def trust_scores_report() -> Response:
    """List all packages with trust score columns.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: 'true' to restrict to internal packages
        min_score: Minimum effective_score (default: 0.0, max: 10.0)
        sort_by: 'effective_score' or 'direct_score' (default: effective_score)

    Returns:
        HTML table, or JSON with purl, project_name, direct_score,
        effective_score, confidence, sources_used.
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    min_score = validate_float_param(
        request.args.get("min_score"),
        default=0.0,
        min_val=0.0,
        max_val=10.0,
    )
    sort_by_raw = request.args.get("sort_by", "effective_score")
    sort_by = "effective_score" if sort_by_raw == "effective_score" else "direct_score"

    service = get_falkordb_service()
    rows = service.get_all_trust_scores_for_report(
        internal_only=internal_only,
        min_score=min_score,
        sort_by=sort_by,
    )

    if output_format == "excel":
        excel_data = [
            {
                "PURL": r["purl"],
                "Project Name": r.get("project_name", ""),
                "Version": r.get("version", ""),
                "Direct Score": r["direct_score"],
                "Effective Score": r["effective_score"],
                "Confidence": r["confidence"],
                "Sources Used": ", ".join(r["sources_used"]) if r["sources_used"] else "-",
            }
            for r in rows
        ]
        filename = "internal_trust_scores.xlsx" if internal_only else "trust_scores.xlsx"
        return create_generic_excel(
            excel_data,
            columns=[
                "PURL",
                "Project Name",
                "Version",
                "Direct Score",
                "Effective Score",
                "Confidence",
                "Sources Used",
            ],
            sheet_name="Trust Scores",
            filename=filename,
        )

    if output_format == "json":
        data = {
            "report_type": "trust-scores",
            "generated_at": datetime.now(UTC).isoformat(),
            "trust_scores": rows,
            "count": len(rows),
            "internal_only": internal_only,
            "min_score": min_score,
            "sort_by": sort_by,
        }
        return build_json_response(data, "trust_scores.json")

    title = get_internal_title("Trust Scores", internal_only)
    base_url = "/reports/trust-scores"
    headers = [
        "Package",
        "Version",
        "Direct Score",
        "Effective Score",
        "Confidence",
        "Factors",
    ]

    # Compute stats
    ds_scores = [r["direct_score"] for r in rows if r.get("direct_score") is not None]
    es_scores = [r["effective_score"] for r in rows if r.get("effective_score") is not None]
    avg_direct = sum(ds_scores) / len(ds_scores) if ds_scores else 0
    avg_effective = sum(es_scores) / len(es_scores) if es_scores else 0
    low = sum(1 for s in es_scores if s < 4)
    medium = sum(1 for s in es_scores if 4 <= s < 7)
    high = sum(1 for s in es_scores if s >= 7)
    stats = {
        "Total Packages": len(rows),
        "Avg Direct Score": f"{avg_direct:.2f}" if ds_scores else "-",
        "Avg Effective Score": f"{avg_effective:.2f}" if es_scores else "-",
        "Distribution (Low/Med/High)": f"{low}/{medium}/{high}",
        "Min Score Filter": min_score,
        "Sort By": sort_by,
    }

    data_rows = [
        [
            r.get("project_name") or r.get("purl", ""),
            r.get("version") or "-",
            _trust_score_cell(r.get("direct_score")),
            _trust_score_cell(r.get("effective_score")),
            _confidence_badge(r.get("confidence")),
            ", ".join(r["sources_used"]) if r.get("sources_used") else "-",
        ]
        for r in rows
    ]

    excel_url_full = (
        build_url_with_params(base_url, format="excel", internal_only=internal_only)
        + f"&min_score={min_score}&sort_by={sort_by}"
    )
    json_url_full = (
        build_url_with_params(base_url, format="json", internal_only=internal_only)
        + f"&min_score={min_score}&sort_by={sort_by}"
    )

    html = render_template(
        "trust_scores.html",
        title=title,
        internal_only=internal_only,
        headers=headers,
        data=data_rows,
        stats=stats,
        excel_url=excel_url_full,
        json_url=json_url_full,
        schema_url="/schemas/trust-scores",
    )

    return Response(html, mimetype="text/html")


@bp.route("/trust-score-gaps")
@auth_required
def trust_score_gaps_report() -> Response:
    """List packages with low confidence (gaps in trust score data).

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        limit: Maximum packages to return (default: 20, max: 100)

    Returns:
        HTML table or JSON with purl, confidence, sources_used,
        direct_score, dependents_count.
    """
    output_format = validate_format(request.args.get("format"))
    limit = validate_int_param(
        request.args.get("limit"),
        default=20,
        min_val=1,
        max_val=100,
    )

    service = get_falkordb_service()
    rows = service.get_trust_score_gaps(limit=limit)

    if output_format == "excel":
        excel_data = []
        for r in rows:
            missing = _missing_factors(r.get("sources_used"))
            excel_data.append(
                {
                    "PURL": r["purl"],
                    "Package": r.get("project_name", ""),
                    "Version": r.get("version", ""),
                    "Confidence": r["confidence"],
                    "Missing Factors": "; ".join(missing),
                    "Recommendation": _recommendation(missing),
                    "Direct Score": r["direct_score"],
                    "Dependents Count": r["dependents_count"],
                }
            )
        return create_generic_excel(
            excel_data,
            columns=[
                "PURL",
                "Package",
                "Version",
                "Confidence",
                "Missing Factors",
                "Recommendation",
                "Direct Score",
                "Dependents Count",
            ],
            sheet_name="Trust Score Gaps",
            filename="trust_score_gaps.xlsx",
        )

    if output_format == "json":
        data = {
            "report_type": "trust-score-gaps",
            "generated_at": datetime.now(UTC).isoformat(),
            "gaps": rows,
            "count": len(rows),
            "limit": limit,
        }
        return build_json_response(data, "trust_score_gaps.json")

    headers = [
        "Package",
        "Version",
        "Confidence",
        "Missing Factors",
        "Recommendation",
    ]
    data_rows = []
    for r in rows:
        missing = _missing_factors(r.get("sources_used"))
        data_rows.append(
            [
                r.get("project_name") or r.get("purl", ""),
                r.get("version") or "-",
                _confidence_badge(r.get("confidence")),
                ", ".join(missing),
                _recommendation(missing),
            ]
        )

    html = render_template(
        "trust_score_gaps.html",
        title="Trust Score Gaps",
        headers=headers,
        data=data_rows,
        stats={
            "Packages with Low Confidence": len(rows),
            "Limit": limit,
        },
        excel_url=f"/reports/trust-score-gaps?format=excel&limit={limit}",
        json_url=f"/reports/trust-score-gaps?format=json&limit={limit}",
        schema_url="/schemas/trust-score-gaps",
    )

    return Response(html, mimetype="text/html")
