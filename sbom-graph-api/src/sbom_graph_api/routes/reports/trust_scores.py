"""Trust score reports: all trust scores, trust score gaps."""

from datetime import UTC, datetime

from flask import Response, abort, render_template, request
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
    validate_purl,
    validate_sort_param,
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


def _heatmap_cell(score: float | None) -> dict[str, str]:
    """Return cell data for heatmap: value and CSS class (heat-low/medium/high/na)."""
    if score is None:
        return {"value": "-", "css": "heat-na"}
    try:
        s = float(score)
    except (TypeError, ValueError):
        return {"value": "-", "css": "heat-na"}
    if s < 4:
        css = "heat-low"
    elif s < 7:
        css = "heat-medium"
    else:
        css = "heat-high"
    return {"value": f"{s:.1f}", "css": css}


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
    sort_by = validate_sort_param(
        request.args.get("sort_by"),
        allowed=frozenset({"effective_score", "direct_score"}),
        default="effective_score",
    )

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


@bp.route("/application-risk-dashboard")
@auth_required
def application_risk_dashboard() -> Response:
    """Display per-application supply-chain risk dashboard.

    Query Parameters:
        format: 'json' to return raw data (default: html)
        internal_only: 'true' to restrict to internal applications
        limit: Maximum applications (default: 100, max: 500)

    Returns:
        HTML dashboard or JSON with application risk data.
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    limit = validate_int_param(
        request.args.get("limit"),
        default=100,
        min_val=1,
        max_val=500,
    )

    service = get_falkordb_service()
    rows = service.get_application_risk_dashboard(
        internal_only=internal_only,
        limit=limit,
    )

    if output_format == "json":
        data = {
            "report_type": "application-risk-dashboard",
            "generated_at": datetime.now(UTC).isoformat(),
            "applications": rows,
            "count": len(rows),
            "internal_only": internal_only,
            "limit": limit,
        }
        return build_json_response(data, "application_risk_dashboard.json")

    title = get_internal_title("Application Risk Dashboard", internal_only)
    base_url = "/reports/application-risk-dashboard"
    json_url_full = (
        build_url_with_params(base_url, format="json", internal_only=internal_only)
        + f"&limit={limit}"
    )

    applications = []
    for r in rows:
        score = r.get("effective_score")
        if score is not None:
            try:
                s = float(score)
            except (TypeError, ValueError):
                s = None
        else:
            s = None
        if s is not None:
            if s < 4:
                score_css, score_badge, score_color = "score-low", "trust-score-low", "#d32f2f"
            elif s < 7:
                score_css, score_badge, score_color = "score-medium", "trust-score-medium", "#f57c00"
            else:
                score_css, score_badge, score_color = "score-high", "trust-score-high", "#388e3c"
            score_pct = min(100, (s / 10) * 100)
            score_display = f"{s:.1f}"
        else:
            score_css, score_badge, score_color = "", "trust-score-medium", "#757575"
            score_pct = 0
            score_display = "-"
        applications.append(
            {
                "name": r.get("project_name") or r.get("purl", "Unknown"),
                "effective_score": score_display,
                "score_css": score_css,
                "score_badge": score_badge,
                "score_color": score_color,
                "score_pct": score_pct,
                "direct_dep_count": r.get("direct_dep_count", 0),
                "transitive_dep_count": r.get("transitive_dep_count", 0),
            }
        )

    stats = {"Total Applications": len(rows), "Limit": limit}

    html = render_template(
        "application_risk_dashboard.html",
        title=title,
        internal_only=internal_only,
        applications=applications,
        stats=stats,
        json_url=json_url_full,
    )

    return Response(html, mimetype="text/html")


@bp.route("/risk-propagation-graph")
@auth_required
def risk_propagation_graph() -> Response:
    """Display risk propagation network graph using vis.js.

    Nodes are sized by fan-in (dependants count), colored by effective trust score.
    Fetches data from trust-score-distribution and remediation-priorities APIs.

    Query Parameters:
        internal_only: 'true' to restrict to internal packages (filter applied
            via API when available)
    """
    internal_only = validate_boolean(request.args.get("internal_only"))
    title = get_internal_title("Risk Propagation Graph", internal_only)
    api_base = "/api/v1"
    html = render_template(
        "risk_propagation_graph.html",
        title=title,
        internal_only=internal_only,
        api_base=api_base,
    )
    return Response(html, mimetype="text/html")


@bp.route("/risk-outliers")
@auth_required
def risk_outliers() -> Response:
    """Display packages with low score and high fan-in (risk outliers).

    Shows packages with effective_score < 4 that are dependencies of >= 3
    applications/packages.

    Query Parameters:
        format: 'json' to return raw data (default: html)
        min_dependents: Minimum dependants count (default: 3)
        limit: Maximum packages (default: 50, max: 200)
    """
    output_format = validate_format(request.args.get("format"))
    min_dependents = validate_int_param(
        request.args.get("min_dependents"),
        default=3,
        min_val=1,
        max_val=100,
    )
    limit = validate_int_param(
        request.args.get("limit"),
        default=50,
        min_val=1,
        max_val=200,
    )

    service = get_falkordb_service()
    rows = service.get_risk_outliers(
        min_dependents=min_dependents,
        limit=limit,
    )

    if output_format == "json":
        data = {
            "report_type": "risk-outliers",
            "generated_at": datetime.now(UTC).isoformat(),
            "outliers": rows,
            "count": len(rows),
            "min_dependents": min_dependents,
            "limit": limit,
        }
        return build_json_response(data, "risk_outliers.json")

    data = []
    for r in rows:
        score_cell = _trust_score_cell(r.get("effective_score"))
        data.append(
            {
                "package": r.get("project_name") or r.get("purl", ""),
                "version": r.get("version") or "-",
                "purl": r.get("purl", ""),
                "score_cell": score_cell,
                "dependants_count": r.get("dependents_count", 0),
            }
        )

    base_url = "/reports/risk-outliers"
    json_url_full = f"{base_url}?format=json&min_dependents={min_dependents}&limit={limit}"

    html = render_template(
        "risk_outliers.html",
        title="Risk Outliers",
        data=data,
        stats={
            "Packages": len(rows),
            "Min Dependants": min_dependents,
            "Limit": limit,
        },
        json_url=json_url_full,
    )

    return Response(html, mimetype="text/html")


@bp.route("/risk-path-explorer/<path:purl>")
@auth_required
def risk_path_explorer(purl: str) -> Response:
    """Display dependency risk paths for a package.

    Uses data from /api/v1/package/{purl}/trust-score/risk-path.

    Path Parameters:
        purl: Package URL (path parameter)

    Query Parameters:
        format: 'json' to return raw data (default: html)
        limit: Maximum risk paths (default: 10, max: 50)
    """
    if not validate_purl(purl):
        abort(400, "Invalid purl")

    output_format = validate_format(request.args.get("format"))
    limit = validate_int_param(
        request.args.get("limit"),
        default=10,
        min_val=1,
        max_val=50,
    )

    service = get_falkordb_service()
    score = service.get_trust_score_for_purl(purl)
    paths = service.get_trust_score_risk_path(purl, limit=limit)

    if output_format == "json":
        data = {
            "report_type": "risk-path-explorer",
            "purl": purl,
            "trust_score": score,
            "risk_path": paths,
            "count": len(paths),
        }
        return build_json_response(data, "risk_path.json")

    effective_score = score.get("effective_score") if score else None
    package_name = None
    if score and score.get("purl"):
        parts = str(score["purl"]).split("/")
        package_name = parts[-1] if parts else score["purl"]

    score_css = ""
    if effective_score is not None:
        try:
            s = float(effective_score)
            if s < 4:
                score_css = "trust-score-low"
            elif s < 7:
                score_css = "trust-score-medium"
            else:
                score_css = "trust-score-high"
        except (TypeError, ValueError):
            pass

    path_rows = []
    for p in paths:
        ds = p.get("direct_score")
        try:
            s = float(ds) if ds is not None else None
        except (TypeError, ValueError):
            s = None
        if s is not None:
            if s < 4:
                p_css = "low"
            elif s < 7:
                p_css = "medium"
            else:
                p_css = "high"
        else:
            p_css = "medium"
        path_rows.append(
            {
                "purl": p.get("purl", ""),
                "direct_score": f"{ds:.1f}" if ds is not None else None,
                "depth": p.get("depth"),
                "score_css": p_css,
            }
        )

    html = render_template(
        "risk_path_explorer.html",
        title="Risk Path Explorer",
        purl=purl,
        package_name=package_name or purl,
        effective_score=f"{effective_score:.1f}" if effective_score is not None else None,
        score_css=score_css,
        risk_paths=path_rows,
    )

    return Response(html, mimetype="text/html")


@bp.route("/whatif-simulator")
@auth_required
def whatif_simulator() -> Response:
    """Interactive what-if simulator for risk propagation impact.

    Form submits to /api/v1/analysis/risk-propagation-impact via JavaScript.
    Displays projected changes without page reload.
    """
    html = render_template(
        "whatif_simulator.html",
        title="What-If Simulator",
        api_base="/api/v1",
    )
    return Response(html, mimetype="text/html")


@bp.route("/trust-score-heatmap")
@auth_required
def trust_score_heatmap() -> Response:
    """Display trust scores as a colour-coded heatmap grid.

    Query Parameters:
        format: 'json' to return raw data (default: html)
        internal_only: 'true' to restrict to internal packages
        limit: Maximum packages (default: 200, max: 500)

    Returns:
        HTML heatmap table or JSON with category breakdowns.
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    limit = validate_int_param(
        request.args.get("limit"),
        default=200,
        min_val=1,
        max_val=500,
    )

    service = get_falkordb_service()
    rows = service.get_trust_scores_heatmap(
        internal_only=internal_only,
        limit=limit,
    )

    if output_format == "json":
        data = {
            "report_type": "trust-score-heatmap",
            "generated_at": datetime.now(UTC).isoformat(),
            "packages": rows,
            "count": len(rows),
            "internal_only": internal_only,
            "limit": limit,
        }
        return build_json_response(data, "trust_score_heatmap.json")

    title = get_internal_title("Trust Score Heatmap", internal_only)
    base_url = "/reports/trust-score-heatmap"
    json_url_full = (
        build_url_with_params(base_url, format="json", internal_only=internal_only)
        + f"&limit={limit}"
    )

    data = []
    for r in rows:
        cells = [
            _heatmap_cell(r.get("security_practices_score")),
            _heatmap_cell(r.get("vulnerability_profile_score")),
            _heatmap_cell(r.get("maintenance_health_score")),
            _heatmap_cell(r.get("supply_chain_hygiene_score")),
            _heatmap_cell(r.get("effective_score")),
        ]
        data.append(
            {
                "package": r.get("project_name") or r.get("purl", ""),
                "version": r.get("version") or "-",
                "cells": cells,
            }
        )

    stats = {
        "Total Packages": len(rows),
        "Limit": limit,
    }

    html = render_template(
        "trust_score_heatmap.html",
        title=title,
        internal_only=internal_only,
        data=data,
        stats=stats,
        json_url=json_url_full,
    )

    return Response(html, mimetype="text/html")
