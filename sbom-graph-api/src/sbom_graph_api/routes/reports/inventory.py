"""Inventory reports: projects, applications, centrality, source repos."""

from html import escape
from urllib.parse import urlencode

from flask import (
    Response,
    jsonify,
    render_template,
    request,
)
from markupsafe import Markup

from sbom_graph_api.exports.excel import (
    create_source_impact_excel,
    excel_response,
)
from sbom_graph_api.exports.json_format import (
    centrality_json,
    source_impact_json,
)
from sbom_graph_api.exports.streaming import (
    SheetSpec,
    stream_json_response,
    stream_multi_sheet_workbook_response,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    build_json_response,
    get_internal_title,
    parse_pagination,
    render_paged_report,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_format,
    validate_limit,
    validate_max_depth,
    validate_search_term,
    validate_sort_order,
    validate_sort_param,
    validate_url,
)
from sbom_graph_api.visualizations.source_impact import create_source_impact_graph


def _trust_score_cell(score: float | None) -> Markup | str:
    """Return HTML for a colour-coded trust score cell (0-3 red, 4-6 amber, 7-10 green)."""
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


# ------------------------------------------------------------------
# Projects
# ------------------------------------------------------------------


@bp.route("/projects")
@auth_required
def all_projects() -> Response | tuple[Response, int]:
    """Endpoint 5: Paged table view of all projects with versions.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        page / page_size: Pagination (page_size 1..1000, default 100)
        all: 'true' to lift the total cap (exports stream the full set)
        limit: Legacy alias for page_size when page_size is absent
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        Paged HTML table, streamed Excel download, or streamed JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    name = validate_search_term(request.args.get("name"))
    req = parse_pagination()
    service = get_falkordb_service()

    policy_labels = {"bad": "banned", "good": "approved", "hold": "deprecated"}

    def _policy_badge(label: str | None) -> Markup | str:
        if label == "banned":
            return Markup('<span class="policy-badge policy-badge-banned">Banned</span>')
        if label == "approved":
            return Markup('<span class="policy-badge policy-badge-approved">Approved</span>')
        if label == "deprecated":
            return Markup('<span class="policy-badge policy-badge-deprecated">Deprecated</span>')
        return ""

    def _source_repo_cell(url: str | None) -> str | Markup:
        if not url:
            return ""
        escaped_url = escape(url)
        return Markup(f'<a href="{escaped_url}" target="_blank" rel="noopener">{escaped_url}</a>')

    def fetch_page(offset: int, limit: int) -> list[dict]:
        rows = service.get_all_projects(
            limit=limit, offset=offset, internal_only=internal_only, name=name
        )
        purls = [p["package_url"] for p in rows if p.get("package_url")]
        policy_map = service.get_policy_annotations_for_purls(purls) if purls else {}
        for p in rows:
            purl = p.get("package_url")
            p["policy"] = policy_labels.get(policy_map[purl]) if purl and purl in policy_map else None
        return rows

    def to_cells(p: dict) -> list:
        return [
            p["project_name"],
            p["version"],
            p.get("project_group") or "",
            p.get("package_url") or "",
            p.get("language") or "",
            _policy_badge(p.get("policy")),
            p.get("spdx_id") or "",
            (p.get("risk_category") or "").replace("_", " ").title(),
            _source_repo_cell(p.get("source_repo_url")),
            _trust_score_cell(p.get("direct_score")),
            _trust_score_cell(p.get("effective_score")),
            _confidence_badge(p.get("confidence")),
        ]

    def to_export_cells(p: dict) -> list:
        return [
            p["project_name"],
            p["version"],
            p.get("project_group") or "",
            p.get("package_url") or "",
            p.get("language") or "",
            p.get("policy") or "",
            p.get("spdx_id") or "",
            (p.get("risk_category") or "").replace("_", " ").title(),
            p.get("source_repo_url") or "",
            p.get("direct_score"),
            p.get("effective_score"),
            p.get("confidence"),
        ]

    def _unique() -> int | None:
        try:
            return int(service.count_unique_projects(internal_only, name=name))
        except (TypeError, ValueError):
            return None

    def stats_builder(total: int) -> dict:
        unique = _unique()
        return {
            "Total Project Versions": total,
            "Unique Projects": total if unique is None else unique,
        }

    def json_stats_builder(total: int) -> dict:
        unique = _unique()
        return {
            "total_project_versions": total,
            "unique_projects": total if unique is None else unique,
        }

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_all_projects(internal_only, name=name),
        headers=[
            "Project Name", "Version", "Group", "PURL", "Language", "Policy",
            "License", "License Risk", "Source Repo", "Direct Score",
            "Effective Score", "Confidence",
        ],
        to_cells=to_cells,
        to_export_cells=to_export_cells,
        title=get_internal_title("Projects", internal_only),
        base_url="/reports/projects",
        params={"internal_only": internal_only, "name": name},
        filename_stem="internal_projects" if internal_only else "all_projects",
        report_type="projects",
        schema_url="/schemas/projects",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        json_meta={"filter": "internal_only" if internal_only else "all"},
        internal_only=internal_only,
        extra_context={"show_name_search": True, "name_search": name},
    )


# ------------------------------------------------------------------
# Applications
# ------------------------------------------------------------------


@bp.route("/applications")
@auth_required
def all_applications() -> Response | tuple[Response, int]:
    """Report of all applications with their versions.

    Applications are nodes with the 'Application' label in the
    graph.  This report shows all applications with their metadata
    including scan IDs, app IDs, and repository URLs.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        limit: Maximum number of results (default: 10000,
            max: 100000)
        internal_only: Set to 'true' to show only internal-labeled
            nodes (default: false)
        latest_only: Set to 'true' to show only the latest version
            per application (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    latest_only = validate_boolean(request.args.get("latest_only"))
    name = validate_search_term(request.args.get("name"))
    req = parse_pagination()
    service = get_falkordb_service()
    base_url = "/reports/applications"

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.get_all_applications(
            limit=limit,
            internal_only=internal_only,
            latest_only=latest_only,
            offset=offset,
            name=name,
        )

    def to_cells(app: dict) -> list:
        return [
            app["project_name"],
            app["version"],
            app.get("project_group") or "",
            app.get("package_url") or "",
            app.get("language") or "",
            app.get("scan_id") or "",
            app.get("public_id") or "",
            app.get("repo_url") or "",
            "Yes" if app.get("is_internal") else "No",
            app.get("spdx_id") or "",
            (app.get("risk_category") or "").replace("_", " ").title(),
            _trust_score_cell(app.get("direct_score")),
            _trust_score_cell(app.get("effective_score")),
            _confidence_badge(app.get("confidence")),
        ]

    def to_export_cells(app: dict) -> list:
        return [
            app["project_name"],
            app["version"],
            app.get("project_group") or "",
            app.get("package_url") or "",
            app.get("language") or "",
            app.get("scan_id") or "",
            app.get("public_id") or "",
            app.get("repo_url") or "",
            "Yes" if app.get("is_internal") else "No",
            app.get("spdx_id") or "",
            (app.get("risk_category") or "").replace("_", " ").title(),
            app.get("direct_score"),
            app.get("effective_score"),
            app.get("confidence"),
        ]

    def _unique() -> int | None:
        try:
            return int(service.count_unique_applications(internal_only, name=name))
        except (TypeError, ValueError):
            return None

    def stats_builder(total: int) -> dict:
        unique = _unique()
        return {
            "Total Application Versions": total,
            "Unique Applications": total if unique is None else unique,
            "Version Mode": "Latest Only" if latest_only else "All Versions",
        }

    def json_stats_builder(total: int) -> dict:
        unique = _unique()
        return {
            "total_application_versions": total,
            "unique_applications": total if unique is None else unique,
        }

    title_parts: list[str] = []
    if internal_only:
        title_parts.append("Internal")
    if latest_only:
        title_parts.append("Latest")
    title_parts.append("Applications")

    stem_parts: list[str] = []
    if internal_only:
        stem_parts.append("internal")
    if latest_only:
        stem_parts.append("latest")
    stem_parts.append("applications")

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_all_applications(internal_only, latest_only, name=name),
        headers=[
            "Project Name", "Version", "Group", "PURL", "Language", "Scan ID",
            "Public ID", "Repo URL", "Is Internal", "License", "License Risk",
            "Direct Score", "Effective Score", "Confidence",
        ],
        to_cells=to_cells,
        to_export_cells=to_export_cells,
        title=" ".join(title_parts),
        base_url=base_url,
        params={"internal_only": internal_only, "latest_only": latest_only, "name": name},
        filename_stem="_".join(stem_parts),
        report_type="applications",
        schema_url="/schemas/applications",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        json_meta={
            "filter": "internal_only" if internal_only else "all",
            "version_mode": "latest_only" if latest_only else "all_versions",
        },
        extra_toggles=[
            {
                "name": "latest_only",
                "label": "Latest Only",
                "checked": latest_only,
                "url": build_url_with_params(
                    base_url,
                    internal_only=internal_only,
                    latest_only=not latest_only,
                ),
            },
        ],
        internal_only=internal_only,
        extra_context={"show_name_search": True, "name_search": name},
    )


# ------------------------------------------------------------------
# Duplicate / provenance-split Version nodes (Phase 3b diagnostic)
# ------------------------------------------------------------------


@bp.route("/duplicate-nodes")
@auth_required
def duplicate_nodes() -> Response | tuple[Response, int]:
    """Diagnostic report of duplicate / provenance-split Version nodes.

    Groups Version nodes by (project_name, version) and surfaces groups that
    either span multiple (project_group, package_url) coordinates (provenance
    splits — expected once purl is part of node identity) or have more than one
    node for a single coordinate (genuine duplicates — should not happen).

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        page / page_size: Pagination (page_size 1..1000, default 100)
        all: 'true' to lift the total cap (exports stream the full set)

    Returns:
        Paged HTML table, streamed Excel download, or streamed JSON
    """
    output_format = validate_format(request.args.get("format"))
    req = parse_pagination()
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.find_duplicate_version_nodes(limit=limit, offset=offset)

    def to_cells(r: dict) -> list:
        return [
            r["project_name"],
            r["version"],
            r["classification"],
            r["distinct_coordinates"],
            r["total_nodes"],
            r["max_node_count"],
            ", ".join(r.get("project_groups", [])),
            ", ".join(r.get("package_urls", [])),
        ]

    # Compute the KPI breakdown once (data-quality KPI, reporting-gap #2) and
    # reuse it across the HTML/JSON/Excel stats builders.
    dup_stats_cache: dict[str, dict] = {}

    def _dup_stats() -> dict:
        if "value" not in dup_stats_cache:
            dup_stats_cache["value"] = service.get_duplicate_node_stats()
        return dup_stats_cache["value"]

    def stats_builder(_total: int) -> dict:
        s = _dup_stats()
        return {
            "Affected Groups": s["affected_groups"],
            "Provenance Splits": s["provenance_splits"],
            "Genuine Duplicates": s["genuine_duplicates"],
        }

    def json_stats_builder(_total: int) -> dict:
        return _dup_stats()

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=service.count_duplicate_version_nodes,
        headers=[
            "Project Name", "Version", "Classification", "Distinct Coordinates",
            "Total Nodes", "Max Nodes / Coordinate", "Groups", "PURLs",
        ],
        to_cells=to_cells,
        title="Duplicate & Provenance-Split Version Nodes",
        base_url="/reports/duplicate-nodes",
        params={},
        filename_stem="duplicate_nodes",
        report_type="duplicate-nodes",
        schema_url="/schemas/duplicate-nodes",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
    )


# ------------------------------------------------------------------
# Centrality
# ------------------------------------------------------------------


@bp.route("/centrality")
@auth_required
def internal_centrality() -> Response:
    """Report of centrality metrics for internal libraries.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        sort_by: Field to sort by — 'inDegree' or 'outDegree'
            (default: inDegree)
        sort_order: Sort direction — 'asc' or 'desc'
            (default: desc)
        limit: Maximum number of results (default: 1000)

    Returns:
        HTML table with drill-down links, Excel download,
        or JSON
    """
    output_format = validate_format(request.args.get("format"))
    sort_by = validate_sort_param(
        request.args.get("sort_by"),
        allowed=frozenset({"indegree", "outdegree", "project_name", "version_name"}),
        default="indegree",
    )
    _CENTRALITY_FIELD_MAP = {"indegree": "inDegree", "outdegree": "outDegree"}
    sort_by = _CENTRALITY_FIELD_MAP.get(sort_by, sort_by)
    sort_order = validate_sort_order(request.args.get("sort_order"))
    limit = validate_limit(
        request.args.get("limit", type=int),
        1000,
    )

    service = get_falkordb_service()
    cd = service.get_internal_centrality(
        sort_by=sort_by,
        sort_order=sort_order,
        limit=limit,
    )

    total_libs = len(cd)
    total_in = sum(d.get("inDegree", 0) for d in cd)
    total_out = sum(d.get("outDegree", 0) for d in cd)
    max_in = max(
        (d.get("inDegree", 0) for d in cd),
        default=0,
    )
    max_out = max(
        (d.get("outDegree", 0) for d in cd),
        default=0,
    )

    if output_format == "excel":
        _headers = ["Project Name", "Version", "In-Degree", "Out-Degree", "PURL"]

        def _rows():
            for item in cd:
                yield [
                    item.get("project_name", ""),
                    item.get("version_name", ""),
                    item.get("inDegree", 0),
                    item.get("outDegree", 0),
                    item.get("purl", ""),
                ]

        summary_rows = [
            ["Total Internal Libraries", total_libs],
            ["Max In-Degree", max_in],
            ["Max Out-Degree", max_out],
        ]
        return stream_multi_sheet_workbook_response(
            [
                SheetSpec(title="Centrality", headers=_headers, rows=_rows()),
                SheetSpec(title="Summary", headers=["Metric", "Value"], rows=iter(summary_rows)),
            ],
            "internal_centrality.xlsx",
        )

    if output_format == "json":
        payload, fn = centrality_json(cd, total_libs, total_in, total_out, max_in, max_out)
        meta = {k: v for k, v in payload.items() if k != "data"}
        return stream_json_response(meta, iter(cd), fn)

    # HTML
    base_url = "/reports/centrality"
    opposite = "asc" if sort_order == "desc" else "desc"

    def _sort_url(col: str, default_order: str) -> str:
        order = default_order if sort_by != col else opposite
        return f"{base_url}?sort_by={col}&sort_order={order}&limit={limit}"

    sort_urls = {
        "inDegree": _sort_url("inDegree", "desc"),
        "outDegree": _sort_url("outDegree", "desc"),
        "project_name": _sort_url("project_name", "asc"),
        "version_name": _sort_url("version_name", "asc"),
    }

    excel_url = f"{base_url}?format=excel&sort_by={sort_by}&sort_order={sort_order}&limit={limit}"
    json_url = f"{base_url}?format=json&sort_by={sort_by}&sort_order={sort_order}&limit={limit}"

    html = render_template(
        "centrality.html",
        title="Internal Library Centrality",
        centrality_data=cd,
        stats={
            "Total Internal Libraries": total_libs,
            "Total Inward Connections": total_in,
            "Total Outward Connections": total_out,
            "Max inDegree": max_in,
            "Max outDegree": max_out,
        },
        sort_by=sort_by,
        sort_order=sort_order,
        sort_urls=sort_urls,
        excel_url=excel_url,
        json_url=json_url,
        schema_url="/schemas/centrality",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Source Repositories
# ------------------------------------------------------------------


@bp.route("/source-repos")
@auth_required
def source_repos() -> Response | tuple[Response, int]:
    """List all tracked source repositories.

    Query Parameters:
        format: 'json' to download (default: html)
        internal_only: Set to 'true' to show only
            internal-labeled nodes (default: false)
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination()
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.get_all_source_repos(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def to_cells(r: dict) -> list:
        return [
            r.get("url", ""),
            r.get("vcs_type", ""),
            r.get("namespace", ""),
            r.get("name", ""),
            r.get("package_count", 0),
        ]

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_source_repos(internal_only),
        headers=["URL", "VCS Type", "Namespace", "Name", "Packages"],
        to_cells=to_cells,
        title=get_internal_title("Source Repositories", internal_only),
        base_url="/reports/source-repos",
        params={"internal_only": internal_only},
        filename_stem="source_repositories",
        report_type="source-repos",
        schema_url="/schemas/source-repos",
        stats_builder=lambda total: {"Total Repositories": total},
        json_stats_builder=lambda total: {"total_repositories": total},
        json_meta={"filter": "internal_only" if internal_only else "all"},
        internal_only=internal_only,
    )


# ------------------------------------------------------------------
# Source Impact
# ------------------------------------------------------------------


@bp.route("/source-impact")
@auth_required
def source_impact() -> Response | tuple[Response, int]:
    """Source Impact report: packages from a repo and downstream consumers.

    Query Parameters:
        repo_url: Source repository URL (required)
        format: html, excel, or json (default: html)
        internal_only: Set to 'true' for internal-only (default: false)
        max_depth: Max traversal depth for dependants (default: 50)

    Returns:
        HTML report, Excel, or JSON
    """
    repo_url = validate_url(request.args.get("repo_url"))
    if not repo_url:
        return jsonify({"error": "Missing or invalid repo_url parameter"}), 400

    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    max_depth = (
        validate_max_depth(
            request.args.get("max_depth", type=int),
            50,
        )
        or 50
    )

    service = get_falkordb_service()
    impact = service.get_source_repo_impact(
        repo_url=repo_url,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    if output_format == "excel":
        buf = create_source_impact_excel(impact, repo_url)
        safe_name = repo_url.replace("/", "_").replace(":", "_")[:80]
        filename = f"{safe_name}_source_impact.xlsx"
        return excel_response(buf, filename)  # bounded per repo

    if output_format == "json":
        data, fn = source_impact_json(impact, repo_url)
        return build_json_response(data, fn)  # bounded per repo

    # HTML
    base_url = "/reports/source-impact"
    params = {
        "repo_url": repo_url,
        "internal_only": "true" if internal_only else "false",
        "max_depth": str(max_depth),
    }
    excel_url = f"{base_url}?{urlencode({**params, 'format': 'excel'})}"
    json_url = f"{base_url}?{urlencode({**params, 'format': 'json'})}"
    graph_url = f"{base_url}/graph?{urlencode(params)}"

    return Response(
        render_template(
            "source_impact.html",
            title="Source Impact",
            repo_url=repo_url,
            packages=impact.get("packages", []),
            stats=impact.get("stats", {}),
            internal_only=internal_only,
            graph_url=graph_url,
            excel_url=excel_url,
            json_url=json_url,
            schema_url="/schemas/source-impact",
        ),
        mimetype="text/html",
    )


@bp.route("/source-impact/graph")
@auth_required
def source_impact_graph() -> Response | tuple[Response, int]:
    """Return the source impact graph as standalone HTML for iframe embedding."""
    repo_url = validate_url(request.args.get("repo_url"))
    if not repo_url:
        return jsonify({"error": "Missing or invalid repo_url parameter"}), 400

    internal_only = validate_boolean(request.args.get("internal_only"))
    max_depth = (
        validate_max_depth(
            request.args.get("max_depth", type=int),
            50,
        )
        or 50
    )

    service = get_falkordb_service()
    impact = service.get_source_repo_impact(
        repo_url=repo_url,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    graph_html = create_source_impact_graph(
        impact.get("graph_nodes", []),
        impact.get("graph_edges", []),
        height="600px",
        width="100%",
    )

    return Response(graph_html, mimetype="text/html")


# ------------------------------------------------------------------
# Ecosystem breakdown (Phase 7 gap #3)
# ------------------------------------------------------------------


@bp.route("/ecosystem-breakdown")
@auth_required
def ecosystem_breakdown() -> Response | tuple[Response, int]:
    """Component counts per purl ecosystem (package type).

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
        return service.get_ecosystem_breakdown(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def to_cells(r: dict) -> list:
        return [
            r["ecosystem"],
            r["language"],
            r["components"],
            r["projects"],
            f"{r['pct']}%",
        ]

    def stats_builder(total: int) -> dict:
        return {"Ecosystems": total}

    def json_stats_builder(total: int) -> dict:
        return {"ecosystems": total}

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: service.count_ecosystems(internal_only=internal_only),
        headers=["Ecosystem", "Language", "Components", "Distinct Projects", "% of Components"],
        to_cells=to_cells,
        title=get_internal_title("Ecosystem Breakdown", internal_only),
        base_url="/reports/ecosystem-breakdown",
        params={"internal_only": "true"} if internal_only else {},
        filename_stem="ecosystem_breakdown",
        report_type="ecosystem-breakdown",
        schema_url="/schemas/ecosystem-breakdown",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        internal_only=internal_only,
    )


# ------------------------------------------------------------------
# purl-identity coverage (Phase 7 gap #6)
# ------------------------------------------------------------------


@bp.route("/purl-coverage")
@auth_required
def purl_coverage() -> Response | tuple[Response, int]:
    """purl node-identity rollout coverage over Version nodes.

    Shows how many Version nodes carry a ``package_url`` (participating in the
    Phase 3a purl identity) versus the fallback name/group bucket.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: 'true' to restrict to internal-labeled nodes

    Returns:
        Paged HTML table, streamed Excel download, or streamed JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    req = parse_pagination()
    service = get_falkordb_service()

    coverage = service.get_purl_coverage(internal_only=internal_only)
    total = coverage["total"]

    def _pct(n: int) -> float:
        return round(n / total * 100, 1) if total else 0.0

    bucket_rows = [
        {
            "bucket": "With package_url (purl identity)",
            "count": coverage["with_purl"],
            "pct": _pct(coverage["with_purl"]),
        },
        {
            "bucket": "Fallback (no package_url)",
            "count": coverage["without_purl"],
            "pct": _pct(coverage["without_purl"]),
        },
    ]

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return bucket_rows[offset : offset + limit]

    def to_cells(r: dict) -> list:
        return [r["bucket"], r["count"], f"{r['pct']}%"]

    def stats_builder(_total: int) -> dict:
        return {
            "Total Version Nodes": total,
            "With PURL": coverage["with_purl"],
            "Coverage": f"{_pct(coverage['with_purl'])}%",
        }

    def json_stats_builder(_total: int) -> dict:
        return {
            "total": total,
            "with_purl": coverage["with_purl"],
            "without_purl": coverage["without_purl"],
            "coverage_pct": _pct(coverage["with_purl"]),
        }

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=lambda: len(bucket_rows),
        headers=["Bucket", "Version Nodes", "% of Total"],
        to_cells=to_cells,
        title=get_internal_title("PURL Identity Coverage", internal_only),
        base_url="/reports/purl-coverage",
        params={"internal_only": "true"} if internal_only else {},
        filename_stem="purl_coverage",
        report_type="purl-coverage",
        schema_url="/schemas/purl-coverage",
        stats_builder=stats_builder,
        json_stats_builder=json_stats_builder,
        internal_only=internal_only,
    )
