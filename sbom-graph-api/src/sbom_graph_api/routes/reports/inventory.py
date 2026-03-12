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
    create_all_projects_excel,
    create_applications_excel,
    create_centrality_excel,
    create_source_impact_excel,
    excel_response,
)
from sbom_graph_api.exports.json_format import (
    applications_json,
    centrality_json,
    projects_json,
    source_impact_json,
    source_repos_json,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    TABLE_TEMPLATE,
    build_json_response,
    get_internal_title,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_format,
    validate_limit,
    validate_max_depth,
    validate_sort_order,
    validate_sort_param,
    validate_url,
)


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
def all_projects() -> Response:
    """Endpoint 5: Table view of all projects with versions.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        limit: Maximum number of results (default: 10000, max: 100000)
        internal_only: Set to 'true' to show only internal-labeled
            nodes (default: false)

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    limit = validate_limit(
        request.args.get("limit", type=int),
        10000,
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    projects = service.get_all_projects(limit, internal_only)
    unique_projects = len(
        {p["project_name"] for p in projects},
    )

    purls = [p["package_url"] for p in projects if p.get("package_url")]
    policy_map = service.get_policy_annotations_for_purls(purls) if purls else {}

    def _policy_badge(purl: str | None) -> Markup | str:
        if not purl:
            return ""
        ptype = policy_map.get(purl)
        if ptype == "bad":
            return Markup('<span class="policy-badge policy-badge-banned">Banned</span>')
        if ptype == "good":
            return Markup('<span class="policy-badge policy-badge-approved">Approved</span>')
        if ptype == "hold":
            return Markup('<span class="policy-badge policy-badge-deprecated">Deprecated</span>')
        return ""

    if output_format == "excel":
        filename = "internal_projects.xlsx" if internal_only else "all_projects.xlsx"
        buf = create_all_projects_excel(
            service,
            limit,
            internal_only,
        )
        return excel_response(buf, filename)

    if output_format == "json":
        policy_labels = {"bad": "banned", "good": "approved", "hold": "deprecated"}
        projects_with_policy = []
        for p in projects:
            purl = p.get("package_url")
            policy = policy_labels.get(policy_map[purl]) if purl and purl in policy_map else None
            projects_with_policy.append({**p, "policy": policy})
        data, fn = projects_json(
            projects_with_policy,
            unique_projects,
            internal_only,
        )
        return build_json_response(data, fn)

    # HTML table
    title = get_internal_title("Projects", internal_only)
    base_url = "/reports/projects"

    def _source_repo_cell(url: str | None) -> str | Markup:
        if not url:
            return ""
        escaped_url = escape(url)
        return Markup(f'<a href="{escaped_url}" target="_blank" rel="noopener">{escaped_url}</a>')

    html = render_template(
        TABLE_TEMPLATE,
        title=title,
        internal_only=internal_only,
        headers=[
            "Project Name",
            "Version",
            "Policy",
            "License",
            "License Risk",
            "Source Repo",
            "Direct Score",
            "Effective Score",
            "Confidence",
        ],
        data=[
            [
                p["project_name"],
                p["version"],
                _policy_badge(p.get("package_url")),
                p.get("spdx_id") or "",
                (p.get("risk_category") or "").replace("_", " ").title(),
                _source_repo_cell(p.get("source_repo_url")),
                _trust_score_cell(p.get("direct_score")),
                _trust_score_cell(p.get("effective_score")),
                _confidence_badge(p.get("confidence")),
            ]
            for p in projects
        ],
        stats={
            "Total Project Versions": len(projects),
            "Unique Projects": unique_projects,
        },
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            limit=limit,
            internal_only=internal_only,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            limit=limit,
            internal_only=internal_only,
        ),
        schema_url="/schemas/projects",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Applications
# ------------------------------------------------------------------


@bp.route("/applications")
@auth_required
def all_applications() -> Response:
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
    limit = validate_limit(
        request.args.get("limit", type=int),
        10000,
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    latest_only = validate_boolean(
        request.args.get("latest_only"),
    )

    service = get_falkordb_service()
    applications = service.get_all_applications(
        limit,
        internal_only,
        latest_only,
    )
    unique_apps = len(
        {a["project_name"] for a in applications},
    )

    if output_format == "excel":
        parts: list[str] = []
        if internal_only:
            parts.append("internal")
        if latest_only:
            parts.append("latest")
        parts.append("applications.xlsx")
        filename = "_".join(parts) if len(parts) > 1 else "applications.xlsx"
        buf = create_applications_excel(
            service,
            limit,
            internal_only,
            latest_only,
        )
        return excel_response(buf, filename)

    if output_format == "json":
        data, fn = applications_json(
            applications,
            unique_apps,
            internal_only,
            latest_only,
        )
        return build_json_response(data, fn)

    # HTML table
    title_parts: list[str] = []
    if internal_only:
        title_parts.append("Internal")
    if latest_only:
        title_parts.append("Latest")
    title_parts.append("Applications")
    title = " ".join(title_parts)

    base_url = "/reports/applications"

    table_data = []
    for app in applications:
        table_data.append(
            [
                app["project_name"],
                app["version"],
                app.get("scan_id") or "",
                app.get("public_id") or "",
                app.get("repo_url") or "",
                "Yes" if app.get("is_internal") else "No",
                app.get("spdx_id") or "",
                (app.get("risk_category") or "").replace("_", " ").title(),
                _trust_score_cell(app.get("direct_score")),
                _trust_score_cell(app.get("effective_score")),
                _confidence_badge(app.get("confidence")),
            ],
        )

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
            "License",
            "License Risk",
            "Direct Score",
            "Effective Score",
            "Confidence",
        ],
        data=table_data,
        stats={
            "Total Application Versions": len(applications),
            "Unique Applications": unique_apps,
            "Version Mode": ("Latest Only" if latest_only else "All Versions"),
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
            },
        ],
    )

    return Response(html, mimetype="text/html")


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
        buf = create_centrality_excel(cd)
        return excel_response(
            buf,
            "internal_centrality.xlsx",
        )

    if output_format == "json":
        payload, fn = centrality_json(
            cd,
            total_libs,
            total_in,
            total_out,
            max_in,
            max_out,
        )
        return build_json_response(payload, fn)

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
def source_repos() -> Response:
    """List all tracked source repositories.

    Query Parameters:
        format: 'json' to download (default: html)
        internal_only: Set to 'true' to show only
            internal-labeled nodes (default: false)
    """
    output_format = validate_format(
        request.args.get("format"),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    repos = service.get_all_source_repos(
        internal_only=internal_only,
    )

    if output_format == "json":
        payload, fn = source_repos_json(
            repos,
            internal_only,
        )
        return build_json_response(payload, fn)

    return Response(
        render_template(
            TABLE_TEMPLATE,
            title=get_internal_title(
                "Source Repositories",
                internal_only,
            ),
            internal_only=internal_only,
            headers=[
                "URL",
                "VCS Type",
                "Namespace",
                "Name",
                "Packages",
            ],
            data=[
                [
                    r.get("url", ""),
                    r.get("vcs_type", ""),
                    r.get("namespace", ""),
                    r.get("name", ""),
                    r.get("package_count", 0),
                ]
                for r in repos
            ],
            stats={"Total Repositories": len(repos)},
            json_url=build_url_with_params(
                "/reports/source-repos",
                format="json",
                internal_only=internal_only,
            ),
            schema_url="/schemas/source-repos",
        ),
        mimetype="text/html",
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
        return excel_response(buf, filename)

    if output_format == "json":
        data, fn = source_impact_json(impact, repo_url)
        return build_json_response(data, fn)

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

    from sbom_graph_api.visualizations.source_impact import (
        create_source_impact_graph,
    )

    graph_html = create_source_impact_graph(
        impact.get("graph_nodes", []),
        impact.get("graph_edges", []),
        height="600px",
        width="100%",
    )

    return Response(graph_html, mimetype="text/html")
