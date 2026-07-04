"""Vulnerability reports: listing, dependants, freshness, VEX."""

from flask import (
    Response,
    jsonify,
    render_template,
    request,
    url_for,
)
from markupsafe import escape

from sbom_graph_api.exports.json_format import (
    enrichment_coverage_json,
    incident_response_json,
    vex_coverage_json,
    vulnerability_dependants_json,
)
from sbom_graph_api.exports.streaming import (
    SheetSpec,
    stream_json_response,
    stream_multi_sheet_workbook_response,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    _safe_int,
    get_internal_title,
    parse_pagination,
    render_paged_report,
    ts,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service, iterate_pages
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_defect_id,
    validate_defect_id_match_filter,
    validate_format,
    validate_max_depth,
    validate_vex_filter,
)
from sbom_graph_api.visualizations.blast_radius import create_blast_radius_graph

# ------------------------------------------------------------------
# All vulnerabilities
# ------------------------------------------------------------------


@bp.route("/vulnerabilities")
@auth_required
def all_vulnerabilities() -> Response | tuple[Response, int]:
    """Report of all vulnerabilities ordered by severity.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only
            internal-labeled nodes
        vex_filter: 'all' (default), 'hide_not_affected', or
            'under_investigation'
        defect_id_match: Optional defect id prefix or ``*`` glob
            (e.g. ``CVE-2024``, ``GHSA-*-abc``). Matched case-insensitively.

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))
    vex_filter = validate_vex_filter(request.args.get("vex_filter"))
    defect_id_match = validate_defect_id_match_filter(request.args.get("defect_id_match"))
    req = parse_pagination()
    service = get_falkordb_service()
    base_url = "/reports/vulnerabilities"
    params: dict = {
        "internal_only": internal_only,
        "vex_filter": vex_filter if vex_filter != "all" else None,
        "defect_id_match": defect_id_match,
    }
    title = get_internal_title("Vulnerabilities", internal_only)
    filename = "vulnerabilities_internal.xlsx" if internal_only else "vulnerabilities.xlsx"

    def fetch_page(offset: int, limit: int) -> list[dict]:
        return service.get_all_vulnerabilities_paged(
            internal_only, defect_id_match, vex_filter, offset=offset, limit=limit
        )

    def count() -> int:
        return service.count_all_vulnerabilities(internal_only, defect_id_match, vex_filter)

    def to_export_cells(v: dict) -> list:
        return [
            v.get("defect_id", ""),
            v.get("severity", ""),
            v.get("cvss_score", ""),
            v.get("title", ""),
            v.get("cwe_id", ""),
            v.get("published_date", ""),
            v.get("vex_status", ""),
            len(v.get("affected_versions", [])),
        ]

    export_headers = [
        "Defect ID", "Severity", "CVSS", "Title", "CWE", "Published", "VEX Status", "Affected Count"
    ]

    if output_format == "excel":
        _stats = service.get_vulnerability_summary_stats(internal_only, defect_id_match)
        sc = _stats.get("severity_counts", {})
        _total_v = _stats.get("total", 0)
        _with_vex = _stats.get("with_vex", 0)
        _vex_pct = round(_with_vex / _total_v * 100, 1) if _total_v else 0.0
        summary_rows = [
            ["Total Vulnerabilities", _total_v],
            ["Critical", sc.get("CRITICAL", 0)],
            ["High", sc.get("HIGH", 0)],
            ["Medium", sc.get("MEDIUM", 0)],
            ["Low", sc.get("LOW", 0)],
            ["VEX Coverage", f"{_vex_pct}%"],
        ]
        rows = (to_export_cells(r) for page in iterate_pages(fetch_page) for r in page)
        return stream_multi_sheet_workbook_response(
            [
                SheetSpec(title=title[:31] or "Vulnerabilities", headers=export_headers, rows=rows),
                SheetSpec(title="Summary", headers=["Metric", "Value"], rows=iter(summary_rows)),
            ],
            filename,
        )

    if output_format == "json":
        _stats = service.get_vulnerability_summary_stats(internal_only, defect_id_match)
        total_v = _stats["total"]
        severity_counts = _stats["severity_counts"]
        total_affected = _stats["total_affected"]
        with_vex = _stats["with_vex"]
        vex_coverage_pct = round(with_vex / total_v * 100, 1) if total_v else 0.0
        meta = {
            "report_type": "vulnerabilities",
            "generated_at": ts(),
            "filter": "internal_only" if internal_only else "all",
        }
        stats = {
            "total_vulnerabilities": total_v,
            "total_affected_versions": total_affected,
            "by_severity": severity_counts,
            "vex_coverage_pct": vex_coverage_pct,
        }
        fn = "vulnerabilities_internal.json" if internal_only else "vulnerabilities.json"
        json_rows = (r for page in iterate_pages(fetch_page) for r in page)
        return stream_json_response(meta, json_rows, fn, stats=stats)

    # HTML — paginated custom template
    def _stats_builder(total: int) -> dict:
        _s = service.get_vulnerability_summary_stats(internal_only, defect_id_match)
        _total = _safe_int(_s.get("total"), total)
        _with_vex = _safe_int(_s.get("with_vex"), 0)
        _vex_pct = round(_with_vex / _total * 100, 1) if _total else 0.0
        sc = _s.get("severity_counts", {})
        return {
            "Total Vulnerabilities": _total,
            "Total Affected Versions": _safe_int(_s.get("total_affected"), 0),
            "Critical": sc.get("CRITICAL", 0),
            "High": sc.get("HIGH", 0),
            "Medium": sc.get("MEDIUM", 0),
            "Low": sc.get("LOW", 0),
            "VEX Coverage": f"{_vex_pct}%",
        }

    def _page_ctx(page: list[dict]) -> dict:
        return {"vulnerabilities": page}

    return render_paged_report(
        req=req,
        output_format="html",
        fetch_page=fetch_page,
        count=count,
        headers=[],
        to_cells=lambda v: [],
        title=title,
        base_url=base_url,
        params=params,
        filename_stem="vulnerabilities_internal" if internal_only else "vulnerabilities",
        report_type="vulnerabilities",
        schema_url="/schemas/vulnerabilities",
        stats_builder=_stats_builder,
        template="vulnerabilities.html",
        internal_only=internal_only,
        extra_context={
            "vex_filter": vex_filter,
            "defect_id_match": defect_id_match or "",
            "excel_url": build_url_with_params(
                base_url,
                format="excel",
                internal_only=internal_only,
                vex_filter=vex_filter,
                defect_id_match=defect_id_match,
            ),
            "json_url": build_url_with_params(
                base_url,
                format="json",
                internal_only=internal_only,
                vex_filter=vex_filter,
                defect_id_match=defect_id_match,
            ),
        },
        page_context_fn=_page_ctx,
    )


# ------------------------------------------------------------------
# Vulnerability dependants
# ------------------------------------------------------------------


@bp.route("/vulnerability-dependants/<defect_id>")
@auth_required
def vulnerability_dependants(
    defect_id: str,
) -> Response | tuple[Response, int]:
    """Report of all dependants affected by a vulnerability.

    Path Parameters:
        defect_id: The vulnerability ID (e.g. CVE-2021-44228)

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        max_depth: Maximum traversal depth (default: 50)
        internal_only: Set to 'true' to show only
            internal-labeled nodes

    Returns:
        HTML table, Excel download, or JSON
    """
    if not validate_defect_id(defect_id):
        return jsonify({"error": "Invalid defect ID"}), 400

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()

    vuln = service.get_vulnerability_by_id(defect_id, internal_only=False)
    if not vuln:
        return Response(
            f"Vulnerability not found: {escape(defect_id)}",
            status=404,
        )

    deps = service.get_vulnerability_dependants(
        defect_id=defect_id,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    max_partition = max((d.get("partition", 0) for d in deps), default=0)
    unique_projects = len({d["project_name"] for d in deps})
    partition_counts: dict[int, int] = {}
    for dep in deps:
        p = dep.get("partition", 0)
        partition_counts[p] = partition_counts.get(p, 0) + 1

    if output_format == "excel":
        fn = f"vulnerability_dependants_{defect_id}.xlsx"
        main_headers = [
            "Partition",
            "Project Name",
            "Version",
            "Is Internal",
            "Affected Via (Project)",
            "Affected Via (Version)",
        ]
        main_rows = []
        for d in deps:
            affected_by = d.get("affected_by", [])
            main_rows.append(
                [
                    d.get("partition", 0),
                    d.get("project_name", ""),
                    d.get("version", ""),
                    "Yes" if d.get("is_internal") else "No",
                    ", ".join(a.get("project_name", "") for a in affected_by),
                    ", ".join(a.get("version", "") for a in affected_by),
                ]
            )
        vuln_rows = [
            ["ID", vuln.get("defect_id", "")],
            ["Severity", vuln.get("severity", "")],
            ["CVSS Score", vuln.get("cvss_score", 0)],
            ["Title", vuln.get("title", "")],
            ["CWE", vuln.get("cwe_id", "")],
            ["Published Date", vuln.get("published_date", "")],
            ["Description", vuln.get("description", "")],
        ]
        summary_rows: list[list] = [
            ["Total Dependants", len(deps)],
            ["Max Partition", max_partition],
            ["Unique Projects", unique_projects],
            ["Filter Mode", "Internal Only" if internal_only else "All"],
            ["By Partition", ""],
        ]
        for partition in sorted(partition_counts):
            summary_rows.append([f"Partition {partition}", partition_counts[partition]])
        sheets = [
            SheetSpec(title="Affected Dependants", headers=main_headers, rows=main_rows),
            SheetSpec(title="Vulnerability", headers=["Field", "Value"], rows=vuln_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
        ]
        return stream_multi_sheet_workbook_response(sheets, fn)

    if output_format == "json":
        payload, fn = vulnerability_dependants_json(
            vuln,
            deps,
            internal_only,
            defect_id,
            max_partition,
            unique_projects,
            partition_counts,
        )
        meta = {k: v for k, v in payload.items() if k != "dependants"}
        return stream_json_response(
            meta, iter(payload.get("dependants", [])), fn, data_key="dependants"
        )

    # HTML table
    title = f"Dependants Affected by {defect_id}"
    base_url = f"/reports/vulnerability-dependants/{defect_id}"

    html = render_template(
        "vulnerability_dependants.html",
        title=title,
        vulnerability=vuln,
        internal_only=internal_only,
        dependants=deps,
        stats={
            "Total Dependants": len(deps),
            "Max Partition": max_partition,
            "Unique Projects": unique_projects,
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
        schema_url="/schemas/vulnerability-dependants",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# Incident response
# ------------------------------------------------------------------


@bp.route("/incident-response/<defect_id>")
@auth_required
def incident_response(defect_id: str) -> Response | tuple[Response, int]:
    """Incident response page: blast radius graph and patch plan table.

    Path Parameters:
        defect_id: The vulnerability ID (e.g., CVE-2021-44228)

    Query Parameters:
        format: 'html', 'excel', or 'json' (default: html)
        internal_only: Set to 'true' for internal-labeled nodes only
        max_depth: Maximum traversal depth (default: 50)

    Returns:
        HTML page, Excel download, or JSON
    """
    if not validate_defect_id(defect_id):
        return jsonify({"error": "Invalid defect ID"}), 400

    output_format = validate_format(request.args.get("format"))
    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()

    vuln = service.get_vulnerability_by_id(defect_id, internal_only=False)
    if not vuln:
        return Response(
            f"Vulnerability not found: {escape(defect_id)}",
            status=404,
        )

    blast_radius = service.get_blast_radius(
        defect_id=defect_id,
        max_depth=max_depth or 50,
        internal_only=internal_only,
    )
    patch_plan = service.get_patch_plan(
        defect_id=defect_id,
        internal_only=internal_only,
    )

    base_url = f"/reports/incident-response/{defect_id}"

    if output_format == "excel":
        fn = f"incident_response_{defect_id}.xlsx"
        patch_headers = ["Package", "Version", "PURL", "Fix Version", "Severity"]
        blast_headers = ["Affected Application", "Partition"]

        def _patch_rows():
            for item in patch_plan:
                yield [
                    item.get("project_name", ""),
                    item.get("version_name", ""),
                    item.get("purl", ""),
                    item.get("fix_version", ""),
                    item.get("severity", ""),
                ]

        def _blast_rows():
            for app in blast_radius.get("affected_applications", []):
                if isinstance(app, dict):
                    yield [app.get("project_name", str(app)), app.get("partition", "")]
                else:
                    yield [str(app), ""]

        short_id = defect_id[:28]
        return stream_multi_sheet_workbook_response(
            [
                SheetSpec(title=f"Blast Radius - {short_id}", headers=blast_headers, rows=_blast_rows()),
                SheetSpec(title="Patch Plan", headers=patch_headers, rows=_patch_rows()),
            ],
            fn,
        )

    if output_format == "json":
        payload, fn = incident_response_json(defect_id, blast_radius, patch_plan, internal_only)
        meta = {k: v for k, v in payload.items() if k not in ("patch_plan",)}
        return stream_json_response(
            meta, iter(payload.get("patch_plan", [])), fn, data_key="patch_plan"
        )

    graph_url = (
        url_for("reports.incident_response_graph", defect_id=defect_id)
        + f"?max_depth={max_depth}"
        + ("&internal_only=true" if internal_only else "")
    )

    html = render_template(
        "incident_response.html",
        title=f"Incident Response: {defect_id}",
        defect_id=defect_id,
        vulnerability=vuln,
        blast_radius=blast_radius,
        patch_plan=patch_plan,
        internal_only=internal_only,
        graph_url=graph_url,
        stats={
            "Total Affected Packages": len(patch_plan),
            "Affected Applications": len(blast_radius.get("affected_applications", [])),
            "Blast Radius Depth": blast_radius.get("max_partition", 0),
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
        schema_url="/schemas/incident-response",
    )

    return Response(html, mimetype="text/html")


@bp.route("/incident-response/<defect_id>/graph")
@auth_required
def incident_response_graph(defect_id: str) -> Response | tuple[Response, int]:
    """Return the blast radius graph as standalone HTML for iframe embedding."""
    if not validate_defect_id(defect_id):
        return jsonify({"error": "Invalid defect ID"}), 400

    max_depth = validate_max_depth(request.args.get("max_depth", type=int))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    blast_radius = service.get_blast_radius(
        defect_id=defect_id,
        max_depth=max_depth or 50,
        internal_only=internal_only,
    )

    graph_html = create_blast_radius_graph(
        blast_radius.get("graph_nodes", []),
        blast_radius.get("graph_edges", []),
        height="600px",
        width="100%",
    )

    return Response(graph_html, mimetype="text/html")


# ------------------------------------------------------------------
# Vulnerability freshness
# ------------------------------------------------------------------


@bp.route("/vulnerability-freshness")
@auth_required
def vulnerability_freshness() -> Response | tuple[str | Response, int]:
    """Report showing enrichment freshness for all packages."""
    internal_only = validate_boolean(request.args.get("internal_only"))
    output_format = validate_format(request.args.get("format", "html"))
    req = parse_pagination(request.args)
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list:
        return service.get_vulnerability_freshness(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def count() -> int:
        return service.count_vulnerability_freshness(internal_only=internal_only)

    def to_cells(d: dict) -> list:
        return [
            d.get("project_group", ""),
            d.get("project_name", ""),
            d.get("version_name", ""),
            d.get("purl", ""),
            d.get("last_enriched_at") or "Never",
        ]

    def stats_builder(total: int) -> dict:
        return {"Total Packages": total}

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=count,
        headers=["Project Group", "Project Name", "Version", "PURL", "Last Enriched At"],
        to_cells=to_cells,
        title=get_internal_title("Vulnerability Enrichment Freshness", internal_only),
        base_url=url_for("reports.vulnerability_freshness"),
        params={"internal_only": internal_only},
        filename_stem="vulnerability_freshness",
        report_type="vulnerability-freshness",
        schema_url="/schemas/vulnerability-freshness",
        stats_builder=stats_builder,
        internal_only=internal_only,
    )


# ------------------------------------------------------------------
# Enrichment coverage
# ------------------------------------------------------------------


@bp.route("/enrichment-coverage")
@auth_required
def enrichment_coverage() -> Response:
    """Report showing enrichment coverage: recent vs stale vs never-scanned.

    Query Parameters:
        format: 'excel' or 'json' to download (default: html)
        internal_only: Set to 'true' to show only internal-labeled nodes

    Returns:
        HTML dashboard, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    base_url = "/reports/enrichment-coverage"

    if output_format == "excel":
        data = service.get_enrichment_coverage(internal_only)
        main_headers = ["PURL", "Project Name", "Version Name", "Last Enriched At", "Status"]
        fn = "enrichment_coverage_internal.xlsx" if internal_only else "enrichment_coverage.xlsx"
        main_rows = [
            [
                p.get("purl", ""),
                p.get("project_name", ""),
                p.get("version_name", ""),
                p.get("last_enriched_at", "") or "",
                p.get("status", ""),
            ]
            for p in data["packages"]
        ]
        summary_rows = [
            ["Total Packages", data.get("total", 0)],
            ["Recent", f"{data.get('recent', 0)} ({data.get('recent_pct', 0)}%)"],
            ["Stale", f"{data.get('stale', 0)} ({data.get('stale_pct', 0)}%)"],
            ["Never", f"{data.get('never', 0)} ({data.get('never_pct', 0)}%)"],
            ["Filter", "Internal Only" if internal_only else "All"],
        ]
        sheets = [
            SheetSpec(title="Enrichment Coverage", headers=main_headers, rows=main_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
        ]
        return stream_multi_sheet_workbook_response(sheets, fn)

    if output_format == "json":
        data = service.get_enrichment_coverage(internal_only)
        payload, fn = enrichment_coverage_json(data, internal_only)
        meta = {k: v for k, v in payload.items() if k != "packages"}
        return stream_json_response(
            meta, iter(data.get("packages", [])), fn, data_key="packages"
        )

    # HTML template — dashboard (bounded aggregate)
    data = service.get_enrichment_coverage(internal_only)
    title = get_internal_title("Enrichment Coverage", internal_only)

    html = render_template(
        "enrichment_coverage.html",
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
        schema_url="/schemas/enrichment-coverage",
    )

    return Response(html, mimetype="text/html")


# ------------------------------------------------------------------
# VEX coverage
# ------------------------------------------------------------------


@bp.route("/vex-coverage")
@auth_required
def vex_coverage() -> Response | tuple[str | Response, int]:
    """Report showing VEX coverage statistics."""
    internal_only = validate_boolean(request.args.get("internal_only"))
    output_format = validate_format(request.args.get("format", "html"))
    req = parse_pagination(request.args)
    service = get_falkordb_service()

    def fetch_page(offset: int, limit: int) -> list:
        return service.get_vulnerabilities_with_vex(
            internal_only=internal_only, limit=limit, offset=offset
        )

    def count() -> int:
        return service.count_vulnerabilities_with_vex(internal_only=internal_only)

    def to_cells(v: dict) -> list:
        return [
            v.get("defect_id", ""),
            v.get("severity", ""),
            (v.get("description", "")[:100] if v.get("description") else ""),
            v.get("vex_status") or "No VEX",
            v.get("vex_count", 0),
        ]

    if output_format == "json":
        coverage = service.get_vex_coverage(internal_only=internal_only)
        vulns = service.get_vulnerabilities_with_vex(internal_only=internal_only)
        payload, fn = vex_coverage_json(coverage, vulns, internal_only)
        meta = {k: v for k, v in payload.items() if k != "data"}
        return stream_json_response(meta, iter(vulns), fn)

    if output_format == "excel":
        vulns = service.get_vulnerabilities_with_vex(internal_only=internal_only)
        coverage = service.get_vex_coverage(internal_only=internal_only)
        main_headers = ["Defect ID", "Severity", "Description", "VEX Status", "VEX Statements"]
        main_rows = [to_cells(v) for v in vulns]
        summary_rows = [
            ["Total Vulnerabilities", coverage.get("total_vulnerabilities", 0)],
            ["With VEX", coverage.get("with_vex", 0)],
            ["Without VEX", coverage.get("without_vex", 0)],
            ["Coverage Percent", f"{coverage.get('coverage_percent', 0)}%"],
            ["Filter", "Internal Only" if internal_only else "All"],
        ]
        sheets = [
            SheetSpec(title="VEX Coverage", headers=main_headers, rows=main_rows),
            SheetSpec(title="Summary", headers=["Metric", "Value"], rows=summary_rows),
        ]
        return stream_multi_sheet_workbook_response(sheets, "vex_coverage.xlsx")

    coverage = service.get_vex_coverage(internal_only=internal_only)

    def stats_builder(total: int) -> dict:
        return {
            "Total Vulnerabilities": coverage.get("total_vulnerabilities", 0),
            "With VEX": coverage.get("with_vex", 0),
            "Without VEX": coverage.get("without_vex", 0),
            "Coverage": f"{coverage.get('coverage_percent', 0)}%",
        }

    return render_paged_report(
        req=req,
        output_format=output_format,
        fetch_page=fetch_page,
        count=count,
        headers=["Vulnerability", "Severity", "Description", "VEX Status", "VEX Statements"],
        to_cells=to_cells,
        title=get_internal_title("VEX Coverage", internal_only),
        base_url=url_for("reports.vex_coverage"),
        params={"internal_only": internal_only},
        filename_stem="vex_coverage",
        report_type="vex-coverage",
        schema_url="/schemas/vex-coverage",
        stats_builder=stats_builder,
        internal_only=internal_only,
    )
