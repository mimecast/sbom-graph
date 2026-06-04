"""Vulnerability reports: listing, dependants, freshness, VEX."""

from flask import (
    Response,
    jsonify,
    render_template,
    request,
    url_for,
)
from markupsafe import escape

from sbom_graph_api.exports.excel import (
    create_generic_excel,
    create_incident_response_excel,
    create_vulnerabilities_excel,
    create_vulnerability_dependants_excel,
    excel_response,
)
from sbom_graph_api.exports.json_format import (
    enrichment_coverage_json,
    incident_response_json,
    vex_coverage_json,
    vulnerabilities_json,
    vulnerability_dependants_json,
    vulnerability_freshness_json,
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
    validate_defect_id,
    validate_defect_id_match_filter,
    validate_format,
    validate_max_depth,
    validate_vex_filter,
)

# ------------------------------------------------------------------
# All vulnerabilities
# ------------------------------------------------------------------


@bp.route("/vulnerabilities")
@auth_required
def all_vulnerabilities() -> Response:
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
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    vex_filter = validate_vex_filter(request.args.get("vex_filter"))
    defect_id_match = validate_defect_id_match_filter(
        request.args.get("defect_id_match"),
    )

    service = get_falkordb_service()
    vulns = service.get_all_vulnerabilities(
        internal_only,
        defect_id_match,
    )

    # VEX coverage: count vulnerabilities with VEX vs total (before filter)
    with_vex = sum(1 for v in vulns if v.get("vex_status"))
    vex_coverage_pct = round(with_vex / len(vulns) * 100, 1) if vulns else 0.0

    # Apply VEX filter
    if vex_filter == "hide_not_affected":
        vulns = [v for v in vulns if v.get("vex_status") != "not_affected"]
    elif vex_filter == "under_investigation":
        vulns = [v for v in vulns if v.get("vex_status") == "under_investigation"]

    severity_counts: dict[str, int] = {}
    total_affected = 0
    for vuln in vulns:
        sev = vuln.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_affected += len(
            vuln.get("affected_versions", []),
        )

    if output_format == "excel":
        buf = create_vulnerabilities_excel(
            vulns,
            internal_only,
        )
        filename = "vulnerabilities_internal.xlsx" if internal_only else "vulnerabilities.xlsx"
        return excel_response(buf, filename)

    if output_format == "json":
        payload, fn = vulnerabilities_json(
            vulns,
            internal_only,
            severity_counts,
            total_affected,
        )
        return build_json_response(payload, fn)

    # HTML table with clickable links
    title = get_internal_title(
        "Vulnerabilities",
        internal_only,
    )
    base_url = "/reports/vulnerabilities"

    stats = {
        "Total Vulnerabilities": len(vulns),
        "Total Affected Versions": total_affected,
        "Critical": severity_counts.get("CRITICAL", 0),
        "High": severity_counts.get("HIGH", 0),
        "Medium": severity_counts.get("MEDIUM", 0),
        "Low": severity_counts.get("LOW", 0),
        "VEX Coverage": f"{vex_coverage_pct}%",
    }

    html = render_template(
        "vulnerabilities.html",
        title=title,
        internal_only=internal_only,
        vulnerabilities=vulns,
        stats=stats,
        vex_filter=vex_filter,
        defect_id_match=defect_id_match or "",
        excel_url=build_url_with_params(
            base_url,
            format="excel",
            internal_only=internal_only,
            vex_filter=vex_filter,
            defect_id_match=defect_id_match,
        ),
        json_url=build_url_with_params(
            base_url,
            format="json",
            internal_only=internal_only,
            vex_filter=vex_filter,
            defect_id_match=defect_id_match,
        ),
        schema_url="/schemas/vulnerabilities",
    )

    return Response(html, mimetype="text/html")


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
    max_depth = validate_max_depth(
        request.args.get("max_depth", type=int),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()

    vuln = service.get_vulnerability_by_id(
        defect_id,
        internal_only=False,
    )
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

    max_partition = max(
        (d.get("partition", 0) for d in deps),
        default=0,
    )
    unique_projects = len(
        {d["project_name"] for d in deps},
    )
    partition_counts: dict[int, int] = {}
    for dep in deps:
        p = dep.get("partition", 0)
        partition_counts[p] = partition_counts.get(p, 0) + 1

    if output_format == "excel":
        buf = create_vulnerability_dependants_excel(
            vuln,
            deps,
            internal_only,
        )
        fn = f"vulnerability_dependants_{defect_id}.xlsx"
        return excel_response(buf, fn)

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
        return build_json_response(payload, fn)

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
    max_depth = validate_max_depth(
        request.args.get("max_depth", type=int),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()

    vuln = service.get_vulnerability_by_id(
        defect_id,
        internal_only=False,
    )
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
        buf = create_incident_response_excel(
            defect_id,
            blast_radius,
            patch_plan,
            internal_only,
        )
        fn = f"incident_response_{defect_id}.xlsx"
        return excel_response(buf, fn)

    if output_format == "json":
        payload, fn = incident_response_json(
            defect_id,
            blast_radius,
            patch_plan,
            internal_only,
        )
        return build_json_response(payload, fn)

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
            "Affected Applications": len(
                blast_radius.get("affected_applications", []),
            ),
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

    max_depth = validate_max_depth(
        request.args.get("max_depth", type=int),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    blast_radius = service.get_blast_radius(
        defect_id=defect_id,
        max_depth=max_depth or 50,
        internal_only=internal_only,
    )

    from sbom_graph_api.visualizations.blast_radius import (
        create_blast_radius_graph,
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
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    output_format = validate_format(
        request.args.get("format", "html"),
    )

    service = get_falkordb_service()
    data = service.get_vulnerability_freshness(
        internal_only=internal_only,
    )

    if output_format == "json":
        payload, fn = vulnerability_freshness_json(
            data,
            internal_only,
        )
        return build_json_response(payload, fn)

    if output_format == "excel":
        return create_generic_excel(
            data=data,
            columns=[
                "project_group",
                "project_name",
                "version_name",
                "purl",
                "last_enriched_at",
            ],
            sheet_name="Vulnerability Freshness",
            filename="vulnerability_freshness.xlsx",
        )

    return Response(
        render_template(
            TABLE_TEMPLATE,
            title=get_internal_title(
                "Vulnerability Enrichment Freshness",
                internal_only,
            ),
            internal_only=internal_only,
            headers=[
                "Project Group",
                "Project Name",
                "Version",
                "PURL",
                "Last Enriched At",
            ],
            data=[
                [
                    d.get("project_group", ""),
                    d.get("project_name", ""),
                    d.get("version_name", ""),
                    d.get("purl", ""),
                    d.get("last_enriched_at") or "Never",
                ]
                for d in data
            ],
            stats={
                "Total Packages": len(data),
                "Never Enriched": sum(1 for d in data if not d.get("last_enriched_at")),
            },
            excel_url=build_url_with_params(
                url_for(
                    "reports.vulnerability_freshness",
                ),
                format="excel",
                internal_only=internal_only,
            ),
            json_url=build_url_with_params(
                url_for(
                    "reports.vulnerability_freshness",
                ),
                format="json",
                internal_only=internal_only,
            ),
            schema_url="/schemas/vulnerability-freshness",
        ),
        mimetype="text/html",
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
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    data = service.get_enrichment_coverage(internal_only)

    if output_format == "excel":
        return create_generic_excel(
            data=data["packages"],
            columns=[
                "purl",
                "project_name",
                "version_name",
                "last_enriched_at",
                "status",
            ],
            sheet_name="Enrichment Coverage",
            filename=(
                "enrichment_coverage_internal.xlsx" if internal_only else "enrichment_coverage.xlsx"
            ),
        )

    if output_format == "json":
        payload, fn = enrichment_coverage_json(data, internal_only)
        return build_json_response(payload, fn)

    # HTML template
    title = get_internal_title(
        "Enrichment Coverage",
        internal_only,
    )
    base_url = "/reports/enrichment-coverage"

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
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    output_format = validate_format(
        request.args.get("format", "html"),
    )

    service = get_falkordb_service()
    coverage = service.get_vex_coverage(
        internal_only=internal_only,
    )
    vulns = service.get_vulnerabilities_with_vex(
        internal_only=internal_only,
    )

    if output_format == "json":
        payload, fn = vex_coverage_json(
            coverage,
            vulns,
            internal_only,
        )
        return build_json_response(payload, fn)

    if output_format == "excel":
        return create_generic_excel(
            data=vulns,
            columns=[
                "defect_id",
                "severity",
                "description",
                "vex_status",
                "vex_count",
            ],
            sheet_name="VEX Coverage",
            filename="vex_coverage.xlsx",
        )

    return Response(
        render_template(
            TABLE_TEMPLATE,
            title=get_internal_title(
                "VEX Coverage",
                internal_only,
            ),
            internal_only=internal_only,
            headers=[
                "Vulnerability",
                "Severity",
                "Description",
                "VEX Status",
                "VEX Statements",
            ],
            data=[
                [
                    v.get("defect_id", ""),
                    v.get("severity", ""),
                    (v.get("description", "")[:100] if v.get("description") else ""),
                    v.get("vex_status") or "No VEX",
                    v.get("vex_count", 0),
                ]
                for v in vulns
            ],
            stats={
                "Total Vulnerabilities": coverage.get(
                    "total_vulnerabilities",
                    0,
                ),
                "With VEX": coverage.get("with_vex", 0),
                "Without VEX": coverage.get(
                    "without_vex",
                    0,
                ),
                "Coverage": (f"{coverage.get('coverage_percent', 0)}%"),
            },
            excel_url=build_url_with_params(
                url_for("reports.vex_coverage"),
                format="excel",
                internal_only=internal_only,
            ),
            json_url=build_url_with_params(
                url_for("reports.vex_coverage"),
                format="json",
                internal_only=internal_only,
            ),
            schema_url="/schemas/vex-coverage",
        ),
        mimetype="text/html",
    )
