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
    create_vulnerabilities_excel,
    create_vulnerability_dependants_excel,
    excel_response,
)
from sbom_graph_api.exports.json_format import (
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
    validate_format,
    validate_max_depth,
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

    Returns:
        HTML table, Excel download, or JSON
    """
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )

    service = get_falkordb_service()
    vulns = service.get_all_vulnerabilities(internal_only)

    severity_counts: dict[str, int] = {}
    total_affected = 0
    for vuln in vulns:
        sev = vuln.get("severity", "UNKNOWN")
        severity_counts[sev] = (
            severity_counts.get(sev, 0) + 1
        )
        total_affected += len(
            vuln.get("affected_versions", []),
        )

    if output_format == "excel":
        buf = create_vulnerabilities_excel(
            vulns,
            internal_only,
        )
        filename = (
            "vulnerabilities_internal.xlsx"
            if internal_only
            else "vulnerabilities.xlsx"
        )
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

    html = render_template(
        "vulnerabilities.html",
        title=title,
        internal_only=internal_only,
        vulnerabilities=vulns,
        stats={
            "Total Vulnerabilities": len(vulns),
            "Total Affected Versions": total_affected,
            "Critical": severity_counts.get("CRITICAL", 0),
            "High": severity_counts.get("HIGH", 0),
            "Medium": severity_counts.get("MEDIUM", 0),
            "Low": severity_counts.get("LOW", 0),
        },
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
        partition_counts[p] = (
            partition_counts.get(p, 0) + 1
        )

    if output_format == "excel":
        buf = create_vulnerability_dependants_excel(
            vuln,
            deps,
            internal_only,
        )
        fn = (
            f"vulnerability_dependants_{defect_id}.xlsx"
        )
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
    base_url = (
        f"/reports/vulnerability-dependants/{defect_id}"
    )

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
                "Never Enriched": sum(
                    1
                    for d in data
                    if not d.get("last_enriched_at")
                ),
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
                    (
                        v.get("description", "")[:100]
                        if v.get("description")
                        else ""
                    ),
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
                "Coverage": (
                    f"{coverage.get('coverage_percent', 0)}%"
                ),
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
