"""License and policy compliance reports."""

from flask import (
    Response,
    jsonify,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue

from sbom_graph_api.exports.excel import create_generic_excel
from sbom_graph_api.exports.json_format import (
    license_conflicts_json,
    license_summary_json,
    licenses_json,
    policy_violations_json,
)
from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.routes.reports import bp
from sbom_graph_api.routes.reports._common import (
    TABLE_TEMPLATE,
    build_json_response,
    get_internal_title,
    ts,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import (
    build_url_with_params,
    validate_boolean,
    validate_format,
    validate_project_group,
    validate_project_name,
    validate_version_name,
)

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
    fmt = validate_format(
        request.args.get("format", "html"),
    )
    internal_only = validate_boolean(
        request.args.get("internal_only", "true"),
    )
    service = get_falkordb_service()
    licenses = service.get_all_licenses(
        internal_only=internal_only,
    )

    if fmt == "json":
        payload, fn = licenses_json(
            licenses,
            internal_only,
        )
        return build_json_response(payload, fn)

    if fmt == "excel":
        return create_generic_excel(
            data=licenses,
            columns=[
                "spdx_id",
                "name",
                "risk_category",
                "usage_count",
            ],
            sheet_name="Licenses",
            filename="licenses.xlsx",
        )

    return render_template(
        "licenses.html",
        title=get_internal_title(
            "Licenses",
            internal_only,
        ),
        licenses=licenses,
        internal_only=internal_only,
        generated_at=ts(),
        schema_url="/schemas/licenses",
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
                    "error": (
                        "project_name and version_name "
                        "are required"
                    ),
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
        payload, fn = license_summary_json(
            summary,
            project_name,
            version_name,
        )
        return build_json_response(payload, fn)

    if fmt == "excel":
        return create_generic_excel(
            data=summary,
            columns=[
                "project_group",
                "project_name",
                "version",
                "purl",
                "spdx_id",
                "license_name",
                "risk_category",
            ],
            sheet_name="License Summary",
            filename="license-summary.xlsx",
        )

    return render_template(
        "license_summary.html",
        title=(
            "License Summary: "
            f"{project_name} {version_name}"
        ),
        project_name=project_name,
        version_name=version_name,
        summary=summary,
        generated_at=ts(),
        schema_url="/schemas/license-summary",
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
    service = get_falkordb_service()
    conflicts = service.get_license_conflicts(
        internal_only=internal_only,
    )

    if fmt == "json":
        payload, fn = license_conflicts_json(
            conflicts,
            internal_only,
        )
        return build_json_response(payload, fn)

    return render_template(
        "license_conflicts.html",
        title=get_internal_title(
            "License Conflicts",
            internal_only,
        ),
        conflicts=conflicts,
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
    internal_only = validate_boolean(
        request.args.get("internal_only"),
    )
    output_format = validate_format(
        request.args.get("format", "html"),
    )

    service = get_falkordb_service()
    data = service.get_policy_violations(
        internal_only=internal_only,
    )

    if output_format == "json":
        payload, fn = policy_violations_json(
            data,
            internal_only,
        )
        return build_json_response(payload, fn)

    if output_format == "excel":
        return create_generic_excel(
            data=data,
            columns=[
                "purl",
                "project_name",
                "version_name",
                "justification",
                "created_by",
                "created_at",
                "dependant_count",
            ],
            sheet_name="Policy Violations",
            filename="policy_violations.xlsx",
        )

    return Response(
        render_template(
            TABLE_TEMPLATE,
            title=get_internal_title(
                "Policy Violations",
                internal_only,
            ),
            internal_only=internal_only,
            headers=[
                "PURL",
                "Project Name",
                "Version",
                "Justification",
                "Created By",
                "Created At",
                "Dependant Count",
            ],
            data=[
                [
                    d.get("purl", ""),
                    d.get("project_name", ""),
                    d.get("version_name", ""),
                    d.get("justification", ""),
                    d.get("created_by", ""),
                    d.get("created_at") or "",
                    d.get("dependant_count", 0),
                ]
                for d in data
            ],
            stats={
                "Total Violations": len(data),
                "Total Affected Dependants": sum(
                    v.get("dependant_count", 0)
                    for v in data
                ),
            },
            excel_url=build_url_with_params(
                url_for("reports.policy_violations"),
                format="excel",
                internal_only=internal_only,
            ),
            json_url=build_url_with_params(
                url_for("reports.policy_violations"),
                format="json",
                internal_only=internal_only,
            ),
            schema_url="/schemas/policy-violations",
        ),
        mimetype="text/html",
    )
