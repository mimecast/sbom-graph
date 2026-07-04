"""Admin routes for policy annotation management."""

from flask import (
    Blueprint,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue

from sbom_graph_api.routes.auth import admin_required, get_current_user
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import validate_purl, validate_search_term

# UI-friendly annotation types; map to internal types (bad/good/hold)
ANNOTATION_TYPE_MAP = {
    "banned": "bad",
    "approved": "good",
    "deprecated": "hold",
}
VALID_ANNOTATION_TYPES = frozenset(ANNOTATION_TYPE_MAP.keys())
MAX_JUSTIFICATION_LENGTH = 500

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/policies", methods=["GET"])
@admin_required
def policy_admin_page() -> ResponseReturnValue:
    """Render the policy admin page with search and filter."""
    search = validate_search_term(request.args.get("search")) or ""
    type_filter = request.args.get("type") or ""
    if type_filter and type_filter not in VALID_ANNOTATION_TYPES:
        type_filter = ""

    # Map UI type to internal type for service
    internal_type = ANNOTATION_TYPE_MAP.get(type_filter) if type_filter else None

    service = get_falkordb_service()
    annotations = service.get_policy_annotations(
        search=search if search else None,
        type_filter=internal_type,
    )
    violations = service.get_policy_violations()

    # Stats
    total = len(annotations)
    banned = sum(1 for a in annotations if a.get("type") == "bad")
    approved = sum(1 for a in annotations if a.get("type") == "good")
    deprecated = sum(1 for a in annotations if a.get("type") == "hold")

    return Response(
        render_template(
            "policy_admin.html",
            annotations=annotations,
            violations=violations,
            search=search,
            type_filter=type_filter,
            stats={
                "Total Annotations": total,
                "Banned": banned,
                "Approved": approved,
                "Deprecated": deprecated,
            },
            type_options=VALID_ANNOTATION_TYPES,
        ),
        mimetype="text/html",
    )


@bp.route("/policies", methods=["POST"])
@admin_required
def add_policy_annotation() -> ResponseReturnValue:
    """Add a new policy annotation (form POST with CSRF)."""
    purl = (request.form.get("purl") or "").strip()
    annotation_type = (request.form.get("annotation_type") or "").strip().lower()
    justification = (request.form.get("justification") or "").strip()

    if not purl:
        return _policy_error("PURL is required"), 400
    if not validate_purl(purl):
        return _policy_error("Invalid PURL format"), 400
    if annotation_type not in VALID_ANNOTATION_TYPES:
        return _policy_error(
            f"Annotation type must be one of: {', '.join(sorted(VALID_ANNOTATION_TYPES))}"
        ), 400
    if not justification:
        return _policy_error("Justification is required"), 400
    if len(justification) > MAX_JUSTIFICATION_LENGTH:
        return _policy_error(
            f"Justification must be at most {MAX_JUSTIFICATION_LENGTH} characters"
        ), 400

    created_by = get_current_user() or "unknown"
    internal_type = ANNOTATION_TYPE_MAP[annotation_type]

    service = get_falkordb_service()
    result = service.add_policy_annotation(
        purl=purl,
        annotation_type=internal_type,
        justification=justification,
        created_by=created_by,
    )

    if result is None:
        return _policy_error("Package not found in graph. Ingest an SBOM first."), 404

    # Redirect back to admin page with success
    return redirect(url_for("admin.policy_admin_page", _anchor="annotations") + "?added=1")


@bp.route("/policies/<path:purl>", methods=["DELETE"])
@admin_required
def remove_policy_annotation(purl: str) -> ResponseReturnValue:
    """Remove a policy annotation by PURL (AJAX)."""
    purl_decoded = purl.strip()
    if not purl_decoded:
        return jsonify({"error": "PURL is required"}), 400
    if not validate_purl(purl_decoded):
        return jsonify({"error": "Invalid PURL format"}), 400

    service = get_falkordb_service()
    removed = service.remove_policy_annotation(purl_decoded)

    if not removed:
        return jsonify({"error": "No annotation found for this package"}), 404

    return jsonify({"status": "removed", "purl": purl_decoded}), 200


def _policy_error(message: str) -> Response:
    """Return HTML error response for policy form errors."""
    return Response(
        render_template(
            "error.html",
            error="Policy Annotation Error",
            message=message,
        ),
        status=400,
        mimetype="text/html",
    )
