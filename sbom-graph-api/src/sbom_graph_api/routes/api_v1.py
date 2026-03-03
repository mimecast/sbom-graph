"""Programmatic JSON API (v1) for machine consumption.

All endpoints return JSON and require JWT authentication.
"""

import uuid
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request

from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.services.falkordb_service import get_falkordb_service

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


_MAX_PURL_LENGTH = 512
_MAX_JUSTIFICATION_LENGTH = 2000


def _validate_purl(purl: str) -> tuple[Response, int] | None:
    """Validate a purl path parameter; returns an error response or None."""
    if not purl:
        return jsonify({"error": "purl path parameter is required"}), 400
    if len(purl) > _MAX_PURL_LENGTH:
        return jsonify({"error": "purl exceeds maximum length"}), 400
    if not purl.startswith("pkg:"):
        return jsonify({"error": "purl must start with 'pkg:'"}), 400
    return None


@bp.route("/package/<path:purl>/licenses")
@auth_required
def package_licenses(purl: str) -> tuple[Response, int]:
    """Return licenses for a specific package identified by purl.

    Returns:
        JSON: ``{purl, licenses: [{spdx_id, name, risk_category, url}]}``.
    """
    err = _validate_purl(purl)
    if err:
        return err

    service = get_falkordb_service()
    licenses = service.get_package_licenses(purl)

    return jsonify({
        "purl": purl,
        "licenses": licenses,
        "count": len(licenses),
    }), 200


@bp.route("/package/<path:purl>/vulns")
@auth_required
def package_vulnerabilities(purl: str) -> tuple[Response, int]:
    """Return vulnerabilities for a package, optionally including transitive deps.

    Query params:
        include_dependencies: "true" to include transitive dep vulns.
    """
    err = _validate_purl(purl)
    if err:
        return err

    include_deps = request.args.get("include_dependencies", "false").lower() == "true"
    service = get_falkordb_service()
    result = service.get_package_vulnerabilities(purl, include_dependencies=include_deps)

    return jsonify(result), 200


@bp.route("/enrich/vulnerabilities", methods=["POST"])
@auth_required
def trigger_enrichment() -> tuple[Response, int]:
    """Trigger on-demand vulnerability enrichment.

    Accepts optional JSON body: ``{"purls": ["pkg:maven/..."]}``.
    Dispatches Celery tasks and returns 202 Accepted.
    """
    try:
        from sbom_graph_enrichment.tasks import enrich_package, enrich_all_packages
    except ImportError:
        return jsonify({"error": "Enrichment pipeline not available"}), 503

    body = request.get_json(silent=True) or {}
    purls = body.get("purls")

    if purls:
        if not isinstance(purls, list):
            return jsonify({"error": "purls must be a list"}), 400
        if len(purls) > 1000:
            return jsonify({"error": "Maximum 1000 purls per request"}), 400
        for p in purls:
            if not isinstance(p, str) or not p.startswith("pkg:"):
                return jsonify({"error": f"Invalid purl: {p}"}), 400
            enrich_package.delay(p)
        return jsonify({"status": "accepted", "dispatched": len(purls)}), 202
    else:
        task = enrich_all_packages.delay()
        return jsonify({"status": "accepted", "task_id": str(task.id)}), 202


@bp.route("/policy/annotate", methods=["POST"])
@auth_required
def create_policy_annotation() -> tuple[Response, int]:
    """Create a policy annotation on a package.

    Body: ``{purl, type: "bad"|"good"|"hold", justification, expires_at?}``.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    purl = body.get("purl", "")
    policy_type = body.get("type", "")
    justification = body.get("justification", "")
    expires_at = body.get("expires_at")

    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return jsonify({"error": "Valid purl is required"}), 400
    if len(purl) > _MAX_PURL_LENGTH:
        return jsonify({"error": "purl exceeds maximum length"}), 400
    if policy_type not in ("bad", "good", "hold"):
        return jsonify({"error": "type must be 'bad', 'good', or 'hold'"}), 400
    if not justification or not isinstance(justification, str):
        return jsonify({"error": "justification is required"}), 400
    if len(justification) > _MAX_JUSTIFICATION_LENGTH:
        return jsonify({"error": "justification exceeds maximum length"}), 400

    annotation_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    service = get_falkordb_service()
    version_exists = service.execute_query(
        "MATCH (v:Version {package_url: $purl}) RETURN 1 LIMIT 1",
        {"purl": purl},
    )
    if not version_exists:
        return jsonify({"error": "Package not found in graph"}), 404

    service.execute_write(
        """
        MERGE (a:PolicyAnnotation {annotation_id: $annotation_id})
        ON CREATE SET
            a.type = $policy_type,
            a.justification = $justification,
            a.created_by = $created_by,
            a.created_at = $created_at
        ON MATCH SET
            a.type = $policy_type,
            a.justification = $justification
        """,
        {
            "annotation_id": annotation_id,
            "policy_type": policy_type,
            "justification": justification,
            "created_by": "api",
            "created_at": created_at,
        },
    )
    if expires_at:
        service.execute_write(
            "MATCH (a:PolicyAnnotation {annotation_id: $aid}) SET a.expires_at = $ea",
            {"aid": annotation_id, "ea": expires_at},
        )

    service.execute_write(
        """
        MATCH (v:Version {package_url: $purl})
        MATCH (a:PolicyAnnotation {annotation_id: $annotation_id})
        MERGE (v)-[:HAS_POLICY]->(a)
        """,
        {"purl": purl, "annotation_id": annotation_id},
    )

    return jsonify({
        "annotation_id": annotation_id,
        "purl": purl,
        "type": policy_type,
        "created_at": created_at,
    }), 201


@bp.route("/policy/annotate/<annotation_id>", methods=["DELETE"])
@auth_required
def delete_policy_annotation(annotation_id: str) -> tuple[Response, int]:
    """Revoke a policy annotation by ID."""
    if not annotation_id:
        return jsonify({"error": "annotation_id is required"}), 400

    service = get_falkordb_service()
    result = service.execute_write(
        """
        MATCH (a:PolicyAnnotation {annotation_id: $annotation_id})
        WITH count(a) AS to_delete
        MATCH (a2:PolicyAnnotation {annotation_id: $annotation_id})
        DETACH DELETE a2
        RETURN to_delete AS deleted
        """,
        {"annotation_id": annotation_id},
    )
    deleted = result[0][0] if result else 0

    if not deleted:
        return jsonify({"error": "Annotation not found"}), 404

    return jsonify({"status": "deleted", "annotation_id": annotation_id}), 200


@bp.route("/patch-plan/<path:defect_id>")
@auth_required
def get_patch_plan(defect_id: str) -> tuple[Response, int]:
    """Return frontier-level patch plan for a vulnerability.

    Query params:
        max_depth: Maximum BFS depth (default 10).
        internal_only: "true" to restrict to internal packages.
    """
    if not defect_id:
        return jsonify({"error": "defect_id is required"}), 400

    max_depth = min(int(request.args.get("max_depth", "10")), 50)
    internal_only = request.args.get("internal_only", "false").lower() == "true"

    service = get_falkordb_service()
    result = service.compute_patch_plan(
        defect_id=defect_id,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    if result.get("defect") is None:
        return jsonify({"error": "Vulnerability not found"}), 404

    return jsonify(result), 200


@bp.route("/blast-radius/<path:purl>")
@auth_required
def get_blast_radius(purl: str) -> tuple[Response, int]:
    """Return blast radius for a compromised package.

    Query params:
        max_depth: Maximum BFS depth (default 10).
        internal_only: "true" to restrict to internal packages.
    """
    err = _validate_purl(purl)
    if err:
        return err

    max_depth = min(int(request.args.get("max_depth", "10")), 50)
    internal_only = request.args.get("internal_only", "false").lower() == "true"

    service = get_falkordb_service()
    result = service.compute_blast_radius(
        purl=purl,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    return jsonify(result), 200


_MAX_EMAIL_LENGTH = 254
_MAX_TEAM_LENGTH = 200


@bp.route("/contacts", methods=["POST"])
@auth_required
def create_contact() -> tuple[Response, int]:
    """Create a PointOfContact linked to a package.

    Body: ``{email, purl, team?, slack_channel?}``.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    email = body.get("email", "")
    purl = body.get("purl", "")
    team = body.get("team")
    slack_channel = body.get("slack_channel")

    if not email or not isinstance(email, str) or "@" not in email:
        return jsonify({"error": "Valid email is required"}), 400
    if len(email) > _MAX_EMAIL_LENGTH:
        return jsonify({"error": "email exceeds maximum length"}), 400
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return jsonify({"error": "Valid purl is required"}), 400
    if len(purl) > _MAX_PURL_LENGTH:
        return jsonify({"error": "purl exceeds maximum length"}), 400
    if team and len(team) > _MAX_TEAM_LENGTH:
        return jsonify({"error": "team exceeds maximum length"}), 400

    service = get_falkordb_service()
    version_exists = service.execute_query(
        "MATCH (v:Version {package_url: $purl}) RETURN 1 LIMIT 1",
        {"purl": purl},
    )
    if not version_exists:
        return jsonify({"error": "Package not found in graph"}), 404

    service.execute_write(
        """
        MERGE (c:PointOfContact {email: $email})
        ON CREATE SET c.team = $team, c.slack_channel = $slack_channel
        ON MATCH SET c.team = $team, c.slack_channel = $slack_channel
        """,
        {"email": email, "team": team, "slack_channel": slack_channel},
    )
    service.execute_write(
        """
        MATCH (c:PointOfContact {email: $email})
        MATCH (v:Version {package_url: $purl})
        MERGE (c)-[:CONTACT_FOR]->(v)
        """,
        {"email": email, "purl": purl},
    )

    return jsonify({
        "email": email,
        "purl": purl,
        "team": team,
        "slack_channel": slack_channel,
    }), 201


@bp.route("/package/<path:purl>/vex")
@auth_required
def package_vex(purl: str) -> tuple[Response, int]:
    """Return VEX statements for a package's vulnerabilities."""
    err = _validate_purl(purl)
    if err:
        return err

    service = get_falkordb_service()
    statements = service.get_vex_for_package(purl)

    return jsonify({
        "purl": purl,
        "statements": statements,
        "count": len(statements),
    }), 200


@bp.route("/package/<path:purl>/policy")
@auth_required
def check_package_policy(purl: str) -> tuple[Response, int]:
    """CI/CD gate: check policy status for a package.

    Returns: ``{purl, status: "pass"|"fail"|"hold", annotations: [...]}``.
    """
    err = _validate_purl(purl)
    if err:
        return err

    service = get_falkordb_service()
    result = service.check_policy(purl)

    return jsonify(result), 200
