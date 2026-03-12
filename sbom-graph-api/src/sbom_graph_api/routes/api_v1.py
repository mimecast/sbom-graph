"""Programmatic JSON API (v1) for machine consumption.

All endpoints return JSON and require JWT authentication.
"""

import uuid
from datetime import UTC, datetime

from flask import Blueprint, Response, jsonify, request

from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.schemas.inbound import (
    CONTACT_CREATE_SCHEMA,
    ENRICHMENT_REQUEST_SCHEMA,
    PATCH_PLAN_EVALUATE_SCHEMA,
    POLICY_ANNOTATION_SCHEMA,
    VEX_AUTO_STUB_SCHEMA,
)
from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.api_helpers import (
    api_response,
    make_pagination,
    paginate_params,
)
from sbom_graph_api.utils.validation import (
    validate_annotation_id,
    validate_boolean,
    validate_defect_id,
    validate_float_param,
    validate_int_param,
    validate_json_body,
    validate_purl,
    validate_record_id,
    validate_sort_param,
    validate_url,
)

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _purl_error(purl: str) -> tuple[Response, int] | None:
    """Return 400 if purl is invalid; otherwise None."""
    validated = validate_purl(purl)
    if not validated:
        return jsonify({"error": "Invalid purl"}), 400
    return None


@bp.route("/package/<path:purl>/licenses")
@auth_required
def package_licenses(purl: str) -> tuple[Response, int]:
    """Return licenses for a specific package identified by purl.

    Returns:
        JSON: ``{purl, licenses: [{spdx_id, name, risk_category, url}]}``.
    """
    err = _purl_error(purl)
    if err:
        return err

    service = get_falkordb_service()
    licenses = service.get_package_licenses(purl)

    return jsonify(
        {
            "purl": purl,
            "licenses": licenses,
            "count": len(licenses),
        }
    ), 200


@bp.route("/package/<path:purl>/vulns")
@auth_required
def package_vulnerabilities(purl: str) -> tuple[Response, int]:
    """Return vulnerabilities for a package, optionally including transitive deps.

    Query params:
        include_dependencies: "true" to include transitive dep vulns.
    """
    err = _purl_error(purl)
    if err:
        return err

    include_deps = validate_boolean(request.args.get("include_dependencies"))
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
        from sbom_graph_enrichment.tasks import (  # type: ignore[import-not-found]
            enrich_all_packages,
            enrich_package,
        )
    except ImportError:
        return jsonify({"error": "Enrichment pipeline not available"}), 503

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, ENRICHMENT_REQUEST_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    purls = body.get("purls")

    if purls:
        for p in purls:
            enrich_package.delay(p)
        return jsonify({"status": "accepted", "dispatched": len(purls)}), 202

    task = enrich_all_packages.delay()
    return jsonify({"status": "accepted", "task_id": str(task.id)}), 202


@bp.route("/policy/annotate", methods=["POST"])
@auth_required
def create_policy_annotation() -> tuple[Response, int]:
    """Create a policy annotation on a package.

    Body: ``{purl, type: "bad"|"good"|"hold", justification, expires_at?}``.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    purl = body["purl"]
    policy_type = body["type"]
    justification = body["justification"]
    expires_at = body.get("expires_at")

    annotation_id = str(uuid.uuid4())
    created_at = datetime.now(UTC).isoformat()

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

    return jsonify(
        {
            "annotation_id": annotation_id,
            "purl": purl,
            "type": policy_type,
            "created_at": created_at,
        }
    ), 201


@bp.route("/policy/annotate/<annotation_id>", methods=["DELETE"])
@auth_required
def delete_policy_annotation(annotation_id: str) -> tuple[Response, int]:
    """Revoke a policy annotation by ID."""
    if not validate_annotation_id(annotation_id):
        return jsonify({"error": "Invalid annotation_id (expected UUID)"}), 400

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
        max_depth: Maximum BFS depth (default 10, max 50).
        internal_only: "true" to restrict to internal packages.
    """
    if not validate_defect_id(defect_id):
        return jsonify({"error": "Invalid defect_id"}), 400

    max_depth = validate_int_param(
        request.args.get("max_depth"),
        default=10,
        min_val=1,
        max_val=50,
    )
    internal_only = validate_boolean(request.args.get("internal_only"))

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
    err = _purl_error(purl)
    if err:
        return err

    max_depth = validate_int_param(
        request.args.get("max_depth"),
        default=10,
        min_val=1,
        max_val=50,
    )
    internal_only = validate_boolean(request.args.get("internal_only"))

    service = get_falkordb_service()
    result = service.compute_blast_radius(
        purl=purl,
        max_depth=max_depth,
        internal_only=internal_only,
    )

    return jsonify(result), 200


@bp.route("/contacts", methods=["POST"])
@auth_required
def create_contact() -> tuple[Response, int]:
    """Create a PointOfContact linked to a package.

    Body: ``{email, purl, team?, slack_channel?}``.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, CONTACT_CREATE_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    email = body["email"]
    purl = body["purl"]
    team = body.get("team")
    slack_channel = body.get("slack_channel")

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

    return jsonify(
        {
            "email": email,
            "purl": purl,
            "team": team,
            "slack_channel": slack_channel,
        }
    ), 201


@bp.route("/package/<path:purl>/vex")
@auth_required
def package_vex(purl: str) -> tuple[Response, int]:
    """Return VEX statements for a package's vulnerabilities."""
    err = _purl_error(purl)
    if err:
        return err

    service = get_falkordb_service()
    statements = service.get_vex_for_package(purl)

    return jsonify(
        {
            "purl": purl,
            "statements": statements,
            "count": len(statements),
        }
    ), 200


@bp.route("/package/<path:purl>/dependencies")
@auth_required
def package_dependencies(purl: str) -> tuple[Response, int]:
    """Return dependency tree for a package (direct + transitive)."""
    err = _purl_error(purl)
    if err:
        return err

    max_depth = validate_int_param(
        request.args.get("max_depth"), default=10, min_val=1, max_val=50
    )
    offset, limit = paginate_params(
        request.args.get("offset"), request.args.get("limit")
    )

    service = get_falkordb_service()
    deps = service.get_transitive_dependency_purls(purl, max_depth=max_depth)

    total = len(deps)
    page = deps[offset : offset + limit]

    return api_response(
        {"purl": purl, "dependencies": page},
        pagination=make_pagination(offset, limit, total),
    )


@bp.route("/package/<path:purl>/dependants")
@auth_required
def package_dependants(purl: str) -> tuple[Response, int]:
    """Return reverse dependency tree (packages that depend on this one)."""
    err = _purl_error(purl)
    if err:
        return err

    max_depth = validate_int_param(
        request.args.get("max_depth"), default=10, min_val=1, max_val=50
    )
    offset, limit = paginate_params(
        request.args.get("offset"), request.args.get("limit")
    )

    service = get_falkordb_service()
    dependants = service.get_transitive_dependant_purls(purl, max_depth=max_depth)

    total = len(dependants)
    page = dependants[offset : offset + limit]

    return api_response(
        {"purl": purl, "dependants": page},
        pagination=make_pagination(offset, limit, total),
    )


@bp.route("/package/<path:purl>/policy")
@auth_required
def check_package_policy(purl: str) -> tuple[Response, int]:
    """CI/CD gate: check policy status for a package.

    Returns: ``{purl, status: "pass"|"fail"|"hold", annotations: [...]}``.
    """
    err = _purl_error(purl)
    if err:
        return err

    service = get_falkordb_service()
    result = service.check_policy(purl)

    return jsonify(result), 200


# --- Source repository endpoints ---


@bp.route("/source/packages")
@auth_required
def source_repo_packages() -> tuple[Response, int]:
    """Return all packages sourced from a given repository URL.

    Query Parameters:
        repo_url (str): Required. The source repository URL (http/https).
    """
    repo_url = validate_url(request.args.get("repo_url", "").strip())
    if not repo_url:
        return jsonify({"error": "Missing or invalid repo_url (must be http/https URL)"}), 400

    service = get_falkordb_service()
    packages = service.get_packages_by_source_repo(repo_url)

    return jsonify(
        {
            "repo_url": repo_url,
            "packages": packages,
            "count": len(packages),
        }
    ), 200


@bp.route("/source/vulnerabilities")
@auth_required
def source_repo_vulnerabilities() -> tuple[Response, int]:
    """Return all vulnerabilities in packages sourced from a repository.

    Query Parameters:
        repo_url (str): Required. The source repository URL (http/https).
    """
    repo_url = validate_url(request.args.get("repo_url", "").strip())
    if not repo_url:
        return jsonify({"error": "Missing or invalid repo_url (must be http/https URL)"}), 400

    service = get_falkordb_service()
    vulns = service.get_vulnerabilities_by_source_repo(repo_url)

    return jsonify(
        {
            "repo_url": repo_url,
            "vulnerabilities": vulns,
            "count": len(vulns),
        }
    ), 200


@bp.route("/package/<path:purl>/trust-score")
@auth_required
def package_trust_score(purl: str) -> tuple[Response, int]:
    """Return full trust score breakdown for a package.

    Returns:
        JSON: full trust score object with all category scores.
    """
    err = _purl_error(purl)
    if err:
        return err

    service = get_falkordb_service()
    score = service.get_trust_score_for_purl(purl)

    if score is None:
        return jsonify({"error": "No trust score found for this package"}), 404

    return jsonify(score), 200


@bp.route("/package/<path:purl>/trust-score/risk-path")
@auth_required
def package_risk_path(purl: str) -> tuple[Response, int]:
    """Return dependency risk path analysis for a package.

    Query params:
        limit: Maximum dependencies to return (default 10, max 50).
    """
    err = _purl_error(purl)
    if err:
        return err

    limit = validate_int_param(request.args.get("limit"), default=10, min_val=1, max_val=50)
    service = get_falkordb_service()
    paths = service.get_trust_score_risk_path(purl, limit=limit)

    return jsonify(
        {
            "purl": purl,
            "risk_path": paths,
            "count": len(paths),
        }
    ), 200


@bp.route("/application/<path:purl>/supply-chain-risk")
@auth_required
def application_supply_chain_risk(purl: str) -> tuple[Response, int]:
    """Return aggregate supply-chain risk for an application.

    Returns:
        JSON: effective_score, min_path_score, dep_count, weakest_links.
    """
    err = _purl_error(purl)
    if err:
        return err

    service = get_falkordb_service()
    risk = service.get_application_supply_chain_risk(purl)

    if "error" in risk:
        return jsonify(risk), 404

    return jsonify(risk), 200


@bp.route("/analysis/trust-score-distribution")
@auth_required
def trust_score_distribution() -> tuple[Response, int]:
    """Return histogram of effective trust scores across all packages."""
    service = get_falkordb_service()
    distribution = service.get_trust_score_distribution()

    return jsonify(
        {
            "distribution": distribution,
        }
    ), 200


@bp.route("/analysis/critical-dependencies")
@auth_required
def critical_dependencies() -> tuple[Response, int]:
    """Return most critical dependencies (high fan-in or low scorecard).

    Query params:
        sort: "fan_in" (default) or "trust_score"
        limit: max results (default 20, max 100)
    """
    sort_by = validate_sort_param(
        request.args.get("sort"),
        allowed=frozenset({"fan_in", "trust_score"}),
        default="fan_in",
    )

    limit = validate_int_param(
        request.args.get("limit"), default=20, min_val=1, max_val=100
    )

    service = get_falkordb_service()

    if sort_by == "trust_score":
        results = service.get_remediation_priorities(limit=limit)
    else:
        results = service.get_most_depended_packages(limit=limit)

    return api_response(
        {"dependencies": results, "sort": sort_by},
    )


@bp.route("/analysis/risk-summary")
@auth_required
def risk_summary() -> tuple[Response, int]:
    """Return aggregate risk metrics: vuln counts by severity, license risk, policy violations."""
    service = get_falkordb_service()

    vuln_result = service.execute_query(
        "MATCH (d:Defect) "
        "RETURN d.severity AS severity, count(d) AS count "
        "ORDER BY count DESC",
        {},
    )
    vuln_by_severity = {
        (row[0] if row else "unknown"): (row[1] if row and len(row) > 1 else 0)
        for row in vuln_result
    }

    license_result = service.execute_query(
        "MATCH (l:License) "
        "RETURN l.risk_category AS category, count(l) AS count "
        "ORDER BY count DESC",
        {},
    )
    license_by_risk = {
        (row[0] if row else "unknown"): (row[1] if row and len(row) > 1 else 0)
        for row in license_result
    }

    policy_result = service.execute_query(
        "MATCH (a:PolicyAnnotation) "
        "RETURN a.type AS type, count(a) AS count "
        "ORDER BY count DESC",
        {},
    )
    policy_by_type = {
        (row[0] if row else "unknown"): (row[1] if row and len(row) > 1 else 0)
        for row in policy_result
    }

    pkg_result = service.execute_query(
        "MATCH (v:Version) WHERE v.package_url IS NOT NULL "
        "RETURN count(DISTINCT v.package_url) AS total",
        {},
    )
    total_packages = (
        pkg_result[0][0] if pkg_result and pkg_result[0] else 0
    )

    data = {
        "total_packages": total_packages,
        "vulnerabilities_by_severity": vuln_by_severity,
        "licenses_by_risk_category": license_by_risk,
        "policy_annotations_by_type": policy_by_type,
    }

    return api_response(data)


@bp.route("/analysis/remediation-priorities")
@auth_required
def remediation_priorities() -> tuple[Response, int]:
    """Return packages ranked by remediation priority.

    Query params:
        limit: Maximum packages to return (default 20, max 100).
    """
    limit = validate_int_param(request.args.get("limit"), default=20, min_val=1, max_val=100)
    service = get_falkordb_service()
    priorities = service.get_remediation_priorities(limit=limit)

    return jsonify(
        {
            "priorities": priorities,
            "count": len(priorities),
        }
    ), 200


@bp.route("/analysis/risk-propagation-impact")
@auth_required
def risk_propagation_impact() -> tuple[Response, int]:
    """What-if simulation: if package X drops to score Y, what apps are impacted?

    Query params:
        purl: Required. Package URL to simulate.
        simulated_score: Required. Simulated trust score (0-10).

    Returns:
        JSON: list of {purl, current_effective, simulated_effective, impact}.
    """
    purl = request.args.get("purl", "").strip()
    err = _purl_error(purl)
    if err:
        return err

    if "simulated_score" not in request.args:
        return jsonify({"error": "simulated_score query parameter is required"}), 400

    simulated_score = validate_float_param(
        request.args.get("simulated_score"),
        default=0.0,
        min_val=0.0,
        max_val=10.0,
    )

    service = get_falkordb_service()
    impacts = service.simulate_risk_propagation(purl, simulated_score)

    return jsonify(
        {
            "purl": purl,
            "simulated_score": simulated_score,
            "impacts": impacts,
            "count": len(impacts),
        }
    ), 200


@bp.route("/sbom/<record_id>")
@auth_required
def get_sbom_record(record_id: str) -> tuple[Response, int]:
    """Return a single SBOM record by ID with linked version purls."""
    if not validate_record_id(record_id):
        return jsonify({"error": "Invalid record_id (expected UUID)"}), 400

    service = get_falkordb_service()
    record = service.get_sbom_record_by_id(record_id)

    if record is None:
        return jsonify({"error": "SBOM record not found"}), 404

    return jsonify(record), 200


@bp.route("/patch-plan/evaluate", methods=["POST"])
@auth_required
def evaluate_patch_plan() -> tuple[Response, int]:
    """Evaluate a proposed dependency update for vulnerability impact.

    Body: {purl, current_version, target_version}.
    Returns which vulnerabilities are resolved and which are added.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, PATCH_PLAN_EVALUATE_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    purl = body["purl"]
    current_version = body["current_version"]
    target_version = body["target_version"]

    service = get_falkordb_service()
    result = service.evaluate_patch_plan(
        purl=purl,
        current_version=current_version,
        target_version=target_version,
    )

    return jsonify(result), 200


@bp.route("/vex/auto-stub", methods=["POST"])
@auth_required
def vex_auto_stub() -> tuple[Response, int]:
    """Auto-generate VEX not_affected stubs for packages with vulns but no VEX.

    Body: {purl, justification?}.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, VEX_AUTO_STUB_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    purl = body["purl"]
    justification = body.get("justification")

    service = get_falkordb_service()
    version_exists = service.execute_query(
        "MATCH (v:Version {package_url: $purl}) RETURN 1 LIMIT 1",
        {"purl": purl},
    )
    if not version_exists:
        return jsonify({"error": "Package not found in graph"}), 404

    created = service.generate_vex_auto_stubs(purl, justification)

    return jsonify(
        {
            "purl": purl,
            "created": created,
            "count": len(created),
        }
    ), 201


@bp.route("/package/<path:purl>/trust-check")
@auth_required
def package_trust_check(purl: str) -> tuple[Response, int]:
    """CI/CD gate: check if a package meets minimum trust score thresholds.

    Query params:
        min_score: Minimum effective_score (default 5.0).
        min_confidence: Minimum confidence (default 0.25).

    Returns:
        JSON: {pass: bool, effective_score, confidence, reason}.
    """
    err = _purl_error(purl)
    if err:
        return err

    min_score = validate_float_param(
        request.args.get("min_score"), default=5.0, min_val=0.0, max_val=10.0
    )
    min_confidence = validate_float_param(
        request.args.get("min_confidence"), default=0.25, min_val=0.0, max_val=1.0
    )

    service = get_falkordb_service()
    score = service.get_trust_score_for_purl(purl)

    if score is None:
        return jsonify(
            {
                "pass": False,
                "purl": purl,
                "reason": "No trust score available",
            }
        ), 200

    effective = score.get("effective_score") or score.get("direct_score") or 0
    confidence = score.get("confidence") or 0

    passed = effective >= min_score and confidence >= min_confidence
    if passed:
        reason = "OK"
    else:
        reason_parts: list[str] = []
        if effective < min_score:
            reason_parts.append(f"effective_score {effective:.1f} < {min_score:.1f}")
        if confidence < min_confidence:
            reason_parts.append(f"confidence {confidence:.2f} < {min_confidence:.2f}")
        reason = "; ".join(reason_parts)

    return jsonify(
        {
            "pass": passed,
            "purl": purl,
            "effective_score": effective,
            "direct_score": score.get("direct_score"),
            "confidence": confidence,
            "reason": reason,
        }
    ), 200


@bp.route("/package/<path:purl>")
@auth_required
def package_metadata(purl: str) -> tuple[Response, int]:
    """Return all metadata for a package: versions, vulns, licenses, scorecard, policy."""
    err = _purl_error(purl)
    if err:
        return err

    service = get_falkordb_service()
    version_info = service.find_version_by_purl(purl)
    if not version_info:
        return jsonify({"error": "Package not found"}), 404

    vulns = service.get_package_vulnerabilities(purl, include_dependencies=False)
    licenses = service.get_package_licenses(purl)
    trust_score = service.get_trust_score_for_purl(purl)
    policy = service.check_policy(purl)
    vex = service.get_vex_for_package(purl)

    data = {
        "purl": purl,
        "vulnerabilities": vulns,
        "licenses": licenses,
        "trust_score": trust_score,
        "policy": policy,
        "vex_statements": vex,
    }

    return api_response(data)


@bp.route("/openapi.json")
@auth_required
def openapi_spec() -> tuple[Response, int]:
    """Return OpenAPI 3.1 specification for the v1 API."""
    spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "SBOM Graph API",
            "version": "1.0.0",
            "description": (
                "Programmatic API for querying SBOM dependency graphs, "
                "vulnerabilities, licenses, trust scores, and policy annotations."
            ),
        },
        "servers": [{"url": "/api/v1"}],
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        "paths": _build_openapi_paths(),
    }
    return jsonify(spec), 200


def _build_openapi_paths() -> dict:
    """Build OpenAPI paths from documented endpoints."""
    return {
        "/package/{purl}": {
            "get": {
                "summary": "Get all metadata for a package",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "Package metadata"}},
            }
        },
        "/package/{purl}/vulns": {
            "get": {
                "summary": "Get vulnerabilities for a package",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "include_dependencies",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "enum": ["true", "false"],
                        },
                    },
                ],
                "responses": {"200": {"description": "Vulnerability list"}},
            }
        },
        "/package/{purl}/licenses": {
            "get": {
                "summary": "Get licenses for a package",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "License list"}},
            }
        },
        "/package/{purl}/dependencies": {
            "get": {
                "summary": "Get dependency tree for a package",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "max_depth",
                        "in": "query",
                        "schema": {"type": "integer", "default": 10},
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "schema": {"type": "integer", "default": 0},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 100},
                    },
                ],
                "responses": {
                    "200": {"description": "Dependency tree with pagination"}
                },
            }
        },
        "/package/{purl}/dependants": {
            "get": {
                "summary": "Get reverse dependency tree",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "max_depth",
                        "in": "query",
                        "schema": {"type": "integer", "default": 10},
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "schema": {"type": "integer", "default": 0},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 100},
                    },
                ],
                "responses": {
                    "200": {"description": "Dependants list with pagination"}
                },
            }
        },
        "/package/{purl}/trust-score": {
            "get": {
                "summary": "Get trust score breakdown",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "Trust score data"}},
            }
        },
        "/package/{purl}/trust-check": {
            "get": {
                "summary": "CI/CD gate: check trust score thresholds",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "min_score",
                        "in": "query",
                        "schema": {"type": "number", "default": 5.0},
                    },
                    {
                        "name": "min_confidence",
                        "in": "query",
                        "schema": {"type": "number", "default": 0.25},
                    },
                ],
                "responses": {"200": {"description": "Trust check result"}},
            }
        },
        "/package/{purl}/policy": {
            "get": {
                "summary": "Check policy status for CI/CD gate",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "Policy check result"}},
            }
        },
        "/package/{purl}/vex": {
            "get": {
                "summary": "Get VEX statements for a package",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "VEX statements"}},
            }
        },
        "/analysis/critical-dependencies": {
            "get": {
                "summary": "Get most critical dependencies",
                "parameters": [
                    {
                        "name": "sort",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "enum": ["fan_in", "trust_score"],
                            "default": "fan_in",
                        },
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 20},
                    },
                ],
                "responses": {
                    "200": {"description": "Critical dependency list"}
                },
            }
        },
        "/analysis/risk-summary": {
            "get": {
                "summary": "Get aggregate risk metrics",
                "responses": {"200": {"description": "Risk summary data"}},
            }
        },
        "/analysis/trust-score-distribution": {
            "get": {
                "summary": "Get trust score histogram",
                "responses": {"200": {"description": "Distribution data"}},
            }
        },
        "/analysis/remediation-priorities": {
            "get": {
                "summary": "Get remediation priority ranking",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 20},
                    },
                ],
                "responses": {"200": {"description": "Priority list"}},
            }
        },
        "/analysis/risk-propagation-impact": {
            "get": {
                "summary": "What-if risk propagation simulation",
                "parameters": [
                    {
                        "name": "purl",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "simulated_score",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "number"},
                    },
                ],
                "responses": {
                    "200": {"description": "Propagation impact data"}
                },
            }
        },
    }
