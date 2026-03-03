"""SBOM ingestion routes.

Provides endpoints for uploading CycloneDX and SPDX SBOM files and
persisting the parsed data (projects, dependencies, defects) to the
graph database via the sbom-graph-model library.
"""

import hashlib
import logging
import os

from flask import Blueprint, Response, jsonify, request
from sbom_graph_model import Persistence
from sbom_graph_model.cyclonedx import CycloneDXProcessor, CycloneDXValidationError
from sbom_graph_model.spdx import SPDXProcessor, SPDXValidationError

from sbom_graph_api.config import get_config
from sbom_graph_api.routes.auth import auth_required

logger = logging.getLogger(__name__)

bp = Blueprint("ingest", __name__, url_prefix="/ingest")

MAX_SBOM_SIZE = 50 * 1024 * 1024  # 50 MB


def _create_persistence() -> Persistence:
    """Create a Persistence instance from the application FalkorDB config.

    Returns:
        A configured Persistence instance connected to FalkorDB.
    """
    config = get_config().falkordb
    internal_prefixes = Persistence.parse_internal_prefixes(
        os.environ.get("INTERNAL_PREFIXES", "")
    )

    return Persistence(
        host=config.host,
        port=config.port,
        graph_name=config.graph_name,
        password=config.password or "",
        ssl=config.ssl,
        ssl_ca_certs=config.ssl_ca_certs,
        internal_prefixes=internal_prefixes,
    )


def _derive_app_id(component_name: str) -> str:
    """Derive a deterministic app_id from the SBOM component name.

    Uses SHA-1 hex digest, matching the pattern used by the Sonatype
    lifecycle release listener.

    Args:
        component_name: The metadata.component.name from the CycloneDX SBOM.

    Returns:
        A hex string suitable for use as an app_id.
    """
    return hashlib.sha1(component_name.encode("utf-8")).hexdigest()  # noqa: S324


@bp.route("/cyclonedx", methods=["POST"])
@auth_required
def upload_cyclonedx() -> tuple[Response, int]:
    """Upload and process a CycloneDX SBOM.

    Accepts a JSON body containing a CycloneDX SBOM and optional metadata.
    Parses the SBOM and persists projects, dependencies, and defects to the
    graph database.

    Request JSON:
        sbom (dict): Required. The CycloneDX JSON document.
        app_id (str): Optional. Custom application ID. Defaults to SHA-1
            of metadata.component.name.
        public_app_id (str): Optional. Public application identifier.
            Defaults to metadata.component.name.
        project_url (str): Optional. URL of the source repository.

    Returns:
        201: SBOM processed successfully with summary counts.
        400: Missing or invalid request body.
        415: Request Content-Type is not application/json.
        422: CycloneDX structural validation failed.
        500: Unexpected processing error.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    sbom = body.get("sbom")
    if sbom is None:
        return jsonify({"error": "Missing required field: sbom"}), 400

    if not isinstance(sbom, dict):
        return jsonify({"error": "Field 'sbom' must be a JSON object"}), 400

    # Extract optional parameters; derive defaults from SBOM metadata
    metadata = sbom.get("metadata", {})
    component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    component_name = component.get("name", "") if isinstance(component, dict) else ""

    public_app_id = body.get("public_app_id") or component_name or "unknown"
    app_id = body.get("app_id") or _derive_app_id(public_app_id)
    project_url = body.get("project_url")

    try:
        persistence = _create_persistence()
        processor = CycloneDXProcessor(persistence=persistence)

        projects, dependency_versions, defects = processor.process_cyclone_dx_json(
            app_id=app_id,
            public_app_id=public_app_id,
            gitlab_project_url=project_url,
            json_data=sbom,
        )

        summary = {
            "status": "ok",
            "app_id": app_id,
            "public_app_id": public_app_id,
            "projects_count": len(projects),
            "dependencies_count": sum(len(deps) for deps in dependency_versions.values()),
            "defects_count": len(defects),
        }

        logger.info(
            "SBOM ingested: app_id=%s, projects=%d, deps=%d, defects=%d",
            app_id,
            summary["projects_count"],
            summary["dependencies_count"],
            summary["defects_count"],
        )

        return jsonify(summary), 201

    except CycloneDXValidationError as e:
        logger.warning("CycloneDX validation failed: %s", e)
        return jsonify({"error": "CycloneDX validation failed", "detail": str(e)}), 422

    except Exception:
        logger.exception("Unexpected error processing SBOM")
        return jsonify({"error": "An unexpected error occurred while processing the SBOM"}), 500


@bp.route("/vex", methods=["POST"])
@auth_required
def upload_vex() -> tuple[Response, int]:
    """Upload an OpenVEX document.

    Accepts a JSON body containing an OpenVEX document. Parses and
    persists VEX statements, linking them to existing Defect and
    Version nodes.

    Returns:
        JSON summary: ``{status, statements_count, linked_vulnerabilities}``.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    try:
        from sbom_graph_model.vex import VexProcessor, VexProcessingError
    except ImportError:
        return jsonify({"error": "VEX processing module not available"}), 503

    persistence = _create_persistence()

    try:
        processor = VexProcessor(persistence)
        result = processor.process_vex_document(body)
    except VexProcessingError as e:
        logger.warning("VEX document validation failed", exc_info=e)
        return jsonify({
            "error": "VEX document validation failed",
            "error_code": "VEX_VALIDATION_ERROR",
        }), 422
    except Exception:
        logger.exception("VEX processing failed")
        return jsonify({"error": "Internal error processing VEX document"}), 500

    return jsonify({
        "status": "ok",
        "statements_count": result["statements_processed"],
        "linked_vulnerabilities": result["linked_vulnerabilities"],
    }), 201


@bp.route("/spdx", methods=["POST"])
@auth_required
def upload_spdx() -> tuple[Response, int]:
    """Upload and process an SPDX 2.3 JSON SBOM.

    Accepts a JSON body containing an SPDX SBOM and optional metadata.
    Parses the SBOM and persists packages, dependencies, licenses, source
    repositories, and defects to the graph database.

    Request JSON:
        sbom (dict): Required. The SPDX JSON document.
        app_id (str): Optional. Custom application ID.
        public_app_id (str): Optional. Public application identifier.
        project_url (str): Optional. URL of the source repository.

    Returns:
        201: SBOM processed successfully with summary counts.
        400: Missing or invalid request body.
        415: Request Content-Type is not application/json.
        422: SPDX structural validation failed.
        500: Unexpected processing error.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    sbom = body.get("sbom")
    if sbom is None:
        return jsonify({"error": "Missing required field: sbom"}), 400

    if not isinstance(sbom, dict):
        return jsonify({"error": "Field 'sbom' must be a JSON object"}), 400

    doc_name = sbom.get("name", "")
    public_app_id = body.get("public_app_id") or doc_name or "unknown"
    app_id = body.get("app_id") or _derive_app_id(public_app_id)
    project_url = body.get("project_url")

    try:
        persistence = _create_persistence()
        processor = SPDXProcessor(persistence=persistence)

        packages, dependency_versions, defects = processor.process_spdx_json(
            app_id=app_id,
            public_app_id=public_app_id,
            project_url=project_url,
            json_data=sbom,
        )

        summary = {
            "status": "ok",
            "format": "spdx",
            "app_id": app_id,
            "public_app_id": public_app_id,
            "projects_count": len(packages),
            "dependencies_count": sum(len(deps) for deps in dependency_versions.values()),
            "defects_count": len(defects),
        }

        logger.info(
            "SPDX SBOM ingested: app_id=%s, projects=%d, deps=%d, defects=%d",
            app_id,
            summary["projects_count"],
            summary["dependencies_count"],
            summary["defects_count"],
        )

        return jsonify(summary), 201

    except SPDXValidationError as e:
        logger.warning("SPDX validation failed: %s", e)
        return jsonify({"error": "SPDX validation failed", "detail": str(e)}), 422

    except Exception:
        logger.exception("Unexpected error processing SPDX SBOM")
        return jsonify({"error": "An unexpected error occurred while processing the SBOM"}), 500


def _detect_sbom_format(sbom: dict) -> str | None:
    """Auto-detect the SBOM format from document structure.

    Returns:
        ``"cyclonedx"`` or ``"spdx"`` or ``None`` if unrecognised.
    """
    if "bomFormat" in sbom and sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in sbom:
        return "spdx"
    if "metadata" in sbom and "component" in sbom.get("metadata", {}):
        return "cyclonedx"
    return None


@bp.route("/sbom", methods=["POST"])
@auth_required
def upload_sbom() -> tuple[Response, int]:
    """Upload and process an SBOM in either CycloneDX or SPDX format.

    Auto-detects the SBOM format from the document structure and
    delegates to the appropriate processor.

    Request JSON:
        sbom (dict): Required. The SBOM JSON document.
        app_id (str): Optional. Custom application ID.
        public_app_id (str): Optional. Public application identifier.
        project_url (str): Optional. URL of the source repository.

    Returns:
        201: SBOM processed successfully.
        400: Missing fields or unrecognised SBOM format.
        415: Not application/json.
        422: Validation failed.
        500: Unexpected error.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    sbom = body.get("sbom")
    if sbom is None:
        return jsonify({"error": "Missing required field: sbom"}), 400

    if not isinstance(sbom, dict):
        return jsonify({"error": "Field 'sbom' must be a JSON object"}), 400

    detected_format = _detect_sbom_format(sbom)
    if detected_format is None:
        return jsonify({
            "error": "Unable to detect SBOM format. "
            "Provide a CycloneDX or SPDX 2.3 JSON document."
        }), 400

    persistence = _create_persistence()

    if detected_format == "cyclonedx":
        metadata = sbom.get("metadata", {})
        component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
        component_name = component.get("name", "") if isinstance(component, dict) else ""
        public_app_id = body.get("public_app_id") or component_name or "unknown"
        app_id = body.get("app_id") or _derive_app_id(public_app_id)
        project_url = body.get("project_url")

        try:
            processor = CycloneDXProcessor(persistence=persistence)
            projects, dep_v, defects = processor.process_cyclone_dx_json(
                app_id=app_id,
                public_app_id=public_app_id,
                gitlab_project_url=project_url,
                json_data=sbom,
            )
            return jsonify({
                "status": "ok",
                "format": "cyclonedx",
                "app_id": app_id,
                "public_app_id": public_app_id,
                "projects_count": len(projects),
                "dependencies_count": sum(len(d) for d in dep_v.values()),
                "defects_count": len(defects),
            }), 201
        except CycloneDXValidationError:
            logger.exception("CycloneDX SBOM validation error")
            return jsonify({"error": "CycloneDX validation failed"}), 422
        except Exception:
            logger.exception("Unexpected error processing CycloneDX SBOM")
            return jsonify({"error": "An unexpected error occurred"}), 500

    else:
        doc_name = sbom.get("name", "")
        public_app_id = body.get("public_app_id") or doc_name or "unknown"
        app_id = body.get("app_id") or _derive_app_id(public_app_id)
        project_url = body.get("project_url")

        try:
            processor = SPDXProcessor(persistence=persistence)
            packages, dep_v, defects = processor.process_spdx_json(
                app_id=app_id,
                public_app_id=public_app_id,
                project_url=project_url,
                json_data=sbom,
            )
            return jsonify({
                "status": "ok",
                "format": "spdx",
                "app_id": app_id,
                "public_app_id": public_app_id,
                "projects_count": len(packages),
                "dependencies_count": sum(len(d) for d in dep_v.values()),
                "defects_count": len(defects),
            }), 201
        except SPDXValidationError as e:
            logger.exception("SPDX validation failed during SBOM upload")
            return jsonify({"error": "SPDX validation failed"}), 422
        except Exception:
            logger.exception("Unexpected error processing SPDX SBOM")
            return jsonify({"error": "An unexpected error occurred"}), 500
