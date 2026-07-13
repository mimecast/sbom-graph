"""SBOM ingestion routes.

Provides endpoints for uploading CycloneDX and SPDX SBOM files and an
OpenVEX document.  By default the heavy parse-and-persist work is
delegated to the dedicated ``ingest`` Celery worker pool so that Flask
request workers are freed immediately (returns ``202 Accepted`` with a
job id).  A synchronous escape hatch (``?sync=true``) preserves the
legacy ``201`` behaviour for callers that genuinely need to block on
completion.

See :mod:`sbom_graph_enrichment.ingest_tasks` for the worker side.
"""

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from celery.result import AsyncResult
from flask import Blueprint, Response, jsonify, request
from sbom_graph_model import Persistence
from sbom_graph_model.cyclonedx import CycloneDXProcessor, CycloneDXValidationError
from sbom_graph_model.spdx import SPDXProcessor, SPDXValidationError

from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.schemas.inbound import SBOM_UPLOAD_SCHEMA, VEX_UPLOAD_SCHEMA
from sbom_graph_api.services.celery_client import get_celery_client
from sbom_graph_api.services.ingestion_persistence import create_ingestion_persistence
from sbom_graph_api.utils.validation import validate_json_body

logger = logging.getLogger(__name__)

bp = Blueprint("ingest", __name__, url_prefix="/ingest")

MAX_SBOM_SIZE = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _derive_app_id(component_name: str) -> str:
    """Derive a deterministic ``app_id`` from a component name via SHA-1.

    Matches the pattern used by the Sonatype lifecycle release listener.
    """
    return hashlib.sha1(component_name.encode("utf-8")).hexdigest()  # noqa: S324  # nosec B324


def _should_run_sync() -> bool:
    """Return ``True`` when the caller explicitly opted into synchronous mode.

    The escape hatch exists so that callers without async support (legacy
    scripts, debug sessions, tests for very small SBOMs) can keep the
    pre-existing behaviour. See ``docs/sbom-graph-api-troubleshooting.md``
    §10 for the rationale.
    """
    flag = request.args.get("sync", "").strip().lower()
    return flag in {"1", "true", "yes"}


def _enqueue_async(
    task_name: str,
    args: list[Any],
    record_id: str,
    format_hint: str | None,
) -> tuple[Response, int]:
    """Enqueue a worker task on the high-priority ``ingest`` queue.

    Returns a ``202 Accepted`` response with the job id and a polling
    URL.  When the broker is unreachable or the Celery client fails to
    initialise the endpoint degrades to ``503`` -- mirroring the
    fallback used by ``/api/v1/enrich/vulnerabilities``.

    The API never imports any ``sbom_graph_enrichment`` symbols; the
    task name + queue is the only contract between the two packages.
    See ``sbom_graph_api.services.celery_client`` and
    ``docs/ingest-pipeline.md`` for the full design and threat model.
    """
    try:
        from sbom_graph_api.services.celery_client import get_celery_client

        celery_app = get_celery_client()
        async_result = celery_app.send_task(task_name, args=args, queue="ingest")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # CWE-209: never propagate the underlying broker/celery exception
        # to the client.  Log a typed summary, return a static message.
        logger.error(
            "Failed to enqueue ingest task %s: %s",
            task_name,
            exc.__class__.__name__,
        )
        return jsonify({"error": "Ingest pipeline not available"}), 503

    payload: dict[str, Any] = {
        "status": "accepted",
        "record_id": record_id,
        "job_id": async_result.id,
        "status_url": f"/ingest/jobs/{async_result.id}",
    }
    if format_hint is not None:
        payload["format"] = format_hint

    logger.info(
        "SBOM ingest enqueued: record_id=%s job_id=%s task=%s",
        record_id,
        async_result.id,
        task_name,
    )

    response = jsonify(payload)
    response.headers["Location"] = payload["status_url"]
    return response, 202


# Mapping of Celery task states → public status string.  Keeps the API
# contract independent of the underlying broker; we never expose Celery
# internals directly to clients.
_TERMINAL_STATES = {"SUCCESS", "FAILURE", "REVOKED"}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@bp.route("/cyclonedx", methods=["POST"])
@auth_required
def upload_cyclonedx() -> tuple[Response, int]:
    """Upload a CycloneDX SBOM (async by default, ``?sync=true`` for inline).

    Request JSON:
        sbom (dict): Required. The CycloneDX JSON document.
        app_id (str): Optional. Defaults to SHA-1 of metadata.component.name.
        public_app_id (str): Optional. Defaults to metadata.component.name.
        project_url (str): Optional. URL of the source repository.

    Query string:
        sync (bool): Optional. ``true`` to run inline and return ``201``;
            default ``false`` returns ``202`` with a job id.

    Returns:
        202: Job accepted (default async path).
        201: SBOM processed inline (``?sync=true``).
        400: Missing or invalid request body.
        415: Content-Type not application/json.
        422: CycloneDX structural validation failed (sync path only).
        500: Unexpected processing error (sync path only).
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    sbom = body["sbom"]
    metadata = sbom.get("metadata", {})
    component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    component_name = component.get("name", "") if isinstance(component, dict) else ""

    public_app_id = body.get("public_app_id") or component_name or "unknown"
    app_id = body.get("app_id") or _derive_app_id(public_app_id)
    project_url = body.get("project_url")

    record_id = str(uuid.uuid4())

    if not _should_run_sync():
        return _enqueue_async(
            task_name="sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx",
            args=[record_id, sbom, app_id, public_app_id, project_url, "api_upload"],
            record_id=record_id,
            format_hint="cyclonedx",
        )

    return _run_cyclonedx_inline(
        record_id=record_id,
        sbom=sbom,
        app_id=app_id,
        public_app_id=public_app_id,
        project_url=project_url,
    )


@bp.route("/spdx", methods=["POST"])
@auth_required
def upload_spdx() -> tuple[Response, int]:
    """Upload an SPDX 2.3 SBOM (async by default, ``?sync=true`` for inline)."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    sbom = body["sbom"]
    doc_name = sbom.get("name", "")
    public_app_id = body.get("public_app_id") or doc_name or "unknown"
    app_id = body.get("app_id") or _derive_app_id(public_app_id)
    project_url = body.get("project_url")

    record_id = str(uuid.uuid4())

    if not _should_run_sync():
        return _enqueue_async(
            task_name="sbom_graph_enrichment.ingest_tasks.ingest_spdx",
            args=[record_id, sbom, app_id, public_app_id, project_url, "api_upload"],
            record_id=record_id,
            format_hint="spdx",
        )

    return _run_spdx_inline(
        record_id=record_id,
        sbom=sbom,
        app_id=app_id,
        public_app_id=public_app_id,
        project_url=project_url,
    )


@bp.route("/sbom", methods=["POST"])
@auth_required
def upload_sbom() -> tuple[Response, int]:
    """Upload an SBOM in either CycloneDX or SPDX format with auto-detection."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    sbom = body["sbom"]
    detected_format = _detect_sbom_format(sbom)
    if detected_format is None:
        return jsonify(
            {
                "error": "Unable to detect SBOM format. "
                "Provide a CycloneDX or SPDX 2.3 JSON document."
            }
        ), 400

    if detected_format == "cyclonedx":
        metadata = sbom.get("metadata", {})
        component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
        component_name = component.get("name", "") if isinstance(component, dict) else ""
        public_app_id = body.get("public_app_id") or component_name or "unknown"
    else:
        doc_name = sbom.get("name", "")
        public_app_id = body.get("public_app_id") or doc_name or "unknown"

    app_id = body.get("app_id") or _derive_app_id(public_app_id)
    project_url = body.get("project_url")
    record_id = str(uuid.uuid4())

    if not _should_run_sync():
        return _enqueue_async(
            task_name="sbom_graph_enrichment.ingest_tasks.ingest_sbom",
            args=[record_id, sbom, app_id, public_app_id, project_url, "api_upload"],
            record_id=record_id,
            format_hint=detected_format,
        )

    if detected_format == "cyclonedx":
        return _run_cyclonedx_inline(
            record_id=record_id,
            sbom=sbom,
            app_id=app_id,
            public_app_id=public_app_id,
            project_url=project_url,
        )
    return _run_spdx_inline(
        record_id=record_id,
        sbom=sbom,
        app_id=app_id,
        public_app_id=public_app_id,
        project_url=project_url,
    )


@bp.route("/vex", methods=["POST"])
@auth_required
def upload_vex() -> tuple[Response, int]:
    """Upload an OpenVEX document (async by default)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    errors = validate_json_body(body, VEX_UPLOAD_SCHEMA)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    if not _should_run_sync():
        return _enqueue_async(
            task_name="sbom_graph_enrichment.ingest_tasks.ingest_vex",
            args=[body],
            record_id=str(uuid.uuid4()),  # informational only for VEX
            format_hint=None,
        )

    return _run_vex_inline(body)


@bp.route("/jobs/<job_id>", methods=["GET"])
@auth_required
def get_ingest_job(job_id: str) -> tuple[Response, int]:
    """Return the status of an asynchronous ingest job.

    Path:
        job_id: The ``job_id`` returned from a prior async ``POST /ingest/*``.

    Returns:
        200: Job state plus, when terminal, the same summary dict the
            synchronous path would have produced.
        400: ``job_id`` is not a valid UUID.
        404: Job is unknown to the result backend.  Note that Celery's
            Redis backend returns ``PENDING`` for unknown ids; we map a
            ``PENDING`` state older than the broker's ``result_expires``
            window to ``404`` if needed, but for now we return the raw
            state and let the caller poll.
        503: Enrichment pipeline (Celery) not installed in this image.
    """
    # Validate the job id shape up-front so an attacker can't use this
    # endpoint to probe arbitrary backend keys.
    try:
        uuid.UUID(job_id)
    except (ValueError, AttributeError):
        return jsonify({"error": "Invalid job id"}), 400

    try:
        celery_app = get_celery_client()
        result = AsyncResult(job_id, app=celery_app)
        state = result.state
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # CWE-209: never propagate the underlying broker/celery exception.
        logger.error(
            "Failed to query ingest job state: %s",
            exc.__class__.__name__,
        )
        return jsonify({"error": "Ingest pipeline not available"}), 503

    payload: dict[str, Any] = {
        "job_id": job_id,
        "state": state,
        "terminal": state in _TERMINAL_STATES,
    }

    if state == "SUCCESS":
        # ``result`` is the dict returned by the worker task -- pass it
        # through verbatim since it's already sanitised for caller view.
        payload["result"] = result.result
    elif state == "FAILURE":
        # The worker tasks catch their own exceptions and return a
        # sanitised ``{"status": "error", "error": ...}`` dict; an actual
        # ``FAILURE`` state means an uncaught exception or worker crash.
        # Do not propagate the raw exception (CWE-209).
        logger.warning("Ingest job %s failed in worker; see worker logs", job_id)
        payload["result"] = {"status": "error", "error": "Ingest job failed; see server logs"}

    return jsonify(payload), 200


# ---------------------------------------------------------------------------
# Synchronous fallbacks.  These keep the legacy ``201`` behaviour for
# callers that pass ``?sync=true``.  Implementation is the same code that
# previously lived inline in each route handler -- now factored out so the
# async path can stay tightly focused on validate-and-enqueue.
# ---------------------------------------------------------------------------


def _extract_cyclonedx_tool_info(sbom: dict) -> tuple[str | None, str | None]:
    """Return ``(tool_name, tool_version)`` from a CycloneDX document."""
    metadata = sbom.get("metadata") or {}
    if not isinstance(metadata, dict):
        return None, None

    tools = metadata.get("tools")
    if tools is None:
        return None, None

    if isinstance(tools, dict):
        components = tools.get("components")
        if isinstance(components, list) and components:
            first = components[0]
            if isinstance(first, dict):
                return (
                    first.get("name") if isinstance(first.get("name"), str) else None,
                    first.get("version") if isinstance(first.get("version"), str) else None,
                )
        return None, None

    if isinstance(tools, list) and tools:
        first = tools[0]
        if isinstance(first, dict):
            name = first.get("name")
            version = first.get("version")
            return (
                name if isinstance(name, str) else None,
                version if isinstance(version, str) else None,
            )
    return None, None


def _parse_spdx_tool_creator(value: str) -> tuple[str | None, str | None]:
    """Split an SPDX ``Tool:`` creator string into ``(name, version)``.

    Uses plain string ops to avoid ReDoS (CWE-1333).
    """
    if not value:
        return None, None

    dash_idx = value.rfind("-")
    if 0 < dash_idx < len(value) - 1:
        candidate = value[dash_idx + 1:]
        if candidate[0].isdigit() and all(c.isdigit() or c == "." for c in candidate):
            name = value[:dash_idx].strip() or None
            return name, candidate

    return value or None, None


def _extract_spdx_tool_info(sbom: dict) -> tuple[str | None, str | None]:
    """Return ``(tool_name, tool_version)`` from an SPDX document."""
    creation_info = sbom.get("creationInfo") or {}
    if not isinstance(creation_info, dict):
        return None, None

    creators = creation_info.get("creators")
    if not isinstance(creators, list):
        return None, None

    for creator in creators:
        if not isinstance(creator, str):
            continue
        stripped = creator.strip()
        if not stripped.lower().startswith("tool:"):
            continue
        tool_value = stripped[5:].strip()
        name, version = _parse_spdx_tool_creator(tool_value)
        if name:
            return name, version
    return None, None


def _link_versions_to_sbom_record(
    persistence: Persistence,
    projects: dict[str, tuple[Any, Any]],
    record_id: str,
) -> None:
    """Link every project version to the SBOM record."""
    for _bom_ref, (project, version) in projects.items():
        if project.purl:
            persistence.link_version_to_sbom_record(project.purl, record_id)
        elif project.name and version.version:
            persistence.link_version_to_sbom_record_by_name(
                project.name,
                project.group,
                version.version,
                record_id,
            )


def _detect_sbom_format(sbom: dict) -> str | None:
    """Return ``"cyclonedx"`` / ``"spdx"`` or ``None`` if unrecognised."""
    if "bomFormat" in sbom and sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in sbom:
        return "spdx"
    if "metadata" in sbom and "component" in sbom.get("metadata", {}):
        return "cyclonedx"
    return None


def _run_cyclonedx_inline(
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None,
) -> tuple[Response, int]:
    """Synchronous CycloneDX processing path (`?sync=true`)."""
    try:
        persistence = create_ingestion_persistence()
        processor = CycloneDXProcessor(persistence=persistence)

        projects, dependency_versions, defects = processor.process_cyclone_dx_json(
            app_id=app_id,
            public_app_id=public_app_id,
            gitlab_project_url=project_url,
            json_data=sbom,
        )

        ingested_at = datetime.now(UTC).isoformat()
        document_hash = hashlib.sha256(
            json.dumps(sbom, sort_keys=True).encode("utf-8")
        ).hexdigest()
        tool_name, tool_version = _extract_cyclonedx_tool_info(sbom)
        serial_number = (
            sbom.get("serialNumber") if isinstance(sbom.get("serialNumber"), str) else None
        )

        persistence.create_sbom_record(
            record_id=record_id,
            sbom_format="cyclonedx",
            ingested_at=ingested_at,
            source="api_upload",
            tool_name=tool_name,
            tool_version=tool_version,
            serial_number=serial_number,
            document_hash=document_hash,
        )
        _link_versions_to_sbom_record(persistence, projects, record_id)

        summary = {
            "status": "ok",
            "record_id": record_id,
            "format": "cyclonedx",
            "app_id": app_id,
            "public_app_id": public_app_id,
            "projects_count": len(projects),
            "dependencies_count": sum(len(deps) for deps in dependency_versions.values()),
            "defects_count": len(defects),
        }

        logger.info(
            "CycloneDX SBOM ingested (sync): record_id=%s app_id=%s, "
            "projects=%d, deps=%d, defects=%d",
            record_id,
            app_id,
            summary["projects_count"],
            summary["dependencies_count"],
            summary["defects_count"],
        )

        return jsonify(summary), 201

    except CycloneDXValidationError as e:
        logger.warning("CycloneDX validation failed: %s", e)
        return jsonify({"error": "CycloneDX validation failed"}), 422

    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Unexpected error processing SBOM")
        return jsonify(
            {"error": "An unexpected error occurred while processing the SBOM"}
        ), 500


def _run_spdx_inline(
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None,
) -> tuple[Response, int]:
    """Synchronous SPDX processing path (`?sync=true`)."""
    try:
        persistence = create_ingestion_persistence()
        processor = SPDXProcessor(persistence=persistence)

        packages, dependency_versions, defects = processor.process_spdx_json(
            app_id=app_id,
            public_app_id=public_app_id,
            project_url=project_url,
            json_data=sbom,
        )

        ingested_at = datetime.now(UTC).isoformat()
        document_hash = hashlib.sha256(
            json.dumps(sbom, sort_keys=True).encode("utf-8")
        ).hexdigest()
        tool_name, tool_version = _extract_spdx_tool_info(sbom)

        persistence.create_sbom_record(
            record_id=record_id,
            sbom_format="spdx",
            ingested_at=ingested_at,
            source="api_upload",
            tool_name=tool_name,
            tool_version=tool_version,
            serial_number=None,
            document_hash=document_hash,
        )
        _link_versions_to_sbom_record(persistence, packages, record_id)

        summary = {
            "status": "ok",
            "record_id": record_id,
            "format": "spdx",
            "app_id": app_id,
            "public_app_id": public_app_id,
            "projects_count": len(packages),
            "dependencies_count": sum(len(deps) for deps in dependency_versions.values()),
            "defects_count": len(defects),
        }

        logger.info(
            "SPDX SBOM ingested (sync): record_id=%s app_id=%s, "
            "projects=%d, deps=%d, defects=%d",
            record_id,
            app_id,
            summary["projects_count"],
            summary["dependencies_count"],
            summary["defects_count"],
        )

        return jsonify(summary), 201

    except SPDXValidationError as e:
        logger.warning("SPDX validation failed: %s", e)
        return jsonify({"error": "SPDX validation failed"}), 422

    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Unexpected error processing SPDX SBOM")
        return jsonify(
            {"error": "An unexpected error occurred while processing the SBOM"}
        ), 500


def _run_vex_inline(body: dict) -> tuple[Response, int]:
    """Synchronous VEX processing path (`?sync=true`)."""
    try:
        from sbom_graph_model.vex import VexProcessingError, VexProcessor
    except ImportError:
        return jsonify({"error": "VEX processing module not available"}), 503

    persistence = create_ingestion_persistence()

    try:
        processor = VexProcessor(persistence)
        result = processor.process_vex_document(body)
    except VexProcessingError as e:
        logger.warning("VEX document validation failed", exc_info=e)
        return jsonify(
            {
                "error": "VEX document validation failed",
                "error_code": "VEX_VALIDATION_ERROR",
            }
        ), 422
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("VEX processing failed")
        return jsonify({"error": "Internal error processing VEX document"}), 500

    return jsonify(
        {
            "status": "ok",
            "statements_count": result["statements_processed"],
            "linked_vulnerabilities": result["linked_vulnerabilities"],
        }
    ), 201
