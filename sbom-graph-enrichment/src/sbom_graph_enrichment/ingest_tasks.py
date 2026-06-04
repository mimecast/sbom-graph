"""Celery tasks for asynchronous SBOM ingestion.

These tasks accept the same payload shape as the synchronous
``/ingest/*`` REST handlers in ``sbom-graph-api``, but run inside a
dedicated Celery worker pool (``-Q ingest``) so that long-running
parse-and-persist work cannot saturate Flask request workers or stall
behind in-flight enrichment jobs.

Design rationale
----------------

* **True priority over enrichment.**  The deployment topology runs a
  separate worker pool that listens *only* on the ``ingest`` queue
  (``helm/charts/sbom-graph/templates/enrichment-ingest-worker-deployment.yaml``).
  An ingest task never waits behind an
  :func:`~sbom_graph_enrichment.tasks.enrich_all_packages` call -- a
  shared pool with ``-Q ingest,enrichment`` would only re-check queue
  order *between* tasks, which is not the same as priority.

* **JSON-only serialisation.**  The Celery app is configured with
  ``accept_content=["json"]`` (see
  :mod:`sbom_graph_enrichment.celery_app`), so payloads cannot smuggle
  pickled objects through the broker.

* **Logging hygiene.**  Errors are logged with the full stack at
  ``ERROR`` level inside the worker and propagated to the result
  backend as a static, sanitised error message.  No exception details
  leak to API callers (CWE-209 / CWE-497).

* **Per-process resource caching.**  Each prefork child has its own
  :class:`~sbom_graph_model.Persistence` and HTTP client created via
  the ``worker_process_init`` signal -- see
  :mod:`sbom_graph_enrichment.persistence_helpers`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from celery import shared_task
from sbom_graph_model import Persistence
from sbom_graph_model.cyclonedx import CycloneDXProcessor, CycloneDXValidationError
from sbom_graph_model.spdx import SPDXProcessor, SPDXValidationError

from .persistence_helpers import get_persistence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers lifted verbatim from sbom-graph-api routes/ingest.py.  Keeping the
# logic identical preserves byte-for-byte behaviour when migrating callers
# from synchronous to asynchronous ingest.
# ---------------------------------------------------------------------------


def _derive_app_id(component_name: str) -> str:
    """Derive a deterministic ``app_id`` from a component name via SHA-1.

    Matches the pattern used by the Sonatype lifecycle release listener.
    """
    return hashlib.sha1(component_name.encode("utf-8")).hexdigest()  # noqa: S324  # nosec B324


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


def _document_hash(sbom: dict) -> str:
    """Stable SHA-256 hash of the canonicalised SBOM JSON."""
    return hashlib.sha256(json.dumps(sbom, sort_keys=True).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    """Current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Core processing functions -- pure, callable from anywhere (worker, test,
# or the synchronous escape hatch in the API).
# ---------------------------------------------------------------------------


def process_cyclonedx(
    persistence: Persistence,
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None,
    source: str = "api_upload",
) -> dict[str, Any]:
    """Parse a CycloneDX SBOM and persist its contents.

    Args:
        persistence: Connected :class:`Persistence`.
        record_id: Pre-computed SBOM record UUID; the API allocates this
            up-front so it can return it to the caller before enqueueing.
        sbom: The CycloneDX JSON document.
        app_id: Internal application identifier.
        public_app_id: Human-readable application name.
        project_url: Optional source-repo URL.
        source: Free-form provenance marker (defaults to ``api_upload``).

    Returns:
        Summary dict in the same shape as the legacy ``201`` response.

    Raises:
        CycloneDXValidationError: When the document fails structural checks.
    """
    processor = CycloneDXProcessor(persistence=persistence)
    projects, dependency_versions, defects = processor.process_cyclone_dx_json(
        app_id=app_id,
        public_app_id=public_app_id,
        gitlab_project_url=project_url,
        json_data=sbom,
    )

    tool_name, tool_version = _extract_cyclonedx_tool_info(sbom)
    serial_number = sbom.get("serialNumber") if isinstance(sbom.get("serialNumber"), str) else None

    persistence.create_sbom_record(
        record_id=record_id,
        sbom_format="cyclonedx",
        ingested_at=_now_iso(),
        source=source,
        tool_name=tool_name,
        tool_version=tool_version,
        serial_number=serial_number,
        document_hash=_document_hash(sbom),
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
        "CycloneDX SBOM ingested: record_id=%s app_id=%s, projects=%d, deps=%d, defects=%d",
        record_id,
        app_id,
        summary["projects_count"],
        summary["dependencies_count"],
        summary["defects_count"],
    )
    return summary


def process_spdx(
    persistence: Persistence,
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None,
    source: str = "api_upload",
) -> dict[str, Any]:
    """Parse an SPDX 2.3 SBOM and persist its contents.

    Args:
        persistence: Connected :class:`Persistence`.
        record_id: Pre-computed SBOM record UUID.
        sbom: The SPDX JSON document.
        app_id: Internal application identifier.
        public_app_id: Human-readable application name.
        project_url: Optional source-repo URL.
        source: Free-form provenance marker.

    Returns:
        Summary dict matching the legacy ``201`` response shape.

    Raises:
        SPDXValidationError: When the document fails structural checks.
    """
    processor = SPDXProcessor(persistence=persistence)
    packages, dependency_versions, defects = processor.process_spdx_json(
        app_id=app_id,
        public_app_id=public_app_id,
        project_url=project_url,
        json_data=sbom,
    )

    tool_name, tool_version = _extract_spdx_tool_info(sbom)

    persistence.create_sbom_record(
        record_id=record_id,
        sbom_format="spdx",
        ingested_at=_now_iso(),
        source=source,
        tool_name=tool_name,
        tool_version=tool_version,
        serial_number=None,
        document_hash=_document_hash(sbom),
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
        "SPDX SBOM ingested: record_id=%s app_id=%s, projects=%d, deps=%d, defects=%d",
        record_id,
        app_id,
        summary["projects_count"],
        summary["dependencies_count"],
        summary["defects_count"],
    )
    return summary


def detect_sbom_format(sbom: dict) -> str | None:
    """Return ``"cyclonedx"`` / ``"spdx"`` or ``None`` if unrecognised."""
    if "bomFormat" in sbom and sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in sbom:
        return "spdx"
    if "metadata" in sbom and "component" in sbom.get("metadata", {}):
        return "cyclonedx"
    return None


# ---------------------------------------------------------------------------
# Celery task wrappers.  These run inside the ``ingest`` worker pool and are
# the only public entry points called via ``.apply_async(queue="ingest")``
# from the API.
# ---------------------------------------------------------------------------


def _safe_error(message: str) -> dict[str, Any]:
    """Build a sanitised error result for return through the broker.

    Per AGENTS.md and CWE-209, exception detail must not flow to HTTP
    callers.  The detail is already logged inside the worker.
    """
    return {"status": "error", "error": message}


@shared_task(name="sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx")
def ingest_cyclonedx(
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None = None,
    source: str = "api_upload",
) -> dict[str, Any]:
    """Worker entry point for a CycloneDX ingest job.

    Designed to be invoked via
    ``ingest_cyclonedx.apply_async(args=[...], queue="ingest")`` from the
    API.  Returns the same summary dict the legacy synchronous handler
    produced, so existing test fixtures and clients see no schema change.
    """
    persistence = get_persistence()
    try:
        return process_cyclonedx(
            persistence,
            record_id=record_id,
            sbom=sbom,
            app_id=app_id,
            public_app_id=public_app_id,
            project_url=project_url,
            source=source,
        )
    except CycloneDXValidationError:
        logger.warning("CycloneDX validation failed for record_id=%s", record_id)
        return _safe_error("CycloneDX validation failed")
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("CycloneDX ingest task failed for record_id=%s", record_id)
        return _safe_error("An unexpected error occurred while processing the SBOM")


@shared_task(name="sbom_graph_enrichment.ingest_tasks.ingest_spdx")
def ingest_spdx(
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None = None,
    source: str = "api_upload",
) -> dict[str, Any]:
    """Worker entry point for an SPDX 2.3 ingest job."""
    persistence = get_persistence()
    try:
        return process_spdx(
            persistence,
            record_id=record_id,
            sbom=sbom,
            app_id=app_id,
            public_app_id=public_app_id,
            project_url=project_url,
            source=source,
        )
    except SPDXValidationError:
        logger.warning("SPDX validation failed for record_id=%s", record_id)
        return _safe_error("SPDX validation failed")
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("SPDX ingest task failed for record_id=%s", record_id)
        return _safe_error("An unexpected error occurred while processing the SBOM")


@shared_task(name="sbom_graph_enrichment.ingest_tasks.ingest_sbom")
def ingest_sbom(
    record_id: str,
    sbom: dict,
    app_id: str,
    public_app_id: str,
    project_url: str | None = None,
    source: str = "api_upload",
) -> dict[str, Any]:
    """Auto-detect format and dispatch to the appropriate processor.

    Mirrors the legacy ``POST /ingest/sbom`` handler.  Format detection
    is intentionally identical to the synchronous path so callers can
    flip between sync and async without behaviour drift.
    """
    detected_format = detect_sbom_format(sbom)
    if detected_format is None:
        logger.warning("Ingest task could not detect SBOM format: record_id=%s", record_id)
        return _safe_error(
            "Unable to detect SBOM format. "
            "Provide a CycloneDX or SPDX 2.3 JSON document."
        )

    if detected_format == "cyclonedx":
        return ingest_cyclonedx(
            record_id=record_id,
            sbom=sbom,
            app_id=app_id,
            public_app_id=public_app_id,
            project_url=project_url,
            source=source,
        )

    return ingest_spdx(
        record_id=record_id,
        sbom=sbom,
        app_id=app_id,
        public_app_id=public_app_id,
        project_url=project_url,
        source=source,
    )


@shared_task(name="sbom_graph_enrichment.ingest_tasks.ingest_vex")
def ingest_vex(document: dict) -> dict[str, Any]:
    """Worker entry point for an OpenVEX document.

    Returns the legacy summary shape:
    ``{status, statements_count, linked_vulnerabilities}``.
    """
    try:
        from sbom_graph_model.vex import VexProcessingError, VexProcessor
    except ImportError:
        logger.error("VEX processing module not available in worker image")
        return _safe_error("VEX processing module not available")

    persistence = get_persistence()
    try:
        processor = VexProcessor(persistence)
        result = processor.process_vex_document(document)
    except VexProcessingError:
        logger.warning("VEX document validation failed")
        return {"status": "error", "error": "VEX document validation failed",
                "error_code": "VEX_VALIDATION_ERROR"}
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("VEX ingest task failed")
        return _safe_error("Internal error processing VEX document")

    return {
        "status": "ok",
        "statements_count": result["statements_processed"],
        "linked_vulnerabilities": result["linked_vulnerabilities"],
    }
