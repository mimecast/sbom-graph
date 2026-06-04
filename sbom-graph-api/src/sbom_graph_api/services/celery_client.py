"""Thin Celery client used by the API to enqueue ingest jobs.

The API never imports any symbols from ``sbom_graph_enrichment``.  Its
contract with the worker is just three things:

* the broker URL (same Redis the FalkorDB instance hosts),
* the task name (``sbom_graph_enrichment.ingest_tasks.<...>``),
* the queue (``ingest``).

This keeps the API image lean — no enrichment HTTP clients,
deps.dev/OSV/etc. logic, or scheduler — and means a broken or missing
worker package is invisible to the API except as ``AsyncResult.state``
never leaving ``PENDING``.

Configuration mirrors ``sbom_graph_enrichment.celery_app`` so the two
processes agree on broker/result DBs, TLS, and result expiry.  See
``docs/ingest-pipeline.md`` for the design rationale and threat model.
"""

from __future__ import annotations

import logging
import os
import re
import ssl
import threading
from typing import Any

from celery import Celery

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection material
# ---------------------------------------------------------------------------

# The worker uses ``FALKORDB_HOST/PORT/PASSWORD`` (same Redis instance);
# the API container already has the same variables wired in via the chart.
_DEFAULT_BROKER_DB = "1"
_DEFAULT_RESULT_DB = "2"

# We never let the password be ``None``; an empty string disables auth in
# the URL just like the worker.
_REDIS_HOST = os.environ.get("FALKORDB_HOST", "localhost") or "localhost"
_REDIS_PORT = os.environ.get("FALKORDB_PORT", "6379") or "6379"
_REDIS_PASSWORD = os.environ.get("FALKORDB_PASSWORD", "") or ""
_BROKER_DB = os.environ.get("CELERY_BROKER_DB", _DEFAULT_BROKER_DB) or _DEFAULT_BROKER_DB
_RESULT_DB = os.environ.get("CELERY_RESULT_DB", _DEFAULT_RESULT_DB) or _DEFAULT_RESULT_DB

# Honour either the API-side ``FALKORDB_SSL`` (already set in the chart)
# or the worker-side ``CELERY_REDIS_SSL`` for symmetry.
_REDIS_SSL = (
    os.environ.get("FALKORDB_SSL", os.environ.get("CELERY_REDIS_SSL", "false"))
    .lower()
    == "true"
)


def _build_url(db: str) -> str:
    """Build a single ``rediss?://...`` URL for either broker or backend."""
    scheme = "rediss" if _REDIS_SSL else "redis"
    auth = f":{_REDIS_PASSWORD}@" if _REDIS_PASSWORD else ""
    return f"{scheme}://{auth}{_REDIS_HOST}:{_REDIS_PORT}/{db}"


def _build_ssl_opts() -> dict[str, object]:
    """Return Redis-SSL options matching the API's existing FALKORDB_* config.

    Falls back to the worker-side ``FALKORDB_CACERTS`` name if the API
    container ever switches to that schema.
    """
    opts: dict[str, object] = {"ssl_cert_reqs": ssl.CERT_REQUIRED}

    ca_certs = os.environ.get("FALKORDB_CA_FILE") or os.environ.get("FALKORDB_CACERTS")
    if ca_certs:
        opts["ssl_ca_certs"] = ca_certs

    client_cert = os.environ.get("FALKORDB_CLIENT_CERT")
    client_key = os.environ.get("FALKORDB_CLIENT_KEY")
    if client_cert:
        opts["ssl_certfile"] = client_cert
    if client_key:
        opts["ssl_keyfile"] = client_key

    return opts


# ---------------------------------------------------------------------------
# Defence-in-depth: redact Redis URL credentials in any log output.
# Mirrors the worker's _RedactSecretsFilter (CWE-209/CWE-532).
# ---------------------------------------------------------------------------
_REDIS_URL_RE = re.compile(r"(rediss?://):.+@(?=[\w.-]+:\d)")


class _RedactSecretsFilter(logging.Filter):
    """Replace ``redis://:password@host`` with ``redis://:*****@host``."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (
                        _REDIS_URL_RE.sub(r"\1:*****@", str(v))
                        if isinstance(v, str)
                        else v
                    )
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    _REDIS_URL_RE.sub(r"\1:*****@", str(a))
                    if isinstance(a, str)
                    else a
                    for a in record.args
                )
        if isinstance(record.msg, str):
            record.msg = _REDIS_URL_RE.sub(r"\1:*****@", record.msg)
        return True


# Attach once at import so we never log a Redis password.  Idempotent --
# logging.Filter equality is by identity, so re-attaching the same
# instance is a no-op even under module reloads.
_REDACTOR = _RedactSecretsFilter()
for _name in ("celery", "kombu"):
    _logger = logging.getLogger(_name)
    if _REDACTOR not in _logger.filters:
        _logger.addFilter(_REDACTOR)


# ---------------------------------------------------------------------------
# Lazy, thread-safe singleton.  Built on first use so unit tests can
# patch env vars without paying the Celery-import cost at module load.
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_celery_app: Celery | None = None


def _build_app() -> Celery:
    """Construct the Celery client.  Called under ``_lock``."""
    broker_url = _build_url(_BROKER_DB)
    result_url = _build_url(_RESULT_DB)

    app = Celery("sbom_graph_api_ingest_client")

    conf: dict[str, Any] = {
        "broker_url": broker_url,
        "result_backend": result_url,
        # Keep the on-the-wire format identical to the worker -- mismatched
        # serializers cause silent deserialisation failures at the worker.
        "task_serializer": "json",
        "accept_content": ["json"],
        "result_serializer": "json",
        "result_expires": 86400,
        "timezone": "UTC",
        "enable_utc": True,
        "broker_connection_retry_on_startup": True,
        # The API only enqueues; it never runs tasks.  Setting a default
        # queue means an accidental ``send_task`` without ``queue=`` lands
        # on the ingest pool rather than the general-purpose pool.
        "task_default_queue": "ingest",
    }

    if _REDIS_SSL:
        ssl_opts = _build_ssl_opts()
        conf["broker_use_ssl"] = ssl_opts
        conf["redis_backend_use_ssl"] = ssl_opts

    app.conf.update(conf)
    logger.info(
        "Initialised ingest Celery client: broker=%s result=%s ssl=%s",
        broker_url,
        result_url,
        _REDIS_SSL,
    )
    return app


def get_celery_client() -> Celery:
    """Return the process-wide Celery client used to enqueue ingest jobs.

    Thread-safe.  The client is built lazily on first call so that tests
    that swap env vars before importing routes get a fresh configuration
    if they also call :func:`clear_celery_client`.

    Raises:
        RuntimeError: if Celery itself fails to construct.  Callers should
            translate this into ``HTTP 503`` -- treating it the same as a
            broker unreachable state -- without leaking the underlying
            exception (CWE-209).
    """
    global _celery_app  # noqa: PLW0603  -- cached singleton

    if _celery_app is None:
        with _lock:
            if _celery_app is None:
                try:
                    _celery_app = _build_app()
                except Exception as exc:  # pragma: no cover -- celery init error
                    logger.error(
                        "Failed to initialise ingest Celery client: %s",
                        exc.__class__.__name__,
                    )
                    raise RuntimeError("Celery client unavailable") from exc

    return _celery_app


def clear_celery_client() -> None:
    """Reset the cached client.  Intended for unit-test cleanup only."""
    global _celery_app  # noqa: PLW0603
    with _lock:
        _celery_app = None
