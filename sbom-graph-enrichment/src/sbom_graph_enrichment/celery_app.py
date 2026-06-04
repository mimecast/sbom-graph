"""Celery application factory for the enrichment pipeline.

Configures Celery to use FalkorDB's Redis instance (database 1) as both
the broker and result backend, keeping infrastructure minimal.

**Password handling**: Celery's standard Redis transport requires the
password to be embedded in the broker URL (``redis://:pw@host/db``).
``broker_transport_options`` only supports a separate password for Redis
Sentinel deployments, which we do not use.  To prevent the credential
from leaking into logs, a :class:`_RedactSecretsFilter` is attached to
the ``celery`` and ``kombu`` loggers as defence-in-depth.
"""

import logging
import os
import re
import ssl

from celery import Celery
from celery.signals import worker_process_init
from sbom_graph_model.k8s_service_host import resolve_k8s_service_link_host

_redis_host_raw = os.environ.get("FALKORDB_HOST", "localhost") or "localhost"
_REDIS_HOST = resolve_k8s_service_link_host(_redis_host_raw)
_REDIS_PORT = os.environ.get("FALKORDB_PORT", "6379")
_REDIS_PASSWORD = os.environ.get("FALKORDB_PASSWORD", "")
_BROKER_DB = os.environ.get("CELERY_BROKER_DB", "1")
_RESULT_DB = os.environ.get("CELERY_RESULT_DB", "2")
_REDIS_SSL = os.environ.get("CELERY_REDIS_SSL", "false").lower() == "true"

_SCHEME = "rediss" if _REDIS_SSL else "redis"
_AUTH = f":{_REDIS_PASSWORD}@" if _REDIS_PASSWORD else ""

BROKER_URL = f"{_SCHEME}://{_AUTH}{_REDIS_HOST}:{_REDIS_PORT}/{_BROKER_DB}"
RESULT_URL = f"{_SCHEME}://{_AUTH}{_REDIS_HOST}:{_REDIS_PORT}/{_RESULT_DB}"

app = Celery("sbom_graph_enrichment")

app.conf.update(
    broker_url=BROKER_URL,
    result_backend=RESULT_URL,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    result_expires=86400,
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="enrichment",
)

if _REDIS_SSL:
    _ssl_opts: dict[str, object] = {"ssl_cert_reqs": ssl.CERT_REQUIRED}
    _ca_certs = os.environ.get("FALKORDB_CACERTS")
    if _ca_certs:
        _ssl_opts["ssl_ca_certs"] = _ca_certs
    _client_cert = os.environ.get("FALKORDB_CLIENT_CERT")
    _client_key = os.environ.get("FALKORDB_CLIENT_KEY")
    if _client_cert:
        _ssl_opts["ssl_certfile"] = _client_cert
    if _client_key:
        _ssl_opts["ssl_keyfile"] = _client_key
    app.conf.update(
        broker_use_ssl=_ssl_opts,
        redis_backend_use_ssl=_ssl_opts,
    )

_ENRICHMENT_INTERVAL = int(os.environ.get("ENRICHMENT_INTERVAL", "3600"))
_TRUST_SCORE_INTERVAL = int(os.environ.get("TRUST_SCORE_INTERVAL", "7200"))
_TRUST_SCORE_ENABLED = os.environ.get("TRUST_SCORE_ENABLED", "true").lower() == "true"
_CENTRALITY_REFRESH_INTERVAL = int(
    os.environ.get("CENTRALITY_REFRESH_INTERVAL", "7200"),
)
_CENTRALITY_REFRESH_ENABLED = (
    os.environ.get("CENTRALITY_REFRESH_ENABLED", "true").lower() == "true"
)

_ENRICHMENT_SOURCES_RAW = os.environ.get("ENRICHMENT_SOURCES", "")
try:
    import json as _json

    _ENRICHMENT_SOURCES: list[str] | None = (
        _json.loads(_ENRICHMENT_SOURCES_RAW) if _ENRICHMENT_SOURCES_RAW else None
    )
except ValueError, TypeError:
    _ENRICHMENT_SOURCES = None

app.conf.beat_schedule = {
    "scheduled-enrichment": {
        "task": "sbom_graph_enrichment.tasks.enrich_all_packages",
        "schedule": _ENRICHMENT_INTERVAL,
        "args": (_ENRICHMENT_SOURCES,),
    },
}

if _TRUST_SCORE_ENABLED:
    app.conf.beat_schedule["propagate-effective-scores"] = {
        "task": "sbom_graph_enrichment.tasks.propagate_effective_scores",
        "schedule": _TRUST_SCORE_INTERVAL,
        "args": (),
    }

if _CENTRALITY_REFRESH_ENABLED:
    app.conf.beat_schedule["refresh-internal-centrality"] = {
        "task": "sbom_graph_enrichment.tasks.refresh_internal_centrality",
        "schedule": _CENTRALITY_REFRESH_INTERVAL,
        "args": (),
    }

# ``autodiscover_tasks`` defaults to ``related_name="tasks"`` and so only
# imports ``sbom_graph_enrichment/tasks.py``.  The asynchronous SBOM ingest
# pipeline lives in a second module, ``ingest_tasks.py``, which must be
# discovered separately or Celery will reject incoming ingest jobs with
# ``Received unregistered task of type 'sbom_graph_enrichment.ingest_tasks.*'``.
# See ``docs/ingest-pipeline.md`` for the broader rationale.
app.autodiscover_tasks(["sbom_graph_enrichment"])
app.autodiscover_tasks(["sbom_graph_enrichment"], related_name="ingest_tasks")


# ---------------------------------------------------------------------------
# Log redaction filter -- strips Redis passwords from URLs that Celery may
# emit during startup, reconnection, or error reporting.
# ---------------------------------------------------------------------------
_REDIS_URL_RE = re.compile(r"(rediss?://):.+@(?=[\w.-]+:\d)")


class _RedactSecretsFilter(logging.Filter):
    """Replaces ``redis://:password@host`` with ``redis://:*****@host``."""

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
                    _REDIS_URL_RE.sub(r"\1:*****@", str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        if isinstance(record.msg, str):
            record.msg = _REDIS_URL_RE.sub(r"\1:*****@", record.msg)
        return True


logging.getLogger("celery").addFilter(_RedactSecretsFilter())
logging.getLogger("kombu").addFilter(_RedactSecretsFilter())

# Connect the worker_process_init signal so each prefork child creates
# its own Persistence (and underlying Redis connection) after the fork.
from .persistence_helpers import _on_worker_process_init  # noqa: E402

worker_process_init.connect(_on_worker_process_init)
