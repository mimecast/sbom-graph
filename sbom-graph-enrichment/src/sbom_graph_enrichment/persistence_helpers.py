"""Per-worker resource pool using Celery's ``worker_process_init`` signal.

Each prefork worker child creates exactly one :class:`Persistence` instance
and one :class:`httpx.Client` after the fork, avoiding both per-task
connection churn and shared-socket corruption across processes.

Tasks obtain the cached instances via :func:`get_persistence` and
:func:`get_http_client`.  The original :func:`create_persistence` remains
available for one-off use (e.g. the ``enrich_all_packages`` fan-out task
that runs in the main worker process before any forking, or in tests).
"""

from __future__ import annotations

import logging
import os

import httpx

from sbom_graph_model import Persistence
from sbom_graph_model.k8s_service_host import resolve_k8s_service_link_host

logger = logging.getLogger(__name__)

_process_persistence: Persistence | None = None
_process_http_client: httpx.Client | None = None

_HTTP_TIMEOUT = float(os.environ.get("ENRICHMENT_HTTP_TIMEOUT", "30"))


def create_persistence() -> Persistence:
    """Build a fresh :class:`Persistence` from environment variables.

    Prefer :func:`get_persistence` inside Celery tasks -- this function
    is intended for contexts that run outside the worker process pool
    (fan-out tasks, CLI scripts, tests).
    """
    internal_prefixes = Persistence.parse_internal_prefixes(
        os.environ.get("INTERNAL_PREFIXES", "")
    )
    _host_raw = os.environ.get("FALKORDB_HOST", "localhost") or "localhost"
    host = resolve_k8s_service_link_host(_host_raw)
    port = int(os.environ.get("FALKORDB_PORT", "6379"))
    graph_name = os.environ.get("FALKORDB_GRAPH_NAME", "acme-corp")
    password = os.environ.get("FALKORDB_PASSWORD", "")
    ssl = os.environ.get("FALKORDB_SSL", "false").lower() == "true"
    ssl_ca_certs = os.environ.get("FALKORDB_CACERTS") or None
    ssl_certfile = os.environ.get("FALKORDB_CLIENT_CERT") or None
    ssl_keyfile = os.environ.get("FALKORDB_CLIENT_KEY") or None

    if not password:
        # Fail closed: the Helm charts always provision a FALKORDB_PASSWORD (auto-
        # generated, reused across upgrades), so an empty value in a real deployment
        # means it was removed/misconfigured — connecting to an unauthenticated DB
        # then is a security regression (CWE-306). Local development that genuinely
        # runs FalkorDB without auth must opt in explicitly.
        allow_no_auth = (
            os.environ.get("FALKORDB_ALLOW_NO_AUTH", "false").lower() == "true"
        )
        if not allow_no_auth:
            raise RuntimeError(
                "FALKORDB_PASSWORD is empty — refusing to connect to an "
                "unauthenticated FalkorDB. The Helm chart provisions this "
                "automatically; if it is missing it was removed. For local "
                "development against an auth-less FalkorDB, set "
                "FALKORDB_ALLOW_NO_AUTH=true to override."
            )
        logger.warning(
            "FALKORDB_PASSWORD is empty and FALKORDB_ALLOW_NO_AUTH=true — "
            "connecting to FalkorDB without authentication (development only)."
        )

    return Persistence(
        host=host,
        port=port,
        graph_name=graph_name,
        password=password,
        ssl=ssl,
        ssl_ca_certs=ssl_ca_certs,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        internal_prefixes=internal_prefixes,
    )


def get_persistence() -> Persistence:
    """Return the per-process cached :class:`Persistence` instance.

    Falls back to :func:`create_persistence` if called outside a Celery
    worker (e.g. during tests or in the beat scheduler).
    """
    global _process_persistence  # noqa: PLW0603  # pylint: disable=global-statement
    if _process_persistence is None:
        logger.debug("No cached Persistence found; creating a new instance")
        _process_persistence = create_persistence()
    return _process_persistence


def get_http_client() -> httpx.Client:
    """Return the per-process cached :class:`httpx.Client`.

    Connection pooling across certifier calls avoids repeated TCP/TLS
    handshakes when enriching thousands of packages.
    """
    global _process_http_client  # noqa: PLW0603  # pylint: disable=global-statement
    if _process_http_client is None:
        logger.debug("No cached httpx.Client found; creating a new instance")
        _process_http_client = httpx.Client(timeout=_HTTP_TIMEOUT)
    return _process_http_client


def _on_worker_process_init(**_kwargs: object) -> None:
    """Celery ``worker_process_init`` signal handler.

    Creates a :class:`Persistence` instance and an :class:`httpx.Client`
    for this worker child process immediately after the fork, so they
    are ready before the first task runs.
    """
    global _process_persistence, _process_http_client  # noqa: PLW0603  # pylint: disable=global-statement
    logger.info("Initialising per-process connections (pid=%d)", os.getpid())
    _process_persistence = create_persistence()
    _process_http_client = httpx.Client(timeout=_HTTP_TIMEOUT)


def _on_worker_process_shutdown(**_kwargs: object) -> None:
    """Celery ``worker_process_shutdown`` signal handler.

    Closes the per-process httpx client and FalkorDB connection when a worker
    child is recycled (e.g. via ``--max-tasks-per-child``) or shut down, so
    sockets/connections are drained cleanly instead of being abandoned.
    """
    global _process_persistence, _process_http_client  # noqa: PLW0603  # pylint: disable=global-statement
    logger.info("Closing per-process connections (pid=%d)", os.getpid())
    if _process_http_client is not None:
        _process_http_client.close()
        _process_http_client = None
    if _process_persistence is not None:
        _process_persistence.close()
        _process_persistence = None


def _reset_persistence() -> None:
    """Clear the cached instances (for testing only)."""
    global _process_persistence, _process_http_client  # noqa: PLW0603  # pylint: disable=global-statement
    _process_persistence = None
    if _process_http_client is not None:
        _process_http_client.close()
    _process_http_client = None
