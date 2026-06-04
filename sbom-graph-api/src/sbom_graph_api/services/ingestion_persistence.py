"""Factory for model :class:`Persistence` instances used during SBOM ingestion.

Both the REST ingestion routes and the Sonatype release listener rely on the
same internal-prefix merging rules: Helm ``INTERNAL_PREFIXES`` (base) plus an
optional overlay stored in FalkorDB via the administrative API.

Keeping construction in one module avoids divergence between ingestion paths.
"""

from __future__ import annotations

import logging
import os

from sbom_graph_model import Persistence

from sbom_graph_api.config import AppConfig, get_config

logger = logging.getLogger(__name__)


def create_ingestion_persistence(app_config: AppConfig | None = None) -> Persistence:
    """Build a Persistence instance wired for CycloneDX/SPDX ingestion.

    Args:
        app_config: Optional pre-loaded :class:`AppConfig`; defaults to
            :func:`sbom_graph_api.config.get_config`.

    Returns:
        Connected :class:`Persistence` whose ``internal_prefixes`` merges
        ``INTERNAL_PREFIXES`` with the FalkorDB overlay when present.

    Raises:
        ValueError: When ``INTERNAL_PREFIXES`` fails to parse.

    Overlay read failures degrade gracefully: callers still get env-only prefixes
    and a WARNING log entry.  Parsing errors in stored overlay discard the overlay
    and fall back to env-only (also logged).
    """
    cfg = app_config if app_config is not None else get_config()
    falk = cfg.falkordb
    env_csv = os.environ.get("INTERNAL_PREFIXES", "") or ""

    base_prefixes = Persistence.parse_internal_prefixes(env_csv.strip())
    persistence = Persistence(
        host=falk.host,
        port=falk.port,
        graph_name=falk.graph_name,
        password=falk.password or "",
        ssl=falk.ssl,
        ssl_ca_certs=falk.ssl_ca_certs,
        ssl_certfile=falk.ssl_certfile,
        ssl_keyfile=falk.ssl_keyfile,
        internal_prefixes=base_prefixes,
    )

    try:
        persistence.reload_internal_prefixes_from_env_and_overlay(env_csv)
    except ValueError as exc:
        logger.warning(
            "Invalid internal-prefix overlay in FalkorDB; using env INTERNAL_PREFIXES "
            "only: %s",
            exc,
        )
        persistence.internal_prefixes = list(base_prefixes)
    except Exception:
        logger.exception(
            "Failed merging FalkorDB internal-prefix overlay; using INTERNAL_PREFIXES only"
        )
        persistence.internal_prefixes = list(base_prefixes)

    return persistence
