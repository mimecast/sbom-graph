"""Source repo certifier -- extracts source repository URLs from deps.dev.

Queries the deps.dev API for version-level metadata and extracts the
SOURCE_REPO link.  Rate-limits at 100 req/min.  Only accepts URLs from
allowed hosts (SSRF mitigation).
"""

from __future__ import annotations

import logging
import threading
import time
from urllib.parse import quote, urlparse

import httpx

from .base import Certifier, Finding, FindingKind
from .depsdev import purl_to_depsdev_params

logger = logging.getLogger(__name__)

DEPSDEV_API_BASE = "https://api.deps.dev/v3"
_RATE_LIMIT_PER_MINUTE = 100

# Allowed hosts for source repo URLs (SSRF mitigation).
_ALLOWED_REPO_HOSTS = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "sourcehut.org",
        "codeberg.org",
    }
)


class _TokenBucket:
    """Thread-safe token bucket for rate-limiting."""

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last = now

            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                time.sleep(wait)
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= 1.0


_bucket = _TokenBucket(
    rate=_RATE_LIMIT_PER_MINUTE / 60.0,
    capacity=_RATE_LIMIT_PER_MINUTE,
)


def _extract_source_repo_url(links: list[dict]) -> str | None:
    """Extract SOURCE_REPO URL from deps.dev links, validating against allowlist."""
    for link in links:
        label = (link.get("label") or "").upper()
        if label != "SOURCE_REPO":
            continue
        url = link.get("url") or ""
        if not url:
            continue
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        # Normalise: github.com and www.github.com
        if host.startswith("www."):
            host = host[4:]
        if host in _ALLOWED_REPO_HOSTS:
            return url
        # Subdomains: e.g. gist.github.com
        if host.endswith(".github.com") or host == "github.com":
            return url
        if host.endswith(".gitlab.com") or host == "gitlab.com":
            return url
        if host.endswith(".bitbucket.org") or host == "bitbucket.org":
            return url
    return None


class SourceRepoCertifier(Certifier):
    """Fetches source repository URLs from the deps.dev API."""

    @property
    def name(self) -> str:
        return "source_repo"

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        params = purl_to_depsdev_params(purl)
        if params is None:
            logger.debug("Unsupported PURL type for source repo: %s", purl)
            return []

        _bucket.acquire()

        system = params["system"]
        package = quote(params["package"], safe="")
        version = quote(params["version"], safe="")

        version_url = (
            f"{DEPSDEV_API_BASE}/systems/{system}/packages/{package}/versions/{version}"
        )
        resp = client.get(version_url)

        if resp.status_code == 404:
            logger.debug("deps.dev has no data for %s", purl)
            return []
        resp.raise_for_status()

        version_data = resp.json()
        links = version_data.get("links", [])
        repo_url = _extract_source_repo_url(links)

        if not repo_url:
            logger.debug("No SOURCE_REPO link for %s", purl)
            return []

        parsed = urlparse(repo_url)
        repo_host = (parsed.hostname or "").lower()

        finding = Finding(
            kind=FindingKind.SOURCE_REPO,
            source="depsdev",
            package_url=purl,
            data={
                "repo_url": repo_url,
                "repo_host": repo_host,
                "source": "depsdev",
            },
        )
        logger.info("Source repo for %s: %s", purl, repo_url)
        return [finding]
