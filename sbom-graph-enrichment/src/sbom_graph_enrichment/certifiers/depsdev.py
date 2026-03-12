"""deps.dev certifier -- project health and activity signals.

Queries the deps.dev REST API for version-level metadata and
project-level data (scorecard scores, oss-fuzz status, advisory counts).

Maps PURL types to deps.dev system identifiers and constructs the
correct API paths.  Rate-limits at 150 req/min (deps.dev is generous
but undocumented).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .base import Certifier, Finding, FindingKind

logger = logging.getLogger(__name__)

DEPSDEV_API_BASE = "https://api.deps.dev/v3"
DEPSDEV_API_ALPHA = "https://api.deps.dev/v3alpha"
_RATE_LIMIT_PER_MINUTE = 150

_PURL_RE = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?:(?P<ns>[^/]+)/)?(?P<name>[^@]+)@(?P<version>.+)$"
)

_SYSTEM_MAP: dict[str, str] = {
    "maven": "MAVEN",
    "npm": "NPM",
    "pypi": "PYPI",
    "nuget": "NUGET",
    "cargo": "CARGO",
    "golang": "GO",
}


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


def purl_to_depsdev_params(purl: str) -> dict[str, str] | None:
    """Convert a PURL to deps.dev API path parameters.

    Returns a dict with ``system``, ``package``, and ``version`` keys,
    or *None* if the PURL type is unsupported.
    """
    m = _PURL_RE.match(purl)
    if not m:
        return None

    ptype = m.group("type")
    system = _SYSTEM_MAP.get(ptype)
    if system is None:
        return None

    ns = m.group("ns")
    name = m.group("name")
    version = m.group("version")

    if ptype == "maven" and ns:
        package = f"{ns}:{name}"
    elif ns and ns != "-":
        package = f"{ns}/{name}"
    else:
        package = name

    return {"system": system, "package": package, "version": version}


class DepsDevCertifier(Certifier):
    """Fetches package and project data from the deps.dev API."""

    @property
    def name(self) -> str:
        return "depsdev"

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        params = purl_to_depsdev_params(purl)
        if params is None:
            logger.debug("Unsupported PURL type for deps.dev: %s", purl)
            return []

        _bucket.acquire()

        system = params["system"]
        package = quote(params["package"], safe="")
        version = quote(params["version"], safe="")

        version_url = (
            f"{DEPSDEV_API_BASE}/systems/{system}/packages/{package}/versions/"
            f"{version}"
        )
        resp = client.get(version_url)

        if resp.status_code == 404:
            logger.debug("deps.dev has no data for %s", purl)
            return []
        resp.raise_for_status()

        version_data = resp.json()

        project_data = _fetch_project(version_data, client)

        return _build_findings(purl, version_data, project_data)


def _fetch_project(
    version_data: dict[str, Any],
    client: httpx.Client,
) -> dict[str, Any] | None:
    """Attempt to fetch project-level data from the version's linked project."""
    links = version_data.get("links", [])
    for link in links:
        label = (link.get("label") or "").upper()
        url = link.get("url", "")
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if (
            label in ("SOURCE_REPO", "HOMEPAGE", "REPOSITORY")
            and (host == "github.com" or host.endswith(".github.com"))
        ):
            project_key = quote(url, safe="")
            project_url = f"{DEPSDEV_API_ALPHA}/projects/{project_key}"
            try:
                _bucket.acquire()
                resp = client.get(project_url)
                if resp.status_code == 200:
                    return resp.json()
            except httpx.HTTPError:
                logger.debug("Failed to fetch deps.dev project for %s", url)
    return None


def _build_findings(
    purl: str,
    version_data: dict[str, Any],
    project_data: dict[str, Any] | None,
) -> list[Finding]:
    """Combine version and project data into a single DEPSDEV finding."""
    advisory_count = len(version_data.get("advisoryKeys", []))

    data: dict[str, Any] = {
        "advisory_count": advisory_count,
        "published_at": version_data.get("publishedAt"),
        "is_default": version_data.get("isDefault", False),
        "licenses": version_data.get("licenses", []),
    }

    if project_data:
        scorecard = project_data.get("scorecardV2") or project_data.get("scorecard")
        if scorecard:
            data["scorecard_overall"] = scorecard.get("overallScore")
            data["scorecard_checks"] = {
                c.get("name", ""): c.get("score")
                for c in scorecard.get("checks", [])
                if c.get("name")
            }
        data["oss_fuzz"] = project_data.get("openSsfFuzz", {})
        data["project_key"] = project_data.get("projectKey", {}).get("id", "")

    finding = Finding(
        kind=FindingKind.DEPSDEV,
        source="depsdev",
        package_url=purl,
        data=data,
    )
    logger.info(
        "deps.dev returned %d advisories for %s (project data: %s)",
        advisory_count,
        purl,
        "yes" if project_data else "no",
    )
    return [finding]
