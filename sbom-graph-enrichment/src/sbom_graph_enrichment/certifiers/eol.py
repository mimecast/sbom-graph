"""EOL certifier -- end-of-life data from endoflife.date.

Queries the endoflife.date API for product lifecycle information,
mapping PURL ecosystems and package names to endoflife.date product
identifiers.  Rate-limits at 30 req/min.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any
from urllib.parse import quote

import httpx

from .base import Certifier, Finding, FindingKind

logger = logging.getLogger(__name__)

EOL_API_BASE = "https://endoflife.date/api"
_RATE_LIMIT_PER_MINUTE = 30

_PURL_RE = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?:(?P<ns>[^/]+)/)?(?P<name>[^@]+)@(?P<version>.+)$"
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


def _purl_to_eol_product(purl: str) -> tuple[str, str] | None:
    """Map a PURL to an endoflife.date product name and version.

    Returns (product, version) or None if the PURL cannot be parsed.
    Product naming:
    - npm: package name directly
    - pypi: package name directly
    - maven: groupId-artifactId (dots/colons replaced with hyphens)
    - golang: last path segment of the package path
    - Other ecosystems: package name
    """
    m = _PURL_RE.match(purl)
    if not m:
        return None

    ptype = m.group("type")
    ns = m.group("ns") or ""
    name = (m.group("name") or "").strip()
    version = (m.group("version") or "").strip()

    if not name or not version:
        return None

    # Normalise name: strip leading slash placeholder for unscoped packages.
    if name.startswith("-/"):
        name = name[2:]
    name = name.replace("%2F", "/").replace("%40", "@")

    if ptype == "npm":
        product = name.split("/")[-1] if "/" in name else name
    elif ptype == "pypi":
        product = name.split("/")[-1] if "/" in name else name
    elif ptype == "maven" and ns:
        # groupId-artifactId: replace dots and colons with hyphens
        group_part = ns.replace(".", "-").replace(":", "-")
        artifact_part = name.replace(".", "-")
        product = f"{group_part}-{artifact_part}"
    elif ptype == "golang":
        product = name.split("/")[-1] if "/" in name else name
    else:
        product = name.split("/")[-1] if "/" in name else name

    # Sanitise product for URL: lowercase, replace spaces/special chars
    product = product.lower().replace(" ", "-").replace("_", "-")
    if not product:
        return None

    return (product, version)


def _find_matching_cycle(
    cycles: list[dict[str, Any]], version: str
) -> dict[str, Any] | None:
    """Find the EOL cycle that best matches the package version.

    Uses prefix matching: cycle "3.12" matches version "3.12.2".
    Strips leading 'v' from version for comparison.
    """
    version_normalised = version.lstrip("vV")
    if not version_normalised:
        return None

    best_match: dict[str, Any] | None = None
    best_length = 0

    for cycle_data in cycles:
        cycle = cycle_data.get("cycle") or ""
        if not cycle:
            continue
        cycle_str = str(cycle)
        # Check if version starts with cycle (e.g. "3.12.2" starts with "3.12")
        if version_normalised.startswith(cycle_str) or cycle_str.startswith(
            version_normalised
        ):
            match_len = min(len(cycle_str), len(version_normalised))
            if match_len > best_length:
                best_length = match_len
                best_match = cycle_data

    return best_match


def _build_eol_data(
    product: str,
    cycle_data: dict[str, Any] | None,
    version: str,
) -> dict[str, Any]:
    """Build the data dict for an EOL finding."""
    data: dict[str, Any] = {
        "product": product,
        "cycle": None,
        "eol": None,
        "eol_date": None,
        "lts": None,
        "latest": None,
        "release_date": None,
        "support": None,
    }

    if cycle_data is None:
        return data

    eol_val = cycle_data.get("eol")
    data["cycle"] = cycle_data.get("cycle")
    data["eol"] = eol_val
    data["eol_date"] = eol_val if isinstance(eol_val, str) else None
    data["lts"] = cycle_data.get("lts")
    data["latest"] = cycle_data.get("latest")
    data["release_date"] = cycle_data.get("releaseDate") or cycle_data.get(
        "release_date"
    )
    data["support"] = cycle_data.get("support")

    return data


class EOLCertifier(Certifier):
    """Fetches end-of-life data from the endoflife.date API."""

    @property
    def name(self) -> str:
        return "eol"

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        params = _purl_to_eol_product(purl)
        if params is None:
            logger.debug("Unsupported or invalid PURL for EOL: %s", purl)
            return []

        product, version = params
        product_encoded = quote(product, safe="")

        _bucket.acquire()

        url = f"{EOL_API_BASE}/{product_encoded}.json"
        resp = client.get(url)

        if resp.status_code == 404:
            logger.debug("endoflife.date has no data for product %s", product)
            return []
        resp.raise_for_status()

        cycles = resp.json()
        if not isinstance(cycles, list) or not cycles:
            logger.debug("endoflife.date returned empty cycles for %s", product)
            return []

        cycle_data = _find_matching_cycle(cycles, version)
        data = _build_eol_data(product, cycle_data, version)

        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url=purl,
            data=data,
        )
        logger.info(
            "EOL data for %s: product=%s cycle=%s eol=%s",
            purl,
            product,
            data.get("cycle"),
            data.get("eol"),
        )
        return [finding]
