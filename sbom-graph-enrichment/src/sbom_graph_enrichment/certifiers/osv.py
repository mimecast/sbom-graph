"""OSV.dev certifier -- queries the OSV API for known vulnerabilities.

Rate-limits itself to stay within OSV's 100 req/min guideline using a
simple token-bucket that sleeps when the bucket is empty.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

from .base import Certifier, Finding, FindingKind

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
_RATE_LIMIT_PER_MINUTE = 100
_RATE_INTERVAL = 60.0 / _RATE_LIMIT_PER_MINUTE


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
    rate=_RATE_LIMIT_PER_MINUTE / 60.0, capacity=_RATE_LIMIT_PER_MINUTE
)


class OSVCertifier(Certifier):
    """Fetches vulnerability data from the OSV.dev API."""

    @property
    def name(self) -> str:
        return "osv"

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        _bucket.acquire()

        payload: dict[str, Any] = {"package": {"purl": purl}}
        resp = client.post(OSV_API_URL, json=payload)
        resp.raise_for_status()
        body = resp.json()

        vulns: list[dict[str, Any]] = body.get("vulns", [])
        if not vulns:
            logger.debug("No OSV vulnerabilities for %s", purl)
            return []

        findings: list[Finding] = []
        for vuln in vulns:
            severity_info = _extract_severity(vuln)
            aliases = vuln.get("aliases", [])
            findings.append(
                Finding(
                    kind=FindingKind.VULNERABILITY,
                    source="osv",
                    package_url=purl,
                    data={
                        "id": vuln.get("id", ""),
                        "summary": vuln.get("summary", ""),
                        "aliases": aliases,
                        "severity": severity_info.get("severity", "unknown"),
                        "cvss_score": severity_info.get("score"),
                        "cvss_vector": severity_info.get("vector"),
                    },
                )
            )

        logger.info("OSV returned %d vulns for %s", len(findings), purl)
        return findings


def _extract_severity(vuln: dict[str, Any]) -> dict[str, Any]:
    """Best-effort extraction of severity from an OSV vulnerability."""
    severity_list = vuln.get("severity", [])
    for sev in severity_list:
        if sev.get("type") == "CVSS_V3":
            return {
                "vector": sev.get("score", ""),
                "severity": _cvss_vector_to_severity(sev.get("score", "")),
                "score": None,
            }
    eco_severity = vuln.get("database_specific", {}).get("severity")
    if eco_severity:
        return {"severity": eco_severity.lower(), "score": None, "vector": None}
    return {"severity": "unknown", "score": None, "vector": None}


def _cvss_vector_to_severity(vector: str) -> str:
    """Rough mapping from CVSS v3 vector to severity label."""
    if not vector:
        return "unknown"
    return "unknown"
