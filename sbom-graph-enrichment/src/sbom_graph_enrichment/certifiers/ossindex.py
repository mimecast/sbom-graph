"""Sonatype OSS Index certifier -- proprietary vulnerability intelligence.

Queries ``POST https://ossindex.sonatype.org/api/v3/component-report``
with up to 128 PURLs per batch.  Authentication is optional: when
``OSSINDEX_USER`` and ``OSSINDEX_TOKEN`` environment variables are set
the certifier uses HTTP Basic auth for higher rate limits (120 req/min);
without credentials it operates at 60 req/min.

Security note:
    Credentials are read from environment variables only -- never from
    user input.  The target host is hardcoded so SSRF is not possible.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import httpx

from .base import Certifier, Finding, FindingKind

logger = logging.getLogger(__name__)

OSSINDEX_API_URL = "https://ossindex.sonatype.org/api/v3/component-report"
_BATCH_SIZE = 128
_RATE_UNAUTHENTICATED = 60
_RATE_AUTHENTICATED = 120


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


def _get_auth() -> tuple[str, str] | None:
    """Read optional OSS Index credentials from environment."""
    user = os.environ.get("OSSINDEX_USER", "").strip()
    token = os.environ.get("OSSINDEX_TOKEN", "").strip()
    if user and token:
        return (user, token)
    return None


def _make_bucket() -> _TokenBucket:
    """Create a rate-limit bucket sized for the current auth level."""
    auth = _get_auth()
    rate = _RATE_AUTHENTICATED if auth else _RATE_UNAUTHENTICATED
    return _TokenBucket(rate=rate / 60.0, capacity=rate)


_bucket: _TokenBucket = _make_bucket()


class OSSIndexCertifier(Certifier):
    """Fetches vulnerability data from the Sonatype OSS Index API."""

    @property
    def name(self) -> str:
        return "ossindex"

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        return enrich_batch([purl], client=client)


def enrich_batch(purls: list[str], *, client: httpx.Client) -> list[Finding]:
    """Query OSS Index for a batch of PURLs (max 128)."""
    if not purls:
        return []

    _bucket.acquire()

    auth = _get_auth()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    kwargs: dict[str, Any] = {"headers": headers, "json": {"coordinates": purls[:_BATCH_SIZE]}}
    if auth:
        kwargs["auth"] = auth

    resp = client.post(OSSINDEX_API_URL, **kwargs)
    resp.raise_for_status()

    body: list[dict[str, Any]] = resp.json()

    findings: list[Finding] = []
    for component in body:
        comp_purl = component.get("coordinates", "")
        vulns: list[dict[str, Any]] = component.get("vulnerabilities", [])
        if not vulns:
            continue

        for vuln in vulns:
            cvss_score = vuln.get("cvssScore")
            severity = _score_to_severity(cvss_score)
            findings.append(
                Finding(
                    kind=FindingKind.OSSINDEX,
                    source="ossindex",
                    package_url=comp_purl,
                    data={
                        "id": vuln.get("id", ""),
                        "display_name": vuln.get("displayName", ""),
                        "title": vuln.get("title", ""),
                        "description": vuln.get("description", ""),
                        "cvss_score": cvss_score,
                        "cvss_vector": vuln.get("cvssVector", ""),
                        "severity": severity,
                        "cwe": vuln.get("cwe", ""),
                        "reference": vuln.get("reference", ""),
                    },
                )
            )

    if findings:
        logger.info("OSS Index returned %d vulns for %d PURLs", len(findings), len(purls))
    return findings


def _score_to_severity(score: float | None) -> str:
    """Map CVSS score to severity label."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"
