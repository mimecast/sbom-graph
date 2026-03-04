"""OpenSSF Scorecard certifier -- queries api.scorecard.dev for project health.

Extracts a GitHub repository URL from the graph (via the SourceRepository
node or Version.repo property) and fetches security check scores from the
OpenSSF Scorecard API.

Rate-limits to 30 req/min (conservative -- the API has no published quota).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any

import httpx

from .base import Certifier, Finding, FindingKind

logger = logging.getLogger(__name__)

SCORECARD_API_URL = "https://api.scorecard.dev/projects/github.com"
_RATE_LIMIT_PER_MINUTE = 30


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

_GITHUB_REPO_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/@#?.]+)"
)


def extract_github_owner_repo(url: str | None) -> tuple[str, str] | None:
    """Parse ``owner/repo`` from a GitHub URL, or return *None*."""
    if not url:
        return None
    m = _GITHUB_REPO_RE.search(url)
    if not m:
        return None
    owner = m.group("owner")
    repo = m.group("repo").removesuffix(".git")
    return (owner, repo)


class ScorecardCertifier(Certifier):
    """Fetches OpenSSF Scorecard data for GitHub-hosted packages."""

    @property
    def name(self) -> str:
        return "scorecard"

    def __init__(self, repo_url: str | None = None) -> None:
        self._repo_url = repo_url

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        parsed = extract_github_owner_repo(self._repo_url)
        if parsed is None:
            logger.debug("No GitHub repo for %s -- skipping Scorecard", purl)
            return []

        owner, repo = parsed
        _bucket.acquire()

        url = f"{SCORECARD_API_URL}/{owner}/{repo}"
        resp = client.get(url)

        if resp.status_code == 404:
            logger.debug("Scorecard has no data for %s/%s", owner, repo)
            return []
        resp.raise_for_status()

        body = resp.json()
        return _parse_scorecard_response(purl, body)


def _parse_scorecard_response(purl: str, body: dict[str, Any]) -> list[Finding]:
    """Convert the Scorecard JSON response to findings."""
    overall_score = body.get("score")
    checks: list[dict[str, Any]] = body.get("checks", [])

    check_scores: dict[str, float] = {}
    for check in checks:
        check_name = check.get("name", "")
        score = check.get("score")
        if check_name and score is not None:
            check_scores[check_name] = float(score)

    if not check_scores and overall_score is None:
        return []

    finding = Finding(
        kind=FindingKind.SCORECARD,
        source="scorecard",
        package_url=purl,
        data={
            "overall_score": overall_score,
            "checks": check_scores,
            "repo": body.get("repo", {}).get("name", ""),
            "commit": body.get("repo", {}).get("commit", ""),
        },
    )
    logger.info(
        "Scorecard returned score=%.1f with %d checks for %s",
        overall_score or 0.0,
        len(check_scores),
        purl,
    )
    return [finding]
