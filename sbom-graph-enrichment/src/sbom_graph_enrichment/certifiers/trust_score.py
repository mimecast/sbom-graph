"""Trust score calculator -- composite scoring from multiple certifier findings.

This is *not* a Certifier subclass; it is a **compositor** that consumes
findings produced by the other certifiers and computes a single
composite trust score per package version.

The score is decomposed into four weighted categories:

- **Security Practices** (default 30%): OpenSSF Scorecard check averages,
  with deps.dev project data as fallback.
- **Vulnerability Profile** (default 35%): signals from OSV + OSS Index.
- **Maintenance Health** (default 20%): Scorecard Maintained/Contributors
  or deps.dev activity data.
- **Supply-Chain Hygiene** (default 15%): Scorecard Pinned-Dependencies,
  Signed-Releases, or deps.dev equivalents.

All category scores are on a 0--10 scale.  The direct_score is the
weighted sum, also on 0--10.  Confidence is the fraction of data sources
(out of 4) that contributed data.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

from .base import Finding, FindingKind

logger = logging.getLogger(__name__)

_DEFAULT_WEIGHTS: dict[str, float] = {
    "security_practices": 0.30,
    "vulnerability_profile": 0.35,
    "maintenance_health": 0.20,
    "supply_chain_hygiene": 0.15,
}

_SECURITY_CHECKS = frozenset({
    "Branch-Protection", "Code-Review", "Token-Permissions",
    "Dangerous-Workflow", "SAST", "Fuzzing", "CI-Tests",
})

_MAINTENANCE_CHECKS = frozenset({
    "Maintained", "Contributors",
})

_HYGIENE_CHECKS = frozenset({
    "Pinned-Dependencies", "Signed-Releases", "Packaging",
})


def _env_weights() -> dict[str, float]:
    """Read category weights from environment, falling back to defaults."""
    w = dict(_DEFAULT_WEIGHTS)
    for key in _DEFAULT_WEIGHTS:
        env_key = f"TRUST_SCORE_WEIGHT_{key.upper()}"
        val = os.environ.get(env_key)
        if val:
            try:
                w[key] = float(val)
            except ValueError:
                logger.warning("Invalid weight for %s: %s", env_key, val)
    return w


@dataclass(slots=True)
class TrustScoreResult:
    """Result of a trust score computation for a single PURL."""

    purl: str
    direct_score: float
    confidence: float
    security_practices_score: float
    vulnerability_profile_score: float
    maintenance_health_score: float
    supply_chain_hygiene_score: float
    sources_used: list[str] = field(default_factory=list)
    scorecard_raw: str | None = None
    depsdev_raw: str | None = None


class TrustScoreCalculator:
    """Computes a composite trust score from certifier findings."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self._weights = weights or _env_weights()

    def compute(self, purl: str, findings: list[Finding]) -> TrustScoreResult:
        """Compute the direct trust score for *purl* from collected findings."""
        grouped = _group_findings(findings)
        sources_used: list[str] = []

        scorecard_data = grouped.get(FindingKind.SCORECARD)
        ossindex_data = grouped.get(FindingKind.OSSINDEX)
        osv_data = grouped.get(FindingKind.VULNERABILITY)
        depsdev_data = grouped.get(FindingKind.DEPSDEV)

        sec_score = self._compute_security_practices(scorecard_data, depsdev_data)
        vuln_score = self._compute_vulnerability_profile(osv_data, ossindex_data)
        maint_score = self._compute_maintenance_health(scorecard_data, depsdev_data)
        hygiene_score = self._compute_supply_chain_hygiene(scorecard_data, depsdev_data)

        if scorecard_data:
            sources_used.append("scorecard")
        if osv_data:
            sources_used.append("osv")
        if ossindex_data:
            sources_used.append("ossindex")
        if depsdev_data:
            sources_used.append("depsdev")

        confidence = len(sources_used) / 4.0

        w = self._weights
        direct_score = (
            sec_score * w["security_practices"]
            + vuln_score * w["vulnerability_profile"]
            + maint_score * w["maintenance_health"]
            + hygiene_score * w["supply_chain_hygiene"]
        )

        scorecard_raw = None
        if scorecard_data:
            scorecard_raw = json.dumps([f.data for f in scorecard_data], default=str)

        depsdev_raw = None
        if depsdev_data:
            depsdev_raw = json.dumps([f.data for f in depsdev_data], default=str)

        return TrustScoreResult(
            purl=purl,
            direct_score=round(direct_score, 2),
            confidence=round(confidence, 2),
            security_practices_score=round(sec_score, 2),
            vulnerability_profile_score=round(vuln_score, 2),
            maintenance_health_score=round(maint_score, 2),
            supply_chain_hygiene_score=round(hygiene_score, 2),
            sources_used=sources_used,
            scorecard_raw=scorecard_raw,
            depsdev_raw=depsdev_raw,
        )

    # ------------------------------------------------------------------
    # Category scoring
    # ------------------------------------------------------------------

    def _compute_security_practices(
        self,
        scorecard: list[Finding] | None,
        depsdev: list[Finding] | None,
    ) -> float:
        """Security practices: average of relevant Scorecard check scores."""
        checks = _extract_scorecard_checks(scorecard)
        if checks:
            relevant = [v for k, v in checks.items() if k in _SECURITY_CHECKS]
            if relevant:
                return sum(relevant) / len(relevant)

        if depsdev:
            dd_checks = _extract_depsdev_scorecard_checks(depsdev)
            relevant = [v for k, v in dd_checks.items() if k in _SECURITY_CHECKS]
            if relevant:
                return sum(relevant) / len(relevant)

        return 5.0

    def _compute_vulnerability_profile(
        self,
        osv: list[Finding] | None,
        ossindex: list[Finding] | None,
    ) -> float:
        """Vulnerability profile: score based on count and severity of vulns."""
        osv_count = len(osv) if osv else 0
        oss_count = len(ossindex) if ossindex else 0

        total = osv_count + oss_count
        if total == 0:
            return 10.0

        high_count = 0
        critical_count = 0
        for finding in (osv or []) + (ossindex or []):
            sev = finding.data.get("severity", "").lower()
            if sev == "critical":
                critical_count += 1
            elif sev == "high":
                high_count += 1

        penalty = critical_count * 3.0 + high_count * 1.5 + max(0, total - critical_count - high_count) * 0.5
        return max(0.0, min(10.0, 10.0 - penalty))

    def _compute_maintenance_health(
        self,
        scorecard: list[Finding] | None,
        depsdev: list[Finding] | None,
    ) -> float:
        """Maintenance health: Scorecard Maintained/Contributors scores."""
        checks = _extract_scorecard_checks(scorecard)
        if checks:
            relevant = [v for k, v in checks.items() if k in _MAINTENANCE_CHECKS]
            if relevant:
                return sum(relevant) / len(relevant)

        if depsdev:
            dd_checks = _extract_depsdev_scorecard_checks(depsdev)
            relevant = [v for k, v in dd_checks.items() if k in _MAINTENANCE_CHECKS]
            if relevant:
                return sum(relevant) / len(relevant)

        return 5.0

    def _compute_supply_chain_hygiene(
        self,
        scorecard: list[Finding] | None,
        depsdev: list[Finding] | None,
    ) -> float:
        """Supply-chain hygiene: Scorecard pinned-deps, signed-releases."""
        checks = _extract_scorecard_checks(scorecard)
        if checks:
            relevant = [v for k, v in checks.items() if k in _HYGIENE_CHECKS]
            if relevant:
                return sum(relevant) / len(relevant)

        if depsdev:
            dd_checks = _extract_depsdev_scorecard_checks(depsdev)
            relevant = [v for k, v in dd_checks.items() if k in _HYGIENE_CHECKS]
            if relevant:
                return sum(relevant) / len(relevant)

        return 5.0


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _group_findings(findings: list[Finding]) -> dict[FindingKind, list[Finding]]:
    """Group findings by kind."""
    groups: dict[FindingKind, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.kind, []).append(f)
    return groups


def _extract_scorecard_checks(
    findings: list[Finding] | None,
) -> dict[str, float]:
    """Extract check name->score from Scorecard findings."""
    if not findings:
        return {}
    for f in findings:
        checks = f.data.get("checks", {})
        if checks:
            return {k: float(v) for k, v in checks.items() if v is not None}
    return {}


def _extract_depsdev_scorecard_checks(
    findings: list[Finding] | None,
) -> dict[str, float]:
    """Extract scorecard check scores from deps.dev findings."""
    if not findings:
        return {}
    for f in findings:
        checks = f.data.get("scorecard_checks", {})
        if checks:
            return {k: float(v) for k, v in checks.items() if v is not None}
    return {}
