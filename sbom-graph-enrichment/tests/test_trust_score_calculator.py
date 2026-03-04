"""Unit tests for the trust score calculator."""

from __future__ import annotations

import pytest

from sbom_graph_enrichment.certifiers.base import Finding, FindingKind
from sbom_graph_enrichment.certifiers.trust_score import (
    TrustScoreCalculator,
    TrustScoreResult,
)


def _make_finding(kind: FindingKind, source: str, data: dict) -> Finding:
    return Finding(kind=kind, source=source, package_url="pkg:npm/test@1.0", data=data)


class TestTrustScoreCalculator:
    """Tests for TrustScoreCalculator.compute."""

    def test_all_sources_present(self) -> None:
        findings = [
            _make_finding(FindingKind.SCORECARD, "scorecard", {
                "overall_score": 7.5,
                "checks": {
                    "Code-Review": 8,
                    "Maintained": 10,
                    "Branch-Protection": 6,
                    "Pinned-Dependencies": 7,
                },
            }),
            _make_finding(FindingKind.VULNERABILITY, "osv", {
                "id": "GHSA-1", "severity": "high",
            }),
            _make_finding(FindingKind.OSSINDEX, "ossindex", {
                "id": "sonatype-1", "severity": "medium", "cvss_score": 5.0,
            }),
            _make_finding(FindingKind.DEPSDEV, "depsdev", {
                "advisory_count": 1, "published_at": "2024-01-01",
            }),
        ]
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/test@1.0", findings)

        assert result.confidence == 1.0
        assert len(result.sources_used) == 4
        assert 0 <= result.direct_score <= 10
        assert result.scorecard_raw is not None
        assert result.depsdev_raw is not None

    def test_no_findings_uses_defaults(self) -> None:
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/empty@1.0", [])

        assert result.confidence == 0.0
        assert result.sources_used == []
        assert result.security_practices_score == 5.0
        assert result.maintenance_health_score == 5.0
        assert result.supply_chain_hygiene_score == 5.0
        assert result.vulnerability_profile_score == 10.0

    def test_only_osv_vulns(self) -> None:
        findings = [
            _make_finding(FindingKind.VULNERABILITY, "osv", {
                "id": "CVE-1", "severity": "critical",
            }),
            _make_finding(FindingKind.VULNERABILITY, "osv", {
                "id": "CVE-2", "severity": "high",
            }),
        ]
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/risky@1.0", findings)

        assert result.confidence == 0.25
        assert "osv" in result.sources_used
        assert result.vulnerability_profile_score < 10.0

    def test_no_vulns_perfect_vuln_score(self) -> None:
        findings = [
            _make_finding(FindingKind.SCORECARD, "scorecard", {
                "checks": {"Code-Review": 10, "Maintained": 10},
            }),
        ]
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/safe@1.0", findings)

        assert result.vulnerability_profile_score == 10.0

    def test_custom_weights(self) -> None:
        weights = {
            "security_practices": 0.5,
            "vulnerability_profile": 0.2,
            "maintenance_health": 0.2,
            "supply_chain_hygiene": 0.1,
        }
        calc = TrustScoreCalculator(weights=weights)
        result = calc.compute("pkg:npm/test@1.0", [])

        expected = 5.0 * 0.5 + 10.0 * 0.2 + 5.0 * 0.2 + 5.0 * 0.1
        assert abs(result.direct_score - expected) < 0.01

    def test_depsdev_fallback_for_scorecard_checks(self) -> None:
        findings = [
            _make_finding(FindingKind.DEPSDEV, "depsdev", {
                "scorecard_checks": {"Code-Review": 7, "SAST": 8},
                "advisory_count": 0,
            }),
        ]
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/test@1.0", findings)

        assert result.security_practices_score == 7.5
        assert "depsdev" in result.sources_used

    def test_many_critical_vulns_floor_at_zero(self) -> None:
        findings = [
            _make_finding(FindingKind.VULNERABILITY, "osv", {
                "id": f"CVE-{i}", "severity": "critical",
            })
            for i in range(10)
        ]
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/terrible@1.0", findings)

        assert result.vulnerability_profile_score == 0.0

    def test_scorecard_raw_is_serialized(self) -> None:
        findings = [
            _make_finding(FindingKind.SCORECARD, "scorecard", {
                "overall_score": 5.0,
                "checks": {"Maintained": 5},
            }),
        ]
        calc = TrustScoreCalculator()
        result = calc.compute("pkg:npm/test@1.0", findings)

        assert result.scorecard_raw is not None
        assert "Maintained" in result.scorecard_raw


class TestTrustScoreResult:
    """Tests for the TrustScoreResult dataclass."""

    def test_dataclass_fields(self) -> None:
        result = TrustScoreResult(
            purl="pkg:npm/test@1.0",
            direct_score=7.5,
            confidence=0.75,
            security_practices_score=8.0,
            vulnerability_profile_score=7.0,
            maintenance_health_score=6.0,
            supply_chain_hygiene_score=8.5,
            sources_used=["scorecard", "osv", "depsdev"],
        )
        assert result.purl == "pkg:npm/test@1.0"
        assert result.direct_score == 7.5
        assert result.scorecard_raw is None
