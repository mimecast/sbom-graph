"""Phase 1.6: tests asserting restored full-set aggregate stats.

Covers:
- trust-scores: Avg Direct Score, Avg Effective Score, Distribution (Low/Med/High) in HTML and JSON stats
- sbom-inventory: By Format / By Source in HTML; top-level count in JSON
- policy-violations: Total Affected Dependants in HTML stats
- sbom-coverage: flat JSON payload validates against updated SBOM_COVERAGE_SCHEMA
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import jsonschema
import pytest

from sbom_graph_api.schemas.definitions import SBOM_COVERAGE_SCHEMA

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TRUST_SUMMARY = {
    "total": 3,
    "avg_direct": 6.25,
    "avg_effective": 5.80,
    "low": 1,
    "medium": 1,
    "high": 1,
}


def _trust_service(rows=None, count=3, summary=None):
    svc = MagicMock()
    svc.get_all_trust_scores_for_report.return_value = rows or []
    svc.count_all_trust_scores_for_report.return_value = count
    svc.get_trust_scores_summary.return_value = summary or _TRUST_SUMMARY
    return svc


# ---------------------------------------------------------------------------
# 1. trust-scores
# ---------------------------------------------------------------------------


class TestTrustScoresRestoredStats:
    """Restored stats: Avg Direct/Effective Score and Distribution in HTML + JSON."""

    _rows = [
        {
            "purl": "pkg:npm/a@1.0",
            "project_name": "a",
            "version": "1.0",
            "direct_score": 3.0,
            "effective_score": 2.5,
            "confidence": 0.6,
            "sources_used": ["osv"],
        },
        {
            "purl": "pkg:npm/b@2.0",
            "project_name": "b",
            "version": "2.0",
            "direct_score": 5.0,
            "effective_score": 5.5,
            "confidence": 0.8,
            "sources_used": ["osv", "scorecard"],
        },
        {
            "purl": "pkg:npm/c@3.0",
            "project_name": "c",
            "version": "3.0",
            "direct_score": 9.0,
            "effective_score": 8.5,
            "confidence": 0.95,
            "sources_used": ["osv", "scorecard", "sonatype", "depsdev"],
        },
    ]

    def test_html_includes_avg_direct_score(self, client) -> None:
        """HTML stats block shows 'Avg Direct Score'."""
        svc = _trust_service(rows=self._rows, count=3)
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/trust-scores")
        assert resp.status_code == 200
        assert b"Avg Direct Score" in resp.data

    def test_html_includes_avg_effective_score(self, client) -> None:
        """HTML stats block shows 'Avg Effective Score'."""
        svc = _trust_service(rows=self._rows, count=3)
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/trust-scores")
        assert b"Avg Effective Score" in resp.data

    def test_html_includes_distribution(self, client) -> None:
        """HTML stats block shows 'Distribution (Low/Med/High)'."""
        svc = _trust_service(rows=self._rows, count=3)
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/trust-scores")
        assert b"Distribution" in resp.data
        assert b"Low/Med/High" in resp.data or b"1/1/1" in resp.data

    def test_json_stats_contains_avg_and_distribution(self, client) -> None:
        """JSON stats block contains avg and distribution keys."""
        svc = _trust_service(rows=self._rows, count=3)
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/trust-scores?format=json")
        assert resp.status_code == 200
        data = resp.get_json()
        stats = data.get("stats", {})
        assert "Avg Direct Score" in stats
        assert "Avg Effective Score" in stats
        assert "Distribution (Low/Med/High)" in stats
        assert stats["Distribution (Low/Med/High)"] == "1/1/1"
        assert stats["Avg Direct Score"] == "6.25"
        assert stats["Avg Effective Score"] == "5.80"

    def test_json_still_has_total_packages(self, client) -> None:
        """JSON stats still includes Total Packages."""
        svc = _trust_service(rows=self._rows, count=3)
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/trust-scores?format=json")
        stats = resp.get_json()["stats"]
        assert "Total Packages" in stats

    def test_summary_called_with_correct_params(self, client) -> None:
        """get_trust_scores_summary receives internal_only, min_score, sort_by."""
        svc = _trust_service()
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            client.get("/reports/trust-scores?internal_only=true&min_score=3.0&sort_by=direct_score")
        svc.get_trust_scores_summary.assert_called_once_with(
            internal_only=True,
            min_score=3.0,
            sort_by="direct_score",
            name=None,
        )

    def test_null_avg_shows_dash(self, client) -> None:
        """When avg_direct/avg_effective is None, stats show '-'."""
        svc = _trust_service(
            rows=[],
            count=0,
            summary={"total": 0, "avg_direct": None, "avg_effective": None, "low": 0, "medium": 0, "high": 0},
        )
        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/trust-scores?format=json")
        stats = resp.get_json()["stats"]
        assert stats["Avg Direct Score"] == "-"
        assert stats["Avg Effective Score"] == "-"


# ---------------------------------------------------------------------------
# 2. sbom-inventory
# ---------------------------------------------------------------------------


def _inv_service(page=None, count=0, tools=None, summary=None):
    svc = MagicMock()
    svc.get_sbom_inventory_paged.return_value = page or []
    svc.count_sbom_inventory.return_value = count
    svc.get_sbom_inventory_tools.return_value = tools or []
    svc.get_sbom_inventory_summary.return_value = summary or {
        "total": 0,
        "by_format": {},
        "by_source": {},
    }
    return svc


class TestSbomInventoryRestoredStats:
    """Restored stats: By Format / By Source in HTML; top-level count in JSON."""

    _summary = {
        "total": 4,
        "by_format": {"CycloneDX": 3, "SPDX": 1},
        "by_source": {"api_upload": 2, "webhook": 2},
    }
    _rows = [
        {
            "record_id": "r1",
            "format": "CycloneDX",
            "ingested_at": "2024-01-01T00:00:00Z",
            "source": "api_upload",
            "tool_name": "trivy",
            "tool_version": "0.48",
            "serial_number": None,
            "document_hash": None,
            "version_count": 1,
        },
    ]

    def test_html_shows_by_format(self, client) -> None:
        """HTML stats block includes 'By Format (CycloneDX)'."""
        svc = _inv_service(page=self._rows, count=4, summary=self._summary)
        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/sbom-inventory")
        assert resp.status_code == 200
        assert b"By Format (CycloneDX)" in resp.data

    def test_html_shows_by_source(self, client) -> None:
        """HTML stats block includes 'By Source (api_upload)'."""
        svc = _inv_service(page=self._rows, count=4, summary=self._summary)
        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/sbom-inventory")
        assert b"By Source (api_upload)" in resp.data

    def test_json_has_top_level_count(self, client) -> None:
        """JSON response has a top-level 'count' key."""
        svc = _inv_service(page=self._rows, count=4, summary=self._summary)
        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/sbom-inventory?format=json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "count" in data
        assert data["count"] == 4

    def test_json_report_type_still_present(self, client) -> None:
        """JSON response still has report_type."""
        svc = _inv_service(summary=self._summary)
        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/sbom-inventory?format=json")
        data = resp.get_json()
        assert data["report_type"] == "sbom-inventory"

    def test_summary_called_with_filters(self, client) -> None:
        """get_sbom_inventory_summary is called with the request filters."""
        svc = _inv_service(summary=self._summary)
        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=svc,
        ):
            client.get("/reports/sbom-inventory?search=trivy")
        svc.get_sbom_inventory_summary.assert_called_once()
        kwargs = svc.get_sbom_inventory_summary.call_args.kwargs
        assert kwargs.get("search") == "trivy"


# ---------------------------------------------------------------------------
# 3. policy-violations
# ---------------------------------------------------------------------------


def _pol_service(data=None, count=0, total_dependants=0):
    svc = MagicMock()
    svc.get_policy_violations.return_value = data or []
    svc.count_policy_violations.return_value = count
    svc.get_policy_violations_total_dependants.return_value = total_dependants
    return svc


class TestPolicyViolationsRestoredStats:
    """Restored stats: Total Affected Dependants in HTML."""

    _data = [
        {
            "annotation_id": "ann-1",
            "purl": "pkg:npm/bad-lib@1.0",
            "project_name": "bad-lib",
            "version_name": "1.0",
            "justification": "Deprecated",
            "created_by": "admin",
            "created_at": "2024-01-01",
            "expires_at": None,
            "dependant_count": 5,
        },
        {
            "annotation_id": "ann-2",
            "purl": "pkg:npm/evil-dep@2.0",
            "project_name": "evil-dep",
            "version_name": "2.0",
            "justification": "Security risk",
            "created_by": "admin",
            "created_at": "2024-02-01",
            "expires_at": None,
            "dependant_count": 3,
        },
    ]

    def test_html_shows_total_affected_dependants(self, client) -> None:
        """HTML stats block shows 'Total Affected Dependants'."""
        svc = _pol_service(data=self._data, count=2, total_dependants=8)
        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/policy-violations")
        assert resp.status_code == 200
        assert b"Total Affected Dependants" in resp.data

    def test_html_total_dependants_value(self, client) -> None:
        """HTML stats block shows the correct dependant count value."""
        svc = _pol_service(data=self._data, count=2, total_dependants=8)
        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/policy-violations")
        assert b"8" in resp.data

    def test_html_still_shows_total_violations(self, client) -> None:
        """HTML stats block still shows 'Total Violations'."""
        svc = _pol_service(data=self._data, count=2, total_dependants=8)
        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/policy-violations")
        assert b"Total Violations" in resp.data

    def test_total_dependants_service_called_with_internal_only(self, client) -> None:
        """get_policy_violations_total_dependants is called with internal_only."""
        svc = _pol_service()
        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=svc,
        ):
            client.get("/reports/policy-violations?internal_only=true")
        svc.get_policy_violations_total_dependants.assert_called_once_with(internal_only=True)

    def test_json_stats_contains_total_affected_dependants(self, client) -> None:
        """JSON stats block contains 'Total Affected Dependants'."""
        svc = _pol_service(data=self._data, count=2, total_dependants=8)
        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=svc,
        ):
            resp = client.get("/reports/policy-violations?format=json")
        assert resp.status_code == 200
        data = resp.get_json()
        stats = data.get("stats", {})
        assert "Total Affected Dependants" in stats
        assert stats["Total Affected Dependants"] == 8


# ---------------------------------------------------------------------------
# 4. sbom-coverage schema validation
# ---------------------------------------------------------------------------


class TestSbomCoverageSchemaFlat:
    """SBOM_COVERAGE_SCHEMA updated to flat shape — no 'coverage' wrapper."""

    _flat_payload = {
        "report_type": "sbom-coverage",
        "generated_at": "2024-06-01T00:00:00+00:00",
        "recent_days": 30,
        "internal_only": False,
        "stats": {
            "total_projects": 10,
            "fresh": 4,
            "stale": 3,
            "never": 3,
            "fresh_pct": 40.0,
            "stale_pct": 30.0,
            "never_pct": 30.0,
        },
        "projects": [
            {
                "project_name": "app-a",
                "version_name": "1.0",
                "project_group": "",
                "status": "fresh",
                "last_ingested": "2024-06-01T00:00:00Z",
                "tool_name": "trivy",
            },
        ],
    }

    def test_flat_payload_validates_against_schema(self) -> None:
        """A flat sbom-coverage payload passes jsonschema validation."""
        jsonschema.validate(instance=self._flat_payload, schema=SBOM_COVERAGE_SCHEMA)

    def test_old_nested_coverage_payload_fails_schema(self) -> None:
        """A payload with the old 'coverage' wrapper no longer validates."""
        old_payload = {
            "report_type": "sbom-coverage",
            "generated_at": "2024-06-01T00:00:00+00:00",
            "coverage": {
                "stats": {"total_projects": 10, "fresh": 4, "stale": 3, "never": 3},
                "projects": [],
            },
            "recent_days": 30,
            "internal_only": False,
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=old_payload, schema=SBOM_COVERAGE_SCHEMA)

    def test_schema_requires_stats_and_projects_not_coverage(self) -> None:
        """Schema required list contains stats and projects but not coverage."""
        required = SBOM_COVERAGE_SCHEMA["required"]
        assert "stats" in required
        assert "projects" in required
        assert "coverage" not in required

    def test_coverage_route_json_validates_against_schema(self, client) -> None:
        """Live /reports/coverage?format=json output validates against the schema."""
        mock_service = MagicMock()
        mock_service.get_sbom_coverage_for_dashboard.return_value = {
            "stats": {
                "total_projects": 2,
                "fresh": 1,
                "stale": 1,
                "never": 0,
                "fresh_pct": 50.0,
                "stale_pct": 50.0,
                "never_pct": 0.0,
            },
            "projects": [
                {
                    "project_name": "proj-a",
                    "version_name": "1.0",
                    "project_group": "",
                    "status": "fresh",
                    "last_ingested": "2024-06-01T00:00:00Z",
                    "tool_name": "trivy",
                },
            ],
            "recent_days": 30,
        }
        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/coverage?format=json")
        assert resp.status_code == 200
        data = resp.get_json()
        jsonschema.validate(instance=data, schema=SBOM_COVERAGE_SCHEMA)
