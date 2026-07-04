"""Tests for trust score report routes and helper functions.

Covers _trust_score_cell, _heatmap_cell, _confidence_badge, _missing_factors,
_recommendation, and report endpoints: trust-scores, trust-score-gaps,
trust-score-heatmap, application-risk-dashboard, risk-outliers, risk-path-explorer.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sbom_graph_api.routes.reports.trust_scores import (
    _confidence_badge,
    _heatmap_cell,
    _missing_factors,
    _recommendation,
    _trust_score_cell,
)


class TestTrustScoreCell:
    """Tests for _trust_score_cell helper."""

    def test_low_score_returns_low_css(self) -> None:
        """Score < 4 returns trust-score-low class."""
        result = _trust_score_cell(2.5)
        assert "trust-score-low" in str(result)
        assert "2.5" in str(result)

    def test_medium_score_returns_medium_css(self) -> None:
        """Score 4 <= x < 7 returns trust-score-medium class."""
        result = _trust_score_cell(5.0)
        assert "trust-score-medium" in str(result)
        assert "5.0" in str(result)

    def test_high_score_returns_high_css(self) -> None:
        """Score >= 7 returns trust-score-high class."""
        result = _trust_score_cell(8.5)
        assert "trust-score-high" in str(result)
        assert "8.5" in str(result)

    def test_none_returns_empty_string(self) -> None:
        """None returns empty string."""
        result = _trust_score_cell(None)
        assert result == ""

    def test_invalid_type_returns_empty_string(self) -> None:
        """Invalid type (e.g. string) returns empty string."""
        result = _trust_score_cell("not-a-number")  # type: ignore[arg-type]
        assert result == ""

    def test_boundary_four_returns_medium(self) -> None:
        """Score exactly 4.0 returns medium (4 < 7)."""
        result = _trust_score_cell(4.0)
        assert "trust-score-medium" in str(result)

    def test_boundary_seven_returns_high(self) -> None:
        """Score exactly 7.0 returns high."""
        result = _trust_score_cell(7.0)
        assert "trust-score-high" in str(result)


class TestHeatmapCell:
    """Tests for _heatmap_cell helper."""

    def test_low_score_returns_heat_low(self) -> None:
        """Score < 4 returns heat-low."""
        result = _heatmap_cell(2.0)
        assert result["css"] == "heat-low"
        assert result["value"] == "2.0"

    def test_medium_score_returns_heat_medium(self) -> None:
        """Score 4 <= x < 7 returns heat-medium."""
        result = _heatmap_cell(5.5)
        assert result["css"] == "heat-medium"
        assert result["value"] == "5.5"

    def test_high_score_returns_heat_high(self) -> None:
        """Score >= 7 returns heat-high."""
        result = _heatmap_cell(9.0)
        assert result["css"] == "heat-high"
        assert result["value"] == "9.0"

    def test_none_returns_heat_na(self) -> None:
        """None returns heat-na with dash value."""
        result = _heatmap_cell(None)
        assert result["css"] == "heat-na"
        assert result["value"] == "-"

    def test_invalid_type_returns_heat_na(self) -> None:
        """Invalid type returns heat-na."""
        result = _heatmap_cell("invalid")  # type: ignore[arg-type]
        assert result["css"] == "heat-na"
        assert result["value"] == "-"


class TestConfidenceBadge:
    """Tests for _confidence_badge helper."""

    def test_valid_confidence_returns_badge(self) -> None:
        """Valid confidence (0-1) returns percentage badge."""
        result = _confidence_badge(0.85)
        assert "confidence-badge" in str(result)
        assert "85%" in str(result)

    def test_zero_confidence_returns_badge(self) -> None:
        """Zero confidence returns 0% badge."""
        result = _confidence_badge(0.0)
        assert "0%" in str(result)

    def test_none_returns_empty_string(self) -> None:
        """None returns empty string."""
        result = _confidence_badge(None)
        assert result == ""

    def test_invalid_type_returns_empty_string(self) -> None:
        """Invalid type returns empty string."""
        result = _confidence_badge("not-a-float")  # type: ignore[arg-type]
        assert result == ""


class TestMissingFactors:
    """Tests for _missing_factors helper."""

    def test_all_present_returns_all_sources_present(self) -> None:
        """When all four sources used, returns ['All sources present']."""
        sources = ["scorecard", "osv", "sonatype", "depsdev"]
        result = _missing_factors(sources)
        assert result == ["All sources present"]

    def test_some_missing_returns_missing_labels(self) -> None:
        """When some sources missing, returns No X for each."""
        sources = ["scorecard", "osv"]
        result = _missing_factors(sources)
        assert "No Sonatype OSS Index" in result
        assert "No deps.dev" in result
        assert "No OpenSSF Scorecard" not in result
        assert "No Vulnerability scan (OSV)" not in result

    def test_none_present_returns_all_missing(self) -> None:
        """When sources_used is empty, returns all four No X labels."""
        result = _missing_factors([])
        assert len(result) == 4
        assert any("OpenSSF Scorecard" in m for m in result)
        assert any("Vulnerability" in m for m in result)
        assert any("Sonatype" in m for m in result)
        assert any("deps.dev" in m for m in result)

    def test_none_input_returns_all_missing(self) -> None:
        """When sources_used is None, returns all four No X labels."""
        result = _missing_factors(None)
        assert len(result) == 4

    def test_case_insensitive_matching(self) -> None:
        """Source IDs are matched case-insensitively."""
        sources = ["SCORECARD", "OSV", "SONATYPE", "DEPSDEV"]
        result = _missing_factors(sources)
        assert result == ["All sources present"]


class TestRecommendation:
    """Tests for _recommendation helper."""

    def test_empty_missing_returns_data_complete(self) -> None:
        """Empty missing list returns Data complete."""
        assert _recommendation([]) == "Data complete"

    def test_all_sources_present_returns_data_complete(self) -> None:
        """All sources present returns Data complete."""
        assert _recommendation(["All sources present"]) == "Data complete"

    def test_vulnerability_missing_returns_enrichment(self) -> None:
        """Missing vulnerability/OSV returns Run vulnerability enrichment."""
        assert (
            _recommendation(["No Vulnerability scan (OSV)"])
            == "Run vulnerability enrichment"
        )
        assert (
            _recommendation(["No deps.dev", "No Vulnerability scan (OSV)"])
            == "Run vulnerability enrichment"
        )

    def test_scorecard_missing_returns_link_repo(self) -> None:
        """Missing Scorecard returns Link source repo for Scorecard."""
        assert (
            _recommendation(["No OpenSSF Scorecard"])
            == "Link source repo for Scorecard"
        )

    def test_other_missing_returns_add_sources(self) -> None:
        """Other missing factors returns Add missing data sources."""
        assert (
            _recommendation(["No Sonatype OSS Index"])
            == "Add missing data sources"
        )
        assert (
            _recommendation(["No deps.dev"])
            == "Add missing data sources"
        )


_TRUST_SCORES_SUMMARY = {
    "total": 1,
    "avg_direct": 7.5,
    "avg_effective": 6.8,
    "low": 0,
    "medium": 1,
    "high": 0,
}


def _make_trust_scores_mock(rows=None, count=0) -> MagicMock:
    """Return a mock service with all trust-scores methods stubbed."""
    mock_service = MagicMock()
    mock_service.get_all_trust_scores_for_report.return_value = rows or []
    mock_service.count_all_trust_scores_for_report.return_value = count
    mock_service.get_trust_scores_summary.return_value = _TRUST_SCORES_SUMMARY
    return mock_service


class TestTrustScoresReport:
    """Tests for GET /reports/trust-scores."""

    def test_returns_html(self, client) -> None:
        """Default format returns HTML."""
        rows = [
            {
                "purl": "pkg:npm/foo@1.0",
                "project_name": "foo",
                "version": "1.0",
                "direct_score": 7.5,
                "effective_score": 6.8,
                "confidence": 0.85,
                "sources_used": ["osv", "scorecard"],
            },
        ]
        mock_service = _make_trust_scores_mock(rows=rows, count=1)

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores")

        assert resp.status_code == 200
        assert b"Trust Scores" in resp.data
        assert b"foo" in resp.data

    def test_returns_json(self, client) -> None:
        """format=json returns streamed JSON with report_type in meta."""
        rows = [
            {
                "purl": "pkg:npm/foo@1.0",
                "project_name": "foo",
                "version": "1.0",
                "direct_score": 7.5,
                "effective_score": 6.8,
                "confidence": 0.85,
                "sources_used": ["osv", "scorecard"],
            },
        ]
        mock_service = _make_trust_scores_mock(rows=rows, count=1)

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "trust-scores"
        assert any(r["purl"] == "pkg:npm/foo@1.0" for r in data["data"])

    def test_returns_excel(self, client) -> None:
        """format=excel returns Excel download."""
        rows = [
            {
                "purl": "pkg:npm/foo@1.0",
                "project_name": "foo",
                "version": "1.0",
                "direct_score": 7.5,
                "effective_score": 6.8,
                "confidence": 0.85,
                "sources_used": ["osv"],
            },
        ]
        mock_service = _make_trust_scores_mock(rows=rows, count=1)

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores?format=excel")

        assert resp.status_code == 200
        assert "spreadsheet" in resp.content_type or "excel" in resp.content_type

    def test_internal_only_passed_to_service(self, client) -> None:
        """internal_only param is passed to service."""
        mock_service = _make_trust_scores_mock()

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/trust-scores?internal_only=true")

        call_kwargs = mock_service.get_all_trust_scores_for_report.call_args.kwargs
        assert call_kwargs.get("internal_only") is True

    def test_name_filter_threaded_and_search_box_renders(self, client) -> None:
        """The name param reaches page/count/summary and the search box is prefilled."""
        mock_service = _make_trust_scores_mock()

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores?name=foo")

        assert resp.status_code == 200
        assert mock_service.get_all_trust_scores_for_report.call_args.kwargs.get("name") == "foo"
        assert mock_service.count_all_trust_scores_for_report.call_args.kwargs.get("name") == "foo"
        assert mock_service.get_trust_scores_summary.call_args.kwargs.get("name") == "foo"
        html = resp.data.decode("utf-8")
        assert "nameSearch" in html
        assert 'value="foo"' in html

    def test_html_includes_avg_direct_score(self, client) -> None:
        """HTML stats block includes Avg Direct Score (restored in Phase 1.6)."""
        mock_service = _make_trust_scores_mock()
        mock_service.get_trust_scores_summary.return_value = {
            "total": 3,
            "avg_direct": 6.20,
            "avg_effective": 5.80,
            "low": 1,
            "medium": 1,
            "high": 1,
        }

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores")

        assert resp.status_code == 200
        assert b"Avg Direct Score" in resp.data
        assert b"6.20" in resp.data

    def test_html_includes_avg_effective_score(self, client) -> None:
        """HTML stats block includes Avg Effective Score (restored in Phase 1.6)."""
        mock_service = _make_trust_scores_mock()
        mock_service.get_trust_scores_summary.return_value = {
            "total": 3,
            "avg_direct": 6.20,
            "avg_effective": 5.80,
            "low": 1,
            "medium": 1,
            "high": 1,
        }

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores")

        assert resp.status_code == 200
        assert b"Avg Effective Score" in resp.data
        assert b"5.80" in resp.data

    def test_html_includes_distribution(self, client) -> None:
        """HTML stats block includes Distribution (Low/Med/High) (restored in Phase 1.6)."""
        mock_service = _make_trust_scores_mock()
        mock_service.get_trust_scores_summary.return_value = {
            "total": 3,
            "avg_direct": 6.20,
            "avg_effective": 5.80,
            "low": 1,
            "medium": 1,
            "high": 1,
        }

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores")

        assert resp.status_code == 200
        assert b"Distribution (Low/Med/High)" in resp.data
        assert b"1/1/1" in resp.data

    def test_json_stats_include_avg_and_distribution(self, client) -> None:
        """JSON stats block includes avg scores and distribution (Phase 1.6)."""
        mock_service = _make_trust_scores_mock()
        mock_service.get_trust_scores_summary.return_value = {
            "total": 2,
            "avg_direct": 8.00,
            "avg_effective": 7.50,
            "low": 0,
            "medium": 0,
            "high": 2,
        }
        mock_service.count_all_trust_scores_for_report.return_value = 2

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        stats = data.get("stats", {})
        assert "Avg Direct Score" in stats
        assert "Avg Effective Score" in stats
        assert "Distribution (Low/Med/High)" in stats
        assert stats["Distribution (Low/Med/High)"] == "0/0/2"


class TestTrustScoreGapsReport:
    """Tests for GET /reports/trust-score-gaps."""

    def test_returns_html(self, client) -> None:
        """Default format returns HTML."""
        mock_service = MagicMock()
        mock_service.get_trust_score_gaps.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "project_name": "lib",
                "version": "1.0",
                "confidence": 0.3,
                "sources_used": ["scorecard"],
                "direct_score": 6.0,
                "dependents_count": 5,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-gaps")

        assert resp.status_code == 200
        assert b"Trust Score Gaps" in resp.data
        assert b"lib" in resp.data

    def test_returns_json(self, client) -> None:
        """format=json returns JSON."""
        mock_service = MagicMock()
        mock_service.get_trust_score_gaps.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "project_name": "lib",
                "version": "1.0",
                "confidence": 0.3,
                "sources_used": ["scorecard"],
                "direct_score": 6.0,
                "dependents_count": 5,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-gaps?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "trust-score-gaps"
        assert data["stats"]["count"] == 1

    def test_limit_param_passed_to_service(self, client) -> None:
        """limit param is passed to service."""
        mock_service = MagicMock()
        mock_service.get_trust_score_gaps.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/trust-score-gaps?limit=50")

        mock_service.get_trust_score_gaps.assert_called_once_with(limit=50)


class TestTrustScoreHeatmap:
    """Tests for GET /reports/trust-score-heatmap."""

    def test_returns_html(self, client) -> None:
        """Default format returns HTML heatmap."""
        mock_service = MagicMock()
        mock_service.get_trust_scores_heatmap.return_value = [
            {
                "purl": "pkg:npm/foo@1.0",
                "project_name": "foo",
                "version": "1.0",
                "security_practices_score": 7.0,
                "vulnerability_profile_score": 6.0,
                "maintenance_health_score": 8.0,
                "supply_chain_hygiene_score": 7.5,
                "effective_score": 7.0,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-heatmap")

        assert resp.status_code == 200
        assert b"Trust Score Heatmap" in resp.data or b"Heatmap" in resp.data
        assert b"foo" in resp.data

    def test_returns_json(self, client) -> None:
        """format=json returns JSON."""
        mock_service = MagicMock()
        mock_service.get_trust_scores_heatmap.return_value = [
            {
                "purl": "pkg:npm/foo@1.0",
                "project_name": "foo",
                "version": "1.0",
                "effective_score": 7.0,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-heatmap?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "trust-score-heatmap"
        assert data["stats"]["count"] == 1
        assert len(data["packages"]) == 1


class TestApplicationRiskDashboard:
    """Tests for GET /reports/application-risk-dashboard."""

    def test_returns_html(self, client) -> None:
        """Default format returns HTML dashboard."""
        mock_service = MagicMock()
        mock_service.get_application_risk_dashboard.return_value = [
            {
                "purl": "pkg:maven/org/app@1.0",
                "project_name": "app",
                "effective_score": 7.5,
                "direct_dep_count": 10,
                "transitive_dep_count": 50,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/application-risk-dashboard")

        assert resp.status_code == 200
        assert b"app" in resp.data

    def test_returns_json(self, client) -> None:
        """format=json returns JSON."""
        mock_service = MagicMock()
        mock_service.get_application_risk_dashboard.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/application-risk-dashboard?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "application-risk-dashboard"


class TestRiskPropagationGraph:
    """Tests for GET /reports/risk-propagation-graph."""

    def test_returns_html(self, client) -> None:
        """Returns HTML page with vis.js graph."""
        resp = client.get("/reports/risk-propagation-graph")
        assert resp.status_code == 200
        assert b"risk" in resp.data.lower() or b"propagation" in resp.data.lower()


class TestRiskOutliers:
    """Tests for GET /reports/risk-outliers."""

    def test_returns_html(self, client) -> None:
        """Default format returns HTML."""
        mock_service = MagicMock()
        mock_service.get_risk_outliers.return_value = [
            {
                "purl": "pkg:maven/org/weak@1.0",
                "project_name": "weak",
                "version": "1.0",
                "effective_score": 2.5,
                "dependents_count": 10,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/risk-outliers")

        assert resp.status_code == 200
        assert b"weak" in resp.data

    def test_returns_json(self, client) -> None:
        """format=json returns JSON."""
        mock_service = MagicMock()
        mock_service.get_risk_outliers.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/risk-outliers?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "risk-outliers"


class TestRiskPathExplorer:
    """Tests for GET /reports/risk-path-explorer/<purl>."""

    def test_returns_html(self, client) -> None:
        """Valid purl returns HTML risk path explorer."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "purl": "pkg:maven/org/lib@1.0",
            "effective_score": 5.0,
        }
        mock_service.get_trust_score_risk_path.return_value = [
            {"purl": "pkg:maven/org/dep@1.0", "direct_score": 3.0, "depth": 1},
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            purl = "pkg:maven/org/lib@1.0"
            resp = client.get(f"/reports/risk-path-explorer/{purl}")

        assert resp.status_code == 200
        assert b"Risk Path" in resp.data or b"risk" in resp.data.lower()

    def test_returns_json(self, client) -> None:
        """format=json returns JSON."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "purl": "pkg:maven/org/lib@1.0",
            "effective_score": 5.0,
        }
        mock_service.get_trust_score_risk_path.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            purl = "pkg:maven/org/lib@1.0"
            resp = client.get(f"/reports/risk-path-explorer/{purl}?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "risk-path-explorer"
        assert data["purl"] == "pkg:maven/org/lib@1.0"

    def test_invalid_purl_returns_400(self, client) -> None:
        """Invalid purl returns 400."""
        resp = client.get("/reports/risk-path-explorer/not-a-purl")
        assert resp.status_code == 400


class TestWhatifSimulator:
    """Tests for GET /reports/whatif-simulator."""

    def test_returns_html(self, client) -> None:
        """Returns HTML what-if simulator page."""
        resp = client.get("/reports/whatif-simulator")
        assert resp.status_code == 200
        assert b"What-If" in resp.data or b"Simulator" in resp.data
