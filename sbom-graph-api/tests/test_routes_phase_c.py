"""Unit tests for Phase C API routes: trust scores, SBOM provenance, patch plan, VEX auto-stub."""

from unittest.mock import MagicMock, patch


class TestPackageLicenses:
    """Tests for GET /api/v1/package/<purl>/licenses."""

    def test_invalid_purl_returns_400(self, client) -> None:
        """Invalid purl returns 400."""
        resp = client.get("/api/v1/package/invalid-purl/licenses")
        assert resp.status_code == 400

    def test_returns_licenses(self, client) -> None:
        """Valid purl returns licenses."""
        mock_service = MagicMock()
        mock_service.get_package_licenses.return_value = [
            {"spdx_id": "MIT", "name": "MIT", "risk_category": "low"},
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/licenses"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["licenses"][0]["spdx_id"] == "MIT"


class TestPackageVulnerabilities:
    """Tests for GET /api/v1/package/<purl>/vulns."""

    def test_invalid_purl_returns_400(self, client) -> None:
        """Invalid purl returns 400."""
        resp = client.get("/api/v1/package/not-purl/vulns")
        assert resp.status_code == 400


class TestPackageTrustCheck:
    """Tests for GET /api/v1/package/<purl>/trust-check."""

    def test_no_trust_score_returns_fail(self, client) -> None:
        """When no trust score, returns pass=False."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = None

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/trust-check"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["pass"] is False
        assert "No trust score" in data["reason"]

    def test_meets_threshold_returns_pass(self, client) -> None:
        """When score meets threshold, returns pass=True."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 7.0,
            "direct_score": 7.0,
            "confidence": 0.8,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/trust-check"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["pass"] is True
        assert data["reason"] == "OK"


class TestSupplyChainRisk:
    """Tests for GET /api/v1/application/<purl>/supply-chain-risk."""

    def test_returns_risk(self, client) -> None:
        """Valid purl returns supply chain risk."""
        mock_service = MagicMock()
        mock_service.get_application_supply_chain_risk.return_value = {
            "effective_score": 6.5,
            "min_path_score": 4.0,
            "dep_count": 42,
            "weakest_links": [{"purl": "pkg:maven/org/weak@1.0", "score": 4.0}],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/application/pkg:maven/org/app@1.0/supply-chain-risk"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["effective_score"] == 6.5
        assert data["dep_count"] == 42

    def test_invalid_purl_returns_400(self, client) -> None:
        """Invalid purl returns 400."""
        resp = client.get(
            "/api/v1/application/not-a-purl/supply-chain-risk"
        )
        assert resp.status_code == 400

    def test_error_in_risk_returns_404(self, client) -> None:
        """Service returning error dict returns 404."""
        mock_service = MagicMock()
        mock_service.get_application_supply_chain_risk.return_value = {
            "error": "Application not found",
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/application/pkg:maven/org/missing@1.0/supply-chain-risk"
            )

        assert resp.status_code == 404


class TestTrustScoreDistribution:
    """Tests for GET /api/v1/analysis/trust-score-distribution."""

    def test_returns_distribution(self, client) -> None:
        """Returns histogram of trust scores."""
        mock_service = MagicMock()
        mock_service.get_trust_score_distribution.return_value = {
            "5.0": 10,
            "6.0": 20,
            "7.0": 15,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/analysis/trust-score-distribution")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "distribution" in data
        assert data["distribution"]["5.0"] == 10


class TestRemediationPriorities:
    """Tests for GET /api/v1/analysis/remediation-priorities."""

    def test_returns_priorities(self, client) -> None:
        """Returns packages ranked by remediation priority."""
        mock_service = MagicMock()
        mock_service.get_remediation_priorities.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "effective_score": 3.0,
                "dependant_count": 50,
            },
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/analysis/remediation-priorities")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "priorities" in data
        assert len(data["priorities"]) == 1
        assert data["priorities"][0]["purl"] == "pkg:maven/org/lib@1.0"

    def test_limit_param_passed_to_service(self, client) -> None:
        """limit query param is passed to service."""
        mock_service = MagicMock()
        mock_service.get_remediation_priorities.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/api/v1/analysis/remediation-priorities?limit=50")

        mock_service.get_remediation_priorities.assert_called_once_with(limit=50)


class TestRiskPropagationImpact:
    """Tests for GET /api/v1/analysis/risk-propagation-impact."""

    def test_returns_impacts(self, client) -> None:
        """Valid purl and simulated_score return impact list."""
        mock_service = MagicMock()
        mock_service.simulate_risk_propagation.return_value = [
            {
                "purl": "pkg:maven/org/app@1.0",
                "current_effective": 7.5,
                "simulated_effective": 5.0,
                "impact": 2.5,
            }
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/analysis/risk-propagation-impact"
                "?purl=pkg:maven/org/lib@1.0&simulated_score=5.0"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["purl"] == "pkg:maven/org/lib@1.0"
        assert data["simulated_score"] == 5.0
        assert len(data["impacts"]) == 1
        assert data["impacts"][0]["impact"] == 2.5

    def test_missing_purl_returns_400(self, client) -> None:
        """Missing purl returns 400."""
        resp = client.get("/api/v1/analysis/risk-propagation-impact?simulated_score=5.0")
        assert resp.status_code == 400

    def test_missing_simulated_score_returns_400(self, client) -> None:
        """Missing simulated_score returns 400."""
        resp = client.get("/api/v1/analysis/risk-propagation-impact?purl=pkg:maven/org/lib@1.0")
        assert resp.status_code == 400

    def test_invalid_purl_returns_400(self, client) -> None:
        """Non-purl returns 400."""
        resp = client.get(
            "/api/v1/analysis/risk-propagation-impact?purl=not-a-purl&simulated_score=5.0"
        )
        assert resp.status_code == 400


class TestGetSbomRecord:
    """Tests for GET /api/v1/sbom/<record_id>."""

    def test_returns_record(self, client) -> None:
        """Valid UUID returns SBOM record with purls."""
        mock_service = MagicMock()
        mock_service.get_sbom_record_by_id.return_value = {
            "record_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "format": "cyclonedx",
            "ingested_at": "2024-01-15T00:00:00Z",
            "source": "api_upload",
            "tool_name": "trivy",
            "tool_version": "0.48.0",
            "serial_number": None,
            "document_hash": None,
            "purls": ["pkg:maven/org/lib@1.0"],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/sbom/a1b2c3d4-e5f6-7890-abcd-ef1234567890")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["record_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert data["format"] == "cyclonedx"
        assert data["purls"] == ["pkg:maven/org/lib@1.0"]

    def test_invalid_record_id_returns_400(self, client) -> None:
        """Non-UUID record_id returns 400."""
        resp = client.get("/api/v1/sbom/not-a-uuid")
        assert resp.status_code == 400

    def test_record_not_found_returns_404(self, client) -> None:
        """Non-existent record returns 404."""
        mock_service = MagicMock()
        mock_service.get_sbom_record_by_id.return_value = None

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/sbom/a1b2c3d4-e5f6-7890-abcd-ef1234567890")

        assert resp.status_code == 404


class TestEvaluatePatchPlan:
    """Tests for POST /api/v1/patch-plan/evaluate."""

    def test_returns_evaluation(self, client) -> None:
        """Valid body returns vulnerability comparison."""
        mock_service = MagicMock()
        mock_service.evaluate_patch_plan.return_value = {
            "purl": "pkg:maven/org/lib@",
            "current_version": "1.0.0",
            "target_version": "2.0.0",
            "current_vulns": ["CVE-2024-1234"],
            "target_vulns": [],
            "resolved": ["CVE-2024-1234"],
            "added": [],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/patch-plan/evaluate",
                json={
                    "purl": "pkg:maven/org/lib@1.0.0",
                    "current_version": "1.0.0",
                    "target_version": "2.0.0",
                },
                content_type="application/json",
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["resolved"] == ["CVE-2024-1234"]
        assert data["added"] == []

    def test_missing_purl_returns_400(self, client) -> None:
        """Missing purl returns 400."""
        resp = client.post(
            "/api/v1/patch-plan/evaluate",
            json={"current_version": "1.0", "target_version": "2.0"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_no_body_returns_400(self, client) -> None:
        """Missing body returns 400."""
        resp = client.post(
            "/api/v1/patch-plan/evaluate",
            content_type="application/json",
        )
        assert resp.status_code == 400


class TestVexAutoStub:
    """Tests for POST /api/v1/vex/auto-stub."""

    def test_creates_stubs(self, client) -> None:
        """Valid purl creates VEX stubs and returns 201."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = [[1]]
        mock_service.generate_vex_auto_stubs.return_value = [
            {
                "statement_id": "stmt-1",
                "defect_id": "CVE-2024-1234",
                "status": "not_affected",
            }
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/vex/auto-stub",
                json={"purl": "pkg:maven/org/lib@1.0"},
                content_type="application/json",
            )

        assert resp.status_code == 201
        data = resp.get_json()
        assert data["purl"] == "pkg:maven/org/lib@1.0"
        assert data["count"] == 1
        assert data["created"][0]["status"] == "not_affected"

    def test_package_not_found_returns_404(self, client) -> None:
        """Non-existent package returns 404."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/vex/auto-stub",
                json={"purl": "pkg:maven/org/missing@1.0"},
                content_type="application/json",
            )

        assert resp.status_code == 404

    def test_missing_purl_returns_400(self, client) -> None:
        """Missing purl returns 400."""
        resp = client.post(
            "/api/v1/vex/auto-stub",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400


class TestTrustScoresReport:
    """Tests for GET /reports/trust-scores."""

    def test_json_format(self, client) -> None:
        """JSON format returns trust scores."""
        mock_service = MagicMock()
        mock_service.get_all_trust_scores_for_report.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "project_name": "lib",
                "direct_score": 7.5,
                "effective_score": 7.0,
                "confidence": 0.8,
                "sources_used": ["scorecard", "depsdev"],
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["trust_scores"][0]["purl"] == "pkg:maven/org/lib@1.0"

    def test_html_template_renders(self, client) -> None:
        """HTML format renders trust_scores template with colour-coded scores."""
        mock_service = MagicMock()
        mock_service.get_all_trust_scores_for_report.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "project_name": "lib",
                "version": "1.0",
                "direct_score": 7.5,
                "effective_score": 7.0,
                "confidence": 0.8,
                "sources_used": ["scorecard", "depsdev"],
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores")

        assert resp.status_code == 200
        assert b"Trust Scores" in resp.data
        assert b"trust-score-high" in resp.data
        assert b"confidence-badge" in resp.data
        assert b"lib" in resp.data

    def test_excel_format(self, client) -> None:
        """Excel format returns download."""
        mock_service = MagicMock()
        mock_service.get_all_trust_scores_for_report.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "project_name": "lib",
                "version": "1.0",
                "direct_score": 7.5,
                "effective_score": 7.0,
                "confidence": 0.8,
                "sources_used": ["scorecard"],
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores?format=excel")

        assert resp.status_code == 200
        assert "spreadsheet" in resp.content_type or "excel" in resp.content_type

    def test_min_score_passed_to_service(self, client) -> None:
        """min_score param is passed to service."""
        mock_service = MagicMock()
        mock_service.get_all_trust_scores_for_report.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/trust-scores?min_score=5.0")

        call_kwargs = mock_service.get_all_trust_scores_for_report.call_args.kwargs
        assert call_kwargs.get("min_score") == 5.0

    def test_sort_by_direct_score_passed_to_service(self, client) -> None:
        """sort_by=direct_score is passed to service."""
        mock_service = MagicMock()
        mock_service.get_all_trust_scores_for_report.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/trust-scores?sort_by=direct_score")

        mock_service.get_all_trust_scores_for_report.assert_called_once()
        call_kwargs = mock_service.get_all_trust_scores_for_report.call_args.kwargs
        assert call_kwargs.get("sort_by") == "direct_score"

    def test_low_medium_high_scores_render_correct_css(self, client) -> None:
        """Low/medium/high scores render correct CSS classes."""
        mock_service = MagicMock()
        mock_service.get_all_trust_scores_for_report.return_value = [
            {"purl": "p1", "project_name": "low", "version": "1", "direct_score": 2.0,
             "effective_score": 2.0, "confidence": 0.3, "sources_used": []},
            {"purl": "p2", "project_name": "med", "version": "1", "direct_score": 5.0,
             "effective_score": 5.0, "confidence": None, "sources_used": ["osv"]},
            {"purl": "p3", "project_name": "high", "version": "1", "direct_score": 8.0,
             "effective_score": 8.0, "confidence": 0.9, "sources_used": ["all"]},
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-scores")

        assert resp.status_code == 200
        assert b"trust-score-low" in resp.data
        assert b"trust-score-medium" in resp.data
        assert b"trust-score-high" in resp.data


class TestTrustScoreGapsReport:
    """Tests for GET /reports/trust-score-gaps."""

    def test_json_format(self, client) -> None:
        """JSON format returns gaps."""
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
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-gaps?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["gaps"][0]["confidence"] == 0.3

    def test_html_template_renders_with_missing_factors(self, client) -> None:
        """HTML format renders trust_score_gaps template with missing factors."""
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
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-gaps")

        assert resp.status_code == 200
        assert b"Trust Score Gaps" in resp.data
        assert b"lib" in resp.data
        assert b"Missing Factors" in resp.data
        assert b"Run vulnerability enrichment" in resp.data

    def test_all_sources_present_shows_data_complete(self, client) -> None:
        """When all sources present, recommendation is Data complete."""
        mock_service = MagicMock()
        mock_service.get_trust_score_gaps.return_value = [
            {
                "purl": "pkg:maven/org/lib@1.0",
                "project_name": "lib",
                "version": "1.0",
                "confidence": 0.9,
                "sources_used": ["scorecard", "osv", "sonatype", "depsdev"],
                "direct_score": 7.0,
                "dependents_count": 0,
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-gaps")

        assert resp.status_code == 200
        assert b"All sources present" in resp.data or b"Data complete" in resp.data

    def test_excel_format(self, client) -> None:
        """Excel format returns download."""
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
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.trust_scores.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/trust-score-gaps?format=excel")

        assert resp.status_code == 200
        assert "spreadsheet" in resp.content_type or "excel" in resp.content_type


class TestSbomInventoryReport:
    """Tests for GET /reports/sbom-inventory."""

    def test_json_format(self, client) -> None:
        """JSON format returns inventory."""
        mock_service = MagicMock()
        mock_service.get_sbom_inventory.return_value = [
            {
                "record_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "format": "cyclonedx",
                "ingested_at": "2024-01-15T00:00:00Z",
                "source": "api_upload",
                "tool_name": "trivy",
                "tool_version": "0.48.0",
                "serial_number": None,
                "document_hash": None,
                "version_count": 10,
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/sbom-inventory?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["inventory"][0]["format"] == "cyclonedx"

    def test_excel_format(self, client) -> None:
        """Excel format returns download."""
        mock_service = MagicMock()
        mock_service.get_sbom_inventory.return_value = [
            {
                "record_id": "rec-001",
                "format": "CycloneDX",
                "ingested_at": "2024-06-01T00:00:00Z",
                "source": "api",
                "tool_name": "trivy",
                "tool_version": "0.48",
                "serial_number": None,
                "document_hash": None,
                "version_count": 5,
            }
        ]

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/sbom-inventory?format=excel")

        assert resp.status_code == 200
        assert "spreadsheet" in resp.content_type or "excel" in resp.content_type


class TestSbomCoverageReport:
    """Tests for GET /reports/coverage."""

    def test_json_format(self, client) -> None:
        """JSON format returns coverage stats and project details."""
        mock_service = MagicMock()
        mock_service.get_sbom_coverage_for_dashboard.return_value = {
            "stats": {
                "total_projects": 100,
                "fresh": 60,
                "stale": 20,
                "never": 20,
                "fresh_pct": 60.0,
                "stale_pct": 20.0,
                "never_pct": 20.0,
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
            "recent_days": 30,
        }

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/coverage?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["coverage"]["stats"]["total_projects"] == 100
        assert data["coverage"]["stats"]["fresh"] == 60
        assert len(data["coverage"]["projects"]) == 1

    def test_excel_format(self, client) -> None:
        """Excel format returns download."""
        mock_service = MagicMock()
        mock_service.get_sbom_coverage_for_dashboard.return_value = {
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
            "recent_days": 30,
        }

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/coverage?format=excel")

        assert resp.status_code == 200
        assert "spreadsheet" in resp.content_type or "excel" in resp.content_type
