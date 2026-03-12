"""Tests for uncovered api_v1 endpoints to improve coverage.

Covers: trust-check (fail threshold, custom params), critical-dependencies,
remediation-priorities, risk-summary, package metadata, dependencies,
dependants, trust-score, risk-path, openapi.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestPackageTrustCheck:
    """Tests for GET /api/v1/package/<purl>/trust-check."""

    def test_fails_when_below_min_score(self, client) -> None:
        """When effective_score below threshold, returns pass=False."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 3.0,
            "direct_score": 3.0,
            "confidence": 0.8,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/trust-check"
                "?min_score=7.0"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["pass"] is False
        assert "effective_score" in data["reason"] or "3.0" in data["reason"]

    def test_fails_when_below_min_confidence(self, client) -> None:
        """When confidence below threshold, returns pass=False."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 8.0,
            "direct_score": 8.0,
            "confidence": 0.1,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/trust-check"
                "?min_confidence=0.5"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["pass"] is False
        assert "confidence" in data["reason"]

    def test_uses_direct_score_when_effective_missing(self, client) -> None:
        """When effective_score missing, uses direct_score."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
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
        assert data["effective_score"] == 7.0


class TestRemediationPriorities:
    """Tests for GET /api/v1/analysis/remediation-priorities."""

    def test_returns_priorities_with_limit(self, client) -> None:
        """Returns prioritized list with limit param."""
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
            resp = client.get(
                "/api/v1/analysis/remediation-priorities?limit=20"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "priorities" in data
        assert data["count"] == 1
        mock_service.get_remediation_priorities.assert_called_once_with(
            limit=20
        )


class TestCriticalDependencies:
    """Tests for GET /api/v1/analysis/critical-dependencies."""

    def test_sort_by_fan_in_returns_most_depended(self, client) -> None:
        """sort=fan_in calls get_most_depended_packages."""
        mock_service = MagicMock()
        mock_service.get_most_depended_packages.return_value = [
            {"purl": "pkg:maven/org/popular@1.0", "fan_in": 100},
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/analysis/critical-dependencies?sort=fan_in&limit=20"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert data["data"]["sort"] == "fan_in"
        mock_service.get_most_depended_packages.assert_called_once_with(
            limit=20
        )

    def test_sort_by_trust_score_returns_remediation_priorities(
        self, client
    ) -> None:
        """sort=trust_score calls get_remediation_priorities."""
        mock_service = MagicMock()
        mock_service.get_remediation_priorities.return_value = [
            {
                "purl": "pkg:maven/org/weak@1.0",
                "effective_score": 2.0,
                "dependant_count": 10,
            },
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/analysis/critical-dependencies"
                "?sort=trust_score&limit=10"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["data"]["sort"] == "trust_score"
        mock_service.get_remediation_priorities.assert_called_once_with(
            limit=10
        )


class TestRiskSummary:
    """Tests for GET /api/v1/analysis/risk-summary."""

    def test_returns_risk_metrics(self, client) -> None:
        """Returns aggregate risk metrics."""
        mock_service = MagicMock()
        mock_service.execute_query.side_effect = [
            [["critical", 5], ["high", 10]],
            [["high", 2], ["low", 50]],
            [["bad", 1], ["hold", 2]],
            [[100]],
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/analysis/risk-summary")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert "total_packages" in data["data"]
        assert "vulnerabilities_by_severity" in data["data"]
        assert "licenses_by_risk_category" in data["data"]
        assert "policy_annotations_by_type" in data["data"]


class TestPackageMetadata:
    """Tests for GET /api/v1/package/<purl>."""

    def test_returns_full_metadata(self, client) -> None:
        """Returns package metadata with vulns, licenses, trust score, policy."""
        mock_service = MagicMock()
        mock_service.find_version_by_purl.return_value = {"purl": "pkg:maven/org/lib@1.0"}
        mock_service.get_package_vulnerabilities.return_value = []
        mock_service.get_package_licenses.return_value = [
            {"spdx_id": "MIT", "name": "MIT", "risk_category": "low"},
        ]
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 7.0,
            "direct_score": 7.0,
        }
        mock_service.check_policy.return_value = {"status": "pass"}
        mock_service.get_vex_for_package.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert data["data"]["purl"] == "pkg:maven/org/lib@1.0"
        assert "vulnerabilities" in data["data"]
        assert "licenses" in data["data"]
        assert "trust_score" in data["data"]
        assert "policy" in data["data"]

    def test_package_not_found_returns_404(self, client) -> None:
        """Non-existent package returns 404."""
        mock_service = MagicMock()
        mock_service.find_version_by_purl.return_value = None

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/nonexistent@1.0")

        assert resp.status_code == 404


class TestPackageDependencies:
    """Tests for GET /api/v1/package/<purl>/dependencies."""

    def test_returns_paginated_dependencies(self, client) -> None:
        """Returns paginated dependency tree."""
        mock_service = MagicMock()
        mock_service.get_transitive_dependency_purls.return_value = [
            "pkg:maven/org/dep1@1.0",
            "pkg:maven/org/dep2@2.0",
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/dependencies"
                "?max_depth=5&offset=0&limit=10"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert "dependencies" in data["data"]
        assert "pagination" in data


class TestPackageDependants:
    """Tests for GET /api/v1/package/<purl>/dependants."""

    def test_returns_paginated_dependants(self, client) -> None:
        """Returns paginated dependant tree."""
        mock_service = MagicMock()
        mock_service.get_transitive_dependant_purls.return_value = [
            "pkg:maven/org/app1@1.0",
            "pkg:maven/org/app2@2.0",
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/dependants"
                "?max_depth=5&offset=0&limit=10"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert "dependants" in data["data"]
        assert "pagination" in data


class TestPackageTrustScore:
    """Tests for GET /api/v1/package/<purl>/trust-score."""

    def test_returns_trust_score(self, client) -> None:
        """Valid purl returns trust score breakdown."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "purl": "pkg:maven/org/lib@1.0",
            "effective_score": 7.5,
            "direct_score": 7.0,
            "confidence": 0.9,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0/trust-score")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["effective_score"] == 7.5
        assert data["purl"] == "pkg:maven/org/lib@1.0"

    def test_no_trust_score_returns_404(self, client) -> None:
        """Package without trust score returns 404."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = None

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/noscore@1.0/trust-score")

        assert resp.status_code == 404


class TestPackageRiskPath:
    """Tests for GET /api/v1/package/<purl>/trust-score/risk-path."""

    def test_returns_risk_path(self, client) -> None:
        """Returns risk propagation path."""
        mock_service = MagicMock()
        mock_service.get_trust_score_risk_path.return_value = [
            {"purl": "pkg:maven/org/dep@1.0", "direct_score": 3.0, "depth": 1},
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/trust-score/risk-path"
                "?limit=10"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "risk_path" in data
        assert data["count"] == 1
        mock_service.get_trust_score_risk_path.assert_called_once_with(
            "pkg:maven/org/lib@1.0", limit=10
        )


class TestOpenapiSpec:
    """Tests for GET /api/v1/openapi.json."""

    def test_returns_openapi_spec(self, client) -> None:
        """Returns OpenAPI 3.1 specification."""
        resp = client.get("/api/v1/openapi.json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["openapi"] == "3.1.0"
        assert "paths" in data
        assert "/package/{purl}" in data["paths"]
        assert "/package/{purl}/trust-check" in data["paths"]
        assert "/analysis/remediation-priorities" in data["paths"]
