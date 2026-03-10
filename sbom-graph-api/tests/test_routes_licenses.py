"""Unit tests for license report routes and API v1 license endpoint."""

from unittest.mock import MagicMock, patch


class TestLicensesReport:
    """Tests for GET /reports/licenses."""

    def test_json_format(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_all_licenses.return_value = [
            {"spdx_id": "MIT", "name": "MIT", "risk_category": "permissive", "usage_count": 42},
            {
                "spdx_id": "GPL-3.0-only",
                "name": "GPL-3.0-only",
                "risk_category": "strong_copyleft",
                "usage_count": 3,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/licenses?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 2
        assert data["licenses"][0]["spdx_id"] == "MIT"

    def test_html_format(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_all_licenses.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/licenses")

        assert resp.status_code == 200
        assert b"Licenses" in resp.data

    def test_internal_only_toggle(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_all_licenses.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/licenses?internal_only=false&format=json")

        assert resp.status_code == 200
        mock_service.get_all_licenses.assert_called_once_with(internal_only=False)


class TestLicenseSummaryReport:
    """Tests for GET /reports/license-summary."""

    def test_missing_params(self, client) -> None:
        resp = client.get("/reports/license-summary?format=json")
        assert resp.status_code == 400

    def test_json_format(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_license_summary.return_value = [
            {
                "project_group": "com.example",
                "project_name": "my-lib",
                "version": "1.0.0",
                "purl": "pkg:maven/com.example/my-lib@1.0.0",
                "spdx_id": "MIT",
                "license_name": "MIT",
                "risk_category": "permissive",
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/reports/license-summary?project_name=my-lib&version_name=1.0.0&format=json",
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert data["licenses"][0]["spdx_id"] == "MIT"


class TestLicenseConflictsReport:
    """Tests for GET /reports/license-conflicts."""

    def test_json_format(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_license_conflicts.return_value = [
            {
                "project_group": "com.example",
                "project_name": "my-app",
                "version_name": "2.0.0",
                "licenses": ["MIT", "GPL-3.0-only"],
                "risk_categories": ["permissive", "strong_copyleft"],
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/license-conflicts?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert "GPL-3.0-only" in data["conflicts"][0]["licenses"]


class TestPackageLicensesApi:
    """Tests for GET /api/v1/package/<purl>/licenses."""

    def test_returns_licenses(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_package_licenses.return_value = [
            {
                "spdx_id": "Apache-2.0",
                "name": "Apache-2.0",
                "risk_category": "permissive",
                "url": "",
            },
        ]

        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service", return_value=mock_service):
            resp = client.get("/api/v1/package/pkg:maven/org.example/lib@1.0.0/licenses")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["licenses"][0]["spdx_id"] == "Apache-2.0"

    def test_empty_result(self, client) -> None:
        mock_service = MagicMock()
        mock_service.get_package_licenses.return_value = []

        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service", return_value=mock_service):
            resp = client.get("/api/v1/package/pkg:maven/org.example/nolib@0.0.0/licenses")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
