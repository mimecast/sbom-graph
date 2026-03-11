"""Tests for license dashboard report route."""

from unittest.mock import MagicMock, patch


class TestLicenseDashboardRoute:
    """Tests for GET /reports/license-dashboard endpoint."""

    def test_returns_html_by_default(self, client):
        """License dashboard returns HTML by default."""
        mock_service = MagicMock()
        mock_service.get_license_risk_dashboard.return_value = {
            "total_packages": 2,
            "categories": {
                "permissive": {
                    "count": 1,
                    "pct": 50.0,
                    "packages": [
                        {
                            "purl": "pkg:maven/com.example/lib@1.0",
                            "project_name": "lib",
                            "version_name": "1.0",
                            "spdx_id": "MIT",
                            "license_name": "MIT License",
                        },
                    ],
                },
                "strong_copyleft": {
                    "count": 1,
                    "pct": 50.0,
                    "packages": [
                        {
                            "purl": "pkg:maven/com.example/gpl@2.0",
                            "project_name": "gpl",
                            "version_name": "2.0",
                            "spdx_id": "GPL-3.0",
                            "license_name": "GPL v3",
                        },
                    ],
                },
            },
        }

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/license-dashboard")

        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"
        assert b"License Compliance Dashboard" in response.data
        assert b"permissive" in response.data
        assert b"strong_copyleft" in response.data
        assert b"lib" in response.data
        assert b"gpl" in response.data

    def test_returns_json_when_requested(self, client):
        """License dashboard returns JSON when format=json."""
        mock_service = MagicMock()
        mock_service.get_license_risk_dashboard.return_value = {
            "total_packages": 1,
            "categories": {
                "permissive": {
                    "count": 1,
                    "pct": 100.0,
                    "packages": [
                        {
                            "purl": "pkg:maven/com.example/foo@1.0",
                            "project_name": "foo",
                            "version_name": "1.0",
                            "spdx_id": "Apache-2.0",
                            "license_name": "Apache 2.0",
                        },
                    ],
                },
            },
        }

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/license-dashboard?format=json")

        assert response.status_code == 200
        data = response.get_json()
        assert data["report_type"] == "license-dashboard"
        assert data["stats"]["total_packages"] == 1
        assert "permissive" in data["categories"]
        assert len(data["categories"]["permissive"]["packages"]) == 1

    def test_returns_excel_when_requested(self, client):
        """License dashboard returns Excel when format=excel."""
        mock_service = MagicMock()
        mock_service.get_license_risk_dashboard.return_value = {
            "total_packages": 1,
            "categories": {
                "unknown": {
                    "count": 1,
                    "pct": 100.0,
                    "packages": [
                        {
                            "purl": "pkg:maven/com.example/unk@1.0",
                            "project_name": "unk",
                            "version_name": "1.0",
                            "spdx_id": "",
                            "license_name": "",
                        },
                    ],
                },
            },
        }

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/license-dashboard?format=excel")

        assert response.status_code == 200
        assert (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            in response.content_type
        )
        assert "license_dashboard.xlsx" in response.headers.get("Content-Disposition", "")

    def test_internal_only_filter(self, client):
        """internal_only parameter is passed to service."""
        mock_service = MagicMock()
        mock_service.get_license_risk_dashboard.return_value = {
            "total_packages": 0,
            "categories": {},
        }

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/license-dashboard?internal_only=true")

        mock_service.get_license_risk_dashboard.assert_called_once_with(internal_only=True)

    def test_empty_data_shows_no_packages_message(self, client):
        """Empty dashboard shows appropriate message."""
        mock_service = MagicMock()
        mock_service.get_license_risk_dashboard.return_value = {
            "total_packages": 0,
            "categories": {
                "permissive": {"count": 0, "pct": 0.0, "packages": []},
                "weak_copyleft": {"count": 0, "pct": 0.0, "packages": []},
                "strong_copyleft": {"count": 0, "pct": 0.0, "packages": []},
                "proprietary": {"count": 0, "pct": 0.0, "packages": []},
                "unknown": {"count": 0, "pct": 0.0, "packages": []},
            },
        }

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/license-dashboard")

        assert response.status_code == 200
        assert b"No packages found" in response.data
