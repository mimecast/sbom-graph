"""Tests for enrichment coverage report route."""

from unittest.mock import MagicMock, patch


class TestEnrichmentCoverageRoute:
    """Tests for GET /reports/enrichment-coverage endpoint."""

    def test_returns_html_by_default(self, client):
        """Enrichment coverage returns HTML by default."""
        mock_service = MagicMock()
        mock_service.get_enrichment_coverage.return_value = {
            "total": 3,
            "recent": 1,
            "stale": 1,
            "never": 1,
            "recent_pct": 33.3,
            "stale_pct": 33.3,
            "never_pct": 33.3,
            "packages": [
                {
                    "purl": "pkg:maven/com.example/lib-a@1.0",
                    "project_name": "lib-a",
                    "version_name": "1.0",
                    "last_enriched_at": "2024-06-01T00:00:00Z",
                    "status": "recent",
                },
                {
                    "purl": "pkg:maven/com.example/lib-b@2.0",
                    "project_name": "lib-b",
                    "version_name": "2.0",
                    "last_enriched_at": "2024-01-01T00:00:00Z",
                    "status": "stale",
                },
                {
                    "purl": "pkg:maven/com.example/lib-c@3.0",
                    "project_name": "lib-c",
                    "version_name": "3.0",
                    "last_enriched_at": None,
                    "status": "never",
                },
            ],
        }

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/enrichment-coverage")

        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"
        assert b"Enrichment Coverage" in response.data
        assert b"lib-a" in response.data
        assert b"recent" in response.data
        assert b"stale" in response.data
        assert b"never" in response.data

    def test_returns_json_when_requested(self, client):
        """Enrichment coverage returns JSON when format=json."""
        mock_service = MagicMock()
        mock_service.get_enrichment_coverage.return_value = {
            "total": 2,
            "recent": 1,
            "stale": 0,
            "never": 1,
            "recent_pct": 50.0,
            "stale_pct": 0.0,
            "never_pct": 50.0,
            "packages": [
                {
                    "purl": "pkg:maven/com.example/app@1.0",
                    "project_name": "app",
                    "version_name": "1.0",
                    "last_enriched_at": "2024-06-01T00:00:00Z",
                    "status": "recent",
                },
                {
                    "purl": "pkg:maven/com.example/dep@2.0",
                    "project_name": "dep",
                    "version_name": "2.0",
                    "last_enriched_at": None,
                    "status": "never",
                },
            ],
        }

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/enrichment-coverage?format=json")

        assert response.status_code == 200
        data = response.get_json()
        assert data["report_type"] == "enrichment-coverage"
        assert data["stats"]["total"] == 2
        assert data["stats"]["recent"] == 1
        assert data["stats"]["never"] == 1
        assert len(data["packages"]) == 2

    def test_returns_excel_when_requested(self, client):
        """Enrichment coverage returns Excel when format=excel."""
        mock_service = MagicMock()
        mock_service.get_enrichment_coverage.return_value = {
            "total": 1,
            "recent": 0,
            "stale": 1,
            "never": 0,
            "recent_pct": 0.0,
            "stale_pct": 100.0,
            "never_pct": 0.0,
            "packages": [
                {
                    "purl": "pkg:maven/com.example/old@1.0",
                    "project_name": "old",
                    "version_name": "1.0",
                    "last_enriched_at": "2023-01-01T00:00:00Z",
                    "status": "stale",
                },
            ],
        }

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/enrichment-coverage?format=excel")

        assert response.status_code == 200
        assert (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            in response.content_type
        )
        assert "enrichment_coverage.xlsx" in response.headers.get("Content-Disposition", "")

    def test_internal_only_filter(self, client):
        """internal_only parameter is passed to service."""
        mock_service = MagicMock()
        mock_service.get_enrichment_coverage.return_value = {
            "total": 0,
            "recent": 0,
            "stale": 0,
            "never": 0,
            "recent_pct": 0.0,
            "stale_pct": 0.0,
            "never_pct": 0.0,
            "packages": [],
        }

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/enrichment-coverage?internal_only=true")

        mock_service.get_enrichment_coverage.assert_called_once_with(True)

    def test_empty_data_shows_no_packages_message(self, client):
        """Empty coverage shows appropriate message."""
        mock_service = MagicMock()
        mock_service.get_enrichment_coverage.return_value = {
            "total": 0,
            "recent": 0,
            "stale": 0,
            "never": 0,
            "recent_pct": 0.0,
            "stale_pct": 0.0,
            "never_pct": 0.0,
            "packages": [],
        }

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/enrichment-coverage")

        assert response.status_code == 200
        assert b"No packages found" in response.data
