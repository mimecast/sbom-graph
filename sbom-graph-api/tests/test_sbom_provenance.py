"""Tests for SBOM inventory and coverage report routes."""

from unittest.mock import MagicMock, patch


class TestSbomInventoryTemplate:
    """Tests for SBOM inventory HTML template rendering."""

    def test_inventory_renders_with_mock_data(self, client):
        """SBOM inventory template renders with mock data."""
        mock_service = MagicMock()
        mock_service.get_sbom_inventory.return_value = [
            {
                "record_id": "rec-001",
                "format": "CycloneDX",
                "ingested_at": "2024-06-01T12:00:00Z",
                "source": "api_upload",
                "tool_name": "trivy",
                "tool_version": "0.48.0",
                "serial_number": "urn:uuid:abc-123",
                "document_hash": "sha256:abc123",
                "version_count": 5,
            },
            {
                "record_id": "rec-002",
                "format": "SPDX",
                "ingested_at": "2024-05-15T10:00:00Z",
                "source": "webhook",
                "tool_name": "syft",
                "tool_version": "1.0.0",
                "serial_number": None,
                "document_hash": None,
                "version_count": 3,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/sbom-inventory")

        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"
        assert b"SBOM Inventory" in response.data
        assert b"rec-001" in response.data
        assert b"CycloneDX" in response.data
        assert b"SPDX" in response.data
        assert b"trivy" in response.data
        assert b"syft" in response.data
        assert b"Download as Excel" in response.data
        assert b"Download as JSON" in response.data

    def test_inventory_passes_search_filter_to_service(self, client):
        """Search param is passed to get_sbom_inventory."""
        mock_service = MagicMock()
        mock_service.get_sbom_inventory.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/sbom-inventory?search=trivy")

        mock_service.get_sbom_inventory.assert_called_once()
        call_kwargs = mock_service.get_sbom_inventory.call_args.kwargs
        assert call_kwargs.get("search") == "trivy"

    def test_inventory_passes_date_filters_to_service(self, client):
        """date_from and date_to are passed to get_sbom_inventory."""
        mock_service = MagicMock()
        mock_service.get_sbom_inventory.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get(
                "/reports/sbom-inventory"
                "?date_from=2024-01-01&date_to=2024-12-31"
            )

        mock_service.get_sbom_inventory.assert_called_once()
        call_kwargs = mock_service.get_sbom_inventory.call_args.kwargs
        assert call_kwargs.get("date_from") == "2024-01-01"
        assert call_kwargs.get("date_to") == "2024-12-31"


class TestSbomCoverageTemplate:
    """Tests for SBOM coverage dashboard template rendering."""

    def test_coverage_renders_fresh_stale_never(self, client):
        """Coverage dashboard shows fresh, stale, never categories."""
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
                {
                    "project_name": "app-b",
                    "version_name": "2.0",
                    "project_group": "",
                    "status": "stale",
                    "last_ingested": "2024-01-01T00:00:00Z",
                    "tool_name": "syft",
                },
                {
                    "project_name": "app-c",
                    "version_name": "1.0",
                    "project_group": "",
                    "status": "never",
                    "last_ingested": "-",
                    "tool_name": "-",
                },
            ],
            "recent_days": 30,
        }

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/coverage")

        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"
        assert b"SBOM Coverage" in response.data
        assert b"Total Projects" in response.data
        assert b"With Fresh SBOM" in response.data
        assert b"Stale SBOM" in response.data
        assert b"Never Scanned" in response.data
        assert b"fresh" in response.data
        assert b"stale" in response.data
        assert b"never" in response.data
        assert b"app-a" in response.data
        assert b"app-b" in response.data
        assert b"app-c" in response.data

    def test_coverage_internal_only_passed_to_service(self, client):
        """internal_only param is passed to get_sbom_coverage_for_dashboard."""
        mock_service = MagicMock()
        mock_service.get_sbom_coverage_for_dashboard.return_value = {
            "stats": {
                "total_projects": 0,
                "fresh": 0,
                "stale": 0,
                "never": 0,
                "fresh_pct": 0.0,
                "stale_pct": 0.0,
                "never_pct": 0.0,
            },
            "projects": [],
            "recent_days": 30,
        }

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/coverage?internal_only=true")

        mock_service.get_sbom_coverage_for_dashboard.assert_called_once_with(
            internal_only=True,
            recent_days=30,
        )

    def test_coverage_recent_days_passed_to_service(self, client):
        """recent_days param is passed to get_sbom_coverage_for_dashboard."""
        mock_service = MagicMock()
        mock_service.get_sbom_coverage_for_dashboard.return_value = {
            "stats": {
                "total_projects": 0,
                "fresh": 0,
                "stale": 0,
                "never": 0,
                "fresh_pct": 0.0,
                "stale_pct": 0.0,
                "never_pct": 0.0,
            },
            "projects": [],
            "recent_days": 14,
        }

        with patch(
            "sbom_graph_api.routes.reports.sbom_provenance.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/coverage?recent_days=14")

        mock_service.get_sbom_coverage_for_dashboard.assert_called_once_with(
            internal_only=False,
            recent_days=14,
        )
