"""Tests for GET /reports/vulnerabilities route."""

from unittest.mock import MagicMock, patch


class TestAllVulnerabilitiesRoute:
    """Tests for the all_vulnerabilities report endpoint."""

    def test_vex_filter_hide_not_affected(self, client):
        """vex_filter=hide_not_affected excludes not_affected vulnerabilities."""
        mock_service = MagicMock()
        mock_service.get_all_vulnerabilities.return_value = [
            {
                "defect_id": "CVE-1",
                "severity": "HIGH",
                "vex_status": "not_affected",
                "affected_versions": [{"project_name": "lib", "version": "1.0"}],
            },
            {
                "defect_id": "CVE-2",
                "severity": "MEDIUM",
                "vex_status": "affected",
                "affected_versions": [{"project_name": "lib", "version": "1.0"}],
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/vulnerabilities?vex_filter=hide_not_affected")

        assert response.status_code == 200
        assert b"CVE-2" in response.data
        assert b"CVE-1" not in response.data

    def test_vex_filter_under_investigation(self, client):
        """vex_filter=under_investigation shows only under_investigation vulns."""
        mock_service = MagicMock()
        mock_service.get_all_vulnerabilities.return_value = [
            {
                "defect_id": "CVE-1",
                "severity": "HIGH",
                "vex_status": "affected",
                "affected_versions": [],
            },
            {
                "defect_id": "CVE-2",
                "severity": "MEDIUM",
                "vex_status": "under_investigation",
                "affected_versions": [],
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/vulnerabilities?vex_filter=under_investigation")

        assert response.status_code == 200
        assert b"CVE-2" in response.data
        assert b"CVE-1" not in response.data

    def test_vex_coverage_in_stats(self, client):
        """VEX coverage percentage is included in stats."""
        mock_service = MagicMock()
        mock_service.get_all_vulnerabilities.return_value = [
            {
                "defect_id": "CVE-1",
                "severity": "HIGH",
                "vex_status": "not_affected",
                "affected_versions": [],
            },
            {
                "defect_id": "CVE-2",
                "severity": "LOW",
                "vex_status": None,
                "affected_versions": [],
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/vulnerabilities")

        assert response.status_code == 200
        assert b"VEX Coverage" in response.data
        assert b"50.0%" in response.data

    def test_empty_vulns_vex_coverage_zero(self, client):
        """When no vulns, VEX coverage is 0%."""
        mock_service = MagicMock()
        mock_service.get_all_vulnerabilities.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/vulnerabilities")

        assert response.status_code == 200
        assert b"0.0%" in response.data or b"0%" in response.data

    def test_defect_id_match_passed_to_service(self, client):
        """defect_id_match query param is forwarded when valid."""
        mock_service = MagicMock()
        mock_service.get_all_vulnerabilities.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/vulnerabilities?defect_id_match=CVE-2024")

        mock_service.get_all_vulnerabilities.assert_called_with(
            False,
            "CVE-2024",
        )

    """Tests for GET /reports/vulnerability-dependants/<defect_id>."""

    def test_invalid_defect_id_returns_400(self, client):
        """Invalid defect_id returns 400."""
        resp = client.get("/reports/vulnerability-dependants/invalid@id")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_vulnerability_not_found_returns_404(self, client):
        """Non-existent vulnerability returns 404."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = None

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-dependants/CVE-9999-0000")

        assert resp.status_code == 404

    def test_html_format_returns_200(self, client):
        """Valid defect_id returns HTML table."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-2024-1234",
            "title": "Test",
            "severity": "HIGH",
            "affected_versions": [],
        }
        mock_service.get_vulnerability_dependants.return_value = [
            {
                "project_name": "app-a",
                "version_name": "1.0",
                "partition": 1,
                "paths": [],
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-dependants/CVE-2024-1234")

        assert resp.status_code == 200
        assert b"CVE-2024-1234" in resp.data
        assert b"app-a" in resp.data

    def test_excel_format_returns_excel(self, client):
        """format=excel returns Excel download."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-1",
            "title": "T",
            "severity": "HIGH",
            "affected_versions": [],
        }
        mock_service.get_vulnerability_dependants.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-dependants/CVE-1?format=excel")

        assert resp.status_code == 200
        assert "spreadsheet" in resp.content_type or "excel" in resp.content_type

    def test_json_format_returns_json(self, client):
        """format=json returns JSON payload."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-1",
            "title": "T",
            "severity": "HIGH",
            "affected_versions": [],
        }
        mock_service.get_vulnerability_dependants.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-dependants/CVE-1?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "report_type" in data or "vulnerability" in data or "dependants" in data
