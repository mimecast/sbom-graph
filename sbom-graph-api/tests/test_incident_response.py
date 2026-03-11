"""Tests for incident response route and service methods."""

from unittest.mock import MagicMock, patch


class TestIncidentResponseRoute:
    """Tests for GET /reports/incident-response/<defect_id>."""

    def test_invalid_defect_id_returns_400(self, client) -> None:
        """Invalid defect_id returns 400."""
        resp = client.get("/reports/incident-response/invalid@id")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_vulnerability_not_found_returns_404(self, client) -> None:
        """Non-existent vulnerability returns 404."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = None

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/incident-response/CVE-9999-0000")

        assert resp.status_code == 404

    def test_html_format_returns_200(self, client) -> None:
        """Valid defect_id returns HTML page with blast radius and patch plan."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-2024-1234",
            "title": "Test vulnerability",
            "description": "Test desc",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cwe_id": "CWE-79",
            "published_date": "2024-01-01",
            "affected_versions": [
                {"project_name": "lib-a", "version": "1.0.0", "project_group": "org"},
            ],
        }
        mock_service.get_blast_radius.return_value = {
            "affected_versions": [
                {"project_name": "lib-a", "version": "1.0.0", "project_group": "org"},
            ],
            "affected_applications": [
                {"id": "app-a:1.0", "project_name": "app-a", "version": "1.0", "purl": ""},
            ],
            "graph_nodes": [
                {"id": "defect:CVE-2024-1234", "label": "CVE-2024-1234", "type": "vulnerability"},
                {"id": "lib-a:1.0.0", "label": "lib-a:1.0.0", "type": "affected", "partition": 0},
            ],
            "graph_edges": [
                {
                    "source": "defect:CVE-2024-1234",
                    "target": "lib-a:1.0.0",
                    "type": "VERSION_DEFECT",
                },
            ],
            "max_partition": 1,
        }
        mock_service.get_patch_plan.return_value = [
            {
                "purl": "pkg:maven/org/lib-a@1.0.0",
                "project_name": "lib-a",
                "version_name": "1.0.0",
                "is_direct": True,
                "dependant_count": 2,
                "priority": "high",
                "recommended_action": "upgrade",
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/incident-response/CVE-2024-1234")

        assert resp.status_code == 200
        assert b"Incident Response" in resp.data
        assert b"CVE-2024-1234" in resp.data
        assert b"Blast Radius" in resp.data
        assert b"Patch Plan" in resp.data
        assert b"lib-a" in resp.data

    def test_json_format_returns_json(self, client) -> None:
        """format=json returns JSON payload."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-2024-1234",
            "title": "Test",
            "description": "Desc",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cwe_id": "",
            "published_date": "",
            "affected_versions": [],
        }
        mock_service.get_blast_radius.return_value = {
            "affected_versions": [],
            "affected_applications": [],
            "graph_nodes": [],
            "graph_edges": [],
            "max_partition": 0,
        }
        mock_service.get_patch_plan.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/incident-response/CVE-2024-1234?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "incident-response"
        assert data["defect_id"] == "CVE-2024-1234"
        assert "blast_radius" in data
        assert "patch_plan" in data

    def test_excel_format_returns_excel(self, client) -> None:
        """format=excel returns Excel file."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-2024-1234",
            "title": "Test",
            "description": "Desc",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cwe_id": "",
            "published_date": "",
            "affected_versions": [],
        }
        mock_service.get_blast_radius.return_value = {
            "affected_versions": [],
            "affected_applications": [],
            "graph_nodes": [],
            "graph_edges": [],
            "max_partition": 0,
        }
        mock_service.get_patch_plan.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/incident-response/CVE-2024-1234?format=excel")

        assert resp.status_code == 200
        assert (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            in resp.headers.get("Content-Type", "")
        )
        assert "incident_response" in resp.headers.get("Content-Disposition", "")

    def test_forwards_internal_only_and_max_depth(self, client) -> None:
        """Query params are forwarded to service."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_by_id.return_value = {
            "defect_id": "CVE-1",
            "title": "T",
            "description": "D",
            "severity": "LOW",
            "cvss_score": 0,
            "cwe_id": "",
            "published_date": "",
            "affected_versions": [],
        }
        mock_service.get_blast_radius.return_value = {
            "affected_versions": [],
            "affected_applications": [],
            "graph_nodes": [],
            "graph_edges": [],
            "max_partition": 0,
        }
        mock_service.get_patch_plan.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/incident-response/CVE-1?internal_only=true&max_depth=5")

        mock_service.get_blast_radius.assert_called_once_with(
            defect_id="CVE-1",
            max_depth=5,
            internal_only=True,
        )
        mock_service.get_patch_plan.assert_called_once_with(
            defect_id="CVE-1",
            internal_only=True,
        )


class TestIncidentResponseGraphRoute:
    """Tests for GET /reports/incident-response/<defect_id>/graph."""

    def test_invalid_defect_id_returns_400(self, client) -> None:
        """Invalid defect_id returns 400."""
        resp = client.get("/reports/incident-response/invalid!id/graph")
        assert resp.status_code == 400

    def test_returns_html_graph(self, client) -> None:
        """Graph endpoint returns HTML for iframe embedding."""
        mock_service = MagicMock()
        mock_service.get_blast_radius.return_value = {
            "affected_versions": [],
            "affected_applications": [],
            "graph_nodes": [
                {"id": "defect:CVE-1", "label": "CVE-1", "type": "vulnerability"},
            ],
            "graph_edges": [],
            "max_partition": 0,
        }

        with patch(
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/incident-response/CVE-2024-1234/graph")

        assert resp.status_code == 200
        assert b"<!DOCTYPE html>" in resp.data or b"<html" in resp.data
