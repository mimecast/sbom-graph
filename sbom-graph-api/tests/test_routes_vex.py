"""Unit tests for VEX ingest, API, and report routes."""

from unittest.mock import MagicMock, patch


class TestUploadVex:
    """Tests for POST /ingest/vex."""

    def test_valid_vex_document(self, client) -> None:
        """Valid OpenVEX document is processed and returns 201."""
        mock_persistence = MagicMock()

        with patch(
            "sbom_graph_api.routes.ingest._create_persistence",
            return_value=mock_persistence,
        ), patch(
            "sbom_graph_model.vex.VexProcessor.process_vex_document",
            return_value={"statements_processed": 2, "linked_vulnerabilities": 1},
        ):
            resp = client.post(
                "/ingest/vex",
                json={
                    "@context": "https://openvex.dev/ns/v0.2.0",
                    "@id": "https://example.com/vex/doc-1",
                    "timestamp": "2024-01-15T00:00:00Z",
                    "statements": [
                        {
                            "vulnerability": {"@id": "CVE-2024-1234"},
                            "status": "not_affected",
                            "justification": "component_not_present",
                            "products": ["pkg:maven/org/lib-a@1.0"],
                        },
                        {
                            "vulnerability": {"@id": "CVE-2024-5678"},
                            "status": "fixed",
                            "products": ["pkg:maven/org/lib-b@2.0"],
                        },
                    ],
                },
                content_type="application/json",
            )

        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["statements_count"] == 2
        assert data["linked_vulnerabilities"] == 1

    def test_empty_body_returns_400(self, client) -> None:
        """Empty body returns 400."""
        resp = client.post("/ingest/vex", content_type="application/json")
        assert resp.status_code == 400

    def test_non_object_body_returns_400(self, client) -> None:
        """Non-object body returns 400."""
        resp = client.post(
            "/ingest/vex",
            json=["not", "an", "object"],
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_invalid_vex_returns_422(self, client) -> None:
        """Malformed VEX document returns 422."""
        mock_persistence = MagicMock()

        with patch(
            "sbom_graph_api.routes.ingest._create_persistence",
            return_value=mock_persistence,
        ):
            resp = client.post(
                "/ingest/vex",
                json={"no_statements": True},
                content_type="application/json",
            )

        assert resp.status_code == 422


class TestPackageVex:
    """Tests for GET /api/v1/package/<purl>/vex."""

    def test_returns_vex_statements(self, client) -> None:
        """Returns VEX statements for a package."""
        mock_service = MagicMock()
        mock_service.get_vex_for_package.return_value = [
            {
                "statement_id": "stmt-1",
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": None,
                "action_statement": None,
                "source_document": "doc-1",
                "timestamp": "2024-01-15T00:00:00Z",
                "vulnerability_id": "CVE-2024-1234",
                "vulnerability_severity": "HIGH",
            }
        ]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0/vex")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["purl"] == "pkg:maven/org/lib@1.0"
        assert data["count"] == 1
        assert data["statements"][0]["status"] == "not_affected"

    def test_invalid_purl_returns_400(self, client) -> None:
        """Non-purl returns 400."""
        resp = client.get("/api/v1/package/not-a-purl/vex")
        assert resp.status_code == 400

    def test_empty_results(self, client) -> None:
        """Package with no VEX statements returns empty list."""
        mock_service = MagicMock()
        mock_service.get_vex_for_package.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0/vex")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert data["statements"] == []


class TestVexCoverageReport:
    """Tests for GET /reports/vex-coverage."""

    def test_json_format(self, client) -> None:
        """JSON format returns coverage stats and vulnerability data."""
        mock_service = MagicMock()
        mock_service.get_vex_coverage.return_value = {
            "total_vulnerabilities": 10,
            "with_vex": 3,
            "without_vex": 7,
            "coverage_percent": 30.0,
        }
        mock_service.get_vulnerabilities_with_vex.return_value = [
            {
                "defect_id": "CVE-2024-1234",
                "severity": "HIGH",
                "description": "Test vuln",
                "vex_status": "not_affected",
                "vex_count": 1,
                "affected_versions": [],
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vex-coverage?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_type"] == "vex-coverage"
        assert data["stats"]["total_vulnerabilities"] == 10
        assert data["stats"]["coverage_percent"] == 30.0
        assert len(data["data"]) == 1

    def test_html_format(self, client) -> None:
        """HTML format returns rendered page."""
        mock_service = MagicMock()
        mock_service.get_vex_coverage.return_value = {
            "total_vulnerabilities": 5,
            "with_vex": 2,
            "without_vex": 3,
            "coverage_percent": 40.0,
        }
        mock_service.get_vulnerabilities_with_vex.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vex-coverage")

        assert resp.status_code == 200
        assert b"VEX Coverage" in resp.data
