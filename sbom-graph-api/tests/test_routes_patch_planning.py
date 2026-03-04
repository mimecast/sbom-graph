"""Unit tests for patch planning and blast radius routes."""

from unittest.mock import MagicMock, patch


class TestGetPatchPlan:
    """Tests for GET /api/v1/patch-plan/<defect_id>."""

    def test_returns_patch_plan(self, client) -> None:
        """Valid defect_id returns a frontier-level patch plan."""
        mock_service = MagicMock()
        mock_service.compute_patch_plan.return_value = {
            "defect": {
                "id": "CVE-2024-1234",
                "severity": "HIGH",
                "aliases": ["GHSA-abcd-1234"],
                "description": "Test vuln",
            },
            "frontiers": [
                {
                    "level": 0,
                    "packages": [
                        {
                            "project_name": "lib-a",
                            "version": "1.0.0",
                            "purl": "pkg:maven/org/lib-a@1.0.0",
                            "project_group": "org",
                            "contacts": [{"email": "team@acme.com", "team": "Platform", "slack_channel": "#platform"}],
                        }
                    ],
                },
                {
                    "level": 1,
                    "packages": [
                        {
                            "project_name": "app-a",
                            "version": "2.0.0",
                            "purl": "pkg:maven/org/app-a@2.0.0",
                            "project_group": "org",
                            "contacts": [],
                        }
                    ],
                },
            ],
            "total_affected": 2,
            "contacts": [{"email": "team@acme.com", "team": "Platform", "slack_channel": "#platform"}],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/patch-plan/CVE-2024-1234")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["defect"]["id"] == "CVE-2024-1234"
        assert len(data["frontiers"]) == 2
        assert data["frontiers"][0]["level"] == 0
        assert data["total_affected"] == 2
        assert len(data["contacts"]) == 1

    def test_defect_not_found_returns_404(self, client) -> None:
        """Non-existent defect returns 404."""
        mock_service = MagicMock()
        mock_service.compute_patch_plan.return_value = {
            "defect": None,
            "frontiers": [],
            "total_affected": 0,
            "contacts": [],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/patch-plan/CVE-9999-0000")

        assert resp.status_code == 404

    def test_respects_max_depth_param(self, client) -> None:
        """max_depth query parameter is forwarded to the service."""
        mock_service = MagicMock()
        mock_service.compute_patch_plan.return_value = {
            "defect": {"id": "CVE-1", "severity": "LOW", "aliases": [], "description": ""},
            "frontiers": [],
            "total_affected": 0,
            "contacts": [],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/api/v1/patch-plan/CVE-1?max_depth=5")

        mock_service.compute_patch_plan.assert_called_once_with(
            defect_id="CVE-1",
            max_depth=5,
            internal_only=False,
        )

    def test_max_depth_capped_at_50(self, client) -> None:
        """max_depth is clamped to a maximum of 50."""
        mock_service = MagicMock()
        mock_service.compute_patch_plan.return_value = {
            "defect": {"id": "CVE-1", "severity": "LOW", "aliases": [], "description": ""},
            "frontiers": [],
            "total_affected": 0,
            "contacts": [],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/api/v1/patch-plan/CVE-1?max_depth=100")

        args = mock_service.compute_patch_plan.call_args
        assert args.kwargs["max_depth"] == 50


class TestGetBlastRadius:
    """Tests for GET /api/v1/blast-radius/<purl>."""

    def test_returns_blast_radius(self, client) -> None:
        """Valid purl returns blast radius with frontiers."""
        mock_service = MagicMock()
        mock_service.compute_blast_radius.return_value = {
            "package": "pkg:maven/org/lib-a@1.0.0",
            "frontiers": [
                {
                    "depth": 1,
                    "packages": [
                        {
                            "project_name": "app-a",
                            "version": "2.0.0",
                            "purl": "pkg:maven/org/app-a@2.0.0",
                            "project_group": "org",
                        }
                    ],
                }
            ],
            "total_affected": 1,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/blast-radius/pkg:maven/org/lib-a@1.0.0")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["package"] == "pkg:maven/org/lib-a@1.0.0"
        assert data["total_affected"] == 1
        assert len(data["frontiers"]) == 1

    def test_invalid_purl_returns_400(self, client) -> None:
        """Non-purl string returns 400."""
        resp = client.get("/api/v1/blast-radius/not-a-purl")
        assert resp.status_code == 400

    def test_respects_internal_only(self, client) -> None:
        """internal_only=true is forwarded to service."""
        mock_service = MagicMock()
        mock_service.compute_blast_radius.return_value = {
            "package": "pkg:maven/org/lib@1.0",
            "frontiers": [],
            "total_affected": 0,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/api/v1/blast-radius/pkg:maven/org/lib@1.0?internal_only=true")

        args = mock_service.compute_blast_radius.call_args
        assert args.kwargs["internal_only"] is True


class TestCreateContact:
    """Tests for POST /api/v1/contacts."""

    def test_creates_contact(self, client) -> None:
        """Valid request creates a PointOfContact and returns 201."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = [[1]]
        mock_service.execute_write.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/contacts",
                json={
                    "email": "team@acme.com",
                    "purl": "pkg:maven/org/lib@1.0",
                    "team": "Platform",
                    "slack_channel": "#platform",
                },
                content_type="application/json",
            )

        assert resp.status_code == 201
        data = resp.get_json()
        assert data["email"] == "team@acme.com"
        assert data["purl"] == "pkg:maven/org/lib@1.0"
        assert data["team"] == "Platform"

    def test_missing_email_returns_400(self, client) -> None:
        """Missing email returns 400."""
        resp = client.post(
            "/api/v1/contacts",
            json={"purl": "pkg:maven/org/lib@1.0"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_invalid_email_returns_400(self, client) -> None:
        """Email without @ returns 400."""
        resp = client.post(
            "/api/v1/contacts",
            json={"email": "not-an-email", "purl": "pkg:maven/org/lib@1.0"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_purl_returns_400(self, client) -> None:
        """Missing purl returns 400."""
        resp = client.post(
            "/api/v1/contacts",
            json={"email": "a@b.com"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_package_not_found_returns_404(self, client) -> None:
        """Non-existent package returns 404."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/contacts",
                json={"email": "a@b.com", "purl": "pkg:maven/org/missing@1.0"},
                content_type="application/json",
            )

        assert resp.status_code == 404

    def test_no_body_returns_400(self, client) -> None:
        """Missing body returns 400."""
        resp = client.post("/api/v1/contacts", content_type="application/json")
        assert resp.status_code == 400
