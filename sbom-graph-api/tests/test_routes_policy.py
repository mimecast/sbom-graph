"""Unit tests for policy annotation routes."""

from unittest.mock import MagicMock, patch


class TestCreatePolicyAnnotation:
    """Tests for POST /api/v1/policy/annotate."""

    def test_creates_annotation(self, client) -> None:
        """Valid request creates policy annotation and returns 201."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = [[1]]  # Version exists
        mock_service.execute_write.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/policy/annotate",
                json={
                    "purl": "pkg:maven/org.example/lib@1.0",
                    "type": "bad",
                    "justification": "Known vulnerable, must upgrade",
                },
                content_type="application/json",
            )

        assert resp.status_code == 201
        data = resp.get_json()
        assert data["type"] == "bad"
        assert data["purl"] == "pkg:maven/org.example/lib@1.0"
        assert "annotation_id" in data
        assert "created_at" in data

    def test_invalid_type_returns_400(self, client) -> None:
        """Invalid policy type returns 400."""
        resp = client.post(
            "/api/v1/policy/annotate",
            json={
                "purl": "pkg:maven/org.example/lib@1.0",
                "type": "invalid",
                "justification": "reason",
            },
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_purl_returns_400(self, client) -> None:
        """Missing purl returns 400."""
        resp = client.post(
            "/api/v1/policy/annotate",
            json={"type": "bad", "justification": "reason"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_justification_returns_400(self, client) -> None:
        """Missing justification returns 400."""
        resp = client.post(
            "/api/v1/policy/annotate",
            json={"purl": "pkg:maven/org.example/lib@1.0", "type": "bad"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_package_not_found_returns_404(self, client) -> None:
        """Non-existent package returns 404."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = []  # Version does NOT exist

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/policy/annotate",
                json={
                    "purl": "pkg:maven/no/exist@0.0",
                    "type": "good",
                    "justification": "reason",
                },
                content_type="application/json",
            )

        assert resp.status_code == 404

    def test_with_expires_at(self, client) -> None:
        """Annotation with expires_at triggers additional write for expiry."""
        mock_service = MagicMock()
        mock_service.execute_query.return_value = [[1]]
        mock_service.execute_write.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.post(
                "/api/v1/policy/annotate",
                json={
                    "purl": "pkg:maven/org.example/lib@1.0",
                    "type": "hold",
                    "justification": "Under review",
                    "expires_at": "2025-12-31T23:59:59Z",
                },
                content_type="application/json",
            )

        assert resp.status_code == 201
        assert mock_service.execute_write.call_count == 3

    def test_no_json_body_returns_400(self, client) -> None:
        """Missing JSON body returns 400."""
        resp = client.post("/api/v1/policy/annotate", content_type="application/json")
        assert resp.status_code == 400


class TestDeletePolicyAnnotation:
    """Tests for DELETE /api/v1/policy/annotate/<id>."""

    def test_deletes_existing(self, client) -> None:
        """Deleting existing annotation returns 200."""
        mock_service = MagicMock()
        mock_service.execute_write.return_value = [[1]]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.delete("/api/v1/policy/annotate/550e8400-e29b-41d4-a716-446655440000")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "deleted"

    def test_not_found_returns_404(self, client) -> None:
        """Deleting non-existent annotation returns 404."""
        mock_service = MagicMock()
        mock_service.execute_write.return_value = [[0]]

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.delete("/api/v1/policy/annotate/a1b2c3d4-e5f6-7890-abcd-ef1234567890")

        assert resp.status_code == 404

    def test_invalid_annotation_id_returns_400(self, client) -> None:
        """Non-UUID annotation_id returns 400."""
        resp = client.delete("/api/v1/policy/annotate/not-a-uuid")
        assert resp.status_code == 400


class TestCheckPackagePolicy:
    """Tests for GET /api/v1/package/<purl>/policy."""

    def test_pass_no_annotations(self, client) -> None:
        """Package with no annotations returns pass."""
        mock_service = MagicMock()
        mock_service.check_policy.return_value = {
            "purl": "pkg:maven/org.example/lib@1.0",
            "status": "pass",
            "annotations": [],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org.example/lib@1.0/policy")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "pass"

    def test_fail_bad_annotation(self, client) -> None:
        """Package with bad annotation returns fail."""
        mock_service = MagicMock()
        mock_service.check_policy.return_value = {
            "purl": "pkg:maven/org.example/lib@1.0",
            "status": "fail",
            "annotations": [{"type": "bad", "justification": "CVE"}],
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org.example/lib@1.0/policy")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "fail"

    def test_invalid_purl(self, client) -> None:
        """Invalid purl returns 400."""
        resp = client.get("/api/v1/package/not-valid/policy")
        assert resp.status_code == 400


class TestPolicyViolationsReport:
    """Tests for GET /reports/policy-violations."""

    def _make_policy_mock(self, violations=None, count=0, total_dependants=0) -> MagicMock:
        """Return a mock service with all policy-violations methods stubbed."""
        mock_service = MagicMock()
        mock_service.get_policy_violations.return_value = violations or []
        mock_service.count_policy_violations.return_value = count
        mock_service.get_policy_violations_total_dependants.return_value = total_dependants
        return mock_service

    def test_json_format(self, client) -> None:
        """JSON format returns streamed data with report_type in meta."""
        violation = {
            "annotation_id": "uuid-1",
            "justification": "Known CVE",
            "created_by": "admin",
            "created_at": "2024-06-01",
            "expires_at": None,
            "purl": "pkg:maven/bad/lib@1.0",
            "project_name": "bad-lib",
            "version_name": "1.0",
            "dependant_count": 5,
        }
        mock_service = self._make_policy_mock(violations=[violation], count=1, total_dependants=5)

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/policy-violations?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        # new format: streamed JSON with report_type meta and data array
        assert data["report_type"] == "policy-violations"
        assert any(r.get("purl") == "pkg:maven/bad/lib@1.0" for r in data["data"])

    def test_html_format(self, client) -> None:
        """HTML format returns table page."""
        mock_service = self._make_policy_mock()

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/policy-violations")

        assert resp.status_code == 200
        assert b"Policy Violations" in resp.data

    def test_internal_only(self, client) -> None:
        """internal_only filter is passed to service."""
        mock_service = self._make_policy_mock()

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/policy-violations?internal_only=true&format=html")

        assert resp.status_code == 200
        call_kwargs = mock_service.get_policy_violations.call_args.kwargs
        assert call_kwargs["internal_only"] is True

    def test_html_includes_total_affected_dependants(self, client) -> None:
        """HTML stats block includes Total Affected Dependants (restored Phase 1.6)."""
        violation = {
            "annotation_id": "uuid-2",
            "justification": "Unsafe",
            "created_by": "security",
            "created_at": "2024-01-01",
            "expires_at": None,
            "purl": "pkg:npm/evil@0.1",
            "project_name": "evil",
            "version_name": "0.1",
            "dependant_count": 12,
        }
        mock_service = self._make_policy_mock(
            violations=[violation], count=1, total_dependants=12
        )

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/policy-violations")

        assert resp.status_code == 200
        assert b"Total Affected Dependants" in resp.data
