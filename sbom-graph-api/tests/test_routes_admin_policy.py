"""Unit tests for admin policy routes (GET/POST/DELETE /admin/policies)."""

from unittest.mock import MagicMock, patch


class TestPolicyAdminPage:
    """Tests for GET /admin/policies."""

    def test_renders_page_with_annotations(self, client) -> None:
        """Page renders with annotations and violations."""
        mock_service = MagicMock()
        mock_service.get_policy_annotations.return_value = [
            {
                "purl": "pkg:maven/org.example/lib@1.0",
                "type": "bad",
                "justification": "Known CVE",
                "created_by": "admin",
                "created_at": "2024-06-01T12:00:00",
            },
        ]
        mock_service.get_policy_violations.return_value = []

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/admin/policies")

        assert resp.status_code == 200
        assert b"Policy Annotation Admin" in resp.data
        assert b"pkg:maven/org.example/lib@1.0" in resp.data
        mock_service.get_policy_annotations.assert_called_once()
        mock_service.get_policy_violations.assert_called_once()

    def test_search_filter_passed_to_service(self, client) -> None:
        """Search param is passed to get_policy_annotations."""
        mock_service = MagicMock()
        mock_service.get_policy_annotations.return_value = []
        mock_service.get_policy_violations.return_value = []

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/admin/policies?search=log4j")

        mock_service.get_policy_annotations.assert_called_once_with(
            search="log4j",
            type_filter=None,
        )

    def test_type_filter_maps_to_internal_type(self, client) -> None:
        """Type filter maps banned->bad, approved->good, deprecated->hold."""
        mock_service = MagicMock()
        mock_service.get_policy_annotations.return_value = []
        mock_service.get_policy_violations.return_value = []

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/admin/policies?type=banned")

        mock_service.get_policy_annotations.assert_called_once_with(
            search=None,
            type_filter="bad",
        )

    def test_type_filter_approved_maps_to_good(self, client) -> None:
        """Type filter approved maps to good."""
        mock_service = MagicMock()
        mock_service.get_policy_annotations.return_value = []
        mock_service.get_policy_violations.return_value = []

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/admin/policies?type=approved")

        mock_service.get_policy_annotations.assert_called_once_with(
            search=None,
            type_filter="good",
        )

    def test_type_filter_deprecated_maps_to_hold(self, client) -> None:
        """Type filter deprecated maps to hold."""
        mock_service = MagicMock()
        mock_service.get_policy_annotations.return_value = []
        mock_service.get_policy_violations.return_value = []

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/admin/policies?type=deprecated")

        mock_service.get_policy_annotations.assert_called_once_with(
            search=None,
            type_filter="hold",
        )

    def test_invalid_type_filter_ignored(self, client) -> None:
        """Invalid type filter is ignored (empty string)."""
        mock_service = MagicMock()
        mock_service.get_policy_annotations.return_value = []
        mock_service.get_policy_violations.return_value = []

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/admin/policies?type=invalid")

        mock_service.get_policy_annotations.assert_called_once_with(
            search=None,
            type_filter=None,
        )


class TestAddPolicyAnnotation:
    """Tests for POST /admin/policies."""

    def test_add_success_redirects(self, client) -> None:
        """Valid form adds annotation and redirects."""
        mock_service = MagicMock()
        mock_service.add_policy_annotation.return_value = {
            "purl": "pkg:maven/org.example/lib@1.0",
            "annotation_id": "uuid-123",
            "type": "bad",
            "created_at": "2024-06-01T12:00:00",
        }

        with (
            patch(
                "sbom_graph_api.routes.admin.get_falkordb_service",
                return_value=mock_service,
            ),
            patch(
                "sbom_graph_api.routes.admin.get_current_user",
                return_value="admin",
            ),
        ):
            resp = client.post(
                "/admin/policies",
                data={
                    "purl": "pkg:maven/org.example/lib@1.0",
                    "annotation_type": "banned",
                    "justification": "Known vulnerable",
                },
            )

        assert resp.status_code == 302
        assert "/admin/policies" in resp.headers.get("Location", "")
        mock_service.add_policy_annotation.assert_called_once_with(
            purl="pkg:maven/org.example/lib@1.0",
            annotation_type="bad",
            justification="Known vulnerable",
            created_by="admin",
        )

    def test_invalid_purl_returns_400(self, client) -> None:
        """Invalid PURL returns 400."""
        with patch("sbom_graph_api.routes.admin.get_current_user", return_value="admin"):
            resp = client.post(
                "/admin/policies",
                data={
                    "purl": "not-a-purl",
                    "annotation_type": "banned",
                    "justification": "reason",
                },
            )

        assert resp.status_code == 400
        assert b"Invalid PURL" in resp.data

    def test_invalid_annotation_type_returns_400(self, client) -> None:
        """Invalid annotation type returns 400."""
        with patch("sbom_graph_api.routes.admin.get_current_user", return_value="admin"):
            resp = client.post(
                "/admin/policies",
                data={
                    "purl": "pkg:maven/org.example/lib@1.0",
                    "annotation_type": "invalid",
                    "justification": "reason",
                },
            )

        assert resp.status_code == 400
        assert b"Annotation type" in resp.data

    def test_package_not_found_returns_404(self, client) -> None:
        """Package not in graph returns 404."""
        mock_service = MagicMock()
        mock_service.add_policy_annotation.return_value = None

        with (
            patch(
                "sbom_graph_api.routes.admin.get_falkordb_service",
                return_value=mock_service,
            ),
            patch(
                "sbom_graph_api.routes.admin.get_current_user",
                return_value="admin",
            ),
        ):
            resp = client.post(
                "/admin/policies",
                data={
                    "purl": "pkg:maven/no/exist@0.0",
                    "annotation_type": "banned",
                    "justification": "reason",
                },
            )

        assert resp.status_code == 404
        assert b"not found" in resp.data or b"Package" in resp.data


class TestRemovePolicyAnnotation:
    """Tests for DELETE /admin/policies/<purl>."""

    def test_remove_success_returns_json(self, client) -> None:
        """Removing existing annotation returns 200 JSON."""
        mock_service = MagicMock()
        mock_service.remove_policy_annotation.return_value = True

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.delete(
                "/admin/policies/pkg%3Amaven%2Forg.example%2Flib%401.0",
                headers={"Accept": "application/json"},
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "removed"
        assert "purl" in data
        mock_service.remove_policy_annotation.assert_called_once_with(
            "pkg:maven/org.example/lib@1.0"
        )

    def test_remove_not_found_returns_404(self, client) -> None:
        """Removing non-existent annotation returns 404."""
        mock_service = MagicMock()
        mock_service.remove_policy_annotation.return_value = False

        with patch(
            "sbom_graph_api.routes.admin.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.delete(
                "/admin/policies/pkg%3Amaven%2Forg.example%2Flib%401.0",
                headers={"Accept": "application/json"},
            )

        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data

    def test_invalid_purl_returns_400(self, client) -> None:
        """Invalid PURL in path returns 400."""
        resp = client.delete(
            "/admin/policies/invalid",
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 400
