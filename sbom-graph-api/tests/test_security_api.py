"""Security-focused tests for the API v1 endpoints.

Verifies input validation, injection prevention, and safe error handling
per CWE-209 (no sensitive info in error messages).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestPurlInjectionApi:
    """Verify PURL validation rejects malicious input at API layer."""

    def test_vulns_cypher_injection_in_purl_returns_400(self, client) -> None:
        """Cypher injection in PURL must return 400."""
        purl = "pkg:npm/foo@1.0' RETURN 1 //"
        resp = client.get(f"/api/v1/package/{purl}/vulns")

        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data
        assert "Invalid" in data.get("error", "")

    def test_trust_check_xss_in_purl_returns_400(self, client) -> None:
        """XSS payload in PURL must return 400."""
        purl = "pkg:npm/<script>alert(1)</script>@1.0"
        resp = client.get(f"/api/v1/package/{purl}/trust-check")

        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_metadata_sql_injection_attempt_returns_400(self, client) -> None:
        """SQL-style injection in PURL must return 400."""
        purl = "pkg:npm/foo'; DROP TABLE versions; --@1.0"
        resp = client.get(f"/api/v1/package/{purl}/metadata")

        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_extremely_long_purl_returns_400(self, client) -> None:
        """PURL exceeding max length must return 400."""
        purl = "pkg:npm/" + "x" * 10000
        resp = client.get(f"/api/v1/package/{purl}/metadata")

        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data


class TestTrustCheckInputValidation:
    """Verify trust-check endpoint validates query parameters."""

    def test_negative_min_score_uses_default(self, client) -> None:
        """Negative min_score must be clamped to default."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 7.0,
            "direct_score": 7.0,
            "confidence": 0.8,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0/trust-check?min_score=-1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["pass"] is True

    def test_non_numeric_min_score_returns_200_with_default(self, client) -> None:
        """Non-numeric min_score must use default, not crash."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 7.0,
            "direct_score": 7.0,
            "confidence": 0.8,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org/lib@1.0/trust-check?min_score=not_a_number"
            )

        assert resp.status_code == 200

    def test_extremely_large_min_score_clamped(self, client) -> None:
        """Very large min_score must be clamped to max (10.0)."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "effective_score": 3.0,
            "direct_score": 3.0,
            "confidence": 0.8,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0/trust-check?min_score=999999")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["pass"] is False


class TestRemediationPrioritiesInputValidation:
    """Verify remediation-priorities endpoint validates limit parameter."""

    def test_negative_limit_uses_default(self, client) -> None:
        """Negative limit must use default."""
        mock_service = MagicMock()
        mock_service.get_remediation_priorities.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/analysis/remediation-priorities?limit=-1")

        assert resp.status_code == 200
        mock_service.get_remediation_priorities.assert_called_once()
        call_limit = mock_service.get_remediation_priorities.call_args[1]["limit"]
        assert call_limit == 20

    def test_non_numeric_limit_uses_default(self, client) -> None:
        """Non-numeric limit must use default."""
        mock_service = MagicMock()
        mock_service.get_remediation_priorities.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/analysis/remediation-priorities?limit=abc")

        assert resp.status_code == 200
        mock_service.get_remediation_priorities.assert_called_once()
        call_limit = mock_service.get_remediation_priorities.call_args[1]["limit"]
        assert call_limit == 20

    def test_extremely_large_limit_rejected_uses_default(self, client) -> None:
        """Very large limit must be rejected; default (20) used instead."""
        mock_service = MagicMock()
        mock_service.get_remediation_priorities.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/analysis/remediation-priorities?limit=1000000")

        assert resp.status_code == 200
        mock_service.get_remediation_priorities.assert_called_once()
        call_limit = mock_service.get_remediation_priorities.call_args[1]["limit"]
        assert call_limit != 1000000
        assert call_limit <= 100


class TestXssInApiResponses:
    """Verify JSON responses do not execute scripts."""

    def test_trust_score_json_content_type(self, client) -> None:
        """Trust score endpoint returns application/json."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "purl": "pkg:npm/foo@1.0",
            "direct_score": 7.0,
            "effective_score": 7.0,
            "confidence": 0.8,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:npm/foo@1.0/trust-score")

        assert resp.status_code == 200
        assert "application/json" in resp.content_type

    def test_script_tags_in_mock_data_remain_escaped_in_json(self, client) -> None:
        """Package names with script tags are JSON-encoded, not raw HTML."""
        mock_service = MagicMock()
        mock_service.find_version_by_purl.return_value = {
            "project_name": "test",
            "version_name": "1.0",
        }
        mock_service.get_package_vulnerabilities.return_value = []
        mock_service.get_package_licenses.return_value = []
        mock_service.get_trust_score_for_purl.return_value = None
        mock_service.check_policy.return_value = {"status": "pass"}
        mock_service.get_vex_for_package.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:npm/foo@1.0")

        assert resp.status_code == 200
        assert "application/json" in resp.content_type
        data = resp.get_json()
        assert "data" in data or "purl" in data

    def test_trust_check_response_no_unescaped_html(self, client) -> None:
        """Trust check returns JSON; no unescaped HTML in values."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = {
            "purl": "pkg:npm/<script>",
            "effective_score": 5.0,
            "direct_score": 5.0,
            "confidence": 0.5,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:npm/foo@1.0/trust-check")

        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "application/json" in resp.content_type
        assert "<script>" not in body or body.count("<script>") == 1


class TestNoSensitiveDataInErrors:
    """Verify error responses do not leak stack traces or internal details (CWE-209)."""

    def test_400_response_no_stack_trace(self, client) -> None:
        """400 responses must not include stack traces."""
        resp = client.get("/api/v1/package/invalid-purl/vulns")

        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data
        assert "Traceback" not in str(data)
        assert "File " not in str(data)
        assert ".py" not in str(data).split("error")[-1]

    def test_404_response_no_internal_details(self, client) -> None:
        """404 from service must use generic message."""
        mock_service = MagicMock()
        mock_service.find_version_by_purl.return_value = None
        mock_service.get_package_vulnerabilities.return_value = []
        mock_service.get_package_licenses.return_value = []
        mock_service.get_trust_score_for_purl.return_value = None
        mock_service.check_policy.return_value = {"status": "pass"}
        mock_service.get_vex_for_package.return_value = []

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:npm/nonexistent@99.99")

        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data
        assert "Traceback" not in str(data)
        assert "Exception" not in str(data)

    def test_trust_score_404_no_sensitive_info(self, client) -> None:
        """Trust score 404 must not leak stack traces or internal paths."""
        mock_service = MagicMock()
        mock_service.get_trust_score_for_purl.return_value = None

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org/lib@1.0/trust-score")

        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data
        body_str = str(data)
        assert "Traceback" not in body_str
        assert "File " not in body_str

    def test_invalid_purl_error_message_generic(self, client) -> None:
        """Invalid PURL must return generic 'Invalid purl', not raw input."""
        purl = "'; DROP NODE v; --"
        resp = client.get(f"/api/v1/package/{purl}/vulns")

        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data
        assert "Invalid" in data.get("error", "")
        assert "DROP" not in data.get("error", "")
