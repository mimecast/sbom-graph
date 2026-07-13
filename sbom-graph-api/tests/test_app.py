"""Tests for Flask application module."""

from unittest.mock import MagicMock, patch


class TestCreateApp:
    """Tests for create_app factory function."""

    # Positive tests

    def test_app_creation(self, app):
        """Test that app is created successfully."""
        assert app is not None
        assert app.config["TESTING"] is True

    def test_proxyfix_applied(self, app):
        """M7 (CWE-307): X-Forwarded-* is trusted so rate limiters see the real IP."""
        from werkzeug.middleware.proxy_fix import ProxyFix

        assert isinstance(app.wsgi_app, ProxyFix)

    def test_csp_header_present(self, client):
        """M2 (CWE-1021): every response carries a Content-Security-Policy."""
        resp = client.get("/health")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_rejects_ldap_without_tls_in_production(self, mock_app_config):
        """SECURITY (CWE-319): LDAP enabled without TLS must fail startup
        (non-debug) rather than send bind credentials in cleartext."""
        from dataclasses import replace

        import pytest

        from sbom_graph_api.app import create_app
        from sbom_graph_api.config import reset_config

        insecure_ldap = replace(mock_app_config.ldap, enabled=True, use_ssl=False)
        cfg = replace(mock_app_config, debug=False, ldap=insecure_ldap)
        reset_config()
        try:
            with patch("sbom_graph_api.config.AppConfig.from_env", return_value=cfg):
                with pytest.raises(RuntimeError, match="LDAP"):
                    create_app()
        finally:
            reset_config()

    def test_app_has_secret_key(self, app):
        """Test that app has a secret key configured."""
        assert app.config["SECRET_KEY"] == "test-secret-key"

    def test_blueprints_registered(self, app):
        """Test that all blueprints are registered."""
        blueprint_names = [bp.name for bp in app.blueprints.values()]
        assert "visualizations" in blueprint_names
        assert "reports" in blueprint_names
        # The deprecated /exports blueprint was removed (dead code); ensure it's gone.
        assert "exports" not in blueprint_names


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    # Positive tests

    def test_health_returns_200(self, client):
        """Test health endpoint returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_json(self, client):
        """Test health endpoint returns JSON response."""
        response = client.get("/health")
        data = response.get_json()
        assert data["status"] == "healthy"


class TestReadyEndpoint:
    """Tests for /ready endpoint."""

    # Positive tests

    def test_ready_returns_200_when_db_available(self, client):
        """Test ready endpoint returns 200 when database is available."""
        with patch(
            "sbom_graph_api.services.falkordb_service.get_falkordb_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_service.execute_query.return_value = [[1]]
            mock_get_service.return_value = mock_service

            response = client.get("/ready")

            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] == "ready"

    # Negative tests

    def test_ready_returns_503_when_db_unavailable(self, client):
        """Test ready endpoint returns 503 when database is unavailable."""
        with patch(
            "sbom_graph_api.services.falkordb_service.get_falkordb_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_service.execute_query.side_effect = Exception("Connection failed")
            mock_get_service.return_value = mock_service

            response = client.get("/ready")

            assert response.status_code == 503
            data = response.get_json()
            assert data["status"] == "not_ready"
            assert "error" in data


class TestIndexEndpoint:
    """Tests for / index endpoint."""

    # Positive tests

    def test_index_returns_200(self, client):
        """Test index endpoint returns 200 OK."""
        response = client.get("/")
        assert response.status_code == 200

    def test_index_returns_html(self, client):
        """Test index endpoint returns HTML content."""
        response = client.get("/")
        assert response.content_type == "text/html; charset=utf-8"
        assert b"AppSec Data Views API" in response.data

    def test_index_contains_endpoint_docs(self, client):
        """Test index endpoint contains API documentation."""
        response = client.get("/")
        html = response.data.decode("utf-8")

        # Check for key endpoints in documentation
        assert "/visualizations/kpartite" in html
        assert "/visualizations/bipartite" in html
        assert "/reports/projects" in html
        assert "/health" in html
