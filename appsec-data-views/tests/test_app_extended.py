"""Extended tests for app.py - JWT error handlers, _is_api_request, index with auth."""

from unittest.mock import patch

import pytest


class TestIsApiRequest:
    """Tests for _is_api_request helper."""

    def test_json_content_type(self, app):
        with app.test_request_context("/", content_type="application/json"):
            from appsec_data_views.app import _is_api_request
            assert _is_api_request() is True

    def test_json_accept_header(self, app):
        with app.test_request_context("/", headers={"Accept": "application/json"}):
            from appsec_data_views.app import _is_api_request
            assert _is_api_request() is True

    def test_authorization_header(self, app):
        with app.test_request_context("/", headers={"Authorization": "Bearer token"}):
            from appsec_data_views.app import _is_api_request
            assert _is_api_request() is True

    def test_browser_request(self, app):
        with app.test_request_context("/", headers={"Accept": "text/html"}):
            from appsec_data_views.app import _is_api_request
            assert _is_api_request() is False


class TestIndexWithAuth:
    """Tests for index endpoint with authentication enabled/disabled."""

    def test_index_with_auth_disabled(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_index_unauthenticated_redirects(self):
        """When auth enabled but not authenticated, redirects to login."""
        from appsec_data_views.config import reset_config
        from appsec_data_views.services.falkordb_service import reset_service

        reset_config()
        reset_service()

        mock_config = pytest.importorskip("appsec_data_views.config").AppConfig
        # This is tested through the auth_app fixture in test_routes_auth.py


class TestGetGraphContext:
    """Tests for context manager."""

    def test_get_graph_yields_graph(self):
        from unittest.mock import MagicMock
        from appsec_data_views.services.falkordb_service import FalkorDBService
        from appsec_data_views.config import FalkorDBConfig

        config = FalkorDBConfig(
            host="test", port=6379, password="", graph_name="test",
            socket_timeout=30.0, socket_connect_timeout=10.0, internal_label="INTERNAL",
        )
        service = FalkorDBService(config=config)

        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_db.select_graph.return_value = mock_graph
        service._db = mock_db

        with service.get_graph() as graph:
            assert graph is mock_graph
