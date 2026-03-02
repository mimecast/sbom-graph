"""Tests for purl resolution utilities."""

from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from sbom_graph_api.utils.purl import resolve_purl, resolve_purl_project


@pytest.fixture
def app():
    """Minimal Flask app for request context."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test"
    return app


@pytest.fixture
def mock_service():
    """Create a mock FalkorDBService."""
    return MagicMock()


class TestResolvePurl:
    """Tests for resolve_purl function."""

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_valid_purl_found(self, mock_get_svc):
        svc = MagicMock()
        svc.find_version_by_purl.return_value = {
            "project_name": "foo",
            "version_name": "1.0.0",
            "project_group": "com.example",
        }
        mock_get_svc.return_value = svc

        result = resolve_purl("pkg:maven/com.example/foo@1.0.0")

        assert isinstance(result, dict)
        assert result["project_name"] == "foo"
        assert result["version_name"] == "1.0.0"
        assert result["project_group"] == "com.example"
        svc.find_version_by_purl.assert_called_once_with("pkg:maven/com.example/foo@1.0.0")

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_valid_purl_not_found(self, mock_get_svc):
        svc = MagicMock()
        svc.find_version_by_purl.return_value = None
        mock_get_svc.return_value = svc

        result = resolve_purl("pkg:maven/com.example/foo@9.9.9")

        assert isinstance(result, tuple)
        msg, code = result
        assert code == 404
        assert "No version found" in msg

    def test_invalid_purl_returns_400(self):
        result = resolve_purl("not-a-purl")

        assert isinstance(result, tuple)
        msg, code = result
        assert code == 400
        assert "Invalid package URL format" in msg

    def test_empty_purl_returns_400(self):
        result = resolve_purl("")

        msg, code = result
        assert code == 400

    def test_none_purl_returns_400(self):
        result = resolve_purl(None)

        msg, code = result
        assert code == 400

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_service_not_called_on_invalid_purl(self, mock_get_svc):
        resolve_purl("bad")
        mock_get_svc.assert_not_called()

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_null_project_group(self, mock_get_svc):
        svc = MagicMock()
        svc.find_version_by_purl.return_value = {
            "project_name": "lodash",
            "version_name": "4.17.21",
            "project_group": None,
        }
        mock_get_svc.return_value = svc

        result = resolve_purl("pkg:npm/lodash@4.17.21")

        assert result["project_group"] is None


class TestResolvePurlProject:
    """Tests for resolve_purl_project function."""

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_versioned_purl_uses_find_version(self, mock_get_svc):
        svc = MagicMock()
        svc.find_version_by_purl.return_value = {
            "project_name": "foo",
            "version_name": "1.0.0",
            "project_group": "com.example",
        }
        mock_get_svc.return_value = svc

        result = resolve_purl_project("pkg:maven/com.example/foo@1.0.0")

        assert isinstance(result, dict)
        assert result["project_name"] == "foo"
        assert result["project_group"] == "com.example"
        svc.find_version_by_purl.assert_called_once()
        svc.find_project_by_purl_prefix.assert_not_called()

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_versionless_purl_uses_prefix_search(self, mock_get_svc):
        svc = MagicMock()
        svc.find_project_by_purl_prefix.return_value = {
            "project_name": "foo",
            "project_group": "com.example",
        }
        mock_get_svc.return_value = svc

        result = resolve_purl_project("pkg:maven/com.example/foo")

        assert isinstance(result, dict)
        assert result["project_name"] == "foo"
        assert result["project_group"] == "com.example"
        svc.find_project_by_purl_prefix.assert_called_once()
        svc.find_version_by_purl.assert_not_called()

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_versioned_purl_not_found(self, mock_get_svc):
        svc = MagicMock()
        svc.find_version_by_purl.return_value = None
        mock_get_svc.return_value = svc

        result = resolve_purl_project("pkg:maven/com.example/missing@1.0.0")

        assert isinstance(result, tuple)
        msg, code = result
        assert code == 404
        assert "No project found" in msg

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_versionless_purl_not_found(self, mock_get_svc):
        svc = MagicMock()
        svc.find_project_by_purl_prefix.return_value = None
        mock_get_svc.return_value = svc

        result = resolve_purl_project("pkg:maven/com.example/missing")

        msg, code = result
        assert code == 404

    def test_invalid_purl_returns_400(self):
        result = resolve_purl_project("not-a-purl")

        msg, code = result
        assert code == 400
        assert "Invalid package URL format" in msg

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_result_contains_only_project_fields(self, mock_get_svc):
        """Ensure version_name is stripped from the returned dict."""
        svc = MagicMock()
        svc.find_version_by_purl.return_value = {
            "project_name": "foo",
            "version_name": "1.0.0",
            "project_group": "com.example",
        }
        mock_get_svc.return_value = svc

        result = resolve_purl_project("pkg:maven/com.example/foo@1.0.0")

        assert "version_name" not in result
        assert "project_name" in result
        assert "project_group" in result

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_service_not_called_on_invalid_purl(self, mock_get_svc):
        resolve_purl_project("")
        mock_get_svc.assert_not_called()

    @patch("sbom_graph_api.utils.purl.get_falkordb_service")
    def test_project_group_none_preserved(self, mock_get_svc):
        svc = MagicMock()
        svc.find_project_by_purl_prefix.return_value = {
            "project_name": "lodash",
            "project_group": None,
        }
        mock_get_svc.return_value = svc

        result = resolve_purl_project("pkg:npm/lodash")

        assert result["project_group"] is None
