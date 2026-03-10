"""Extended tests for visualization routes - covering dependencies and dependants-multi."""

from unittest.mock import patch


class TestDependenciesGraphRoute:
    """Tests for /visualizations/dependencies/<project>/<version>."""

    def test_returns_html(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependencies_multi_layout_visualization"
        ) as m:
            m.return_value = "<html>visualization</html>"
            response = client.get("/visualizations/dependencies/my-project/1.0.0")
            assert response.status_code == 200
            assert response.content_type.startswith("text/html")

    def test_not_found(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependencies_multi_layout_visualization"
        ) as m:
            m.return_value = None
            response = client.get("/visualizations/dependencies/nonexistent/1.0.0")
            assert response.status_code == 404

    def test_invalid_project_name(self, client):
        """Path traversal in project name is rejected (Flask normalizes or returns 400/404)."""
        response = client.get("/visualizations/dependencies/.hidden/1.0.0")
        assert response.status_code == 400

    def test_invalid_version(self, client):
        """Path traversal in version is rejected."""
        response = client.get("/visualizations/dependencies/proj/.hidden")
        assert response.status_code == 400

    def test_layout_param_passed(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependencies_multi_layout_visualization"
        ) as m:
            m.return_value = "<html></html>"
            client.get("/visualizations/dependencies/proj/1.0?layout=radial")
            call_kwargs = m.call_args.kwargs
            assert call_kwargs["layout"] == "radial"

    def test_internal_only_param(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependencies_multi_layout_visualization"
        ) as m:
            m.return_value = "<html></html>"
            client.get("/visualizations/dependencies/proj/1.0?internal_only=true")
            call_kwargs = m.call_args.kwargs
            assert call_kwargs["internal_only"] is True


class TestDependantsMultiLayoutRoute:
    """Tests for /visualizations/dependants-multi/<project>/<version>."""

    def test_returns_html(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependants_multi_layout_visualization"
        ) as m:
            m.return_value = "<html>dependants</html>"
            response = client.get("/visualizations/dependants-multi/my-lib/1.0.0")
            assert response.status_code == 200

    def test_not_found(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependants_multi_layout_visualization"
        ) as m:
            m.return_value = None
            response = client.get("/visualizations/dependants-multi/missing/1.0.0")
            assert response.status_code == 404

    def test_invalid_project_name(self, client):
        """Dot-prefixed project name is rejected by validation."""
        response = client.get("/visualizations/dependants-multi/.hidden/1.0.0")
        assert response.status_code == 400

    def test_invalid_version(self, client):
        """Dot-prefixed version is rejected by validation."""
        response = client.get("/visualizations/dependants-multi/proj/.hidden")
        assert response.status_code == 400

    def test_default_layout_is_radial(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependants_multi_layout_visualization"
        ) as m:
            m.return_value = "<html></html>"
            client.get("/visualizations/dependants-multi/proj/1.0")
            call_kwargs = m.call_args.kwargs
            assert call_kwargs["layout"] == "radial"

    def test_custom_layout(self, client):
        with patch(
            "sbom_graph_api.routes.visualizations.create_dependants_multi_layout_visualization"
        ) as m:
            m.return_value = "<html></html>"
            client.get("/visualizations/dependants-multi/proj/1.0?layout=bfs")
            call_kwargs = m.call_args.kwargs
            assert call_kwargs["layout"] == "bfs"
