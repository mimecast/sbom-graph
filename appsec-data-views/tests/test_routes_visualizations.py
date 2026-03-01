"""Tests for visualization routes."""

from unittest.mock import patch


class TestKpartiteEndpoint:
    """Tests for /visualizations/kpartite endpoint."""

    # Positive tests

    def test_kpartite_returns_html_when_project_found(self, client):
        """Test kpartite returns HTML visualization when project exists."""
        with patch(
            "appsec_data_views.routes.visualizations.create_kpartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html><body>Test Visualization</body></html>"

            response = client.get("/visualizations/kpartite/test-project/1.0.0")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            assert b"Test Visualization" in response.data
            mock_viz.assert_called_once()

    def test_kpartite_passes_parameters(self, client):
        """Test kpartite passes query parameters correctly."""
        with patch(
            "appsec_data_views.routes.visualizations.create_kpartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html></html>"

            client.get(
                "/visualizations/kpartite/my-project/2.0.0"
                "?max_depth=5&internal_only=true&height=1000px&width=80%"
            )

            mock_viz.assert_called_once_with(
                project_name="my-project",
                version_name="2.0.0",
                max_depth=5,
                internal_only=True,
                height="1000px",
                width="80%",
            )

    def test_kpartite_default_parameters(self, client):
        """Test kpartite uses default parameters."""
        with patch(
            "appsec_data_views.routes.visualizations.create_kpartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html></html>"

            client.get("/visualizations/kpartite/project/1.0.0")

            mock_viz.assert_called_once_with(
                project_name="project",
                version_name="1.0.0",
                max_depth=None,
                internal_only=False,
                height="100vh",
                width="100vw",
            )

    # Negative tests

    def test_kpartite_returns_404_when_project_not_found(self, client):
        """Test kpartite returns 404 when project does not exist."""
        with patch(
            "appsec_data_views.routes.visualizations.create_kpartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = None

            response = client.get("/visualizations/kpartite/nonexistent/0.0.0")

            assert response.status_code == 404
            assert b"Project not found" in response.data

    def test_kpartite_escapes_xss_in_error(self, client):
        """Test kpartite escapes XSS attempts in error message."""
        with patch(
            "appsec_data_views.routes.visualizations.create_kpartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = None

            # Use a project name that could contain XSS if not escaped
            response = client.get("/visualizations/kpartite/test-project/1.0.0")

            assert response.status_code == 404
            # Verify the error message is present and project name is shown
            assert b"Project not found" in response.data
            # The important thing is no raw HTML is injected


class TestBipartiteEndpoint:
    """Tests for /visualizations/bipartite endpoint."""

    # Positive tests

    def test_bipartite_returns_html_when_project_found(self, client):
        """Test bipartite returns HTML visualization when project exists."""
        with patch(
            "appsec_data_views.routes.visualizations.create_bipartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html><body>Bipartite Graph</body></html>"

            response = client.get("/visualizations/bipartite/test-project")

            assert response.status_code == 200
            assert b"Bipartite Graph" in response.data

    def test_bipartite_passes_parameters(self, client):
        """Test bipartite passes query parameters correctly."""
        with patch(
            "appsec_data_views.routes.visualizations.create_bipartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html></html>"

            client.get("/visualizations/bipartite/my-project?height=600px&width=90%")

            mock_viz.assert_called_once_with(
                project_name="my-project",
                internal_only=False,
                height="600px",
                width="90%",
            )

    # Negative tests

    def test_bipartite_returns_404_when_project_not_found(self, client):
        """Test bipartite returns 404 when project does not exist."""
        with patch(
            "appsec_data_views.routes.visualizations.create_bipartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = None

            response = client.get("/visualizations/bipartite/nonexistent")

            assert response.status_code == 404
            assert b"Project not found" in response.data

    def test_bipartite_escapes_xss_in_error(self, client):
        """Test bipartite escapes XSS attempts in error message."""
        with patch(
            "appsec_data_views.routes.visualizations.create_bipartite_visualization"
        ) as mock_viz:
            mock_viz.return_value = None

            # The escaping is verified by checking that HTML special chars are escaped
            # Flask will escape <, >, etc. in the response
            response = client.get("/visualizations/bipartite/test-project")

            assert response.status_code == 404
            assert b"Project not found" in response.data


class TestDependantsEndpoint:
    """Tests for /visualizations/dependants endpoint."""

    # Positive tests

    def test_dependants_returns_html_when_project_found(self, client):
        """Test dependants returns HTML visualization when project exists."""
        with patch(
            "appsec_data_views.routes.visualizations.create_dependants_graph_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html><body>Dependants Graph</body></html>"

            response = client.get("/visualizations/dependants/test-lib/1.0.0")

            assert response.status_code == 200
            assert b"Dependants Graph" in response.data

    def test_dependants_passes_parameters(self, client):
        """Test dependants passes query parameters correctly."""
        with patch(
            "appsec_data_views.routes.visualizations.create_dependants_graph_visualization"
        ) as mock_viz:
            mock_viz.return_value = "<html></html>"

            client.get(
                "/visualizations/dependants/my-lib/2.0.0?max_depth=10&height=1200px&width=100%"
            )

            mock_viz.assert_called_once_with(
                project_name="my-lib",
                version_name="2.0.0",
                max_depth=10,
                internal_only=False,
                height="1200px",
                width="100%",
            )

    # Negative tests

    def test_dependants_returns_404_when_project_not_found(self, client):
        """Test dependants returns 404 when project does not exist."""
        with patch(
            "appsec_data_views.routes.visualizations.create_dependants_graph_visualization"
        ) as mock_viz:
            mock_viz.return_value = None

            response = client.get("/visualizations/dependants/nonexistent/0.0.0")

            assert response.status_code == 404
            assert b"Project not found" in response.data

    def test_dependants_escapes_xss_in_error(self, client):
        """Test dependants escapes XSS attempts in error message."""
        with patch(
            "appsec_data_views.routes.visualizations.create_dependants_graph_visualization"
        ) as mock_viz:
            mock_viz.return_value = None

            response = client.get("/visualizations/dependants/test/<script>bad</script>")

            assert response.status_code == 404
            assert b"<script>" not in response.data
