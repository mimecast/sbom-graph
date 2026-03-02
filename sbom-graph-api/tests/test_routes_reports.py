"""Tests for report routes."""

from io import BytesIO
from unittest.mock import MagicMock, patch


class TestProjectsReportEndpoint:
    """Tests for /reports/projects endpoint."""

    # Positive tests

    def test_projects_returns_html_by_default(self, client):
        """Test projects endpoint returns HTML by default."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = [
                {"project_name": "project-a", "version": "1.0.0"},
                {"project_name": "project-b", "version": "2.0.0"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            assert b"project-a" in response.data
            assert b"project-b" in response.data

    def test_projects_returns_excel_when_requested(self, client):
        """Test projects endpoint returns Excel when format=excel."""
        mock_buffer = BytesIO(b"excel content")

        with (
            patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service,
            patch("sbom_graph_api.routes.reports.create_all_projects_excel") as mock_export,
        ):
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_export.return_value = mock_buffer

            response = client.get("/reports/projects?format=excel")

            assert response.status_code == 200
            assert (
                response.content_type
                == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

    def test_projects_respects_limit_parameter(self, client):
        """Test projects endpoint respects limit parameter."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            client.get("/reports/projects?limit=50")

            mock_service.get_all_projects.assert_called_once_with(50, False)

    def test_projects_shows_statistics(self, client):
        """Test projects endpoint shows statistics."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = [
                {"project_name": "project-a", "version": "1.0.0"},
                {"project_name": "project-a", "version": "2.0.0"},
                {"project_name": "project-b", "version": "1.0.0"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects")

            html = response.data.decode("utf-8")
            assert "Total Project Versions" in html
            assert "Unique Projects" in html

    # Negative tests

    def test_projects_handles_empty_database(self, client):
        """Test projects endpoint handles empty database gracefully."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects")

            assert response.status_code == 200
            assert b"No data found" in response.data

    def test_projects_invalid_format_defaults_to_html(self, client):
        """Test projects endpoint defaults to HTML for invalid format."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?format=invalid")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"

    def test_projects_internal_only_filter(self, client):
        """Test projects endpoint with internal_only filter."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = [
                {"project_name": "acme_corp-lib", "version": "1.0.0"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?internal_only=true")

            assert response.status_code == 200
            # Verify internal_only was passed to service
            mock_service.get_all_projects.assert_called_once_with(10000, True)
            # Check title reflects the filter
            assert b"Internal Projects" in response.data
            assert b"Internal Only" in response.data

    def test_projects_internal_only_excel(self, client):
        """Test projects endpoint with internal_only filter for Excel export."""
        mock_buffer = BytesIO(b"excel content")

        with (
            patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service,
            patch("sbom_graph_api.routes.reports.create_all_projects_excel") as mock_export,
        ):
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_export.return_value = mock_buffer

            response = client.get("/reports/projects?format=excel&internal_only=true")

            assert response.status_code == 200
            assert "internal_projects.xlsx" in response.headers["Content-Disposition"]
            mock_export.assert_called_once_with(mock_service, 10000, True)


class TestSnapshotsReportEndpoint:
    """Tests for /reports/snapshots endpoint."""

    # Positive tests

    def test_snapshots_returns_html_by_default(self, client):
        """Test snapshots endpoint returns HTML by default."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = [
                {
                    "application": "app-a",
                    "app_version": "1.0.0",
                    "dependency": "lib-a",
                    "dep_version": "1.0.0-SNAPSHOT",
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/snapshots")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            assert b"SNAPSHOT" in response.data
            assert b"app-a" in response.data

    def test_snapshots_returns_excel_when_requested(self, client):
        """Test snapshots endpoint returns Excel when format=excel."""
        mock_buffer = BytesIO(b"excel content")

        with (
            patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service,
            patch("sbom_graph_api.routes.reports.create_snapshot_report_excel") as mock_export,
        ):
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = []
            mock_get_service.return_value = mock_service
            mock_export.return_value = mock_buffer

            response = client.get("/reports/snapshots?format=excel")

            assert response.status_code == 200
            assert "snapshot_dependencies.xlsx" in response.headers["Content-Disposition"]

    def test_snapshots_shows_statistics(self, client):
        """Test snapshots endpoint shows statistics."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = [
                {
                    "application": "app-a",
                    "app_version": "1.0.0",
                    "dependency": "lib-a",
                    "dep_version": "1.0.0-SNAPSHOT",
                },
                {
                    "application": "app-b",
                    "app_version": "2.0.0",
                    "dependency": "lib-a",
                    "dep_version": "1.0.0-SNAPSHOT",
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/snapshots")

            html = response.data.decode("utf-8")
            assert "Total SNAPSHOT Dependencies" in html
            assert "Affected Applications" in html

    # Negative tests

    def test_snapshots_handles_no_snapshots(self, client):
        """Test snapshots endpoint handles no SNAPSHOT dependencies."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/snapshots")

            assert response.status_code == 200
            assert b"No data found" in response.data


class TestSelfDependenciesReportEndpoint:
    """Tests for /reports/self-dependencies endpoint."""

    # Positive tests

    def test_self_dependencies_returns_html_by_default(self, client):
        """Test self-dependencies endpoint returns HTML by default."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = [
                {
                    "project_name": "self-ref-project",
                    "version": "1.0.0",
                    "relationship_type": "DEPENDS_ON",
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/self-dependencies")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            assert b"self-ref-project" in response.data

    def test_self_dependencies_returns_excel_when_requested(self, client):
        """Test self-dependencies endpoint returns Excel when format=excel."""
        mock_buffer = BytesIO(b"excel content")

        with (
            patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service,
            patch(
                "sbom_graph_api.routes.reports.create_self_dependency_report_excel"
            ) as mock_export,
        ):
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = []
            mock_get_service.return_value = mock_service
            mock_export.return_value = mock_buffer

            response = client.get("/reports/self-dependencies?format=excel")

            assert response.status_code == 200
            assert "self_dependencies.xlsx" in response.headers["Content-Disposition"]

    def test_self_dependencies_shows_statistics(self, client):
        """Test self-dependencies endpoint shows statistics."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = [
                {
                    "project_name": "project-a",
                    "version": "1.0.0",
                    "relationship_type": "DEPENDS_ON",
                },
                {
                    "project_name": "project-a",
                    "version": "2.0.0",
                    "relationship_type": "DEPENDS_ON",
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/self-dependencies")

            html = response.data.decode("utf-8")
            assert "Total Self Dependencies" in html
            assert "Affected Projects" in html

    # Negative tests

    def test_self_dependencies_handles_no_self_deps(self, client):
        """Test self-dependencies endpoint handles no self-dependencies."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/self-dependencies")

            assert response.status_code == 200
            assert b"No data found" in response.data


class TestMultiVersionDepsReportEndpoint:
    """Tests for /reports/multi-version-deps/{project_name} endpoint."""

    # Positive tests

    def test_multi_version_deps_returns_html_by_default(self, client):
        """Test multi-version-deps endpoint returns HTML by default."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_library_version_usage.return_value = {
                "library": {"project_name": "jackson-databind", "total_versions": 2},
                "total_dependants": 5,
                "versions": [
                    {
                        "version": "2.14.2",
                        "project_group": "com.fasterxml.jackson.core",
                        "is_internal": False,
                        "dependant_count": 3,
                        "dependants": [
                            {
                                "project_name": "app-a",
                                "version": "1.0.0",
                                "project_group": "com.example",
                                "is_internal": True,
                            }
                        ],
                    },
                    {
                        "version": "2.16.1",
                        "project_group": "com.fasterxml.jackson.core",
                        "is_internal": False,
                        "dependant_count": 2,
                        "dependants": [],
                    },
                ],
            }
            mock_get_service.return_value = mock_service

            response = client.get("/reports/multi-version-deps/jackson-databind")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            assert b"jackson-databind" in response.data
            assert b"2.14.2" in response.data
            assert b"2.16.1" in response.data

    def test_multi_version_deps_returns_excel_when_requested(self, client):
        """Test multi-version-deps endpoint returns Excel when format=excel."""
        mock_buffer = BytesIO(b"excel content")

        with (
            patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service,
            patch("sbom_graph_api.routes.reports.create_multi_version_deps_excel") as mock_export,
        ):
            mock_service = MagicMock()
            mock_service.get_library_version_usage.return_value = {
                "library": {"project_name": "test-lib", "total_versions": 1},
                "total_dependants": 1,
                "versions": [
                    {
                        "version": "1.0.0",
                        "project_group": "com.test",
                        "is_internal": False,
                        "dependant_count": 1,
                        "dependants": [],
                    }
                ],
            }
            mock_get_service.return_value = mock_service
            mock_export.return_value = mock_buffer

            response = client.get("/reports/multi-version-deps/test-lib?format=excel")

            assert response.status_code == 200
            assert (
                response.content_type
                == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

    def test_multi_version_deps_returns_json_when_requested(self, client):
        """Test multi-version-deps endpoint returns JSON when format=json."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_library_version_usage.return_value = {
                "library": {"project_name": "test-lib", "total_versions": 1},
                "total_dependants": 2,
                "versions": [
                    {
                        "version": "1.0.0",
                        "project_group": "com.test",
                        "is_internal": True,
                        "dependant_count": 2,
                        "dependants": [],
                    }
                ],
            }
            mock_get_service.return_value = mock_service

            response = client.get("/reports/multi-version-deps/test-lib?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"
            json_data = response.get_json()
            assert json_data["report_type"] == "multi-version-deps"
            assert json_data["library"]["project_name"] == "test-lib"

    def test_multi_version_deps_passes_internal_only(self, client):
        """Test multi-version-deps endpoint passes internal_only parameter."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_library_version_usage.return_value = {
                "library": {"project_name": "test-lib", "total_versions": 0},
                "total_dependants": 0,
                "versions": [],
            }
            mock_get_service.return_value = mock_service

            client.get("/reports/multi-version-deps/test-lib?internal_only=true")

            mock_service.get_library_version_usage.assert_called_once_with("test-lib", True)

    # Negative tests

    def test_multi_version_deps_handles_not_found(self, client):
        """Test multi-version-deps endpoint handles library not found."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_library_version_usage.return_value = {
                "library": {"project_name": "unknown", "total_versions": 0},
                "total_dependants": 0,
                "versions": [],
            }
            mock_get_service.return_value = mock_service

            response = client.get("/reports/multi-version-deps/unknown")

            assert response.status_code == 404

    def test_multi_version_deps_json_not_found(self, client):
        """Test multi-version-deps endpoint returns JSON 404 when library not found."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_library_version_usage.return_value = {
                "library": {"project_name": "unknown", "total_versions": 0},
                "total_dependants": 0,
                "versions": [],
            }
            mock_get_service.return_value = mock_service

            response = client.get("/reports/multi-version-deps/unknown?format=json")

            assert response.status_code == 404
            json_data = response.get_json()
            assert "error" in json_data


class TestInternalOnlyToggle:
    """Tests for internal_only toggle functionality in reports."""

    def test_toggle_checkbox_present_in_html(self, client):
        """Test that internal_only toggle checkbox is present in HTML reports."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects")

            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert 'id="internalOnlyToggle"' in html
            assert "toggle-switch" in html

    def test_toggle_unchecked_by_default(self, client):
        """Test that toggle is unchecked when internal_only is false."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects")

            html = response.data.decode("utf-8")
            # Should show "All projects" when not checked
            assert "All projects" in html

    def test_toggle_checked_when_internal_only_true(self, client):
        """Test that toggle is checked when internal_only=true."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?internal_only=true")

            html = response.data.decode("utf-8")
            # Toggle should be checked
            assert "checked" in html
            # Should show "Internal Only" when checked
            assert "Internal Only" in html

    def test_download_links_include_internal_only_param(self, client):
        """Test that Excel and JSON download links include internal_only parameter."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?internal_only=true")

            html = response.data.decode("utf-8")
            # Both Excel and JSON download links should include internal_only=true
            assert "format=excel" in html
            assert "format=json" in html
            assert "internal_only=true" in html

    def test_toggle_present_in_snapshots_report(self, client):
        """Test toggle is present in snapshots report."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/snapshots")

            html = response.data.decode("utf-8")
            assert 'id="internalOnlyToggle"' in html

    def test_toggle_present_in_self_dependencies_report(self, client):
        """Test toggle is present in self-dependencies report."""
        with patch("sbom_graph_api.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/self-dependencies")

            html = response.data.decode("utf-8")
            assert 'id="internalOnlyToggle"' in html


class TestInteractiveApiDocs:
    """Tests for interactive API documentation page."""

    def test_api_docs_has_interactive_forms(self, client):
        """Test that API docs page has interactive forms."""
        response = client.get("/")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        # Check for form elements
        assert 'class="try-form"' in html
        assert "<button onclick=" in html

    def test_api_docs_has_clickable_links(self, client):
        """Test that API docs page has clickable links for no-param endpoints."""
        response = client.get("/")

        html = response.data.decode("utf-8")
        # Should have links to endpoints without required parameters
        assert 'href="/reports/projects"' in html
        assert 'href="/reports/snapshots"' in html
        assert 'href="/reports/self-dependencies"' in html
        assert 'href="/reports/non-semver-versions"' in html
        assert 'href="/schemas/"' in html
        assert 'href="/health"' in html
        assert 'href="/ready"' in html

    def test_api_docs_has_schema_dropdown(self, client):
        """Test that API docs has schema selection dropdown."""
        response = client.get("/")

        html = response.data.decode("utf-8")
        assert 'id="schema_name"' in html
        assert '<option value="projects">' in html
        assert '<option value="dependants">' in html

    def test_api_docs_has_internal_only_checkboxes(self, client):
        """Test that API docs forms have internal_only checkboxes."""
        response = client.get("/")

        html = response.data.decode("utf-8")
        # Should have multiple internal_only checkboxes for different forms
        assert "Internal Only" in html
        assert 'type="checkbox"' in html
