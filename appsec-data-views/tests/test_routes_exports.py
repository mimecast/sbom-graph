"""Tests for export routes (now deprecated, redirect to reports)."""

from unittest.mock import MagicMock, patch


class TestExportRedirects:
    """Tests that export endpoints redirect to report endpoints."""

    def test_export_excel_redirects(self, client):
        """Test /exports/dependencies/{project}/excel redirects to latest version."""
        response = client.get("/exports/dependencies/test-project/excel")
        assert response.status_code == 301
        assert "/reports/version-dependencies/test-project/latest" in response.location
        assert "format=excel" in response.location

    def test_export_json_redirects(self, client):
        """Test /exports/dependencies/{project}/json redirects to latest version."""
        response = client.get("/exports/dependencies/test-project/json")
        assert response.status_code == 301
        assert "/reports/version-dependencies/test-project/latest" in response.location
        assert "format=json" in response.location

    def test_export_html_redirects(self, client):
        """Test /exports/dependencies/{project} redirects to latest version."""
        response = client.get("/exports/dependencies/test-project")
        assert response.status_code == 301
        assert "/reports/version-dependencies/test-project/latest" in response.location

    def test_export_preserves_internal_only_param(self, client):
        """Test redirect preserves internal_only parameter."""
        response = client.get("/exports/dependencies/test-project?internal_only=true")
        assert response.status_code == 301
        assert "internal_only=true" in response.location

    def test_export_excel_preserves_internal_only_param(self, client):
        """Test excel redirect preserves internal_only parameter."""
        response = client.get("/exports/dependencies/test-project/excel?internal_only=true")
        assert response.status_code == 301
        assert "internal_only=true" in response.location
        assert "format=excel" in response.location

    def test_export_rejects_invalid_project_name(self, client):
        """Test export endpoint rejects invalid project names."""
        # Path traversal attempt
        response = client.get("/exports/dependencies/../../../etc/passwd/excel")
        assert response.status_code in (400, 404)

    def test_export_accepts_valid_project_names(self, client):
        """Test export endpoint accepts various valid project names."""
        valid_names = ["my-project", "my_project", "my.project", "project123"]
        for name in valid_names:
            response = client.get(f"/exports/dependencies/{name}/excel")
            assert response.status_code == 301, f"Failed for project name: {name}"


class TestVersionDependenciesReport:
    """Tests for the new version-dependencies report endpoint."""

    def test_report_returns_html_by_default(self, client):
        """Test report returns HTML by default."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = [
                {
                    "depth": 1,
                    "dependency_project": "lib-a",
                    "dependency_version": "1.0.0",
                    "is_internal": False,
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            assert b"Version Dependencies" in response.data

    def test_report_with_specific_version(self, client):
        """Test report with specific version parameter."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "2.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = [
                {
                    "depth": 1,
                    "dependency_project": "lib-a",
                    "dependency_version": "1.0.0",
                    "is_internal": False,
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0")

            assert response.status_code == 200
            assert b"1.0.0" in response.data
            mock_service.get_transitive_dependencies_for_report.assert_called_once()

    def test_report_with_latest_version(self, client):
        """Test report with 'latest' version resolves correctly."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "2.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/latest")

            assert response.status_code == 200
            # Should resolve to 2.0.0 and show it in the title
            assert b"2.0.0" in response.data

    def test_report_latest_fails_for_non_semver_project(self, client):
        """Test that 'latest' returns error for non-SemVer compliant projects."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (False, ["bad-version-1"])
            mock_service.get_latest_semver_version.return_value = None
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/latest")

            assert response.status_code == 400
            assert b"non-SemVer" in response.data

    def test_report_returns_json_format(self, client):
        """Test report returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0?format=json")

            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "version-dependencies"
            assert "semver_compliance" in data
            assert data["semver_compliance"]["is_compliant"] is True

    def test_report_shows_semver_compliance_info(self, client):
        """Test report shows SemVer compliance information."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "2.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0")

            html = response.data.decode("utf-8")
            assert "SemVer Compliant" in html or "Latest Version" in html

    def test_report_returns_404_for_nonexistent_project(self, client):
        """Test report returns 404 for nonexistent project."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = None
            mock_service.get_all_versions_of_project.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/nonexistent-project/1.0.0")

            assert response.status_code == 404

    def test_report_returns_404_for_nonexistent_version(self, client):
        """Test report returns 404 for nonexistent version."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/9.9.9")

            assert response.status_code == 404

    def test_report_has_toggle_for_internal_only(self, client):
        """Test report has internal_only toggle."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0")

            html = response.data.decode("utf-8")
            assert 'id="internalOnlyToggle"' in html
