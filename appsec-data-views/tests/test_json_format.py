"""Tests for JSON format output in reports and exports."""

import json
from unittest.mock import MagicMock, patch


class TestProjectsJsonFormat:
    """Tests for /reports/projects?format=json endpoint."""

    def test_projects_returns_json_when_requested(self, client):
        """Test projects endpoint returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = [
                {"project_name": "project-a", "version": "1.0.0"},
                {"project_name": "project-b", "version": "2.0.0"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"

    def test_projects_json_has_required_fields(self, client):
        """Test projects JSON response has required schema fields."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = [
                {"project_name": "project-a", "version": "1.0.0"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?format=json")
            data = json.loads(response.data)

            assert data["report_type"] == "projects"
            assert "generated_at" in data
            assert "stats" in data
            assert "data" in data

    def test_projects_json_has_correct_stats(self, client):
        """Test projects JSON stats are calculated correctly."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = [
                {"project_name": "project-a", "version": "1.0.0"},
                {"project_name": "project-a", "version": "2.0.0"},
                {"project_name": "project-b", "version": "1.0.0"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?format=json")
            data = json.loads(response.data)

            assert data["stats"]["total_project_versions"] == 3
            assert data["stats"]["unique_projects"] == 2

    def test_projects_json_has_content_disposition(self, client):
        """Test projects JSON response has Content-Disposition header."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?format=json")

            assert "Content-Disposition" in response.headers
            assert ".json" in response.headers["Content-Disposition"]

    def test_projects_json_internal_only_filter(self, client):
        """Test projects JSON respects internal_only filter."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects?format=json&internal_only=true")
            data = json.loads(response.data)

            assert data["filter"] == "internal_only"


class TestSnapshotsJsonFormat:
    """Tests for /reports/snapshots?format=json endpoint."""

    def test_snapshots_returns_json_when_requested(self, client):
        """Test snapshots endpoint returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
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

            response = client.get("/reports/snapshots?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"

    def test_snapshots_json_has_required_fields(self, client):
        """Test snapshots JSON response has required schema fields."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/snapshots?format=json")
            data = json.loads(response.data)

            assert data["report_type"] == "snapshots"
            assert "generated_at" in data
            assert "stats" in data
            assert "data" in data


class TestSelfDependenciesJsonFormat:
    """Tests for /reports/self-dependencies?format=json endpoint."""

    def test_self_dependencies_returns_json_when_requested(self, client):
        """Test self-dependencies endpoint returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/self-dependencies?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"

    def test_self_dependencies_json_has_required_fields(self, client):
        """Test self-dependencies JSON response has required schema fields."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_self_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/self-dependencies?format=json")
            data = json.loads(response.data)

            assert data["report_type"] == "self-dependencies"
            assert "generated_at" in data
            assert "stats" in data


class TestNonSemverVersionsJsonFormat:
    """Tests for /reports/non-semver-versions?format=json endpoint."""

    def test_non_semver_returns_json_when_requested(self, client):
        """Test non-semver-versions endpoint returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_non_semver_versions.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/non-semver-versions?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"

    def test_non_semver_json_has_reason_breakdown(self, client):
        """Test non-semver JSON includes reason breakdown in stats."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_non_semver_versions.return_value = [
                {"project_name": "lib-a", "version": "latest", "reason": "Non-standard format"},
                {"project_name": "lib-b", "version": "abc123", "reason": "Git commit hash"},
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/non-semver-versions?format=json")
            data = json.loads(response.data)

            assert "reason_breakdown" in data["stats"]
            assert data["stats"]["reason_breakdown"]["Non-standard format"] == 1
            assert data["stats"]["reason_breakdown"]["Git commit hash"] == 1


class TestMultiVersionSourcesJsonFormat:
    """Tests for /reports/multi-version-sources?format=json endpoint."""

    def test_multi_version_sources_returns_json_when_requested(self, client):
        """Test multi-version-sources endpoint returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_multi_version_dependency_sources.return_value = {
                "target": {
                    "project_name": "test-project",
                    "version": "1.0.0",
                    "scan_ids_count": 2,
                },
                "multi_version_dependencies": [],
            }
            mock_get_service.return_value = mock_service

            response = client.get("/reports/multi-version-sources/test-project/1.0.0?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"

    def test_multi_version_sources_json_not_found(self, client):
        """Test multi-version-sources returns 404 JSON for missing project."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_multi_version_dependency_sources.return_value = {
                "target": None,
                "multi_version_dependencies": [],
            }
            mock_get_service.return_value = mock_service

            response = client.get("/reports/multi-version-sources/missing/1.0.0?format=json")

            assert response.status_code == 404
            data = json.loads(response.data)
            assert "error" in data


class TestVersionDependenciesJsonFormat:
    """Tests for /reports/version-dependencies/{project}?format=json endpoint."""

    def test_dependencies_returns_json_when_requested(self, client):
        """Test version dependencies report returns JSON when format=json."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0?format=json")

            assert response.status_code == 200
            assert response.content_type == "application/json"

    def test_dependencies_json_has_required_fields(self, client):
        """Test version dependencies JSON has required schema fields."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = [
                {
                    "depth": 1,
                    "dependency_project": "lib-a",
                    "dependency_version": "1.0.0",
                    "is_internal": False,
                },
            ]
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0?format=json")
            data = json.loads(response.data)

            assert data["report_type"] == "version-dependencies"
            assert data["project_name"] == "test-project"
            assert data["version"] == "1.0.0"
            assert "generated_at" in data
            assert "summary" in data
            assert "data" in data
            assert "semver_compliance" in data

    def test_dependencies_json_includes_semver_info(self, client):
        """Test version dependencies JSON includes SemVer compliance info."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "2.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0?format=json")
            data = json.loads(response.data)

            assert data["semver_compliance"]["is_compliant"] is True
            assert data["semver_compliance"]["latest_version"] == "2.0.0"

    def test_dependencies_landing_page(self, client):
        """Test version dependencies report landing page."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_project_semver_compliant.return_value = (True, [])
            mock_service.get_latest_semver_version.return_value = "1.0.0"
            mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
            mock_service.get_transitive_dependencies_for_report.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/version-dependencies/test-project/1.0.0")

            assert response.status_code == 200
            assert response.content_type == "text/html; charset=utf-8"
            # Should have download links
            assert b"Download as Excel" in response.data
            assert b"Download as JSON" in response.data
            assert b"View JSON Schema" in response.data


class TestHtmlReportDownloadLinks:
    """Tests that HTML reports include download links for JSON and schema."""

    def test_projects_html_has_json_download_link(self, client):
        """Test projects HTML includes JSON download link."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.get_all_projects.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/projects")
            html = response.data.decode("utf-8")

            assert "format=json" in html
            assert "/schemas/projects" in html

    def test_snapshots_html_has_json_download_link(self, client):
        """Test snapshots HTML includes JSON download link."""
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.find_snapshot_dependencies.return_value = []
            mock_get_service.return_value = mock_service

            response = client.get("/reports/snapshots")
            html = response.data.decode("utf-8")

            assert "format=json" in html
            assert "/schemas/snapshots" in html
