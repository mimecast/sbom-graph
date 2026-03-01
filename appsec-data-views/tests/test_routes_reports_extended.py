"""Extended tests for report routes - covering uncovered endpoints and formats."""

from io import BytesIO
from unittest.mock import MagicMock, patch


class TestApplicationsEndpoint:
    """Tests for /reports/applications endpoint."""

    def _mock_service(self, return_value):
        mock_service = MagicMock()
        mock_service.get_all_applications.return_value = return_value
        return mock_service

    def test_html_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([
                {"project_name": "app-a", "version": "1.0.0", "scan_id": "s1",
                 "public_id": "p1", "repo_url": "https://git", "is_internal": True},
            ])
            response = client.get("/reports/applications")
            assert response.status_code == 200
            assert b"app-a" in response.data

    def test_excel_format(self, client):
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service") as m,
            patch("appsec_data_views.routes.reports.create_applications_excel") as mock_excel,
        ):
            m.return_value = self._mock_service([])
            mock_excel.return_value = BytesIO(b"fake-excel")
            response = client.get("/reports/applications?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type

    def test_json_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([
                {"project_name": "app-a", "version": "1.0.0", "scan_id": "s1",
                 "public_id": None, "repo_url": None, "is_internal": False},
            ])
            response = client.get("/reports/applications?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "applications"

    def test_latest_only_param(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/applications?latest_only=true")
            assert response.status_code == 200


class TestNonSemverEndpoint:
    """Tests for /reports/non-semver-versions endpoint."""

    def _mock_service(self, data):
        mock = MagicMock()
        mock.find_non_semver_versions.return_value = data
        return mock

    def test_html_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([
                {"project_name": "proj", "version": "latest", "reason": "No numeric", "labels": ["Version"]},
            ])
            response = client.get("/reports/non-semver-versions")
            assert response.status_code == 200

    def test_excel_format(self, client):
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service") as m,
            patch("appsec_data_views.routes.reports.create_non_semver_report_excel") as mock_excel,
        ):
            m.return_value = self._mock_service([])
            mock_excel.return_value = BytesIO(b"excel")
            response = client.get("/reports/non-semver-versions?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([
                {"project_name": "p", "version": "x", "reason": "r", "labels": []},
            ])
            response = client.get("/reports/non-semver-versions?format=json")
            data = response.get_json()
            assert data["report_type"] == "non-semver-versions"
            assert "reason_breakdown" in data["stats"]


class TestMultiVersionDepsEndpoint:
    """Tests for /reports/multi-version-deps/<project> endpoint."""

    def test_html_with_data(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {"project_name": "my-lib", "total_versions": 1},
            "total_dependants": 1,
            "versions": [{"version": "1.0", "dependant_count": 1, "is_internal": False,
                          "dependants": [{"project_name": "app", "version": "1.0",
                                          "project_group": "", "is_internal": False}]}],
        }
        with patch("appsec_data_views.routes.reports.get_falkordb_service", return_value=mock_service):
            response = client.get("/reports/multi-version-deps/my-lib")
            assert response.status_code == 200

    def test_not_found_json(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {}, "total_dependants": 0, "versions": [],
        }
        with patch("appsec_data_views.routes.reports.get_falkordb_service", return_value=mock_service):
            response = client.get("/reports/multi-version-deps/nonexistent?format=json")
            assert response.status_code == 404

    def test_not_found_html(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {}, "total_dependants": 0, "versions": [],
        }
        with patch("appsec_data_views.routes.reports.get_falkordb_service", return_value=mock_service):
            response = client.get("/reports/multi-version-deps/nonexistent")
            assert response.status_code == 404

    def test_excel_format(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {"project_name": "lib", "total_versions": 1},
            "total_dependants": 0,
            "versions": [{"version": "1.0", "dependant_count": 0, "is_internal": False, "dependants": []}],
        }
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service", return_value=mock_service),
            patch("appsec_data_views.routes.reports.create_multi_version_deps_excel") as mock_excel,
        ):
            mock_excel.return_value = BytesIO(b"excel")
            response = client.get("/reports/multi-version-deps/lib?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {"project_name": "lib", "total_versions": 1},
            "total_dependants": 0,
            "versions": [{"version": "1.0", "dependant_count": 0, "is_internal": False, "dependants": []}],
        }
        with patch("appsec_data_views.routes.reports.get_falkordb_service", return_value=mock_service):
            response = client.get("/reports/multi-version-deps/lib?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "multi-version-deps"


class TestMultiVersionSourcesEndpoint:
    """Tests for /reports/multi-version-sources/<project>/<version>."""

    def _mock_service(self, result):
        mock = MagicMock()
        mock.find_multi_version_dependency_sources.return_value = result
        return mock

    def test_not_found_json(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service({"target": None, "multi_version_dependencies": []})
            response = client.get("/reports/multi-version-sources/proj/1.0?format=json")
            assert response.status_code == 404

    def test_not_found_html(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service({"target": None, "multi_version_dependencies": []})
            response = client.get("/reports/multi-version-sources/proj/1.0")
            assert response.status_code == 404

    def test_html_with_data(self, client):
        data = {
            "target": {"project_name": "proj", "version": "1.0", "scan_ids_count": 1},
            "multi_version_dependencies": [
                {"dependency_project": "lib", "version_count": 2,
                 "versions": [
                     {"version": "1.0", "contributing_applications": [{"project_name": "app", "version": "1.0"}],
                      "scan_ids_intersection": []},
                     {"version": "2.0", "contributing_applications": [], "scan_ids_intersection": []},
                 ]},
            ],
        }
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(data)
            response = client.get("/reports/multi-version-sources/proj/1.0")
            assert response.status_code == 200

    def test_excel_format(self, client):
        data = {
            "target": {"project_name": "p", "version": "1.0", "scan_ids_count": 0},
            "multi_version_dependencies": [],
        }
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service") as m,
            patch("appsec_data_views.routes.reports.create_multi_version_dependency_report_excel") as mock_excel,
        ):
            m.return_value = self._mock_service(data)
            mock_excel.return_value = BytesIO(b"excel")
            response = client.get("/reports/multi-version-sources/p/1.0?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        data = {
            "target": {"project_name": "p", "version": "1.0", "scan_ids_count": 0},
            "multi_version_dependencies": [],
        }
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(data)
            response = client.get("/reports/multi-version-sources/p/1.0?format=json")
            assert response.status_code == 200


class TestVersionDependenciesEndpoint:
    """Tests for /reports/version-dependencies/<project>/<version>."""

    def _mock_service(self, versions, deps, is_compliant=True, latest=None):
        mock = MagicMock()
        mock.is_project_semver_compliant.return_value = (is_compliant, [] if is_compliant else ["bad"])
        mock.get_latest_semver_version.return_value = latest
        mock.get_all_versions_of_project.return_value = versions
        mock.get_transitive_dependencies_for_report.return_value = deps
        return mock

    def test_html_with_data(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"], [{"depth": 1, "dependency_project": "lib", "dependency_version": "1.0", "is_internal": False}],
            )
            response = client.get("/reports/version-dependencies/proj/1.0.0")
            assert response.status_code == 200

    def test_project_not_found(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([], [])
            response = client.get("/reports/version-dependencies/none/1.0?format=json")
            assert response.status_code == 404

    def test_version_not_found(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(["1.0.0"], [])
            response = client.get("/reports/version-dependencies/proj/2.0.0?format=json")
            assert response.status_code == 404

    def test_latest_version_success(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0", "2.0.0"], [], is_compliant=True, latest="2.0.0",
            )
            response = client.get("/reports/version-dependencies/proj/latest")
            assert response.status_code == 200

    def test_latest_version_not_semver(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(["latest"], [], is_compliant=False)
            response = client.get("/reports/version-dependencies/proj/latest?format=json")
            assert response.status_code == 400

    def test_excel_format(self, client):
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service") as m,
            patch("appsec_data_views.exports.excel.create_version_dependencies_report_excel") as mock_excel,
        ):
            m.return_value = self._mock_service(
                ["1.0.0"], [{"depth": 1, "dependency_project": "lib", "dependency_version": "1.0", "is_internal": False}],
            )
            mock_excel.return_value = BytesIO(b"excel")
            response = client.get("/reports/version-dependencies/proj/1.0.0?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"], [{"depth": 1, "dependency_project": "lib", "dependency_version": "1.0", "is_internal": False}],
            )
            response = client.get("/reports/version-dependencies/proj/1.0.0?format=json")
            data = response.get_json()
            assert data["report_type"] == "version-dependencies"

    def test_json_format_no_dependencies(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(["1.0.0"], [])
            response = client.get("/reports/version-dependencies/proj/1.0.0?format=json")
            data = response.get_json()
            assert data["data"][0]["dependency_project"] == "(no dependencies)"


class TestDependantsEndpoint:
    """Tests for /reports/dependants/<project>/<version>."""

    def _mock_service(self, root_found=True, report_data=None):
        mock = MagicMock()
        mock.find_version.return_value = {"properties": {}, "labels": []} if root_found else None
        mock.get_dependants_with_partitions_and_paths.return_value = report_data or {
            "target": {"project_name": "lib", "version": "1.0", "labels": []},
            "stats": {"total_dependants": 0, "max_partition": 0, "unique_projects": 0},
            "dependants": [],
        }
        return mock

    def test_not_found_json(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(root_found=False)
            response = client.get("/reports/dependants/proj/1.0?format=json")
            assert response.status_code == 404

    def test_not_found_html(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service(root_found=False)
            response = client.get("/reports/dependants/proj/1.0")
            assert response.status_code == 404

    def test_html_with_data(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/dependants/proj/1.0")
            assert response.status_code == 200

    def test_excel_format(self, client):
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service") as m,
            patch("appsec_data_views.routes.reports.create_dependants_report_excel") as mock_excel,
        ):
            m.return_value = self._mock_service()
            mock_excel.return_value = BytesIO(b"excel")
            response = client.get("/reports/dependants/proj/1.0?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/dependants/proj/1.0?format=json")
            data = response.get_json()
            assert data["report_type"] == "dependants"


class TestCentralityEndpoint:
    """Tests for /reports/centrality."""

    def _mock_service(self, data=None):
        mock = MagicMock()
        mock.get_internal_centrality.return_value = data or []
        return mock

    def test_html_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([
                {"inDegree": 10, "outDegree": 5, "project_name": "lib",
                 "project_group": "g", "version_name": "1.0"},
            ])
            response = client.get("/reports/centrality")
            assert response.status_code == 200

    def test_excel_format(self, client):
        with (
            patch("appsec_data_views.routes.reports.get_falkordb_service") as m,
            patch("appsec_data_views.exports.excel.create_centrality_excel") as mock_excel,
        ):
            m.return_value = self._mock_service()
            mock_excel.return_value = BytesIO(b"excel")
            response = client.get("/reports/centrality?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/centrality?format=json")
            data = response.get_json()
            assert data["report_type"] == "centrality"

    def test_invalid_sort_by_defaults(self, client):
        with patch("appsec_data_views.routes.reports.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/centrality?sort_by=invalid")
            assert response.status_code == 200
