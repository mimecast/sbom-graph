"""Extended tests for report routes - covering uncovered endpoints and formats."""

from unittest.mock import MagicMock, patch


class TestApplicationsEndpoint:
    """Tests for /reports/applications endpoint."""

    def _mock_service(self, return_value):
        mock_service = MagicMock()
        mock_service.get_all_applications.return_value = return_value
        mock_service.count_all_applications.return_value = len(return_value)
        mock_service.count_unique_applications.return_value = len(
            {a.get("project_name") for a in return_value}
        )
        return mock_service

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                [
                    {
                        "project_name": "app-a",
                        "version": "1.0.0",
                        "scan_id": "s1",
                        "public_id": "p1",
                        "repo_url": "https://git",
                        "is_internal": True,
                    },
                ]
            )
            response = client.get("/reports/applications")
            assert response.status_code == 200
            assert b"app-a" in response.data

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/applications?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                [
                    {
                        "project_name": "app-a",
                        "version": "1.0.0",
                        "scan_id": "s1",
                        "public_id": None,
                        "repo_url": None,
                        "is_internal": False,
                    },
                ]
            )
            response = client.get("/reports/applications?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "applications"

    def test_latest_only_param(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/applications?latest_only=true")
            assert response.status_code == 200

    def test_name_filter(self, client):
        """The name query param is threaded to the applications service."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/applications?name=svc")
            assert response.status_code == 200
            _, kwargs = m.return_value.get_all_applications.call_args
            assert kwargs.get("name") == "svc"
            assert "nameSearch" in response.data.decode("utf-8")

    def test_provenance_columns(self, client):
        """Applications HTML exposes Group, PURL, and derived Language columns."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                [
                    {
                        "project_name": "app-a",
                        "version": "1.0.0",
                        "scan_id": "s1",
                        "public_id": "p1",
                        "repo_url": "https://git",
                        "is_internal": True,
                        "project_group": "com.example",
                        "package_url": "pkg:maven/com.example/app-a@1.0.0",
                        "language": "Java",
                    },
                ]
            )
            response = client.get("/reports/applications")
            html = response.data.decode("utf-8")
            assert "Group" in html
            assert "PURL" in html
            assert "Language" in html
            assert "com.example" in html
            assert "pkg:maven/com.example/app-a@1.0.0" in html
            assert "Java" in html


class TestDuplicateNodesEndpoint:
    """Tests for /reports/duplicate-nodes endpoint."""

    def _row(self):
        return {
            "project_name": "foo",
            "version": "1.0.0",
            "distinct_coordinates": 2,
            "total_nodes": 3,
            "max_node_count": 2,
            "is_genuine_duplicate": True,
            "is_provenance_split": True,
            "classification": "Duplicate + provenance split",
            "project_groups": ["com.example", "org.other"],
            "package_urls": [
                "pkg:maven/com.example/foo@1.0.0",
                "pkg:maven/org.other/foo@1.0.0",
            ],
        }

    def _mock_service(self, rows):
        m = MagicMock()
        m.find_duplicate_version_nodes.return_value = rows
        m.count_duplicate_version_nodes.return_value = len(rows)
        m.get_duplicate_node_stats.return_value = {
            "affected_groups": len(rows),
            "provenance_splits": len(rows),
            "genuine_duplicates": len(rows),
        }
        return m

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/duplicate-nodes")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "foo" in html
            assert "Classification" in html
            assert "Duplicate + provenance split" in html

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/duplicate-nodes?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "duplicate-nodes"
            assert data["stats"]["affected_groups"] == 1
            assert data["stats"]["provenance_splits"] == 1
            assert data["stats"]["genuine_duplicates"] == 1
            assert data["data"][0]["classification"] == "Duplicate + provenance split"

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/duplicate-nodes?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type

    def test_empty(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/duplicate-nodes")
            assert response.status_code == 200
            assert b"No data found" in response.data


class TestBipartiteReportEndpoint:
    """Tests for /reports/bipartite/<project_name> endpoint."""

    def _mock_service(self):
        m = MagicMock()
        m.get_target_version_recency.return_value = ("2.0.0", "1.5.0")
        m.get_direct_dependants.return_value = [
            {
                "dependant_project": "app-x",
                "dependant_version": "9.9.9",
                "target_project": "lib",
                "target_version": "2.0.0",
            },
            {
                "dependant_project": "app-y",
                "dependant_version": "8.8.8",
                "target_project": "lib",
                "target_version": "1.0.0",
            },
        ]
        return m

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/bipartite/lib")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "Is Latest" in html
            assert "Is Latest-or-(Latest-1)" in html
            assert "app-x" in html

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/bipartite/lib?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "bipartite"
            rows = {r["dependant_project"]: r for r in data["data"]}
            assert rows["app-x"]["is_latest"] is True
            assert rows["app-x"]["is_latest_or_prev"] is True
            assert rows["app-y"]["is_latest"] is False
            assert rows["app-y"]["is_latest_or_prev"] is False

    def test_recency_filter_latest(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/bipartite/lib?format=json&recency=latest")
            data = response.get_json()
            assert [r["dependant_project"] for r in data["data"]] == ["app-x"]

    def test_name_filter(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/bipartite/lib?format=json&name=app-x")
            data = response.get_json()
            assert [r["dependant_project"] for r in data["data"]] == ["app-x"]

    def test_recency_filter_not_latest_or_prev(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get(
                "/reports/bipartite/lib?format=json&recency=not_latest_or_prev"
            )
            data = response.get_json()
            assert [r["dependant_project"] for r in data["data"]] == ["app-y"]

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/bipartite/lib?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type

    def test_invalid_project_name(self, client):
        response = client.get("/reports/bipartite/" + "%20")
        assert response.status_code in (400, 404)


class TestNonSemverEndpoint:
    """Tests for /reports/non-semver-versions endpoint."""

    def _mock_service(self, data):
        mock = MagicMock()
        mock.find_non_semver_versions.return_value = data
        return mock

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                [
                    {
                        "project_name": "proj",
                        "version": "1.0.0-SNAPSHOT",
                        "reason": "SNAPSHOT build (unreleased)",
                        "semver_compliant": True,
                        "released": False,
                        "labels": ["Version"],
                    },
                ]
            )
            response = client.get("/reports/non-semver-versions")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "SemVer Compliant" in html
            assert "Released" in html

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/non-semver-versions?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                [
                    {"project_name": "p", "version": "x", "reason": "r", "labels": []},
                ]
            )
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
            "versions": [
                {
                    "version": "1.0",
                    "dependant_count": 1,
                    "is_internal": False,
                    "dependants": [
                        {
                            "project_name": "app",
                            "version": "1.0",
                            "project_group": "",
                            "is_internal": False,
                        }
                    ],
                }
            ],
        }
        with patch(
            "sbom_graph_api.routes.reports.dependencies.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/multi-version-deps/my-lib")
            assert response.status_code == 200

    def test_not_found_json(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {},
            "total_dependants": 0,
            "versions": [],
        }
        with patch(
            "sbom_graph_api.routes.reports.dependencies.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/multi-version-deps/nonexistent?format=json")
            assert response.status_code == 404

    def test_not_found_html(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {},
            "total_dependants": 0,
            "versions": [],
        }
        with patch(
            "sbom_graph_api.routes.reports.dependencies.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/multi-version-deps/nonexistent")
            assert response.status_code == 404

    def test_excel_format(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {"project_name": "lib", "total_versions": 1},
            "total_dependants": 0,
            "versions": [
                {"version": "1.0", "dependant_count": 0, "is_internal": False, "dependants": []}
            ],
        }
        with patch(
            "sbom_graph_api.routes.reports.dependencies.get_falkordb_service",
            return_value=mock_service,
        ):
            response = client.get("/reports/multi-version-deps/lib?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        mock_service = MagicMock()
        mock_service.get_library_version_usage.return_value = {
            "library": {"project_name": "lib", "total_versions": 1},
            "total_dependants": 0,
            "versions": [
                {"version": "1.0", "dependant_count": 0, "is_internal": False, "dependants": []}
            ],
        }
        with patch(
            "sbom_graph_api.routes.reports.dependencies.get_falkordb_service",
            return_value=mock_service,
        ):
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
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service({"target": None, "multi_version_dependencies": []})
            response = client.get("/reports/multi-version-sources/proj/1.0?format=json")
            assert response.status_code == 404

    def test_not_found_html(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service({"target": None, "multi_version_dependencies": []})
            response = client.get("/reports/multi-version-sources/proj/1.0")
            assert response.status_code == 404

    def test_html_with_data(self, client):
        data = {
            "target": {"project_name": "proj", "version": "1.0", "scan_ids_count": 1},
            "multi_version_dependencies": [
                {
                    "dependency_project": "lib",
                    "version_count": 2,
                    "versions": [
                        {
                            "version": "1.0",
                            "contributing_applications": [
                                {"project_name": "app", "version": "1.0"}
                            ],
                            "scan_ids_intersection": [],
                        },
                        {
                            "version": "2.0",
                            "contributing_applications": [],
                            "scan_ids_intersection": [],
                        },
                    ],
                },
            ],
        }
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(data)
            response = client.get("/reports/multi-version-sources/proj/1.0")
            assert response.status_code == 200

    def test_excel_format(self, client):
        data = {
            "target": {"project_name": "p", "version": "1.0", "scan_ids_count": 0},
            "multi_version_dependencies": [],
        }
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(data)
            response = client.get("/reports/multi-version-sources/p/1.0?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        data = {
            "target": {"project_name": "p", "version": "1.0", "scan_ids_count": 0},
            "multi_version_dependencies": [],
        }
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(data)
            response = client.get("/reports/multi-version-sources/p/1.0?format=json")
            assert response.status_code == 200


class TestVersionDependenciesEndpoint:
    """Tests for /reports/version-dependencies/<project>/<version>."""

    def _mock_service(self, versions, deps, is_compliant=True, latest=None):
        mock = MagicMock()
        mock.is_project_semver_compliant.return_value = (
            is_compliant,
            [] if is_compliant else ["bad"],
        )
        mock.get_latest_semver_version.return_value = latest
        mock.get_all_versions_of_project.return_value = versions
        mock.get_transitive_dependencies_for_report.return_value = deps
        return mock

    def test_html_with_data(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"],
                [
                    {
                        "depth": 1,
                        "dependency_project": "lib",
                        "dependency_version": "1.0",
                        "is_internal": False,
                    }
                ],
            )
            response = client.get("/reports/version-dependencies/proj/1.0.0")
            assert response.status_code == 200

    def test_project_not_found(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([], [])
            response = client.get("/reports/version-dependencies/none/1.0?format=json")
            assert response.status_code == 404

    def test_version_not_found(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(["1.0.0"], [])
            response = client.get("/reports/version-dependencies/proj/2.0.0?format=json")
            assert response.status_code == 404

    def test_latest_version_success(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0", "2.0.0"],
                [],
                is_compliant=True,
                latest="2.0.0",
            )
            response = client.get("/reports/version-dependencies/proj/latest")
            assert response.status_code == 200

    def test_latest_version_not_semver(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(["latest"], [], is_compliant=False)
            response = client.get("/reports/version-dependencies/proj/latest?format=json")
            assert response.status_code == 400

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"],
                [
                    {
                        "depth": 1,
                        "dependency_project": "lib",
                        "dependency_version": "1.0",
                        "is_internal": False,
                    }
                ],
            )
            response = client.get("/reports/version-dependencies/proj/1.0.0?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"],
                [
                    {
                        "depth": 1,
                        "dependency_project": "lib",
                        "dependency_version": "1.0",
                        "is_internal": False,
                    }
                ],
            )
            response = client.get("/reports/version-dependencies/proj/1.0.0?format=json")
            data = response.get_json()
            assert data["report_type"] == "version-dependencies"

    def test_json_format_no_dependencies(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(["1.0.0"], [])
            response = client.get("/reports/version-dependencies/proj/1.0.0?format=json")
            data = response.get_json()
            assert data["data"][0]["dependency_project"] == "(no dependencies)"

    def test_name_filter(self, client):
        """The name param filters the listed dependencies by project name."""
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"],
                [
                    {"depth": 1, "dependency_project": "alpha", "dependency_version": "1.0",
                     "is_internal": False},
                    {"depth": 1, "dependency_project": "beta", "dependency_version": "2.0",
                     "is_internal": False},
                ],
            )
            response = client.get(
                "/reports/version-dependencies/proj/1.0.0?format=json&name=alpha"
            )
            data = response.get_json()
            assert [d["dependency_project"] for d in data["data"]] == ["alpha"]

    def test_name_search_box_renders(self, client):
        """HTML view renders a prefilled name search box."""
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                ["1.0.0"],
                [{"depth": 1, "dependency_project": "alpha", "dependency_version": "1.0",
                  "is_internal": False}],
            )
            response = client.get("/reports/version-dependencies/proj/1.0.0?name=alpha")
            html = response.data.decode("utf-8")
            assert "nameSearch" in html
            assert 'value="alpha"' in html


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
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(root_found=False)
            response = client.get("/reports/dependants/proj/1.0?format=json")
            assert response.status_code == 404

    def test_not_found_html(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service(root_found=False)
            response = client.get("/reports/dependants/proj/1.0")
            assert response.status_code == 404

    def test_html_with_data(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/dependants/proj/1.0")
            assert response.status_code == 200

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/dependants/proj/1.0?format=excel")
            assert response.status_code == 200

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/dependants/proj/1.0?format=json")
            data = response.get_json()
            assert data["report_type"] == "dependants"

    def test_name_filter_threaded_and_search_box_renders(self, client):
        """The name param reaches the service and the HTML shows a prefilled search box."""
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/dependants/proj/1.0?name=app-a")
            assert response.status_code == 200
            call_kwargs = m.return_value.get_dependants_with_partitions_and_paths.call_args.kwargs
            assert call_kwargs.get("name") == "app-a"
            html = response.data.decode("utf-8")
            assert "nameSearch" in html
            assert 'value="app-a"' in html


class TestCentralityEndpoint:
    """Tests for /reports/centrality."""

    def _mock_service(self, data=None):
        mock = MagicMock()
        mock.get_internal_centrality.return_value = data or []
        return mock

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                [
                    {
                        "inDegree": 10,
                        "outDegree": 5,
                        "project_name": "lib",
                        "project_group": "g",
                        "version_name": "1.0",
                    },
                ]
            )
            response = client.get("/reports/centrality")
            assert response.status_code == 200

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service()
            response = client.get("/reports/centrality?format=excel")
            assert response.status_code == 200
            assert "spreadsheet" in response.content_type or "excel" in response.content_type

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/centrality?format=json")
            data = response.get_json()
            assert data["report_type"] == "centrality"

    def test_invalid_sort_by_defaults(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/centrality?sort_by=invalid")
            assert response.status_code == 200


class TestEcosystemBreakdownEndpoint:
    """Tests for /reports/ecosystem-breakdown endpoint."""

    def _row(self):
        return {
            "ecosystem": "maven",
            "language": "Java",
            "components": 6,
            "projects": 3,
            "pct": 60.0,
        }

    def _mock_service(self, rows):
        m = MagicMock()
        m.get_ecosystem_breakdown.return_value = rows
        m.count_ecosystems.return_value = len(rows)
        return m

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/ecosystem-breakdown")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "maven" in html
            assert "Java" in html
            assert "Ecosystem" in html

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/ecosystem-breakdown?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "ecosystem-breakdown"
            assert data["stats"]["ecosystems"] == 1
            assert data["data"][0]["language"] == "Java"

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/ecosystem-breakdown?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type

    def test_empty(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/ecosystem-breakdown")
            assert response.status_code == 200
            assert b"No data found" in response.data


class TestPurlCoverageEndpoint:
    """Tests for /reports/purl-coverage endpoint."""

    def _mock_service(self, coverage):
        m = MagicMock()
        m.get_purl_coverage.return_value = coverage
        return m

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                {"total": 10, "with_purl": 7, "without_purl": 3}
            )
            response = client.get("/reports/purl-coverage")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "package_url" in html
            assert "Fallback" in html

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                {"total": 10, "with_purl": 7, "without_purl": 3}
            )
            response = client.get("/reports/purl-coverage?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "purl-coverage"
            assert data["stats"]["coverage_pct"] == 70.0
            assert data["stats"]["with_purl"] == 7
            assert len(data["data"]) == 2

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service(
                {"total": 0, "with_purl": 0, "without_purl": 0}
            )
            response = client.get("/reports/purl-coverage?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type


class TestUnreleasedInProdEndpoint:
    """Tests for /reports/unreleased-in-prod endpoint."""

    def _row(self):
        return {
            "application": "appA",
            "application_version": "1.0",
            "dependency": "libx",
            "dependency_version": "1.0.0-SNAPSHOT",
            "reason": "SNAPSHOT build (unreleased)",
        }

    def _mock_service(self, rows):
        m = MagicMock()
        m.get_unreleased_in_production.return_value = rows
        m.count_unreleased_in_production.return_value = len(rows)
        return m

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/unreleased-in-prod")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "appA" in html
            assert "SNAPSHOT" in html

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/unreleased-in-prod?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "unreleased-in-prod"
            assert data["stats"]["unreleased_in_use"] == 1
            assert data["data"][0]["application"] == "appA"

    def test_empty(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/unreleased-in-prod")
            assert response.status_code == 200
            assert b"No data found" in response.data


class TestDependencyFreshnessEndpoint:
    """Tests for /reports/dependency-freshness endpoint."""

    def _row(self):
        return {
            "target_project": "libx",
            "latest": "3.0.0",
            "prev": "2.0.0",
            "consumers": 10,
            "on_latest": 5,
            "on_latest_or_prev": 8,
            "stale": 2,
            "pct_stale": 20.0,
        }

    def _mock_service(self, rows):
        m = MagicMock()
        m.get_dependency_freshness.return_value = rows
        m.count_dependency_freshness.return_value = len(rows)
        return m

    def test_html_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/dependency-freshness")
            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "libx" in html
            assert "% Stale" in html

    def test_json_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/dependency-freshness?format=json")
            assert response.status_code == 200
            data = response.get_json()
            assert data["report_type"] == "dependency-freshness"
            assert data["stats"]["libraries"] == 1
            assert data["data"][0]["target_project"] == "libx"
            assert data["data"][0]["stale"] == 2

    def test_excel_format(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/dependency-freshness?format=excel")
            assert response.status_code == 200
            assert "spreadsheetml" in response.content_type

    def test_empty(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as m:
            m.return_value = self._mock_service([])
            response = client.get("/reports/dependency-freshness")
            assert response.status_code == 200
            assert b"No data found" in response.data


class TestPaginationMetadataHeader:
    """X-Total-Count header on paged report responses (gap #5)."""

    def _mock_service(self, rows):
        m = MagicMock()
        m.get_ecosystem_breakdown.return_value = rows
        m.count_ecosystems.return_value = 42  # distinct from len(rows)
        return m

    def _row(self):
        return {
            "ecosystem": "maven",
            "language": "Java",
            "components": 6,
            "projects": 3,
            "pct": 60.0,
        }

    def test_html_has_total_count_header(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/ecosystem-breakdown")
            assert response.status_code == 200
            assert response.headers.get("X-Total-Count") == "42"

    def test_json_has_total_count_header(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/ecosystem-breakdown?format=json")
            assert response.status_code == 200
            assert response.headers.get("X-Total-Count") == "42"

    def test_excel_has_total_count_header(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as m:
            m.return_value = self._mock_service([self._row()])
            response = client.get("/reports/ecosystem-breakdown?format=excel")
            assert response.status_code == 200
            assert response.headers.get("X-Total-Count") == "42"
