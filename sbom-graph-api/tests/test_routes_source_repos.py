"""Tests for source repository API endpoints and reports."""

from io import BytesIO
from unittest.mock import MagicMock, patch


class TestSourceRepoPackages:
    """Tests for GET /api/v1/source/packages."""

    def test_400_when_repo_url_missing(self, client):
        """Request without repo_url returns 400."""
        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service"):
            response = client.get("/api/v1/source/packages")

        assert response.status_code == 400
        data = response.get_json()
        assert "repo_url" in data["error"].lower()

    def test_400_when_repo_url_too_long(self, client):
        """Request with repo_url exceeding 2048 chars returns 400."""
        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service"):
            response = client.get(
                "/api/v1/source/packages",
                query_string={"repo_url": "https://example.com/" + "x" * 2048},
            )

        assert response.status_code == 400
        data = response.get_json()
        assert "invalid" in data["error"].lower() or "repo_url" in data["error"].lower()

    def test_200_returns_packages_list(self, client):
        """Valid repo_url returns 200 with packages list."""
        mock_packages = [
            {"purl": "pkg:maven/org/foo@1.0", "project_name": "foo", "version": "1.0"},
        ]

        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_packages_by_source_repo.return_value = mock_packages
            mock_get_svc.return_value = mock_svc

            response = client.get(
                "/api/v1/source/packages",
                query_string={"repo_url": "https://github.com/org/repo"},
            )

        assert response.status_code == 200
        data = response.get_json()
        assert data["repo_url"] == "https://github.com/org/repo"
        assert data["packages"] == mock_packages
        assert data["count"] == 1


class TestSourceRepoVulnerabilities:
    """Tests for GET /api/v1/source/vulnerabilities."""

    def test_400_when_repo_url_missing(self, client):
        """Request without repo_url returns 400."""
        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service"):
            response = client.get("/api/v1/source/vulnerabilities")

        assert response.status_code == 400
        data = response.get_json()
        assert "repo_url" in data["error"].lower()

    def test_200_returns_vulnerabilities_list(self, client):
        """Valid repo_url returns 200 with vulnerabilities list."""
        mock_vulns = [
            {
                "defect_id": "CVE-2024-1234",
                "severity": "HIGH",
                "affected_purls": ["pkg:maven/org/foo@1.0"],
            },
        ]

        with patch("sbom_graph_api.routes.api_v1.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_vulnerabilities_by_source_repo.return_value = mock_vulns
            mock_get_svc.return_value = mock_svc

            response = client.get(
                "/api/v1/source/vulnerabilities",
                query_string={"repo_url": "https://github.com/org/repo"},
            )

        assert response.status_code == 200
        data = response.get_json()
        assert data["repo_url"] == "https://github.com/org/repo"
        assert data["vulnerabilities"] == mock_vulns
        assert data["count"] == 1


class TestSourceReposReport:
    """Tests for GET /reports/source-repos."""

    def test_200_html_response(self, client):
        """Default request returns 200 HTML."""
        mock_repos = [
            {
                "url": "https://github.com/org/repo",
                "vcs_type": "git",
                "namespace": "org",
                "name": "repo",
                "package_count": 5,
            },
        ]

        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_all_source_repos.return_value = mock_repos
            mock_get_svc.return_value = mock_svc

            response = client.get("/reports/source-repos")

        assert response.status_code == 200
        assert "text/html" in response.content_type
        assert b"Source Repositories" in response.data or b"source" in response.data.lower()

    def test_200_json_format_response(self, client):
        """Request with format=json returns 200 JSON."""
        mock_repos = [
            {
                "url": "https://github.com/org/repo",
                "vcs_type": "git",
                "namespace": "org",
                "name": "repo",
                "package_count": 5,
            },
        ]

        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_all_source_repos.return_value = mock_repos
            mock_svc.count_source_repos.return_value = 1
            mock_get_svc.return_value = mock_svc

            response = client.get(
                "/reports/source-repos",
                query_string={"format": "json"},
            )

        assert response.status_code == 200
        assert "application/json" in response.content_type
        data = response.get_json()
        # Phase 1: unified streamed JSON envelope (data + stats + report_type)
        assert "data" in data
        assert data["data"] == mock_repos
        assert data["stats"]["total_repositories"] == 1
        assert data["report_type"] == "source-repos"


class TestSourceImpactReport:
    """Tests for GET /reports/source-impact."""

    def test_400_when_repo_url_missing(self, client):
        """Request without repo_url returns 400."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service"):
            response = client.get("/reports/source-impact")

        assert response.status_code == 400
        data = response.get_json()
        assert "repo_url" in data["error"].lower() or "invalid" in data["error"].lower()

    def test_400_when_repo_url_invalid(self, client):
        """Request with invalid repo_url returns 400."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service"):
            response = client.get(
                "/reports/source-impact",
                query_string={"repo_url": "not-a-valid-url"},
            )

        assert response.status_code == 400
        data = response.get_json()
        assert "invalid" in data["error"].lower() or "repo_url" in data["error"].lower()

    def test_200_html_response(self, client):
        """Valid repo_url returns 200 HTML with source impact data."""
        mock_impact = {
            "packages": [
                {
                    "project_name": "foo",
                    "version": "1.0.0",
                    "direct_dependants": 2,
                    "transitive_dependants": 5,
                },
            ],
            "dependants": [],
            "affected_applications": [],
            "graph_nodes": [],
            "graph_edges": [],
            "stats": {
                "packages_from_repo": 1,
                "total_downstream_consumers": 0,
                "affected_applications": 0,
            },
        }

        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_source_repo_impact.return_value = mock_impact
            mock_get_svc.return_value = mock_svc

            response = client.get(
                "/reports/source-impact",
                query_string={"repo_url": "https://github.com/org/repo"},
            )

        assert response.status_code == 200
        assert "text/html" in response.content_type
        assert b"Source Impact" in response.data
        assert b"foo" in response.data
        mock_svc.get_source_repo_impact.assert_called_once()
        call_kw = mock_svc.get_source_repo_impact.call_args[1]
        assert call_kw["repo_url"] == "https://github.com/org/repo"

    def test_200_json_format_response(self, client):
        """Request with format=json returns 200 JSON."""
        mock_impact = {
            "packages": [],
            "dependants": [],
            "affected_applications": [],
            "graph_nodes": [],
            "graph_edges": [],
            "stats": {
                "packages_from_repo": 0,
                "total_downstream_consumers": 0,
                "affected_applications": 0,
            },
        }

        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_source_repo_impact.return_value = mock_impact
            mock_get_svc.return_value = mock_svc

            response = client.get(
                "/reports/source-impact",
                query_string={
                    "repo_url": "https://github.com/org/repo",
                    "format": "json",
                },
            )

        assert response.status_code == 200
        assert "application/json" in response.content_type
        data = response.get_json()
        assert data["report_type"] == "source-impact"
        assert data["repo_url"] == "https://github.com/org/repo"
        assert "packages" in data
        assert "stats" in data

    def test_200_excel_format_response(self, client):
        """Request with format=excel returns 200 Excel."""
        mock_impact = {
            "packages": [
                {
                    "project_name": "foo",
                    "version": "1.0.0",
                    "direct_dependants": 1,
                    "transitive_dependants": 2,
                },
            ],
            "stats": {
                "packages_from_repo": 1,
                "total_downstream_consumers": 3,
                "affected_applications": 1,
            },
        }

        with (
            patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get_svc,
            patch(
                "sbom_graph_api.routes.reports.inventory.create_source_impact_excel"
            ) as mock_excel,
        ):
            mock_svc = MagicMock()
            mock_svc.get_source_repo_impact.return_value = mock_impact
            mock_get_svc.return_value = mock_svc
            mock_excel.return_value = BytesIO(b"excel")

            response = client.get(
                "/reports/source-impact",
                query_string={
                    "repo_url": "https://github.com/org/repo",
                    "format": "excel",
                },
            )

        assert response.status_code == 200
        assert "spreadsheet" in response.content_type

    def test_graph_endpoint_400_when_repo_url_missing(self, client):
        """Graph endpoint without repo_url returns 400."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service"):
            response = client.get("/reports/source-impact/graph")

        assert response.status_code == 400

    def test_graph_endpoint_200_returns_html(self, client):
        """Graph endpoint with valid repo_url returns HTML visualization."""
        mock_impact = {
            "graph_nodes": [
                {"id": "repo:url", "label": "Source Repo", "type": "source_repo"},
                {"id": "pkg:1.0", "label": "pkg@1.0", "type": "package"},
            ],
            "graph_edges": [
                {"source": "repo:url", "target": "pkg:1.0", "type": "HAS_SOURCE"},
            ],
        }
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.get_source_repo_impact.return_value = mock_impact
            mock_get.return_value = mock_svc

            response = client.get(
                "/reports/source-impact/graph",
                query_string={"repo_url": "https://github.com/org/repo"},
            )

        assert response.status_code == 200
        assert "text/html" in response.content_type
        assert b"vis-network" in response.data or b"pyvis" in response.data

    def test_projects_includes_source_repo_url(self, client):
        """Projects report includes source_repo_url when linked."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as mock_get_svc:
            mock_svc = MagicMock()
            mock_svc.get_all_projects.return_value = [
                {
                    "project_name": "foo",
                    "version": "1.0.0",
                    "spdx_id": "MIT",
                    "risk_category": "permissive",
                    "source_repo_url": "https://github.com/org/foo",
                },
            ]
            mock_get_svc.return_value = mock_svc

            response = client.get("/reports/projects")

        assert response.status_code == 200
        assert b"https://github.com/org/foo" in response.data
