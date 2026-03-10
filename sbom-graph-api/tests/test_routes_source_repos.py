"""Tests for source repository API endpoints and reports."""

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
            mock_get_svc.return_value = mock_svc

            response = client.get(
                "/reports/source-repos",
                query_string={"format": "json"},
            )

        assert response.status_code == 200
        assert "application/json" in response.content_type
        data = response.get_json()
        assert "data" in data
        assert data["data"] == mock_repos
        assert data["total"] == 1
        assert "report_type" in data
        assert data["report_type"] == "source-repos"
