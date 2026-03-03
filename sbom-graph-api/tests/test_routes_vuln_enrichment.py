"""Unit tests for vulnerability enrichment routes."""

import sys
from unittest.mock import MagicMock, patch


class TestPackageVulnerabilities:
    """Tests for GET /api/v1/package/<purl>/vulns."""

    def test_returns_direct_vulns(self, client) -> None:
        """Direct vulnerabilities are returned with correct structure."""
        mock_service = MagicMock()
        mock_service.get_package_vulnerabilities.return_value = {
            "package": "pkg:maven/org.example/lib@1.0",
            "vulnerabilities": [
                {
                    "id": "CVE-2024-1",
                    "severity": "high",
                    "cvss": 8.1,
                    "cvss_vector": "CVSS:3.1/...",
                    "description": "Test",
                    "aliases": ["GHSA-xxx"],
                    "source": "osv",
                    "last_enriched_at": "2024-06-01T00:00:00Z",
                },
            ],
            "count": 1,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/api/v1/package/pkg:maven/org.example/lib@1.0/vulns")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["vulnerabilities"][0]["id"] == "CVE-2024-1"

    def test_include_dependencies(self, client) -> None:
        """Transitive vulnerabilities are included when requested."""
        mock_service = MagicMock()
        mock_service.get_package_vulnerabilities.return_value = {
            "package": "pkg:maven/org.example/lib@1.0",
            "vulnerabilities": [],
            "count": 0,
            "transitive_vulnerabilities": [
                {
                    "package": "pkg:maven/dep/a@1.0",
                    "id": "CVE-2024-2",
                    "severity": "medium",
                    "description": "dep vuln",
                    "aliases": [],
                    "source": "osv",
                },
            ],
            "transitive_count": 1,
        }

        with patch(
            "sbom_graph_api.routes.api_v1.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/api/v1/package/pkg:maven/org.example/lib@1.0/vulns"
                "?include_dependencies=true"
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["transitive_count"] == 1
        mock_service.get_package_vulnerabilities.assert_called_once_with(
            "pkg:maven/org.example/lib@1.0", include_dependencies=True
        )

    def test_invalid_purl_returns_400(self, client) -> None:
        """PURL without pkg: prefix returns 400."""
        resp = client.get("/api/v1/package/not-a-purl/vulns")
        assert resp.status_code == 400

    def test_empty_purl_returns_400(self, client) -> None:
        """Empty PURL path returns 400 or 404."""
        resp = client.get("/api/v1/package//vulns")
        assert resp.status_code in (400, 404)


class TestTriggerEnrichment:
    """Tests for POST /api/v1/enrich/vulnerabilities."""

    def test_enrich_specific_purls(self, client) -> None:
        """Enrichment with specific purls dispatches per-package tasks."""
        mock_tasks = MagicMock()
        mock_tasks.enrich_package = MagicMock()
        mock_tasks.enrich_package.delay = MagicMock()
        mock_tasks.enrich_all_packages = MagicMock()

        mock_enrichment = MagicMock()
        mock_enrichment.tasks = mock_tasks

        with patch.dict(
            sys.modules,
            {
                "sbom_graph_enrichment": mock_enrichment,
                "sbom_graph_enrichment.tasks": mock_tasks,
            },
        ):
            resp = client.post(
                "/api/v1/enrich/vulnerabilities",
                json={"purls": ["pkg:maven/org.example/lib@1.0"]},
                content_type="application/json",
            )

        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "accepted"
        assert data["dispatched"] == 1

    def test_enrich_all_when_no_purls(self, client) -> None:
        """Enrichment with no purls dispatches enrich_all_packages task."""
        mock_task = MagicMock()
        mock_task.id = "task-123"
        mock_tasks = MagicMock()
        mock_tasks.enrich_package = MagicMock()
        mock_tasks.enrich_all_packages = MagicMock()
        mock_tasks.enrich_all_packages.delay = MagicMock(return_value=mock_task)

        mock_enrichment = MagicMock()
        mock_enrichment.tasks = mock_tasks

        with patch.dict(
            sys.modules,
            {
                "sbom_graph_enrichment": mock_enrichment,
                "sbom_graph_enrichment.tasks": mock_tasks,
            },
        ):
            resp = client.post(
                "/api/v1/enrich/vulnerabilities",
                json={},
                content_type="application/json",
            )

        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "accepted"
        assert data["task_id"] == "task-123"

    def test_invalid_purls_type(self, client) -> None:
        """Non-list purls returns 400."""
        mock_tasks = MagicMock()
        mock_enrichment = MagicMock()
        mock_enrichment.tasks = mock_tasks

        with patch.dict(
            sys.modules,
            {
                "sbom_graph_enrichment": mock_enrichment,
                "sbom_graph_enrichment.tasks": mock_tasks,
            },
        ):
            resp = client.post(
                "/api/v1/enrich/vulnerabilities",
                json={"purls": "not-a-list"},
                content_type="application/json",
            )
        assert resp.status_code == 400

    def test_enrichment_unavailable_returns_503(self, client) -> None:
        """When enrichment module is not available, returns 503."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "sbom_graph_enrichment":
                raise ImportError("No module named 'sbom_graph_enrichment'")
            return real_import(name, *args, **kwargs)  # type: ignore[misc]

        with patch.object(builtins, "__import__", side_effect=mock_import):
            resp = client.post(
                "/api/v1/enrich/vulnerabilities",
                json={},
                content_type="application/json",
            )
        assert resp.status_code == 503


class TestVulnerabilityFreshness:
    """Tests for GET /reports/vulnerability-freshness."""

    def test_json_format(self, client) -> None:
        """JSON format returns stats and data."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_freshness.return_value = [
            {
                "project_group": "com.example",
                "project_name": "my-lib",
                "version_name": "1.0",
                "purl": "pkg:maven/com.example/my-lib@1.0",
                "last_enriched_at": "2024-06-01T00:00:00Z",
            },
            {
                "project_group": "com.example",
                "project_name": "my-app",
                "version_name": "2.0",
                "purl": "pkg:maven/com.example/my-app@2.0",
                "last_enriched_at": None,
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-freshness?format=json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["stats"]["total_packages"] == 2
        assert data["stats"]["never_enriched"] == 1

    def test_html_format(self, client) -> None:
        """HTML format returns table page."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_freshness.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-freshness")

        assert resp.status_code == 200
        assert b"Vulnerability Enrichment Freshness" in resp.data

    def test_internal_only(self, client) -> None:
        """internal_only filter is passed to service."""
        mock_service = MagicMock()
        mock_service.get_vulnerability_freshness.return_value = []

        with patch(
            "sbom_graph_api.routes.reports.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get(
                "/reports/vulnerability-freshness?internal_only=true&format=json"
            )

        assert resp.status_code == 200
        mock_service.get_vulnerability_freshness.assert_called_once_with(
            internal_only=True
        )
