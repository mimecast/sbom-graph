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
                "/api/v1/package/pkg:maven/org.example/lib@1.0/vulns?include_dependencies=true"
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

    def test_empty_purl_returns_error(self, client) -> None:
        """Empty PURL path (double slash) returns 404 after redirect."""
        resp = client.get("/api/v1/package//vulns", follow_redirects=True)
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
        """When the enrichment package can't be imported the route returns 503.

        The route does ``from sbom_graph_enrichment.tasks import ...`` inside
        a ``try``.  Patching ``builtins.__import__`` does NOT reliably
        intercept this form because Python's import machinery short-circuits
        for already-loaded submodules.  We instead clear the relevant entries
        from ``sys.modules`` and install a ``MetaPathFinder`` that refuses
        the package -- the same shape Python uses internally to express a
        missing dependency, which is what production hits when the
        enrichment image isn't deployed.
        """
        # Drop any pre-loaded copies so the route's import attempt actually
        # exercises the meta-path finder we install below.
        preloaded = {
            name: sys.modules.pop(name)
            for name in list(sys.modules)
            if name == "sbom_graph_enrichment"
            or name.startswith("sbom_graph_enrichment.")
        }

        class _RefuseEnrichmentFinder:
            """Meta-path finder that simulates the package being absent."""

            def find_spec(
                self, fullname: str, _path: object = None, _target: object = None
            ) -> None:
                if (
                    fullname == "sbom_graph_enrichment"
                    or fullname.startswith("sbom_graph_enrichment.")
                ):
                    raise ImportError(
                        f"No module named {fullname!r} (test fixture)"
                    )
                return None

        finder = _RefuseEnrichmentFinder()
        sys.meta_path.insert(0, finder)
        try:
            resp = client.post(
                "/api/v1/enrich/vulnerabilities",
                json={},
                content_type="application/json",
            )
        finally:
            sys.meta_path.remove(finder)
            # Restore any modules we evicted so the rest of the test suite
            # keeps its expected import cache.
            sys.modules.update(preloaded)

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
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
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
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
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
            "sbom_graph_api.routes.reports.vulnerabilities.get_falkordb_service",
            return_value=mock_service,
        ):
            resp = client.get("/reports/vulnerability-freshness?internal_only=true&format=json")

        assert resp.status_code == 200
        mock_service.get_vulnerability_freshness.assert_called_once_with(internal_only=True)
