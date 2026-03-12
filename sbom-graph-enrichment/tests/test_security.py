"""Security-focused tests for the enrichment pipeline.

Verifies that persistence functions use parameterised queries and safely
handle malicious or oversized payloads from external data sources.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sbom_graph_enrichment.certifiers.base import Finding, FindingKind
from sbom_graph_enrichment.tasks import (
    _persist_depsdev,
    _persist_eol,
    _persist_source_repo,
    enrich_package,
)


class TestPersistDepsdevInjection:
    """Verify _persist_depsdev uses parameterised queries for all inputs."""

    def test_cypher_injection_in_purl_passed_as_param(self) -> None:
        """Malicious PURL must be in params dict, not interpolated into query."""
        persistence = MagicMock()
        injection_purl = "pkg:npm/foo@1.0' RETURN 1 //"
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url=injection_purl,
            data={"advisory_count": 0, "licenses": []},
        )

        _persist_depsdev(persistence, finding)

        first_call = persistence.run_query.call_args_list[0]
        query = first_call.kwargs["query"]
        params = first_call.kwargs["params"]

        assert injection_purl not in query
        assert params["purl"] == injection_purl

    def test_extremely_long_purl_passed_as_param(self) -> None:
        """Very long PURL must be in params, not concatenated into query."""
        persistence = MagicMock()
        long_purl = "pkg:npm/" + "x" * 10000
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url=long_purl,
            data={"advisory_count": 0, "licenses": []},
        )

        _persist_depsdev(persistence, finding)

        first_call = persistence.run_query.call_args_list[0]
        query = first_call.kwargs["query"]
        params = first_call.kwargs["params"]

        assert long_purl not in query
        assert params["purl"] == long_purl

    def test_xss_payload_in_purl_passed_as_param(self) -> None:
        """HTML/XSS payload in PURL must be in params, not in query."""
        persistence = MagicMock()
        xss_purl = "pkg:npm/<script>alert(1)</script>@1.0"
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url=xss_purl,
            data={"advisory_count": 0, "licenses": []},
        )

        _persist_depsdev(persistence, finding)

        first_call = persistence.run_query.call_args_list[0]
        query = first_call.kwargs["query"]
        params = first_call.kwargs["params"]

        assert "<script>" not in query
        assert params["purl"] == xss_purl


class TestPersistDepsdevMaliciousPayloads:
    """Verify _persist_depsdev safely handles oversized or malformed payloads."""

    def test_large_licenses_list_handled(self) -> None:
        """Licenses with 1000 items must be json.dumps'd without crash."""
        persistence = MagicMock()
        large_licenses = [
            {"spdx_id": f"LIC-{i}", "url": f"https://example.com/{i}"}
            for i in range(1000)
        ]
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "licenses": large_licenses},
        )

        _persist_depsdev(persistence, finding)

        first_call = persistence.run_query.call_args_list[0]
        params = first_call.kwargs["params"]
        assert "licenses" in params
        assert isinstance(params["licenses"], str)
        assert "LIC-0" in params["licenses"]
        assert "LIC-999" in params["licenses"]

    def test_deeply_nested_scorecard_checks_handled(self) -> None:
        """Deeply nested scorecard_checks must be json.dumps'd without crash."""
        persistence = MagicMock()
        nested: dict = {}
        current = nested
        for i in range(50):
            current["level"] = i
            current["nested"] = {}
            current = current["nested"]
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={
                "advisory_count": 0,
                "scorecard_overall": 7.0,
                "scorecard_checks": nested,
            },
        )

        _persist_depsdev(persistence, finding)

        scorecard_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "checks" in c.kwargs.get("params", {})
        ]
        assert len(scorecard_calls) == 1
        checks_json = scorecard_calls[0].kwargs["params"]["checks"]
        assert isinstance(checks_json, str)
        assert '"level"' in checks_json

    def test_large_oss_fuzz_structure_handled(self) -> None:
        """Very large oss_fuzz nested structure must be handled."""
        persistence = MagicMock()
        large_oss_fuzz = {
            "fuzzed": True,
            "data": [{"id": i, "name": f"test-{i}"} for i in range(500)],
        }
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "oss_fuzz": large_oss_fuzz},
        )

        _persist_depsdev(persistence, finding)

        oss_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "oss_fuzz_json" in c.kwargs.get("params", {})
        ]
        assert len(oss_calls) == 1
        assert "test-0" in oss_calls[0].kwargs["params"]["oss_fuzz_json"]
        assert "test-499" in oss_calls[0].kwargs["params"]["oss_fuzz_json"]

    def test_extremely_long_project_key_passed_as_param(self) -> None:
        """Very long project_key must be in params."""
        persistence = MagicMock()
        long_key = "a" * 10000
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "project_key": long_key},
        )

        _persist_depsdev(persistence, finding)

        pk_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "project_key" in c.kwargs.get("params", {})
        ]
        assert len(pk_calls) == 1
        assert pk_calls[0].kwargs["params"]["project_key"] == long_key
        assert long_key not in pk_calls[0].kwargs["query"]

    def test_project_key_integer_passed_through(self) -> None:
        """Non-string project_key (int) must not crash persistence."""
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "project_key": 12345},
        )

        _persist_depsdev(persistence, finding)

        pk_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "project_key" in c.kwargs.get("params", {})
        ]
        assert len(pk_calls) == 1
        assert pk_calls[0].kwargs["params"]["project_key"] == 12345

    def test_project_key_list_passed_through(self) -> None:
        """Non-string project_key (list) must not crash persistence."""
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "project_key": ["a", "b"]},
        )

        _persist_depsdev(persistence, finding)

        pk_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "project_key" in c.kwargs.get("params", {})
        ]
        assert len(pk_calls) == 1
        assert pk_calls[0].kwargs["params"]["project_key"] == ["a", "b"]

    def test_project_key_dict_passed_through(self) -> None:
        """Non-string project_key (dict) must not crash persistence."""
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "project_key": {"key": "value"}},
        )

        _persist_depsdev(persistence, finding)

        pk_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "project_key" in c.kwargs.get("params", {})
        ]
        assert len(pk_calls) == 1
        assert pk_calls[0].kwargs["params"]["project_key"] == {"key": "value"}

    def test_advisory_count_string_passed_through(self) -> None:
        """advisory_count as string must not crash (caller validates)."""
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": "5", "licenses": []},
        )

        _persist_depsdev(persistence, finding)

        params = persistence.run_query.call_args_list[0].kwargs["params"]
        assert params["advisory_count"] == "5"

    def test_published_at_injection_passed_as_param(self) -> None:
        """published_at with injection-like string must be in params."""
        persistence = MagicMock()
        injection = "2024-01-01'; DROP NODE v; --"
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"advisory_count": 0, "published_at": injection, "licenses": []},
        )

        _persist_depsdev(persistence, finding)

        first_call = persistence.run_query.call_args_list[0]
        assert injection not in first_call.kwargs["query"]
        assert first_call.kwargs["params"]["published_at"] == injection


class TestPersistEolInjection:
    """Verify _persist_eol uses parameterised queries."""

    def test_cypher_injection_in_purl_passed_as_param(self) -> None:
        """Malicious PURL must be in params, not in query."""
        persistence = MagicMock()
        injection_purl = "pkg:pypi/python@3.12' OR 1=1 --"
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url=injection_purl,
            data={"eol": True, "product": "python", "cycle": "3.12"},
        )

        _persist_eol(persistence, finding)

        call_args = persistence.run_query.call_args
        query = call_args.kwargs["query"]
        params = call_args.kwargs["params"]

        assert injection_purl not in query
        assert params["purl"] == injection_purl

    def test_injection_in_product_and_cycle_passed_as_param(self) -> None:
        """EOL product/cycle with injection strings must be in params."""
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url="pkg:pypi/python@3.12",
            data={
                "eol": True,
                "product": "python'; DROP NODE v; --",
                "cycle": "3.12' RETURN 1 //",
            },
        )

        _persist_eol(persistence, finding)

        call_args = persistence.run_query.call_args
        query = call_args.kwargs["query"]
        params = call_args.kwargs["params"]

        assert "DROP NODE" not in query
        assert "RETURN 1" not in query
        assert params["product"] == "python'; DROP NODE v; --"
        assert params["cycle"] == "3.12' RETURN 1 //"


class TestPersistSourceRepoInjection:
    """Verify _persist_source_repo uses parameterised queries."""

    def test_javascript_url_passed_as_param(self) -> None:
        """javascript: URL must be in params, not executed."""
        persistence = MagicMock()
        js_url = "javascript:alert(1)"
        finding = Finding(
            kind=FindingKind.SOURCE_REPO,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"repo_url": js_url, "repo_host": ""},
        )

        _persist_source_repo(persistence, finding)

        call_args = persistence.run_query.call_args
        query = call_args.kwargs["query"]
        params = call_args.kwargs["params"]

        assert js_url not in query
        assert params["repo_url"] == js_url

    def test_very_long_repo_url_passed_as_param(self) -> None:
        """Very long repo_url must be in params."""
        persistence = MagicMock()
        long_url = "https://github.com/" + "x" * 10000
        finding = Finding(
            kind=FindingKind.SOURCE_REPO,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"repo_url": long_url, "repo_host": "github.com"},
        )

        _persist_source_repo(persistence, finding)

        call_args = persistence.run_query.call_args
        assert long_url not in call_args.kwargs["query"]
        assert call_args.kwargs["params"]["repo_url"] == long_url


class TestEnrichPackageMaliciousFindings:
    """Verify enrich_package passes malicious findings via parameterised queries."""

    def test_malicious_depsdev_finding_passed_to_persistence(self) -> None:
        """Findings with malicious data must reach persistence via params."""
        mock_pers = MagicMock()
        mock_client = MagicMock()
        malicious_purl = "pkg:npm/foo@1.0' OR '1'='1"
        malicious_finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url=malicious_purl,
            timestamp=datetime.now(timezone.utc),
            data={
                "advisory_count": 0,
                "licenses": [],
                "published_at": "'; DROP NODE v; --",
            },
        )

        mock_depsdev = MagicMock()
        mock_depsdev.enrich.return_value = [malicious_finding]

        with (
            patch(
                "sbom_graph_enrichment.tasks.get_http_client",
                return_value=mock_client,
            ),
            patch(
                "sbom_graph_enrichment.tasks.get_persistence",
                return_value=mock_pers,
            ),
            patch(
                "sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED",
                False,
            ),
            patch.dict(
                "sbom_graph_enrichment.tasks._CERTIFIERS",
                {"depsdev": MagicMock(return_value=mock_depsdev)},
                clear=True,
            ),
        ):
            result = enrich_package.apply(
                args=[malicious_purl],
                kwargs={"sources": ["depsdev"]},
            ).get()

        assert result["depsdev"] == 1
        for call in mock_pers.run_query.call_args_list:
            query = call.kwargs["query"]
            params = call.kwargs["params"]
            assert malicious_purl not in query
            assert "DROP NODE" not in query
            if "purl" in params:
                assert params["purl"] == malicious_purl
