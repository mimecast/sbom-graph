"""Unit tests for Celery tasks."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sbom_graph_enrichment.certifiers.base import Finding, FindingKind
from sbom_graph_enrichment.tasks import (
    _persist_vulnerability,
    _persist_license,
    _persist_eol,
    _persist_source_repo,
    _persist_depsdev,
    enrich_package,
    enrich_all_packages,
    compute_trust_score,
    propagate_effective_scores,
    refresh_internal_centrality,
)


class TestPersistVulnerability:
    """Tests for the vulnerability persistence helper."""

    def test_creates_defect_and_links(self) -> None:
        persistence = MagicMock()
        persistence.get_versions_by_purl.return_value = [
            {"name": "1.0.0", "project_name": "my-lib", "project_group": "com.example"},
        ]

        finding = Finding(
            kind=FindingKind.VULNERABILITY,
            source="osv",
            package_url="pkg:maven/com.example/my-lib@1.0.0",
            data={
                "id": "CVE-2024-9999",
                "summary": "Remote code execution flaw",
                "severity": "high",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "aliases": ["GHSA-abcd-1234-efgh"],
            },
        )

        _persist_vulnerability(persistence, finding)

        persistence.create_defect.assert_called_once()
        defect_arg = persistence.create_defect.call_args.kwargs["defect"]
        assert defect_arg.id == "CVE-2024-9999"
        assert defect_arg.severity == "high"
        assert defect_arg.description == "Remote code execution flaw"
        assert defect_arg.aliases == ["GHSA-abcd-1234-efgh"]
        assert defect_arg.enrichment_source == "osv"
        assert defect_arg.last_enriched_at is not None

        persistence.get_versions_by_purl.assert_called_once_with(
            "pkg:maven/com.example/my-lib@1.0.0"
        )
        persistence.create_version_defect.assert_called_once()

    def test_creates_defect_with_enrichment_fields(self) -> None:
        persistence = MagicMock()
        persistence.get_versions_by_purl.return_value = [
            {"name": "1.0.0", "project_name": "my-lib", "project_group": "com.example"},
        ]

        finding = Finding(
            kind=FindingKind.VULNERABILITY,
            source="osv",
            package_url="pkg:maven/com.example/my-lib@1.0.0",
            data={
                "id": "CVE-2024-9999",
                "summary": "Remote code execution flaw",
                "severity": "critical",
                "aliases": ["GHSA-abcd-1234-efgh"],
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        )

        _persist_vulnerability(persistence, finding)

        defect_arg = persistence.create_defect.call_args.kwargs["defect"]
        assert defect_arg.description == "Remote code execution flaw"
        assert defect_arg.aliases == ["GHSA-abcd-1234-efgh"]
        assert defect_arg.enrichment_source == "osv"
        assert defect_arg.last_enriched_at is not None

    def test_persist_vulnerability_multiple_versions(self) -> None:
        persistence = MagicMock()
        persistence.get_versions_by_purl.return_value = [
            {"name": "1.0.0", "project_name": "lib", "project_group": "com.example"},
            {"name": "2.0.0", "project_name": "lib", "project_group": "com.example"},
        ]

        finding = Finding(
            kind=FindingKind.VULNERABILITY,
            source="osv",
            package_url="pkg:maven/com.example/lib@1.0.0",
            data={
                "id": "CVE-2024-1",
                "summary": "Bug",
                "severity": "medium",
                "aliases": [],
            },
        )

        _persist_vulnerability(persistence, finding)

        persistence.create_defect.assert_called_once()
        assert persistence.create_version_defect.call_count == 2


class TestPersistLicense:
    """Tests for the license persistence helper."""

    def test_creates_license_and_edge(self) -> None:
        persistence = MagicMock()

        finding = Finding(
            kind=FindingKind.LICENSE,
            source="clearlydefined",
            package_url="pkg:maven/com.example/my-lib@1.0.0",
            data={
                "spdx_id": "MIT",
                "name": "MIT",
                "risk_category": "permissive",
            },
        )

        _persist_license(persistence, finding)

        persistence.create_license.assert_called_once_with(
            spdx_id="MIT",
            name="MIT",
            risk_category="permissive",
        )
        persistence.create_version_license.assert_called_once_with(
            purl="pkg:maven/com.example/my-lib@1.0.0",
            spdx_id="MIT",
        )

    def test_persist_license_with_defaults(self) -> None:
        persistence = MagicMock()

        finding = Finding(
            kind=FindingKind.LICENSE,
            source="clearlydefined",
            package_url="pkg:npm/foo@1.0",
            data={"spdx_id": "MIT"},
        )

        _persist_license(persistence, finding)

        persistence.create_license.assert_called_once_with(
            spdx_id="MIT",
            name="MIT",
            risk_category="unknown",
        )
        persistence.create_version_license.assert_called_once_with(
            purl="pkg:npm/foo@1.0",
            spdx_id="MIT",
        )


class TestPersistEol:
    """Tests for the EOL persistence helper."""

    def test_basic_eol_persistence(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url="pkg:pypi/python@3.12.2",
            data={
                "eol": True,
                "eol_date": "2025-10-06",
                "product": "python",
                "cycle": "3.12",
            },
        )

        _persist_eol(persistence, finding)

        persistence.run_query.assert_called_once()
        call_args = persistence.run_query.call_args
        assert "MATCH (v:Version" in call_args.kwargs["query"]
        params = call_args.kwargs["params"]
        assert params["purl"] == "pkg:pypi/python@3.12.2"
        assert params["eol"] is True
        assert params["eol_date"] == "2025-10-06"
        assert params["product"] == "python"
        assert params["cycle"] == "3.12"

    def test_boolean_eol_true(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url="pkg:npm/foo@1.0",
            data={"eol": True, "product": "foo", "cycle": "1"},
        )

        _persist_eol(persistence, finding)

        params = persistence.run_query.call_args.kwargs["params"]
        assert params["eol"] is True

    def test_boolean_eol_false(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url="pkg:npm/foo@1.0",
            data={"eol": False, "product": "foo", "cycle": "1"},
        )

        _persist_eol(persistence, finding)

        params = persistence.run_query.call_args.kwargs["params"]
        assert params["eol"] is False

    def test_string_eol_not_false(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url="pkg:npm/foo@1.0",
            data={"eol": "2025-01-01", "eol_date": "2025-01-01", "product": "foo"},
        )

        _persist_eol(persistence, finding)

        params = persistence.run_query.call_args.kwargs["params"]
        assert params["eol"] is True
        assert params["eol_date"] == "2025-01-01"

    def test_string_eol_false(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.EOL,
            source="endoflife.date",
            package_url="pkg:npm/foo@1.0",
            data={"eol": "false", "product": "foo", "cycle": "1"},
        )

        _persist_eol(persistence, finding)

        params = persistence.run_query.call_args.kwargs["params"]
        assert params["eol"] is False


class TestPersistSourceRepo:
    """Tests for the source repository persistence helper."""

    def test_basic_persistence(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.SOURCE_REPO,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={
                "repo_url": "https://github.com/owner/repo",
                "repo_host": "github.com",
            },
        )

        _persist_source_repo(persistence, finding)

        persistence.run_query.assert_called_once()
        params = persistence.run_query.call_args.kwargs["params"]
        assert params["repo_url"] == "https://github.com/owner/repo"
        assert params["host"] == "github.com"
        assert params["purl"] == "pkg:npm/foo@1.0"

    def test_no_repo_url_early_return(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.SOURCE_REPO,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"repo_host": "github.com"},
        )

        _persist_source_repo(persistence, finding)

        persistence.run_query.assert_not_called()

    def test_empty_repo_url_early_return(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.SOURCE_REPO,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={"repo_url": "", "repo_host": "github.com"},
        )

        _persist_source_repo(persistence, finding)

        persistence.run_query.assert_not_called()


class TestPersistDepsdev:
    """Tests for the deps.dev persistence helper."""

    def test_basic_metadata_persistence(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/lodash@4.17.21",
            data={
                "advisory_count": 1,
                "published_at": "2021-02-20T00:00:00Z",
                "is_default": True,
                "licenses": ["MIT"],
            },
        )

        _persist_depsdev(persistence, finding)

        call_count = persistence.run_query.call_count
        assert call_count >= 1
        first_call = persistence.run_query.call_args_list[0]
        params = first_call.kwargs["params"]
        assert params["purl"] == "pkg:npm/lodash@4.17.21"
        assert params["advisory_count"] == 1
        assert params["published_at"] == "2021-02-20T00:00:00Z"
        assert params["is_default"] is True
        assert params["licenses"] == '["MIT"]'

    def test_scorecard_creation_when_present(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/express@4.18.2",
            data={
                "advisory_count": 0,
                "scorecard_overall": 7.2,
                "scorecard_checks": {"Maintained": 10, "Code-Review": 6},
            },
        )

        _persist_depsdev(persistence, finding)

        assert persistence.run_query.call_count >= 2
        calls = [c.kwargs["query"] for c in persistence.run_query.call_args_list]
        assert any("Scorecard" in q or "HAS_SCORECARD" in q for q in calls)

    def test_oss_fuzz_persistence_when_present(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={
                "advisory_count": 0,
                "oss_fuzz": {"fuzzed": True},
            },
        )

        _persist_depsdev(persistence, finding)

        oss_fuzz_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "oss_fuzz_json" in c.kwargs.get("params", {})
        ]
        assert len(oss_fuzz_calls) == 1
        assert oss_fuzz_calls[0].kwargs["params"]["oss_fuzz_json"] == '{"fuzzed": true}'

    def test_project_key_persistence(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/foo@1.0",
            data={
                "advisory_count": 0,
                "project_key": "github.com/owner/repo",
            },
        )

        _persist_depsdev(persistence, finding)

        project_key_calls = [
            c
            for c in persistence.run_query.call_args_list
            if "project_key" in c.kwargs.get("params", {})
        ]
        assert len(project_key_calls) == 1
        assert (
            project_key_calls[0].kwargs["params"]["project_key"]
            == "github.com/owner/repo"
        )

    def test_minimal_data_no_optional_fields(self) -> None:
        persistence = MagicMock()
        finding = Finding(
            kind=FindingKind.DEPSDEV,
            source="depsdev",
            package_url="pkg:npm/minimal@1.0",
            data={},
        )

        _persist_depsdev(persistence, finding)

        persistence.run_query.assert_called_once()
        params = persistence.run_query.call_args.kwargs["params"]
        assert params["advisory_count"] == 0
        assert params["published_at"] == ""
        assert params["is_default"] is False
        assert params["licenses"] == "[]"


class TestEnrichPackage:
    """Tests for the enrich_package task."""

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_persists_vulns_and_licenses(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client

        mock_pers = MagicMock()
        mock_pers.get_versions_by_purl.return_value = [
            {"name": "1.0", "project_name": "x", "project_group": "com.example"},
        ]
        mock_get_pers.return_value = mock_pers

        with patch("sbom_graph_enrichment.tasks.OSVCertifier") as mock_osv_cls:
            mock_osv = MagicMock()
            mock_osv.enrich.return_value = [
                Finding(
                    kind=FindingKind.VULNERABILITY,
                    source="osv",
                    package_url="pkg:maven/com.example/x@1.0",
                    data={"id": "CVE-1", "severity": "high"},
                ),
            ]
            mock_osv_cls.return_value = mock_osv

            with patch("sbom_graph_enrichment.tasks.LicenseCertifier") as mock_lic_cls:
                mock_lic = MagicMock()
                mock_lic.enrich.return_value = [
                    Finding(
                        kind=FindingKind.LICENSE,
                        source="clearlydefined",
                        package_url="pkg:maven/com.example/x@1.0",
                        data={"spdx_id": "MIT", "name": "MIT"},
                    ),
                ]
                mock_lic_cls.return_value = mock_lic

                with patch.dict(
                    "sbom_graph_enrichment.tasks._CERTIFIERS",
                    {"osv": mock_osv_cls, "clearlydefined": mock_lic_cls},
                    clear=False,
                ):
                    result = enrich_package.apply(
                        args=["pkg:maven/com.example/x@1.0"],
                        kwargs={"sources": ["osv", "clearlydefined"]},
                    ).get()

        assert result["purl"] == "pkg:maven/com.example/x@1.0"
        assert result["vulnerabilities"] == 1
        assert result["licenses"] == 1
        mock_pers.create_defect.assert_called_once()
        mock_pers.create_license.assert_called_once()

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_sources_defaults_to_all(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_cert = MagicMock()
        mock_cert.enrich.return_value = []

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"osv": MagicMock(return_value=mock_cert)},
            clear=True,
        ):
            result = enrich_package.apply(
                args=["pkg:maven/com.example/x@1.0"],
            ).get()

        assert result["purl"] == "pkg:maven/com.example/x@1.0"
        mock_cert.enrich.assert_called_once()

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_skips_unknown_certifier(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {},
            clear=True,
        ):
            result = enrich_package.apply(
                args=["pkg:npm/foo@1.0"],
                kwargs={"sources": ["unknown"]},
            ).get()

        assert result["vulnerabilities"] == 0
        assert result["licenses"] == 0

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_persists_eol(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_eol = MagicMock()
        mock_eol.enrich.return_value = [
            Finding(
                kind=FindingKind.EOL,
                source="endoflife.date",
                package_url="pkg:pypi/python@3.12.2",
                data={"eol": True, "product": "python", "cycle": "3.12"},
            ),
        ]

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"eol": MagicMock(return_value=mock_eol)},
            clear=True,
        ):
            result = enrich_package.apply(
                args=["pkg:pypi/python@3.12.2"],
                kwargs={"sources": ["eol"]},
            ).get()

        assert result["eol"] == 1
        mock_pers.run_query.assert_called()

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_persists_source_repo(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_sr = MagicMock()
        mock_sr.enrich.return_value = [
            Finding(
                kind=FindingKind.SOURCE_REPO,
                source="depsdev",
                package_url="pkg:npm/foo@1.0",
                data={
                    "repo_url": "https://github.com/owner/repo",
                    "repo_host": "github.com",
                },
            ),
        ]

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"source_repo": MagicMock(return_value=mock_sr)},
            clear=True,
        ):
            result = enrich_package.apply(
                args=["pkg:npm/foo@1.0"],
                kwargs={"sources": ["source_repo"]},
            ).get()

        assert result["source_repo"] == 1
        mock_pers.run_query.assert_called()

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_persists_depsdev(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_dd = MagicMock()
        mock_dd.enrich.return_value = [
            Finding(
                kind=FindingKind.DEPSDEV,
                source="depsdev",
                package_url="pkg:npm/lodash@4.17.21",
                data={"advisory_count": 1, "licenses": ["MIT"]},
            ),
        ]

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"depsdev": MagicMock(return_value=mock_dd)},
            clear=True,
        ):
            result = enrich_package.apply(
                args=["pkg:npm/lodash@4.17.21"],
                kwargs={"sources": ["depsdev"]},
            ).get()

        assert result["depsdev"] == 1
        mock_pers.run_query.assert_called()

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    @patch("sbom_graph_enrichment.tasks.enrich_package.retry")
    def test_enrich_package_certifier_exception_retries(
        self,
        mock_retry: MagicMock,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_retry.side_effect = RuntimeError("retry")

        mock_cert = MagicMock()
        mock_cert.enrich.side_effect = RuntimeError("API unavailable")

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"osv": MagicMock(return_value=mock_cert)},
            clear=True,
        ):
            task = enrich_package.apply(
                args=["pkg:npm/foo@1.0"],
                kwargs={"sources": ["osv"]},
            )
            try:
                task.get()
            except RuntimeError as e:
                if "retry" not in str(e):
                    raise
            mock_retry.assert_called_once()

    @patch("sbom_graph_enrichment.tasks.compute_trust_score")
    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", True)
    def test_enrich_package_dispatches_trust_score_when_enabled(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
        mock_compute: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_get_http.return_value = mock_client
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_cert = MagicMock()
        mock_cert.enrich.return_value = [
            Finding(
                kind=FindingKind.LICENSE,
                source="clearlydefined",
                package_url="pkg:npm/foo@1.0",
                data={"spdx_id": "MIT"},
            ),
        ]

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"clearlydefined": MagicMock(return_value=mock_cert)},
            clear=True,
        ):
            result = enrich_package.apply(
                args=["pkg:npm/foo@1.0"],
                kwargs={"sources": ["clearlydefined"]},
            ).get()

        assert result["licenses"] == 1
        mock_compute.delay.assert_called_once()
        call_args = mock_compute.delay.call_args
        assert call_args[0][0] == "pkg:npm/foo@1.0"
        findings_data = call_args[0][1]
        assert len(findings_data) == 1
        assert findings_data[0]["kind"] == "license"

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_stamps_last_enriched_at(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        """A successful run must write last_enriched_at on the Version node.

        This timestamp is what `enrich_all_packages` uses to skip
        recently-enriched packages, so its absence would cause the
        beat fan-out to re-queue the entire graph every tick.
        """
        mock_get_http.return_value = MagicMock()
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_cert = MagicMock()
        mock_cert.enrich.return_value = []  # no findings is still a success

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"osv": MagicMock(return_value=mock_cert)},
            clear=True,
        ):
            enrich_package.apply(
                args=["pkg:maven/com.example/x@1.0"],
                kwargs={"sources": ["osv"]},
            ).get()

        stamp_calls = [
            call
            for call in mock_pers.run_query.call_args_list
            if "last_enriched_at" in call.kwargs.get("query", "")
        ]
        assert len(stamp_calls) == 1
        params = stamp_calls[0].kwargs["params"]
        assert params["purl"] == "pkg:maven/com.example/x@1.0"
        ts = datetime.fromisoformat(params["ts"])
        assert ts <= datetime.now(timezone.utc)

    @patch("sbom_graph_enrichment.tasks.get_http_client")
    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_enrich_package_does_not_stamp_on_retry(
        self,
        mock_get_pers: MagicMock,
        mock_get_http: MagicMock,
    ) -> None:
        """When a certifier raises, self.retry fires and the stamp must be skipped.

        Otherwise a transient failure would mark the package fresh and
        the next beat tick would not pick it up to retry the failed
        certifier.
        """
        mock_get_http.return_value = MagicMock()
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        mock_cert = MagicMock()
        mock_cert.enrich.side_effect = RuntimeError("network down")

        with patch.dict(
            "sbom_graph_enrichment.tasks._CERTIFIERS",
            {"osv": MagicMock(return_value=mock_cert)},
            clear=True,
        ):
            # The task swallows the retry into a Retry exception under
            # eager mode -- we only care that the timestamp was not
            # written, not how the failure surfaces to the caller.
            try:
                enrich_package.apply(
                    args=["pkg:maven/com.example/x@1.0"],
                    kwargs={"sources": ["osv"]},
                ).get()
            except Exception:  # noqa: BLE001 - Celery Retry or RuntimeError
                pass

        stamp_calls = [
            call
            for call in mock_pers.run_query.call_args_list
            if "last_enriched_at" in call.kwargs.get("query", "")
        ]
        assert stamp_calls == []


class TestEnrichAllPackages:
    """Tests for the enrich_all_packages task."""

    @patch("sbom_graph_enrichment.tasks.enrich_package")
    def test_enrich_all_dispatches_batches(self, mock_enrich: MagicMock) -> None:
        mock_pers = MagicMock()
        mock_pers.run_query.return_value = MagicMock(
            result_set=[
                {"purl": "pkg:npm/a@1"},
                {"purl": "pkg:npm/b@2"},
            ]
        )

        with patch(
            "sbom_graph_enrichment.tasks.get_persistence",
            return_value=mock_pers,
        ):
            result = enrich_all_packages.apply(args=[]).get()

        assert result["dispatched"] == 2
        assert mock_enrich.delay.call_count == 2

    @patch("sbom_graph_enrichment.tasks.enrich_package")
    def test_enrich_all_filters_recently_enriched_by_default(
        self, mock_enrich: MagicMock
    ) -> None:
        """Default beat invocation must query with last_enriched_at cutoff."""
        mock_pers = MagicMock()
        mock_pers.run_query.return_value = MagicMock(
            result_set=[{"purl": "pkg:npm/stale@1"}],
        )

        with patch(
            "sbom_graph_enrichment.tasks.get_persistence",
            return_value=mock_pers,
        ):
            result = enrich_all_packages.apply(args=[]).get()

        call = mock_pers.run_query.call_args
        assert "last_enriched_at" in call.kwargs["query"]
        assert "cutoff" in call.kwargs["params"]
        # Cutoff should be a parseable ISO-8601 timestamp in the past.
        cutoff = datetime.fromisoformat(call.kwargs["params"]["cutoff"])
        assert cutoff < datetime.now(timezone.utc)

        assert result == {"dispatched": 1, "force": False}
        mock_enrich.delay.assert_called_once_with("pkg:npm/stale@1", None)

    @patch("sbom_graph_enrichment.tasks.enrich_package")
    def test_enrich_all_force_bypasses_filter(self, mock_enrich: MagicMock) -> None:
        """force=True must run the unfiltered query and dispatch all purls."""
        mock_pers = MagicMock()
        mock_pers.run_query.return_value = MagicMock(
            result_set=[
                {"purl": "pkg:npm/a@1"},
                {"purl": "pkg:npm/b@2"},
            ],
        )

        with patch(
            "sbom_graph_enrichment.tasks.get_persistence",
            return_value=mock_pers,
        ):
            result = enrich_all_packages.apply(kwargs={"force": True}).get()

        call = mock_pers.run_query.call_args
        assert "last_enriched_at" not in call.kwargs["query"]
        assert call.kwargs["params"] == {}
        assert result == {"dispatched": 2, "force": True}
        assert mock_enrich.delay.call_count == 2


class TestComputeTrustScore:
    """Tests for the compute_trust_score task."""

    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", True)
    def test_compute_trust_score_persists(self, mock_get_pers: MagicMock) -> None:
        mock_pers = MagicMock()
        mock_get_pers.return_value = mock_pers

        findings_data = [
            {
                "kind": "scorecard",
                "source": "scorecard",
                "package_url": "pkg:npm/foo@1.0",
                "data": {"checks": {"Code-Review": 8}},
            },
        ]

        result = compute_trust_score.apply(
            args=["pkg:npm/foo@1.0"],
            kwargs={"findings_data": findings_data},
        ).get()

        assert result["purl"] == "pkg:npm/foo@1.0"
        assert "direct_score" in result
        assert "confidence" in result
        mock_pers.create_trust_score.assert_called_once()
        mock_pers.link_version_to_trust_score.assert_called_once()

    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_compute_trust_score_skipped_when_disabled(self) -> None:
        result = compute_trust_score.apply(
            args=["pkg:npm/foo@1.0"],
            kwargs={"findings_data": []},
        ).get()

        assert result["purl"] == "pkg:npm/foo@1.0"
        assert result["skipped"] is True


class TestPropagateEffectiveScores:
    """Tests for the propagate_effective_scores task."""

    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", True)
    def test_propagate_updates_scores(self, mock_create_pers: MagicMock) -> None:
        mock_pers = MagicMock()
        mock_pers.get_all_trust_scores.return_value = [
            {"purl": "pkg:npm/leaf@1", "direct_score": 4.0},
            {"purl": "pkg:npm/root@1", "direct_score": 8.0},
        ]
        mock_pers.get_dependency_graph_for_propagation.return_value = [
            {"parent_purl": "pkg:npm/root@1", "child_purl": "pkg:npm/leaf@1"},
        ]
        mock_create_pers.return_value = mock_pers

        result = propagate_effective_scores.apply(args=[]).get()

        assert result["updated"] == 2
        assert mock_pers.update_trust_score_propagation.call_count == 2

    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", False)
    def test_propagate_skipped_when_disabled(self) -> None:
        result = propagate_effective_scores.apply(args=[]).get()
        assert result["skipped"] is True

    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", True)
    @patch.dict("os.environ", {"TRUST_SCORE_ALERT_THRESHOLD": "5.0"}, clear=False)
    def test_propagate_with_low_score_alerts(self, mock_create_pers: MagicMock) -> None:
        mock_pers = MagicMock()
        mock_pers.get_all_trust_scores.return_value = [
            {"purl": "pkg:npm/low@1", "direct_score": 2.0},
            {"purl": "pkg:npm/high@1", "direct_score": 8.0},
        ]
        mock_pers.get_dependency_graph_for_propagation.return_value = []
        mock_create_pers.return_value = mock_pers

        with patch("sbom_graph_enrichment.tasks.logger") as mock_logger:
            result = propagate_effective_scores.apply(args=[]).get()

        assert result["updated"] == 2
        assert result["alerts"] >= 1
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0]
        assert "below threshold" in call_args[0]


class TestRefreshInternalCentrality:
    """Tests for scheduled internal degree centrality refresh."""

    @patch("sbom_graph_enrichment.tasks.get_persistence")
    def test_calls_persistence_with_internal_label_from_env(
        self,
        mock_get_persistence: MagicMock,
    ) -> None:
        mock_pers = MagicMock()
        mock_get_persistence.return_value = mock_pers

        with patch.dict(
            "os.environ",
            {"FALKORDB_INTERNAL_LABEL": "INTERNAL"},
            clear=False,
        ):
            result = refresh_internal_centrality.apply(args=[]).get()

        assert result["status"] == "ok"
        assert result["internal_label"] == "INTERNAL"
        mock_pers.refresh_internal_degree_centrality.assert_called_once_with(
            internal_label="INTERNAL",
        )
