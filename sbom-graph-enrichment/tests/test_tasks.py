"""Unit tests for Celery tasks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sbom_graph_enrichment.certifiers.base import Finding, FindingKind
from sbom_graph_enrichment.tasks import (
    _persist_vulnerability,
    _persist_license,
    enrich_package,
    enrich_all_packages,
    compute_trust_score,
    propagate_effective_scores,
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

        with patch(
            "sbom_graph_enrichment.tasks.OSVCertifier"
        ) as mock_osv_cls:
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

            with patch(
                "sbom_graph_enrichment.tasks.LicenseCertifier"
            ) as mock_lic_cls:
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


class TestEnrichAllPackages:
    """Tests for the enrich_all_packages task."""

    @patch("sbom_graph_enrichment.tasks.enrich_package")
    def test_enrich_all_dispatches_batches(
        self, mock_enrich: MagicMock
    ) -> None:
        mock_pers = MagicMock()
        mock_pers.run_query.return_value = MagicMock(
            result_set=[
                {"purl": "pkg:npm/a@1"},
                {"purl": "pkg:npm/b@2"},
            ]
        )

        with patch(
            "sbom_graph_enrichment.tasks.create_persistence",
            return_value=mock_pers,
        ):
            result = enrich_all_packages.apply(args=[]).get()

        assert result["dispatched"] == 2
        assert mock_enrich.delay.call_count == 2


class TestComputeTrustScore:
    """Tests for the compute_trust_score task."""

    @patch("sbom_graph_enrichment.tasks.get_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", True)
    def test_compute_trust_score_persists(
        self, mock_get_pers: MagicMock
    ) -> None:
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

    @patch("sbom_graph_enrichment.tasks.create_persistence")
    @patch("sbom_graph_enrichment.tasks._TRUST_SCORE_ENABLED", True)
    def test_propagate_updates_scores(
        self, mock_create_pers: MagicMock
    ) -> None:
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
