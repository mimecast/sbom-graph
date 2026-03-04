"""Unit tests for Celery tasks."""

from __future__ import annotations

from unittest.mock import MagicMock

from sbom_graph_enrichment.certifiers.base import Finding, FindingKind
from sbom_graph_enrichment.tasks import _persist_vulnerability, _persist_license


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
