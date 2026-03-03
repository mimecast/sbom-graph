"""Unit tests for enrichment certifiers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from sbom_graph_enrichment.certifiers.base import FindingKind
from sbom_graph_enrichment.certifiers.osv import OSVCertifier
from sbom_graph_enrichment.certifiers.license import (
    LicenseCertifier,
    classify_license,
    _purl_to_coordinates,
)


def _mock_response(status_code: int, json_data: dict | None = None) -> httpx.Response:
    """Build an httpx.Response with a request attached so raise_for_status works."""
    request = httpx.Request("GET", "https://test.example.com")
    resp = httpx.Response(status_code, json=json_data, request=request)
    return resp


class TestOSVCertifier:
    """Tests for the OSV.dev certifier."""

    def test_name(self) -> None:
        assert OSVCertifier().name == "osv"

    @patch("sbom_graph_enrichment.certifiers.osv._bucket")
    def test_enrich_returns_vulnerabilities(self, mock_bucket: MagicMock) -> None:
        osv_response = {
            "vulns": [
                {
                    "id": "GHSA-1234-5678-abcd",
                    "summary": "Test vulnerability",
                    "aliases": ["CVE-2024-12345"],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                },
                {
                    "id": "OSV-2024-999",
                    "summary": "Another vuln",
                    "aliases": [],
                    "database_specific": {"severity": "LOW"},
                },
            ]
        }

        mock_response = _mock_response(200, osv_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        certifier = OSVCertifier()
        findings = certifier.enrich("pkg:maven/org.example/lib@1.0.0", client=mock_client)

        assert len(findings) == 2
        assert findings[0].kind == FindingKind.VULNERABILITY
        assert findings[0].source == "osv"
        assert findings[0].data["id"] == "GHSA-1234-5678-abcd"
        assert findings[0].data["aliases"] == ["CVE-2024-12345"]
        assert findings[1].data["id"] == "OSV-2024-999"

    @patch("sbom_graph_enrichment.certifiers.osv._bucket")
    def test_enrich_no_vulns(self, mock_bucket: MagicMock) -> None:
        mock_response = _mock_response(200, {"vulns": []})
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        certifier = OSVCertifier()
        findings = certifier.enrich("pkg:maven/org.example/safe@1.0.0", client=mock_client)

        assert findings == []


class TestLicenseCertifier:
    """Tests for the ClearlyDefined certifier."""

    def test_name(self) -> None:
        assert LicenseCertifier().name == "clearlydefined"

    def test_enrich_returns_licenses(self) -> None:
        cd_response = {
            "licensed": {
                "declared": "MIT",
                "discovered": {"expressions": ["MIT", "Apache-2.0"]},
            }
        }

        mock_response = _mock_response(200, cd_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        certifier = LicenseCertifier()
        findings = certifier.enrich("pkg:maven/org.apache/commons-lang3@3.12.0", client=mock_client)

        assert len(findings) == 2
        spdx_ids = {f.data["spdx_id"] for f in findings}
        assert spdx_ids == {"MIT", "Apache-2.0"}
        assert all(f.kind == FindingKind.LICENSE for f in findings)

    def test_enrich_404_returns_empty(self) -> None:
        mock_response = _mock_response(404)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        certifier = LicenseCertifier()
        findings = certifier.enrich("pkg:maven/unknown/pkg@0.0.1", client=mock_client)

        assert findings == []


class TestPurlToCoordinates:
    """Tests for purl-to-ClearlyDefined coordinate conversion."""

    def test_maven(self) -> None:
        assert _purl_to_coordinates("pkg:maven/org.apache/commons-lang3@3.12.0") == \
            "maven/mavencentral/org.apache/commons-lang3/3.12.0"

    def test_npm_scoped(self) -> None:
        assert _purl_to_coordinates("pkg:npm/%40angular/core@16.0.0") == \
            "npm/npmjs/%40angular/core/16.0.0"

    def test_pypi(self) -> None:
        assert _purl_to_coordinates("pkg:pypi/-/requests@2.31.0") == \
            "pypi/pypi/-/requests/2.31.0"

    def test_unsupported_type(self) -> None:
        assert _purl_to_coordinates("pkg:deb/debian/curl@7.88.1") is None

    def test_invalid_purl(self) -> None:
        assert _purl_to_coordinates("not-a-purl") is None


class TestClassifyLicense:
    """Tests for SPDX-to-risk-category classification."""

    @pytest.mark.parametrize("spdx_id,expected", [
        ("MIT", "permissive"),
        ("Apache-2.0", "permissive"),
        ("LGPL-3.0-only", "weak_copyleft"),
        ("MPL-2.0", "weak_copyleft"),
        ("GPL-3.0-only", "strong_copyleft"),
        ("AGPL-3.0-only", "strong_copyleft"),
        ("SSPL-1.0", "strong_copyleft"),
        ("CustomLicense-1.0", "unknown"),
    ])
    def test_classify(self, spdx_id: str, expected: str) -> None:
        assert classify_license(spdx_id) == expected
