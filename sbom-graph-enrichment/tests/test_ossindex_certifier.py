"""Unit tests for the Sonatype OSS Index certifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from sbom_graph_enrichment.certifiers.base import FindingKind
from sbom_graph_enrichment.certifiers.ossindex import (
    OSSIndexCertifier,
    enrich_batch,
    _score_to_severity,
)


def _mock_response(
    status_code: int, json_data: list | dict | None = None
) -> httpx.Response:
    request = httpx.Request("POST", "https://test.example.com")
    return httpx.Response(status_code, json=json_data, request=request)


class TestOSSIndexCertifier:
    """Tests for the OSSIndexCertifier."""

    def test_name(self) -> None:
        assert OSSIndexCertifier().name == "ossindex"

    @patch("sbom_graph_enrichment.certifiers.ossindex._bucket")
    @patch("sbom_graph_enrichment.certifiers.ossindex._get_auth", return_value=None)
    def test_enrich_returns_vulnerabilities(
        self, mock_auth: MagicMock, mock_bucket: MagicMock
    ) -> None:
        api_response = [
            {
                "coordinates": "pkg:maven/org.example/lib@1.0",
                "vulnerabilities": [
                    {
                        "id": "sonatype-2024-001",
                        "displayName": "CVE-2024-001",
                        "title": "Test vuln",
                        "description": "A test vulnerability",
                        "cvssScore": 7.5,
                        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe": "CWE-79",
                        "reference": "https://ossindex.sonatype.org/...",
                    }
                ],
            }
        ]
        mock_response = _mock_response(200, api_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        certifier = OSSIndexCertifier()
        findings = certifier.enrich("pkg:maven/org.example/lib@1.0", client=mock_client)

        assert len(findings) == 1
        assert findings[0].kind == FindingKind.OSSINDEX
        assert findings[0].source == "ossindex"
        assert findings[0].data["cvss_score"] == 7.5
        assert findings[0].data["severity"] == "high"

    @patch("sbom_graph_enrichment.certifiers.ossindex._bucket")
    @patch("sbom_graph_enrichment.certifiers.ossindex._get_auth", return_value=None)
    def test_enrich_no_vulns(
        self, mock_auth: MagicMock, mock_bucket: MagicMock
    ) -> None:
        api_response = [
            {"coordinates": "pkg:maven/org.example/safe@1.0", "vulnerabilities": []}
        ]
        mock_response = _mock_response(200, api_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        certifier = OSSIndexCertifier()
        findings = certifier.enrich(
            "pkg:maven/org.example/safe@1.0", client=mock_client
        )

        assert findings == []


class TestEnrichBatch:
    """Tests for the batch enrichment function."""

    @patch("sbom_graph_enrichment.certifiers.ossindex._bucket")
    @patch("sbom_graph_enrichment.certifiers.ossindex._get_auth", return_value=None)
    def test_batch_multiple_purls(
        self, mock_auth: MagicMock, mock_bucket: MagicMock
    ) -> None:
        api_response = [
            {
                "coordinates": "pkg:npm/foo@1.0",
                "vulnerabilities": [
                    {"id": "vuln-1", "cvssScore": 9.1, "displayName": "CVE-9"},
                ],
            },
            {"coordinates": "pkg:npm/bar@2.0", "vulnerabilities": []},
        ]
        mock_response = _mock_response(200, api_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        findings = enrich_batch(
            ["pkg:npm/foo@1.0", "pkg:npm/bar@2.0"], client=mock_client
        )

        assert len(findings) == 1
        assert findings[0].data["severity"] == "critical"

    def test_empty_purls(self) -> None:
        mock_client = MagicMock(spec=httpx.Client)
        findings = enrich_batch([], client=mock_client)
        assert findings == []
        mock_client.post.assert_not_called()

    @patch("sbom_graph_enrichment.certifiers.ossindex._bucket")
    @patch(
        "sbom_graph_enrichment.certifiers.ossindex._get_auth",
        return_value=("user", "token"),
    )
    def test_uses_auth_when_available(
        self, mock_auth: MagicMock, mock_bucket: MagicMock
    ) -> None:
        api_response = [{"coordinates": "pkg:npm/x@1", "vulnerabilities": []}]
        mock_response = _mock_response(200, api_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = mock_response

        enrich_batch(["pkg:npm/x@1"], client=mock_client)

        call_kwargs = mock_client.post.call_args
        assert call_kwargs.kwargs.get("auth") == ("user", "token")


class TestScoreToSeverity:
    """Tests for CVSS score to severity mapping."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (None, "unknown"),
            (0.0, "none"),
            (2.5, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (10.0, "critical"),
        ],
    )
    def test_mapping(self, score: float | None, expected: str) -> None:
        assert _score_to_severity(score) == expected
