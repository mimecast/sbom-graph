"""Unit tests for the deps.dev certifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from sbom_graph_enrichment.certifiers.base import FindingKind
from sbom_graph_enrichment.certifiers.depsdev import (
    DepsDevCertifier,
    purl_to_depsdev_params,
)


def _mock_response(status_code: int, json_data: dict | list | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://test.example.com")
    return httpx.Response(status_code, json=json_data, request=request)


class TestPurlToDepsdevParams:
    """Tests for PURL-to-deps.dev system mapping."""

    def test_maven(self) -> None:
        result = purl_to_depsdev_params("pkg:maven/org.apache/commons@3.12.0")
        assert result == {"system": "MAVEN", "package": "org.apache:commons", "version": "3.12.0"}

    def test_npm_unscoped(self) -> None:
        result = purl_to_depsdev_params("pkg:npm/-/lodash@4.17.21")
        assert result == {"system": "NPM", "package": "lodash", "version": "4.17.21"}

    def test_npm_scoped(self) -> None:
        result = purl_to_depsdev_params("pkg:npm/%40angular/core@16.0.0")
        assert result == {"system": "NPM", "package": "%40angular/core", "version": "16.0.0"}

    def test_pypi(self) -> None:
        result = purl_to_depsdev_params("pkg:pypi/-/requests@2.31.0")
        assert result == {"system": "PYPI", "package": "requests", "version": "2.31.0"}

    def test_nuget(self) -> None:
        result = purl_to_depsdev_params("pkg:nuget/-/Newtonsoft.Json@13.0.1")
        assert result == {"system": "NUGET", "package": "Newtonsoft.Json", "version": "13.0.1"}

    def test_cargo(self) -> None:
        result = purl_to_depsdev_params("pkg:cargo/-/serde@1.0.0")
        assert result == {"system": "CARGO", "package": "serde", "version": "1.0.0"}

    def test_golang(self) -> None:
        result = purl_to_depsdev_params("pkg:golang/github.com%2Forg/repo@v1.0.0")
        assert result == {"system": "GO", "package": "github.com%2Forg/repo", "version": "v1.0.0"}

    def test_unsupported_type(self) -> None:
        assert purl_to_depsdev_params("pkg:deb/debian/curl@7.88.1") is None

    def test_invalid_purl(self) -> None:
        assert purl_to_depsdev_params("not-a-purl") is None


class TestDepsDevCertifier:
    """Tests for the DepsDevCertifier."""

    def test_name(self) -> None:
        assert DepsDevCertifier().name == "depsdev"

    @patch("sbom_graph_enrichment.certifiers.depsdev._bucket")
    def test_enrich_returns_finding(self, mock_bucket: MagicMock) -> None:
        version_response = {
            "versionKey": {"system": "NPM", "name": "lodash", "version": "4.17.21"},
            "publishedAt": "2021-02-20T00:00:00Z",
            "isDefault": True,
            "licenses": ["MIT"],
            "advisoryKeys": [{"id": "GHSA-xxx"}],
            "links": [],
        }
        mock_resp = _mock_response(200, version_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = DepsDevCertifier()
        findings = certifier.enrich("pkg:npm/-/lodash@4.17.21", client=mock_client)

        assert len(findings) == 1
        assert findings[0].kind == FindingKind.DEPSDEV
        assert findings[0].source == "depsdev"
        assert findings[0].data["advisory_count"] == 1
        assert findings[0].data["published_at"] == "2021-02-20T00:00:00Z"

    @patch("sbom_graph_enrichment.certifiers.depsdev._bucket")
    def test_enrich_with_project_data(self, mock_bucket: MagicMock) -> None:
        version_response = {
            "versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"},
            "publishedAt": "2022-10-08T00:00:00Z",
            "isDefault": False,
            "licenses": ["MIT"],
            "advisoryKeys": [],
            "links": [
                {"label": "SOURCE_REPO", "url": "https://github.com/expressjs/express"},
            ],
        }
        project_response = {
            "projectKey": {"id": "github.com/expressjs/express"},
            "scorecardV2": {
                "overallScore": 7.2,
                "checks": [
                    {"name": "Maintained", "score": 10},
                    {"name": "Code-Review", "score": 6},
                ],
            },
            "openSsfFuzz": {"fuzzed": True},
        }
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = [
            _mock_response(200, version_response),
            _mock_response(200, project_response),
        ]

        certifier = DepsDevCertifier()
        findings = certifier.enrich("pkg:npm/-/express@4.18.2", client=mock_client)

        assert len(findings) == 1
        assert findings[0].data["scorecard_overall"] == 7.2
        assert findings[0].data["scorecard_checks"]["Maintained"] == 10

    @patch("sbom_graph_enrichment.certifiers.depsdev._bucket")
    def test_enrich_404_returns_empty(self, mock_bucket: MagicMock) -> None:
        mock_resp = _mock_response(404)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = DepsDevCertifier()
        findings = certifier.enrich("pkg:npm/-/nonexistent@0.0.1", client=mock_client)

        assert findings == []

    def test_enrich_unsupported_type(self) -> None:
        mock_client = MagicMock(spec=httpx.Client)

        certifier = DepsDevCertifier()
        findings = certifier.enrich("pkg:deb/debian/curl@7.88.1", client=mock_client)

        assert findings == []
        mock_client.get.assert_not_called()
