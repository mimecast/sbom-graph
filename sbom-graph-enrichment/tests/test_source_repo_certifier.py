"""Unit tests for the source repository certifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from sbom_graph_enrichment.certifiers.base import FindingKind
from sbom_graph_enrichment.certifiers.source_repo import (
    SourceRepoCertifier,
    _extract_source_repo_url,
)


class TestExtractSourceRepoUrl:
    """Tests for _extract_source_repo_url."""

    def test_github(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://github.com/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://github.com/owner/repo"

    def test_gitlab(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://gitlab.com/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://gitlab.com/owner/repo"

    def test_bitbucket(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://bitbucket.org/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://bitbucket.org/owner/repo"

    def test_sourcehut(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://git.sr.ht/~user/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result is None

    def test_codeberg(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://codeberg.org/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://codeberg.org/owner/repo"

    def test_www_prefix(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://www.github.com/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://www.github.com/owner/repo"

    def test_subdomain_gist_github(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://gist.github.com/owner/123"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://gist.github.com/owner/123"

    def test_disallowed_host(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://evil.com/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result is None

    def test_no_source_repo_label(self) -> None:
        links = [
            {"label": "HOMEPAGE", "url": "https://github.com/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result is None

    def test_empty_url(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": ""},
        ]
        result = _extract_source_repo_url(links)
        assert result is None

    def test_none_url(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": None},
        ]
        result = _extract_source_repo_url(links)
        assert result is None

    def test_label_case_insensitive(self) -> None:
        links = [
            {"label": "source_repo", "url": "https://github.com/owner/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://github.com/owner/repo"

    def test_first_source_repo_wins(self) -> None:
        links = [
            {"label": "SOURCE_REPO", "url": "https://github.com/first/repo"},
            {"label": "SOURCE_REPO", "url": "https://gitlab.com/second/repo"},
        ]
        result = _extract_source_repo_url(links)
        assert result == "https://github.com/first/repo"


class TestSourceRepoCertifier:
    """Tests for SourceRepoCertifier."""

    def test_name(self) -> None:
        assert SourceRepoCertifier().name == "source_repo"

    @patch("sbom_graph_enrichment.certifiers.source_repo._bucket")
    def test_enrich_successful_returns_finding(
        self, _mock_bucket: MagicMock
    ) -> None:
        version_response = {
            "versionKey": {"system": "NPM", "name": "lodash", "version": "4.17.21"},
            "links": [
                {"label": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"},
            ],
        }
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = version_response
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = SourceRepoCertifier()
        findings = certifier.enrich(
            "pkg:npm/-/lodash@4.17.21", client=mock_client
        )

        assert len(findings) == 1
        assert findings[0].kind == FindingKind.SOURCE_REPO
        assert findings[0].source == "depsdev"
        assert findings[0].package_url == "pkg:npm/-/lodash@4.17.21"
        assert findings[0].data["repo_url"] == "https://github.com/lodash/lodash"
        assert findings[0].data["repo_host"] == "github.com"

    @patch("sbom_graph_enrichment.certifiers.source_repo._bucket")
    def test_enrich_404_returns_empty(self, _mock_bucket: MagicMock) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 404

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = SourceRepoCertifier()
        findings = certifier.enrich(
            "pkg:npm/-/nonexistent@0.0.1", client=mock_client
        )

        assert findings == []

    @patch("sbom_graph_enrichment.certifiers.source_repo._bucket")
    def test_enrich_no_repo_link_returns_empty(
        self, _mock_bucket: MagicMock
    ) -> None:
        version_response = {
            "versionKey": {"system": "NPM", "name": "foo", "version": "1.0"},
            "links": [{"label": "HOMEPAGE", "url": "https://example.com"}],
        }
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = version_response
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = SourceRepoCertifier()
        findings = certifier.enrich("pkg:npm/-/foo@1.0", client=mock_client)

        assert findings == []

    def test_enrich_unsupported_purl_returns_empty(self) -> None:
        mock_client = MagicMock(spec=httpx.Client)

        certifier = SourceRepoCertifier()
        findings = certifier.enrich(
            "pkg:deb/debian/curl@7.88.1", client=mock_client
        )

        assert findings == []
        mock_client.get.assert_not_called()
