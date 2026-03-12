"""Unit tests for the OpenSSF Scorecard certifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from sbom_graph_enrichment.certifiers.base import FindingKind
from sbom_graph_enrichment.certifiers.scorecard import (
    ScorecardCertifier,
    extract_github_owner_repo,
)


def _mock_response(status_code: int, json_data: dict | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://test.example.com")
    return httpx.Response(status_code, json=json_data, request=request)


class TestExtractGithubOwnerRepo:
    """Tests for GitHub URL parsing."""

    def test_standard_url(self) -> None:
        assert extract_github_owner_repo(
            "https://github.com/org/repo"
        ) == ("org", "repo")

    def test_url_with_git_suffix(self) -> None:
        assert extract_github_owner_repo(
            "https://github.com/org/repo.git"
        ) == ("org", "repo")

    def test_url_with_path(self) -> None:
        assert extract_github_owner_repo(
            "https://github.com/org/repo/tree/main"
        ) == ("org", "repo")

    def test_http_url(self) -> None:
        assert extract_github_owner_repo(
            "http://github.com/org/repo"
        ) == ("org", "repo")

    def test_non_github_url(self) -> None:
        assert extract_github_owner_repo("https://gitlab.com/org/repo") is None

    def test_none_url(self) -> None:
        assert extract_github_owner_repo(None) is None

    def test_empty_url(self) -> None:
        assert extract_github_owner_repo("") is None


class TestScorecardCertifier:
    """Tests for the ScorecardCertifier."""

    def test_name(self) -> None:
        assert ScorecardCertifier().name == "scorecard"

    @patch("sbom_graph_enrichment.certifiers.scorecard._bucket")
    def test_enrich_returns_scorecard_finding(self, mock_bucket: MagicMock) -> None:
        scorecard_response = {
            "score": 7.5,
            "repo": {"name": "github.com/org/repo", "commit": "abc123"},
            "checks": [
                {"name": "Code-Review", "score": 8, "documentation": {}},
                {"name": "Maintained", "score": 10, "documentation": {}},
                {"name": "Branch-Protection", "score": 5, "documentation": {}},
            ],
        }
        mock_response = _mock_response(200, scorecard_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        certifier = ScorecardCertifier(repo_url="https://github.com/org/repo")
        findings = certifier.enrich("pkg:maven/org/lib@1.0", client=mock_client)

        assert len(findings) == 1
        assert findings[0].kind == FindingKind.SCORECARD
        assert findings[0].source == "scorecard"
        assert findings[0].data["overall_score"] == 7.5
        assert findings[0].data["checks"]["Code-Review"] == 8
        assert findings[0].data["checks"]["Maintained"] == 10

    @patch("sbom_graph_enrichment.certifiers.scorecard._bucket")
    def test_enrich_404_returns_empty(self, mock_bucket: MagicMock) -> None:
        mock_response = _mock_response(404)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        certifier = ScorecardCertifier(repo_url="https://github.com/org/unknown")
        findings = certifier.enrich("pkg:maven/org/lib@1.0", client=mock_client)

        assert findings == []

    def test_enrich_no_github_repo_returns_empty(self) -> None:
        mock_client = MagicMock(spec=httpx.Client)

        certifier = ScorecardCertifier(repo_url="https://gitlab.com/org/repo")
        findings = certifier.enrich("pkg:maven/org/lib@1.0", client=mock_client)

        assert findings == []
        mock_client.get.assert_not_called()

    def test_enrich_no_repo_url_returns_empty(self) -> None:
        mock_client = MagicMock(spec=httpx.Client)

        certifier = ScorecardCertifier(repo_url=None)
        findings = certifier.enrich("pkg:maven/org/lib@1.0", client=mock_client)

        assert findings == []

    @patch("sbom_graph_enrichment.certifiers.scorecard._bucket")
    def test_enrich_empty_checks_returns_empty(self, mock_bucket: MagicMock) -> None:
        scorecard_response = {"checks": []}
        mock_response = _mock_response(200, scorecard_response)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        certifier = ScorecardCertifier(repo_url="https://github.com/org/repo")
        findings = certifier.enrich("pkg:maven/org/lib@1.0", client=mock_client)

        assert findings == []
