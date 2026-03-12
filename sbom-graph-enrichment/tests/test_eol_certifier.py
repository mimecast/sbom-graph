"""Unit tests for the EOL certifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from sbom_graph_enrichment.certifiers.base import FindingKind
from sbom_graph_enrichment.certifiers.eol import (
    EOLCertifier,
    _build_eol_data,
    _find_matching_cycle,
    _purl_to_eol_product,
)


class TestPurlToEolProduct:
    """Tests for _purl_to_eol_product."""

    def test_npm(self) -> None:
        result = _purl_to_eol_product("pkg:npm/foo@1.0.0")
        assert result == ("foo", "1.0.0")

    def test_npm_scoped(self) -> None:
        result = _purl_to_eol_product("pkg:npm/%40angular/core@16.0.0")
        assert result == ("core", "16.0.0")

    def test_pypi(self) -> None:
        result = _purl_to_eol_product("pkg:pypi/requests@2.31.0")
        assert result == ("requests", "2.31.0")

    def test_pypi_with_hyphen(self) -> None:
        result = _purl_to_eol_product("pkg:pypi/-/python@3.12.2")
        assert result == ("python", "3.12.2")

    def test_maven(self) -> None:
        result = _purl_to_eol_product("pkg:maven/org.apache/commons@3.12.0")
        assert result == ("org-apache-commons", "3.12.0")

    def test_maven_with_colons(self) -> None:
        result = _purl_to_eol_product("pkg:maven/org.apache:commons-lang@3.12.0")
        assert result == ("org.apache:commons-lang", "3.12.0")

    def test_golang(self) -> None:
        result = _purl_to_eol_product("pkg:golang/github.com/foo/bar@v1.0.0")
        assert result == ("bar", "v1.0.0")

    def test_golang_deep_path(self) -> None:
        result = _purl_to_eol_product("pkg:golang/github.com/org/repo/pkg@v2.0.0")
        assert result == ("pkg", "v2.0.0")

    def test_invalid_purl(self) -> None:
        assert _purl_to_eol_product("not-a-purl") is None

    def test_empty_name(self) -> None:
        assert _purl_to_eol_product("pkg:npm/@1.0") is None

    def test_empty_version(self) -> None:
        assert _purl_to_eol_product("pkg:npm/foo@") is None

    def test_unsupported_type_uses_name(self) -> None:
        result = _purl_to_eol_product("pkg:nuget/Newtonsoft.Json@13.0.1")
        assert result == ("newtonsoft.json", "13.0.1")


class TestFindMatchingCycle:
    """Tests for _find_matching_cycle."""

    def test_exact_match(self) -> None:
        cycles = [
            {"cycle": "3.12", "eol": True},
            {"cycle": "3.11", "eol": False},
        ]
        result = _find_matching_cycle(cycles, "3.12")
        assert result is not None
        assert result["cycle"] == "3.12"

    def test_prefix_match(self) -> None:
        cycles = [
            {"cycle": "3.12", "eol": True},
            {"cycle": "3.11", "eol": False},
        ]
        result = _find_matching_cycle(cycles, "3.12.2")
        assert result is not None
        assert result["cycle"] == "3.12"

    def test_prefix_match_cycle_shorter(self) -> None:
        cycles = [{"cycle": "3", "eol": True}]
        result = _find_matching_cycle(cycles, "3.12.2")
        assert result is not None
        assert result["cycle"] == "3"

    def test_no_match(self) -> None:
        cycles = [
            {"cycle": "3.11", "eol": False},
            {"cycle": "3.10", "eol": True},
        ]
        result = _find_matching_cycle(cycles, "3.12.2")
        assert result is None

    def test_empty_version(self) -> None:
        cycles = [{"cycle": "3.12", "eol": True}]
        result = _find_matching_cycle(cycles, "")
        assert result is None

    def test_leading_v_stripped(self) -> None:
        cycles = [{"cycle": "1", "eol": False}]
        result = _find_matching_cycle(cycles, "v1.0.0")
        assert result is not None
        assert result["cycle"] == "1"

    def test_leading_v_uppercase_stripped(self) -> None:
        cycles = [{"cycle": "1", "eol": False}]
        result = _find_matching_cycle(cycles, "V1.0.0")
        assert result is not None

    def test_empty_cycle_skipped(self) -> None:
        cycles = [
            {"cycle": "", "eol": True},
            {"cycle": "3.12", "eol": True},
        ]
        result = _find_matching_cycle(cycles, "3.12.2")
        assert result is not None
        assert result["cycle"] == "3.12"


class TestBuildEolData:
    """Tests for _build_eol_data."""

    def test_with_cycle_data(self) -> None:
        cycle_data = {
            "cycle": "3.12",
            "eol": True,
            "releaseDate": "2023-10-02",
            "support": "2025-10-06",
            "lts": False,
            "latest": "3.12.2",
        }
        result = _build_eol_data("python", cycle_data, "3.12.2")
        assert result["product"] == "python"
        assert result["cycle"] == "3.12"
        assert result["eol"] is True
        assert result["eol_date"] is None
        assert result["release_date"] == "2023-10-02"
        assert result["support"] == "2025-10-06"
        assert result["lts"] is False
        assert result["latest"] == "3.12.2"

    def test_with_cycle_data_eol_string_date(self) -> None:
        cycle_data = {
            "cycle": "3.11",
            "eol": "2025-09-30",
            "release_date": "2022-10-24",
        }
        result = _build_eol_data("python", cycle_data, "3.11.0")
        assert result["eol"] == "2025-09-30"
        assert result["eol_date"] == "2025-09-30"
        assert result["release_date"] == "2022-10-24"

    def test_without_cycle_data(self) -> None:
        result = _build_eol_data("unknown", None, "1.0.0")
        assert result["product"] == "unknown"
        assert result["cycle"] is None
        assert result["eol"] is None
        assert result["eol_date"] is None
        assert result["lts"] is None
        assert result["latest"] is None


class TestEOLCertifier:
    """Tests for EOLCertifier."""

    def test_name(self) -> None:
        assert EOLCertifier().name == "eol"

    @patch("sbom_graph_enrichment.certifiers.eol._bucket")
    def test_enrich_successful_returns_finding(self, _mock_bucket: MagicMock) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"cycle": "3.12", "eol": True, "releaseDate": "2023-10-02"},
        ]
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = EOLCertifier()
        findings = certifier.enrich("pkg:pypi/python@3.12.2", client=mock_client)

        assert len(findings) == 1
        assert findings[0].kind == FindingKind.EOL
        assert findings[0].source == "endoflife.date"
        assert findings[0].package_url == "pkg:pypi/python@3.12.2"
        assert findings[0].data["product"] == "python"
        assert findings[0].data["cycle"] == "3.12"
        assert findings[0].data["eol"] is True
        mock_client.get.assert_called_once()
        assert "endoflife.date" in mock_client.get.call_args[0][0]

    @patch("sbom_graph_enrichment.certifiers.eol._bucket")
    def test_enrich_404_returns_empty(self, _mock_bucket: MagicMock) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 404

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = EOLCertifier()
        findings = certifier.enrich("pkg:pypi/nonexistent@1.0", client=mock_client)

        assert findings == []

    @patch("sbom_graph_enrichment.certifiers.eol._bucket")
    def test_enrich_empty_cycles_returns_empty(self, _mock_bucket: MagicMock) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_resp

        certifier = EOLCertifier()
        findings = certifier.enrich("pkg:pypi/python@3.12.2", client=mock_client)

        assert findings == []

    def test_enrich_invalid_purl_returns_empty(self) -> None:
        mock_client = MagicMock(spec=httpx.Client)

        certifier = EOLCertifier()
        findings = certifier.enrich("not-a-purl", client=mock_client)

        assert findings == []
        mock_client.get.assert_not_called()
