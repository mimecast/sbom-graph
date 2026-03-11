"""Tests for SBOMGraphClient."""

from __future__ import annotations

import httpx
import pytest

from sbom_graph_cli.client import SBOMGraphClient
from sbom_graph_cli.utils import APIError

from .conftest import make_vulns_response


def test_ingest_sbom(mock_httpx: httpx.MockTransport, sample_sbom_file: str) -> None:
    """ingest_sbom posts JSON and returns summary."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    result = client.ingest_sbom(str(sample_sbom_file))
    assert result["status"] == "ok"
    assert "record_id" in result
    assert result["projects_count"] == 1


def test_get_vulnerabilities(mock_httpx: httpx.MockTransport) -> None:
    """get_vulnerabilities returns list."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    vulns = client.get_vulnerabilities("pkg:maven/org/foo@1.0")
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2024-1"
    assert vulns[0]["severity"] == "HIGH"


def test_get_dependencies(mock_httpx: httpx.MockTransport) -> None:
    """get_dependencies returns list."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    deps = client.get_dependencies("pkg:maven/org/foo@1.0")
    assert len(deps) >= 1
    assert deps[0]["dependency_project"] == "bar"


def test_get_dependants(mock_httpx: httpx.MockTransport) -> None:
    """get_dependants returns list."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    deps = client.get_dependants("pkg:maven/org/foo@1.0")
    assert len(deps) >= 1
    assert deps[0]["project_name"] == "app"


def test_get_patch_plan(mock_httpx: httpx.MockTransport) -> None:
    """get_patch_plan returns list."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    plan = client.get_patch_plan("CVE-2024-1234")
    assert len(plan) >= 1
    assert plan[0]["project_name"] == "foo"


def test_annotate_policy(mock_httpx: httpx.MockTransport) -> None:
    """annotate_policy returns created annotation."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    result = client.annotate_policy(
        "pkg:maven/org/foo@1.0",
        "bad",
        "Security issue",
    )
    assert result["type"] == "bad"
    assert "annotation_id" in result


def test_api_error_on_404() -> None:
    """APIError raised on 404."""
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "Not found"})

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", transport=transport)
    with pytest.raises(APIError) as exc_info:
        client.get_vulnerabilities("pkg:maven/org/foo@1.0")
    assert exc_info.value.status_code == 404


def test_client_close() -> None:
    """close() releases resources."""
    client = SBOMGraphClient("http://test")
    client._client = httpx.Client(base_url="http://test")
    client.close()
    assert client._client is None


def test_client_with_token_sends_auth_header() -> None:
    """Client with token includes Bearer header."""
    def handler(req: httpx.Request) -> httpx.Response:
        auth = req.headers.get("Authorization", "")
        assert auth == "Bearer my-token"
        return httpx.Response(200, json=make_vulns_response())

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", token="my-token", transport=transport)
    client.get_vulnerabilities("pkg:maven/org/foo@1.0")


def test_raise_for_status_on_non_json_error_body() -> None:
    """APIError uses text when response is not JSON."""
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"Internal Server Error")

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", transport=transport)
    with pytest.raises(APIError) as exc_info:
        client.get_vulnerabilities("pkg:maven/org/foo@1.0")
    assert "Internal Server Error" in str(exc_info.value)


def test_export_report_returns_content() -> None:
    """export_report returns raw bytes."""
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"xlsx-binary-content")

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", transport=transport)
    content = client.export_report("vulnerabilities", "excel")
    assert content == b"xlsx-binary-content"
