"""Tests for SBOMGraphClient."""

from __future__ import annotations

import httpx
import pytest

from sbom_graph_cli.client import SBOMGraphClient
from sbom_graph_cli.utils import APIError

from .conftest import make_vulns_response


def test_ingest_sbom(mock_httpx: httpx.MockTransport, sample_sbom_file: str) -> None:
    """Default (``wait=True``) ingest_sbom round-trip: 202 then poll to SUCCESS.

    The mock transport returns ``202`` on ``POST /ingest/sbom`` and the
    SUCCESS terminal payload on ``GET /ingest/jobs/<id>``.  The client
    must transparently follow that loop and surface the worker's
    summary -- so existing scripts that called ``ingest_sbom(path)``
    keep working unchanged.
    """
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    result = client.ingest_sbom(str(sample_sbom_file), poll_interval=0.0)
    assert result["status"] == "ok"
    assert "record_id" in result
    assert result["projects_count"] == 1


def test_ingest_sbom_no_wait_returns_envelope(
    mock_httpx: httpx.MockTransport, sample_sbom_file: str
) -> None:
    """``wait=False`` returns the raw 202 envelope without polling."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    envelope = client.ingest_sbom(str(sample_sbom_file), wait=False)
    assert envelope["status"] == "accepted"
    assert envelope["job_id"] == "job-deadbeef"
    assert envelope["status_url"].endswith("/ingest/jobs/job-deadbeef")


def test_ingest_sbom_sync_returns_summary(
    mock_httpx: httpx.MockTransport, sample_sbom_file: str
) -> None:
    """``sync=True`` adds ?sync=true and returns the legacy 201 summary."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    result = client.ingest_sbom(str(sample_sbom_file), sync=True)
    assert result["status"] == "ok"
    assert result["projects_count"] == 1


def test_ingest_sbom_polls_until_terminal(
    sample_sbom_file: str,
) -> None:
    """Client polls /ingest/jobs/<id> until the worker reports SUCCESS."""

    poll_counter = {"calls": 0}
    terminal_payload = {
        "status": "ok",
        "record_id": "rec-1",
        "format": "cyclonedx",
        "projects_count": 1,
        "dependencies_count": 0,
        "defects_count": 0,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "/ingest/sbom" in str(request.url):
            return httpx.Response(
                202,
                json={
                    "status": "accepted",
                    "record_id": "rec-1",
                    "job_id": "job-1",
                    "status_url": "/ingest/jobs/job-1",
                },
            )
        if request.method == "GET" and "/ingest/jobs/job-1" in str(request.url):
            poll_counter["calls"] += 1
            if poll_counter["calls"] < 3:
                return httpx.Response(
                    200,
                    json={
                        "job_id": "job-1",
                        "state": "STARTED",
                        "terminal": False,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "job_id": "job-1",
                    "state": "SUCCESS",
                    "terminal": True,
                    "result": terminal_payload,
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", transport=transport)

    captured: list[dict] = []
    result = client.ingest_sbom(
        str(sample_sbom_file),
        poll_interval=0.0,
        on_poll=captured.append,
    )

    assert result == terminal_payload
    # Three poll calls observed: two STARTED + one SUCCESS.
    assert poll_counter["calls"] == 3
    assert captured[-1]["state"] == "SUCCESS"


def test_ingest_sbom_raises_on_worker_failure(sample_sbom_file: str) -> None:
    """A FAILURE terminal state surfaces as APIError, not a silent success."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                202,
                json={
                    "status": "accepted",
                    "record_id": "rec-1",
                    "job_id": "job-bad",
                    "status_url": "/ingest/jobs/job-bad",
                },
            )
        return httpx.Response(
            200,
            json={
                "job_id": "job-bad",
                "state": "FAILURE",
                "terminal": True,
                "result": {
                    "status": "error",
                    "error": "SBOM validation failed",
                },
            },
        )

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", transport=transport)
    with pytest.raises(APIError) as exc_info:
        client.ingest_sbom(str(sample_sbom_file), poll_interval=0.0)
    assert "SBOM validation failed" in str(exc_info.value)


def test_ingest_sbom_raises_on_poll_timeout(sample_sbom_file: str) -> None:
    """Polling timeout surfaces an APIError that names the job id."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                202,
                json={
                    "status": "accepted",
                    "record_id": "rec-1",
                    "job_id": "job-slow",
                    "status_url": "/ingest/jobs/job-slow",
                },
            )
        return httpx.Response(
            200,
            json={
                "job_id": "job-slow",
                "state": "STARTED",
                "terminal": False,
            },
        )

    transport = httpx.MockTransport(handler)
    client = SBOMGraphClient("http://test", transport=transport)
    with pytest.raises(APIError) as exc_info:
        # Zero timeout forces immediate deadline-exceeded after first poll.
        client.ingest_sbom(
            str(sample_sbom_file),
            poll_interval=0.0,
            poll_timeout=0.0,
        )
    assert "job-slow" in str(exc_info.value)
    assert exc_info.value.status_code == 504


def test_get_ingest_job_status(mock_httpx: httpx.MockTransport) -> None:
    """``get_ingest_job_status`` hits /ingest/jobs/<id> and returns the payload."""
    client = SBOMGraphClient("http://test", transport=mock_httpx)
    status = client.get_ingest_job_status("job-deadbeef")
    assert status["state"] == "SUCCESS"
    assert status["terminal"] is True
    assert status["result"]["projects_count"] == 1


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
