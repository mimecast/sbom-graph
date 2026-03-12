"""Pytest fixtures for sbom-graph-cli tests."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def sample_sbom() -> dict:
    """Minimal CycloneDX SBOM for testing."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"component": {"name": "test-app", "version": "1.0.0"}},
        "components": [],
    }


@pytest.fixture
def sample_sbom_file(tmp_path: Path, sample_sbom: dict) -> Path:
    """Write sample SBOM to a temp file."""
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(sample_sbom), encoding="utf-8")
    return path


def make_ingest_response() -> dict:
    """Response from POST /ingest/sbom."""
    return {
        "status": "ok",
        "record_id": "abc-123",
        "format": "cyclonedx",
        "projects_count": 1,
        "dependencies_count": 0,
        "defects_count": 0,
    }


def make_vulns_response() -> dict:
    """Response from GET /api/v1/package/{purl}/vulns."""
    return {
        "package": "pkg:maven/org/foo@1.0",
        "vulnerabilities": [
            {"id": "CVE-2024-1", "severity": "HIGH", "cvss": 7.5, "title": "Test vuln"},
        ],
        "count": 1,
    }


def make_deps_response() -> dict:
    """Response from version-dependencies report."""
    return {
        "report_type": "version-dependencies",
        "data": [
            {"depth": 1, "dependency_project": "bar", "dependency_version": "2.0"},
        ],
    }


def make_dependants_response() -> dict:
    """Response from dependants report."""
    return {
        "report_type": "dependants",
        "dependants": [
            {"project_name": "app", "version": "1.0", "partition": 1},
        ],
    }


def make_patch_plan_response() -> dict:
    """Response from incident-response report."""
    return {
        "report_type": "incident-response",
        "defect_id": "CVE-2024-1234",
        "patch_plan": [
            {
                "priority": 1,
                "project_name": "foo",
                "version_name": "1.0",
                "is_direct": True,
                "dependant_count": 2,
                "recommended_action": "Upgrade",
            },
        ],
    }


def make_policy_response() -> dict:
    """Response from POST /api/v1/policy/annotate."""
    return {
        "annotation_id": "uuid-123",
        "purl": "pkg:maven/org/foo@1.0",
        "type": "bad",
        "created_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def mock_httpx() -> httpx.MockTransport:
    """Create a mock transport that handles common API routes."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and "/ingest/sbom" in url:
            return httpx.Response(201, json=make_ingest_response())
        if request.method == "GET" and "/vulns" in url:
            return httpx.Response(200, json=make_vulns_response())
        if request.method == "GET" and "/version-dependencies" in url:
            return httpx.Response(200, json=make_deps_response())
        if request.method == "GET" and "/dependants" in url:
            return httpx.Response(200, json=make_dependants_response())
        if request.method == "GET" and "/incident-response" in url:
            return httpx.Response(200, json=make_patch_plan_response())
        if request.method == "POST" and "/policy/annotate" in url:
            return httpx.Response(201, json=make_policy_response())
        if request.method == "GET" and "/reports/" in url:
            return httpx.Response(200, content=b'{"data": []}')
        return httpx.Response(404, json={"error": "Not found"})

    return httpx.MockTransport(handler)
