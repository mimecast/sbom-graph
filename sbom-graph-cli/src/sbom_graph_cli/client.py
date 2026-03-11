"""HTTP client for the sbom-graph API."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx

from sbom_graph_cli.utils import APIError


class SBOMGraphClient:
    """HTTP client for the sbom-graph API.

    Supports all programmatic endpoints for ingestion, querying,
    policy annotation, and report export.
    """

    def __init__(
        self,
        api_url: str,
        token: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialise the API client.

        Args:
            api_url: Base URL of the sbom-graph API (e.g. http://localhost:5000).
            token: Optional API token for authentication.
            transport: Optional HTTP transport (for testing).
        """
        self.api_url = api_url.rstrip("/")
        self.token = token
        self._transport = transport
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        """Return a configured HTTP client with auth headers."""
        if self._client is None:
            headers: dict[str, str] = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            kwargs: dict[str, Any] = {
                "base_url": self.api_url,
                "headers": headers,
                "timeout": 60.0,
            }
            if self._transport is not None:
                kwargs["transport"] = self._transport
            self._client = httpx.Client(**kwargs)
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Raise APIError if response indicates failure."""
        if response.is_success:
            return
        try:
            body = response.json()
            msg = body.get("error", response.text or str(response.status_code))
        except (ValueError, KeyError):
            msg = response.text or response.reason_phrase or "Request failed"
        raise APIError(msg, status_code=response.status_code)

    def ingest_sbom(self, file_path: str) -> dict[str, Any]:
        """Upload and parse an SBOM file (CycloneDX or SPDX).

        Args:
            file_path: Path to the SBOM JSON file.

        Returns:
            Summary dict with record_id, projects_count, dependencies_count,
            defects_count.

        Raises:
            APIError: On HTTP error or validation failure.
        """
        with open(file_path, encoding="utf-8") as f:
            sbom = json.load(f)

        body = {"sbom": sbom}
        client = self._get_client()
        response = client.post("/ingest/sbom", json=body)
        self._raise_for_status(response)
        return response.json()

    def get_vulnerabilities(self, purl: str) -> list[dict[str, Any]]:
        """Get vulnerabilities for a package and optionally its dependencies.

        Args:
            purl: Package URL (e.g. pkg:maven/org/foo@1.0).

        Returns:
            List of vulnerability dicts.

        Raises:
            APIError: On HTTP error.
        """
        encoded = quote(purl, safe="")
        client = self._get_client()
        response = client.get(
            f"/api/v1/package/{encoded}/vulns",
            params={"include_dependencies": "true"},
        )
        self._raise_for_status(response)
        data = response.json()
        return data.get("vulnerabilities", [])

    def get_dependencies(self, purl: str) -> list[dict[str, Any]]:
        """Get dependencies (direct and transitive) for a package.

        Uses the version-dependencies report endpoint with PURL resolution.

        Args:
            purl: Package URL.

        Returns:
            List of dependency dicts with depth, project, version.

        Raises:
            APIError: On HTTP error.
        """
        encoded = quote(purl, safe="")
        client = self._get_client()
        response = client.get(
            f"/reports/version-dependencies/purl/{encoded}",
            params={"format": "json"},
            follow_redirects=True,
        )
        self._raise_for_status(response)
        data = response.json()
        return data.get("data", data.get("dependencies", []))

    def get_dependants(self, purl: str) -> list[dict[str, Any]]:
        """Get dependants (reverse dependencies) for a package.

        Uses the dependants report endpoint with PURL resolution.

        Args:
            purl: Package URL.

        Returns:
            List of dependant dicts with partition, project, version.

        Raises:
            APIError: On HTTP error.
        """
        encoded = quote(purl, safe="")
        client = self._get_client()
        response = client.get(
            f"/reports/dependants/purl/{encoded}",
            params={"format": "json"},
            follow_redirects=True,
        )
        self._raise_for_status(response)
        data = response.json()
        return data.get("dependants", [])

    def get_patch_plan(self, defect_id: str) -> list[dict[str, Any]]:
        """Get patch plan for a vulnerability (incident response).

        Args:
            defect_id: Vulnerability ID (e.g. CVE-2024-1234).

        Returns:
            List of patch plan items with priority, package, action.

        Raises:
            APIError: On HTTP error.
        """
        client = self._get_client()
        response = client.get(
            f"/reports/incident-response/{defect_id}",
            params={"format": "json"},
        )
        self._raise_for_status(response)
        data = response.json()
        return data.get("patch_plan", [])

    def annotate_policy(
        self,
        purl: str,
        annotation: str,
        justification: str,
    ) -> dict[str, Any]:
        """Create a policy annotation (bad/good/hold) on a package.

        Args:
            purl: Package URL.
            annotation: Policy type: bad, good, or hold.
            justification: Human-readable justification.

        Returns:
            Created annotation dict with annotation_id, purl, type.

        Raises:
            APIError: On HTTP error.
        """
        client = self._get_client()
        response = client.post(
            "/api/v1/policy/annotate",
            json={
                "purl": purl,
                "type": annotation,
                "justification": justification,
            },
        )
        self._raise_for_status(response)
        return response.json()

    def export_report(
        self,
        report_name: str,
        output_format: str,
    ) -> bytes:
        """Export a report in the specified format.

        Args:
            report_name: Report path (e.g. vulnerabilities, or
                incident-response/CVE-2024-1234).
            output_format: Output format: json, excel, or csv.

        Returns:
            Raw response bytes.

        Raises:
            APIError: On HTTP error.
        """
        client = self._get_client()
        response = client.get(
            f"/reports/{report_name}",
            params={"format": output_format},
        )
        self._raise_for_status(response)
        return response.content
