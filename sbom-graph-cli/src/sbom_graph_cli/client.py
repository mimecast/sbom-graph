"""HTTP client for the sbom-graph API."""

from __future__ import annotations

import json
import time
from typing import Any, Callable
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

    def ingest_sbom(
        self,
        file_path: str,
        *,
        wait: bool = True,
        sync: bool = False,
        poll_interval: float = 1.0,
        poll_timeout: float = 600.0,
        on_poll: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Upload and parse an SBOM file (CycloneDX or SPDX).

        The server defaults to **asynchronous** ingestion (see
        ``docs/sbom-graph-api-troubleshooting.md`` §10.6): the API
        validates the payload, enqueues the heavy parse-and-persist
        work onto a dedicated Celery worker pool, and returns ``202``
        with a ``job_id``.  This method's default behaviour
        (``wait=True``) preserves the historical "submit and get a
        summary back" UX by polling the job-status endpoint until
        terminal -- so CI/CD scripts that were written against the
        older synchronous API keep working without modification.

        Args:
            file_path: Path to the SBOM JSON file.
            wait: When ``True`` (default) poll until the worker reaches
                a terminal state and return the worker's summary dict.
                When ``False`` return the raw ``202`` envelope
                (``status``, ``record_id``, ``job_id``, ``status_url``)
                immediately so the caller can poll on its own schedule.
            sync: When ``True`` request the legacy synchronous path
                (``?sync=true``) -- the server processes inline and
                returns ``201`` with the summary directly.  Use only
                when the deployment has the dedicated ingest worker
                pool disabled, or for very small SBOMs in scripts that
                need the simplest possible code path.
            poll_interval: Seconds between status polls (default 1s).
            poll_timeout: Seconds to wait for terminal state before
                giving up with :class:`APIError` (default 10 min).
            on_poll: Optional callback invoked with each non-terminal
                status dict; used by the CLI to drive a progress
                spinner.

        Returns:
            * ``wait=True`` (default): The worker's terminal summary
              dict (same shape as the legacy ``201`` response):
              ``status``, ``record_id``, ``format``, ``projects_count``,
              etc.
            * ``wait=False``: The ``202`` envelope from the server.
            * ``sync=True``: The legacy ``201`` summary dict.

        Raises:
            APIError: On HTTP error, validation failure, worker
                failure, or polling timeout.
        """
        with open(file_path, encoding="utf-8") as f:
            sbom = json.load(f)

        body = {"sbom": sbom}
        client = self._get_client()

        params: dict[str, str] = {}
        if sync:
            params["sync"] = "true"

        response = client.post("/ingest/sbom", json=body, params=params)
        self._raise_for_status(response)
        envelope = response.json()

        # Sync path (or accidental 201 from a stale server): return as-is.
        if sync or response.status_code == 201:
            return envelope

        # Async path -- envelope should carry job_id.  If the server
        # returned 200 with a summary (some test doubles do this) just
        # pass it through; real servers return 202.
        job_id = envelope.get("job_id")
        if not job_id or not wait:
            return envelope

        return self._poll_ingest_job(
            job_id=job_id,
            envelope=envelope,
            poll_interval=poll_interval,
            poll_timeout=poll_timeout,
            on_poll=on_poll,
        )

    def get_ingest_job_status(self, job_id: str) -> dict[str, Any]:
        """Fetch the current status of an async ingest job.

        Args:
            job_id: The ``job_id`` returned by an async ``POST
                /ingest/*`` call.

        Returns:
            Status dict with ``job_id``, ``state``, ``terminal``, and
            (for SUCCESS / FAILURE states) ``result``.

        Raises:
            APIError: On HTTP error (e.g. 400 for malformed id, 503 if
                the ingest pipeline is not installed in the API image).
        """
        client = self._get_client()
        response = client.get(f"/ingest/jobs/{quote(job_id, safe='-')}")
        self._raise_for_status(response)
        return response.json()

    def _poll_ingest_job(
        self,
        job_id: str,
        envelope: dict[str, Any],
        poll_interval: float,
        poll_timeout: float,
        on_poll: Callable[[dict[str, Any]], None] | None,
    ) -> dict[str, Any]:
        """Poll ``/ingest/jobs/<id>`` until terminal or timeout.

        Returns the worker's summary dict (same shape as the legacy
        synchronous ``201``).  On worker FAILURE raises :class:`APIError`
        with the sanitised error message the server provides.
        """
        deadline = time.monotonic() + poll_timeout
        while True:
            status = self.get_ingest_job_status(job_id)
            if on_poll is not None:
                on_poll(status)

            if status.get("terminal"):
                result = status.get("result") or {}
                if status.get("state") == "SUCCESS" and result.get("status") == "ok":
                    return result
                # FAILURE / REVOKED or SUCCESS with an error payload from
                # the worker's own try/except.  Surface the sanitised
                # message; never propagate internal exception details.
                message = (
                    result.get("error")
                    if isinstance(result, dict)
                    else None
                ) or f"Ingest job ended in state {status.get('state')!r}"
                raise APIError(message, status_code=500)

            if time.monotonic() >= deadline:
                # Returning the envelope on timeout would silently hide
                # the failure; raise so callers (and exit codes) catch it.
                raise APIError(
                    f"Ingest job {job_id} did not complete within "
                    f"{poll_timeout:.0f}s "
                    f"(last state: {status.get('state', 'unknown')}). "
                    f"Poll {envelope.get('status_url', '/ingest/jobs/' + job_id)} "
                    f"to check progress.",
                    status_code=504,
                )

            time.sleep(poll_interval)

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
