"""Tests for the async ingest path (202 + /ingest/jobs/<id> status endpoint).

The synchronous ``?sync=true`` path is covered by the existing tests in
``test_routes_ingest.py``, ``test_routes_spdx.py`` and ``test_routes_vex.py``.

These tests focus exclusively on the behaviour introduced by
``docs/sbom-graph-api-troubleshooting.md`` §10.6:

* Validate-and-enqueue happy path returns ``202`` plus ``record_id``,
  ``job_id``, ``status_url`` and a ``Location`` header.
* ``GET /ingest/jobs/<job_id>`` returns the worker state and -- when
  terminal -- the same summary dict the synchronous path would have
  produced.
* The endpoint degrades cleanly to ``503`` when the Celery client
  cannot be initialised or the broker is unreachable.
* ``job_id`` is validated as a UUID before any backend lookup is
  performed, so callers cannot use the endpoint to probe arbitrary
  result-store keys.

All tests stub the thin Celery client returned by
``sbom_graph_api.services.celery_client.get_celery_client`` (and
``celery.result.AsyncResult`` for the status endpoint) rather than
talking to a real broker, so the suite remains hermetic and fast.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch


def _minimal_cyclonedx() -> dict:
    """Smallest CycloneDX document that passes SBOM_UPLOAD_SCHEMA validation."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "bom-ref": "app-ref",
                "name": "async-app",
                "version": "1.0.0",
                "type": "application",
            }
        },
        "components": [],
        "dependencies": [],
    }


def _minimal_spdx() -> dict:
    """Smallest SPDX 2.3 document that passes SBOM_UPLOAD_SCHEMA validation."""
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "async-spdx",
        "packages": [],
        "relationships": [],
    }


# ---------------------------------------------------------------------------
# POST /ingest/* — async default path
# ---------------------------------------------------------------------------


class TestAsyncEnqueue:
    """The default path: validate, enqueue on the ``ingest`` queue, return 202."""

    def _patch_celery(self, expected_task_name: str, returned_job_id: str):
        """Stub ``get_celery_client`` and assert the route enqueues correctly.

        The stub asserts the route enqueued onto the ``ingest`` queue with
        the expected task name; tests still inspect the response, but the
        queue/task-name contract is enforced inside the mock so a future
        refactor cannot silently drift.
        """
        mock_celery_app = MagicMock()
        mock_result = MagicMock()
        mock_result.id = returned_job_id

        def _send_task(task_name, args=None, queue=None, **_kwargs):
            # ``args`` is part of Celery's send_task signature and is passed
            # by the route code; we don't introspect it here -- the test
            # focuses on the queue/task-name contract.
            _ = args
            assert queue == "ingest", f"expected queue='ingest', got {queue!r}"
            assert task_name == expected_task_name, (
                f"expected task {expected_task_name!r}, got {task_name!r}"
            )
            return mock_result

        mock_celery_app.send_task.side_effect = _send_task

        return patch(
            "sbom_graph_api.services.celery_client.get_celery_client",
            return_value=mock_celery_app,
        )

    def test_cyclonedx_async_default_returns_202(self, client):
        """POST /ingest/cyclonedx without ?sync=true returns 202 + job metadata."""
        job_id = str(uuid.uuid4())

        with self._patch_celery(
            "sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx",
            job_id,
        ):
            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": _minimal_cyclonedx()},
                content_type="application/json",
            )

        assert response.status_code == 202
        data = response.get_json()
        assert data["status"] == "accepted"
        assert data["job_id"] == job_id
        assert data["format"] == "cyclonedx"
        assert len(data["record_id"]) == 36
        assert data["status_url"] == f"/ingest/jobs/{job_id}"
        assert response.headers["Location"] == f"/ingest/jobs/{job_id}"

    def test_spdx_async_default_returns_202(self, client):
        """POST /ingest/spdx without ?sync=true returns 202 + job metadata."""
        job_id = str(uuid.uuid4())

        with self._patch_celery(
            "sbom_graph_enrichment.ingest_tasks.ingest_spdx",
            job_id,
        ):
            response = client.post(
                "/ingest/spdx",
                json={"sbom": _minimal_spdx()},
                content_type="application/json",
            )

        assert response.status_code == 202
        data = response.get_json()
        assert data["status"] == "accepted"
        assert data["job_id"] == job_id
        assert data["format"] == "spdx"
        assert len(data["record_id"]) == 36

    def test_sbom_autodetect_async_default_returns_202(self, client):
        """POST /ingest/sbom detects format and enqueues the unified task."""
        job_id = str(uuid.uuid4())

        with self._patch_celery(
            "sbom_graph_enrichment.ingest_tasks.ingest_sbom",
            job_id,
        ):
            response = client.post(
                "/ingest/sbom",
                json={"sbom": _minimal_cyclonedx()},
                content_type="application/json",
            )

        assert response.status_code == 202
        data = response.get_json()
        assert data["job_id"] == job_id
        # Format detection still runs server-side so callers see the result
        # without polling.
        assert data["format"] == "cyclonedx"

    def test_vex_async_default_returns_202(self, client):
        """POST /ingest/vex without ?sync=true returns 202 + job metadata."""
        job_id = str(uuid.uuid4())

        with self._patch_celery(
            "sbom_graph_enrichment.ingest_tasks.ingest_vex",
            job_id,
        ):
            response = client.post(
                "/ingest/vex",
                json={
                    "@context": "https://openvex.dev/ns",
                    "@id": "https://example.com/vex/1",
                    "author": "tester",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "statements": [],
                },
                content_type="application/json",
            )

        assert response.status_code == 202
        data = response.get_json()
        assert data["status"] == "accepted"
        assert data["job_id"] == job_id
        # VEX has no SBOM format, so `format` should not be set.
        assert "format" not in data

    def test_async_returns_503_when_celery_unavailable(self, client):
        """When the Celery client cannot be built the path returns 503.

        Production cause: misconfigured FALKORDB_* env vars or unreachable
        broker.  In all cases we must return a static error string -- no
        celery / redis exception detail leaks to the client (CWE-209).
        """
        with patch(
            "sbom_graph_api.services.celery_client.get_celery_client",
            side_effect=RuntimeError("broker unreachable: stacktrace path /tmp/x"),
        ):
            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": _minimal_cyclonedx()},
                content_type="application/json",
            )

        assert response.status_code == 503
        body = response.get_json()
        assert "not available" in body["error"].lower()
        # CWE-209: response body must not echo the underlying exception.
        assert "stacktrace" not in str(body).lower()
        assert "/tmp/x" not in str(body)

    def test_async_returns_503_when_send_task_fails(self, client):
        """``send_task`` exceptions are caught and mapped to 503.

        Mirrors the "client built fine but broker is down" scenario.
        """
        mock_celery_app = MagicMock()
        mock_celery_app.send_task.side_effect = ConnectionError(
            "internal hostname leak: redis-internal.cluster.local"
        )

        with patch(
            "sbom_graph_api.services.celery_client.get_celery_client",
            return_value=mock_celery_app,
        ):
            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": _minimal_cyclonedx()},
                content_type="application/json",
            )

        assert response.status_code == 503
        body = response.get_json()
        # Static error string only.
        assert "not available" in body["error"].lower()
        assert "redis-internal" not in str(body)

    def test_async_path_does_not_call_processor(self, client):
        """The async path must not invoke the in-process CycloneDX processor.

        This is the whole point of §10.6: heavy parse work happens in the
        worker, not the Flask request thread.  If a refactor accidentally
        wires the processor into the async branch we want a loud failure
        here rather than silent ingest-induced probe timeouts in prod.
        """
        job_id = str(uuid.uuid4())

        with (
            self._patch_celery(
                "sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx",
                job_id,
            ),
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_proc,
            patch(
                "sbom_graph_api.routes.ingest.create_ingestion_persistence"
            ) as mock_persist,
        ):
            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": _minimal_cyclonedx()},
                content_type="application/json",
            )

        assert response.status_code == 202
        mock_proc.assert_not_called()
        mock_persist.assert_not_called()


class TestSyncEscapeHatchAcceptance:
    """The ``?sync=true`` flag must accept multiple truthy spellings.

    The legacy ``201`` behaviour is exercised exhaustively in
    ``test_routes_ingest.py``; this test simply pins down which flag
    values flip the route into the synchronous branch.  If someone
    accidentally tightens ``_should_run_sync`` we want this to fail
    loudly so the documented contract stays stable.
    """

    def test_sync_flag_variants_dispatch_to_inline_path(self, client):
        from sbom_graph_model.cyclonedx import CycloneDXValidationError

        for flag in ("true", "1", "yes", "TRUE", "Yes"):
            with (
                patch("sbom_graph_api.routes.ingest.create_ingestion_persistence"),
                patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_cls,
            ):
                # Force the inline path to fail fast with a validation error;
                # we only care that the route entered ``_run_cyclonedx_inline``
                # and not ``_enqueue_async``.
                mock_proc = MagicMock()
                mock_proc.process_cyclone_dx_json.side_effect = (
                    CycloneDXValidationError("forced")
                )
                mock_cls.return_value = mock_proc

                response = client.post(
                    f"/ingest/cyclonedx?sync={flag}",
                    json={"sbom": _minimal_cyclonedx()},
                    content_type="application/json",
                )

            assert response.status_code == 422, (
                f"sync={flag!r} did not dispatch to inline path "
                f"(got {response.status_code})"
            )


# ---------------------------------------------------------------------------
# GET /ingest/jobs/<job_id>
# ---------------------------------------------------------------------------


class TestJobStatusEndpoint:
    """``GET /ingest/jobs/<id>`` mirrors the worker state to the client.

    Celery state strings are mapped onto a public schema so the API
    contract is independent of the broker:

    * Any state in ``_TERMINAL_STATES`` (SUCCESS / FAILURE / REVOKED)
      sets ``terminal: true`` and (for SUCCESS) attaches the worker's
      summary dict.
    * Non-terminal states (PENDING / STARTED / RETRY) set
      ``terminal: false`` so the CLI can keep polling.
    """

    def _patch_async_result(self, state: str, result):
        """Stub ``celery.result.AsyncResult`` and ``get_celery_client``."""
        mock_async_result_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.state = state
        mock_instance.result = result
        mock_async_result_cls.return_value = mock_instance

        mock_celery_app = MagicMock()

        # Patch where ``ingest`` binds the names (module-level imports), not
        # the defining modules — otherwise the route still calls the real
        # AsyncResult and hits Redis when ``.state`` is read.
        return _CombinedPatch(
            patch(
                "sbom_graph_api.routes.ingest.AsyncResult",
                mock_async_result_cls,
            ),
            patch(
                "sbom_graph_api.routes.ingest.get_celery_client",
                return_value=mock_celery_app,
            ),
        )

    def test_invalid_job_id_returns_400(self, client):
        """Non-UUID job ids are rejected before any backend lookup.

        Protects against using the endpoint to probe arbitrary Redis
        keys in the result backend (CWE-639-style misuse).
        """
        response = client.get("/ingest/jobs/not-a-uuid")
        assert response.status_code == 400
        assert "invalid" in response.get_json()["error"].lower()

    def test_success_returns_result(self, client):
        job_id = str(uuid.uuid4())
        worker_summary = {
            "status": "ok",
            "record_id": job_id,
            "format": "cyclonedx",
            "projects_count": 3,
        }

        with self._patch_async_result("SUCCESS", worker_summary):
            response = client.get(f"/ingest/jobs/{job_id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["job_id"] == job_id
        assert data["state"] == "SUCCESS"
        assert data["terminal"] is True
        assert data["result"] == worker_summary

    def test_failure_returns_sanitised_error(self, client):
        """A FAILURE state surfaces only a generic message, no traceback."""
        job_id = str(uuid.uuid4())

        # The worker would normally have caught its own exception; an
        # actual FAILURE state means an uncaught crash.  The endpoint
        # must NOT propagate the raw exception object (CWE-209).
        crash = RuntimeError("internal stacktrace with paths and PII")

        with self._patch_async_result("FAILURE", crash):
            response = client.get(f"/ingest/jobs/{job_id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["state"] == "FAILURE"
        assert data["terminal"] is True
        body = str(data["result"])
        assert "stacktrace" not in body
        assert "PII" not in body
        assert data["result"]["status"] == "error"

    def test_pending_is_not_terminal(self, client):
        """An in-flight or unknown job returns PENDING, not terminal."""
        job_id = str(uuid.uuid4())

        with self._patch_async_result("PENDING", None):
            response = client.get(f"/ingest/jobs/{job_id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["state"] == "PENDING"
        assert data["terminal"] is False
        # No `result` key for non-terminal states — caller should poll.
        assert "result" not in data

    def test_status_returns_503_when_celery_unavailable(self, client):
        """Same 503 fallback as the enqueue path."""
        job_id = str(uuid.uuid4())

        with patch(
            "sbom_graph_api.routes.ingest.get_celery_client",
            side_effect=RuntimeError("broker init failed: secret-host/secret-pw"),
        ):
            response = client.get(f"/ingest/jobs/{job_id}")

        assert response.status_code == 503
        body = response.get_json()
        # CWE-209: never leak the underlying exception detail.
        assert "secret-host" not in str(body)
        assert "secret-pw" not in str(body)


class _CombinedPatch:
    """Tiny helper to apply two ``unittest.mock`` patches as one ``with`` block.

    Avoids ``contextlib.ExitStack`` ceremony in tests that don't otherwise
    need it, and keeps the patch list inspectable from the test body.
    """

    def __init__(self, *patches) -> None:
        self._patches = patches

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for p in reversed(self._patches):
            p.stop()
