"""Unit tests for the asynchronous SBOM ingest tasks.

These tests cover :mod:`sbom_graph_enrichment.ingest_tasks` -- the
dedicated worker pool entry points that back the API's async
``POST /ingest/*`` endpoints (see ``docs/sbom-graph-api-troubleshooting.md``
§10.6).

The strategy is the same as the existing ``test_tasks.py`` suite:

* Call the pure :func:`process_cyclonedx` / :func:`process_spdx`
  functions directly with a fully mocked :class:`Persistence`.
* Mock the SBOM processor classes from ``sbom_graph_model`` so we never
  exercise live SBOM parsing -- that has its own test suite.
* For the ``@shared_task`` wrappers, monkey-patch
  :func:`get_persistence` so the worker tasks don't try to open a real
  FalkorDB connection.

The two security guarantees that must not regress are:

* Validation errors return a static, sanitised error dict (``{"status":
  "error", "error": "...validation failed"}``) -- no traceback leaks
  through the broker (CWE-209).
* Unexpected exceptions are caught and replaced with the generic
  ``"An unexpected error occurred while processing the SBOM"`` message.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from sbom_graph_model.cyclonedx import CycloneDXValidationError
from sbom_graph_model.spdx import SPDXValidationError

from sbom_graph_enrichment.ingest_tasks import (
    _derive_app_id,
    _document_hash,
    _extract_cyclonedx_tool_info,
    _extract_spdx_tool_info,
    _parse_spdx_tool_creator,
    detect_sbom_format,
    ingest_cyclonedx,
    ingest_sbom,
    ingest_spdx,
    ingest_vex,
    process_cyclonedx,
    process_spdx,
)


# ---------------------------------------------------------------------------
# Pure-helper unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    """Helpers that don't touch Persistence or external services."""

    def test_derive_app_id_is_deterministic(self) -> None:
        assert _derive_app_id("acme-service") == _derive_app_id("acme-service")
        assert _derive_app_id("a") != _derive_app_id("b")

    def test_document_hash_is_stable_across_key_order(self) -> None:
        doc1 = {"a": 1, "b": {"x": 1, "y": 2}}
        doc2 = {"b": {"y": 2, "x": 1}, "a": 1}
        assert _document_hash(doc1) == _document_hash(doc2)
        assert len(_document_hash(doc1)) == 64  # SHA-256 hex

    def test_extract_cyclonedx_tool_info_from_v1_5_components(self) -> None:
        sbom = {"metadata": {"tools": {"components": [{"name": "syft", "version": "0.99"}]}}}
        assert _extract_cyclonedx_tool_info(sbom) == ("syft", "0.99")

    def test_extract_cyclonedx_tool_info_from_v1_4_list(self) -> None:
        sbom = {"metadata": {"tools": [{"name": "cyclonedx-cli", "version": "0.25.0"}]}}
        assert _extract_cyclonedx_tool_info(sbom) == ("cyclonedx-cli", "0.25.0")

    def test_extract_cyclonedx_tool_info_missing_tools_returns_none(self) -> None:
        assert _extract_cyclonedx_tool_info({}) == (None, None)
        assert _extract_cyclonedx_tool_info({"metadata": {}}) == (None, None)

    def test_extract_spdx_tool_info_picks_first_tool_creator(self) -> None:
        sbom = {"creationInfo": {"creators": ["Organization: acme", "Tool: trivy-0.45.0"]}}
        assert _extract_spdx_tool_info(sbom) == ("trivy", "0.45.0")

    def test_parse_spdx_tool_creator_handles_no_version(self) -> None:
        assert _parse_spdx_tool_creator("trivy") == ("trivy", None)

    def test_parse_spdx_tool_creator_handles_dashed_name(self) -> None:
        # "syft-cli-1.0.0" -> name has dash, version is the last numeric part.
        assert _parse_spdx_tool_creator("syft-cli-1.0.0") == ("syft-cli", "1.0.0")

    def test_detect_sbom_format(self) -> None:
        assert detect_sbom_format({"bomFormat": "CycloneDX"}) == "cyclonedx"
        assert detect_sbom_format({"spdxVersion": "SPDX-2.3"}) == "spdx"
        assert detect_sbom_format({"metadata": {"component": {}}}) == "cyclonedx"
        assert detect_sbom_format({"random": "json"}) is None


# ---------------------------------------------------------------------------
# process_cyclonedx / process_spdx (pure functions, used by both worker
# tasks and the synchronous API path).
# ---------------------------------------------------------------------------


def _cdx_sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "metadata": {"component": {"name": "svc", "version": "1.0.0", "bom-ref": "app"}},
        "components": [],
        "dependencies": [],
    }


def _spdx_doc() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "svc",
        "packages": [],
        "relationships": [],
    }


class TestProcessCyclonedx:
    def test_returns_summary_and_persists_record(self) -> None:
        persistence = MagicMock()
        with patch("sbom_graph_enrichment.ingest_tasks.CycloneDXProcessor") as proc_cls:
            proj = MagicMock()
            proj.purl = "pkg:maven/com.example/app@1.0.0"
            proj.name = "app"
            proj.group = "com.example"
            ver = MagicMock(version="1.0.0")
            proc = MagicMock()
            proc.process_cyclone_dx_json.return_value = (
                {"app-ref": (proj, ver)},
                {"app-ref": {"c1", "c2"}},
                {},
            )
            proc_cls.return_value = proc

            summary = process_cyclonedx(
                persistence=persistence,
                record_id="rec-1",
                sbom=_cdx_sbom(),
                app_id="aid",
                public_app_id="svc",
                project_url=None,
            )

        assert summary == {
            "status": "ok",
            "record_id": "rec-1",
            "format": "cyclonedx",
            "app_id": "aid",
            "public_app_id": "svc",
            "projects_count": 1,
            "dependencies_count": 2,
            "defects_count": 0,
        }
        persistence.create_sbom_record.assert_called_once()
        kwargs = persistence.create_sbom_record.call_args.kwargs
        assert kwargs["sbom_format"] == "cyclonedx"
        assert kwargs["source"] == "api_upload"
        assert kwargs["serial_number"] == "urn:uuid:11111111-1111-1111-1111-111111111111"
        assert kwargs["document_hash"] == _document_hash(_cdx_sbom())
        persistence.link_version_to_sbom_record.assert_called_once_with(
            "pkg:maven/com.example/app@1.0.0", "rec-1"
        )

    def test_links_by_name_when_no_purl(self) -> None:
        persistence = MagicMock()
        with patch("sbom_graph_enrichment.ingest_tasks.CycloneDXProcessor") as proc_cls:
            proj = MagicMock()
            proj.purl = None
            proj.name = "app"
            proj.group = "com.example"
            ver = MagicMock(version="1.0.0")
            proc = MagicMock()
            proc.process_cyclone_dx_json.return_value = ({"r": (proj, ver)}, {"r": set()}, {})
            proc_cls.return_value = proc

            process_cyclonedx(
                persistence=persistence,
                record_id="rec-2",
                sbom=_cdx_sbom(),
                app_id="aid",
                public_app_id="svc",
                project_url=None,
            )

        persistence.link_version_to_sbom_record_by_name.assert_called_once_with(
            "app", "com.example", "1.0.0", "rec-2"
        )

    def test_validation_error_propagates(self) -> None:
        """``process_cyclonedx`` re-raises validation errors so the task
        wrapper can convert them to the sanitised broker payload."""
        persistence = MagicMock()
        with patch("sbom_graph_enrichment.ingest_tasks.CycloneDXProcessor") as proc_cls:
            proc = MagicMock()
            proc.process_cyclone_dx_json.side_effect = CycloneDXValidationError("missing field")
            proc_cls.return_value = proc

            with pytest.raises(CycloneDXValidationError):
                process_cyclonedx(
                    persistence=persistence,
                    record_id="x",
                    sbom=_cdx_sbom(),
                    app_id="a",
                    public_app_id="s",
                    project_url=None,
                )

        persistence.create_sbom_record.assert_not_called()


class TestProcessSpdx:
    def test_returns_summary_and_persists_record(self) -> None:
        persistence = MagicMock()
        with patch("sbom_graph_enrichment.ingest_tasks.SPDXProcessor") as proc_cls:
            pkg = MagicMock()
            pkg.purl = "pkg:pypi/foo@1.0"
            pkg.name = "foo"
            pkg.group = None
            ver = MagicMock(version="1.0")
            proc = MagicMock()
            proc.process_spdx_json.return_value = ({"p": (pkg, ver)}, {"p": set()}, [])
            proc_cls.return_value = proc

            summary = process_spdx(
                persistence=persistence,
                record_id="r-s",
                sbom=_spdx_doc(),
                app_id="a",
                public_app_id="svc",
                project_url=None,
            )

        assert summary["format"] == "spdx"
        assert summary["projects_count"] == 1
        kwargs = persistence.create_sbom_record.call_args.kwargs
        assert kwargs["sbom_format"] == "spdx"
        # SPDX has no serialNumber concept
        assert kwargs["serial_number"] is None


# ---------------------------------------------------------------------------
# Celery task wrappers — exception path produces sanitised broker payload.
# ---------------------------------------------------------------------------


def _stub_persistence():
    """Build a persistence stub used by the @shared_task wrappers.

    The wrappers call ``get_persistence()`` which returns a per-process
    cached :class:`Persistence`.  We patch it to a MagicMock so the
    tasks never try to open a real FalkorDB connection during tests.
    """
    return MagicMock()


class TestIngestTaskWrappers:
    """The Celery wrappers should never let exceptions escape — they must
    return a static sanitised dict so callers polling the result backend
    don't get a leak of internal state (CWE-209, CWE-497)."""

    def test_ingest_cyclonedx_happy_path(self) -> None:
        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_cyclonedx",
                return_value={"status": "ok", "record_id": "r1"},
            ) as p,
        ):
            result = ingest_cyclonedx(
                record_id="r1",
                sbom=_cdx_sbom(),
                app_id="a",
                public_app_id="s",
            )

        assert result == {"status": "ok", "record_id": "r1"}
        assert p.called

    def test_ingest_cyclonedx_validation_error_is_sanitised(self) -> None:
        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_cyclonedx",
                side_effect=CycloneDXValidationError("bad serial: secret-token-123"),
            ),
        ):
            result = ingest_cyclonedx(
                record_id="r1",
                sbom=_cdx_sbom(),
                app_id="a",
                public_app_id="s",
            )

        assert result == {"status": "error", "error": "CycloneDX validation failed"}
        # The PII from the exception message must NOT be in the result.
        assert "secret-token-123" not in json.dumps(result)

    def test_ingest_cyclonedx_unexpected_exception_is_sanitised(self) -> None:
        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_cyclonedx",
                side_effect=RuntimeError("/etc/secrets/db.pem read failed"),
            ),
        ):
            result = ingest_cyclonedx(
                record_id="r1",
                sbom=_cdx_sbom(),
                app_id="a",
                public_app_id="s",
            )

        assert result["status"] == "error"
        assert "unexpected" in result["error"].lower()
        assert "/etc/secrets" not in json.dumps(result)

    @patch("sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx.retry")
    def test_ingest_cyclonedx_transient_failure_retries_when_dispatched(
        self, mock_retry: MagicMock
    ) -> None:
        """Dispatched via the broker (not a direct call): a transient failure
        must actually retry rather than degrade to a sanitised error -- the
        whole point of adding retry is that a MERGE-based re-run can heal a
        partially-persisted SBOM from a transient Redis/FalkorDB failure."""
        mock_retry.side_effect = RuntimeError("retry")

        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_cyclonedx",
                side_effect=RuntimeError("/etc/secrets/db.pem read failed"),
            ),
        ):
            task = ingest_cyclonedx.apply(
                kwargs={
                    "record_id": "r1",
                    "sbom": _cdx_sbom(),
                    "app_id": "a",
                    "public_app_id": "s",
                },
            )
            try:
                task.get()
            except RuntimeError as e:
                if "retry" not in str(e):
                    raise
        mock_retry.assert_called_once()

    def test_ingest_spdx_validation_error_is_sanitised(self) -> None:
        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_spdx",
                side_effect=SPDXValidationError("malformed: api_key=ABCD1234"),
            ),
        ):
            result = ingest_spdx(
                record_id="r1",
                sbom=_spdx_doc(),
                app_id="a",
                public_app_id="s",
            )

        assert result == {"status": "error", "error": "SPDX validation failed"}
        assert "ABCD1234" not in json.dumps(result)

    def test_ingest_sbom_auto_detect_cyclonedx(self) -> None:
        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_cyclonedx",
                return_value={"status": "ok", "format": "cyclonedx"},
            ),
        ):
            result = ingest_sbom(
                record_id="r1",
                sbom=_cdx_sbom(),
                app_id="a",
                public_app_id="s",
            )
        assert result["format"] == "cyclonedx"

    def test_ingest_sbom_auto_detect_spdx(self) -> None:
        with (
            patch(
                "sbom_graph_enrichment.ingest_tasks.get_persistence",
                return_value=_stub_persistence(),
            ),
            patch(
                "sbom_graph_enrichment.ingest_tasks.process_spdx",
                return_value={"status": "ok", "format": "spdx"},
            ),
        ):
            result = ingest_sbom(
                record_id="r1",
                sbom=_spdx_doc(),
                app_id="a",
                public_app_id="s",
            )
        assert result["format"] == "spdx"

    def test_ingest_sbom_unrecognised_format_returns_error(self) -> None:
        with patch(
            "sbom_graph_enrichment.ingest_tasks.get_persistence",
            return_value=_stub_persistence(),
        ):
            result = ingest_sbom(
                record_id="r1",
                sbom={"random": "blob"},
                app_id="a",
                public_app_id="s",
            )
        assert result["status"] == "error"
        assert "detect" in result["error"].lower()

    def test_ingest_vex_missing_module_returns_error(self) -> None:
        """If the VEX processor isn't packaged in this image, the task
        must surface a clean error rather than crash the worker."""
        with patch.dict("sys.modules", {"sbom_graph_model.vex": None}):
            result = ingest_vex({"@context": "https://openvex.dev/ns"})

        assert result["status"] == "error"
        assert "not available" in result["error"].lower()
