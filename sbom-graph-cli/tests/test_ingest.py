"""Tests for the ``ingest`` CLI command.

The server defaults to asynchronous ingestion (see
``docs/sbom-graph-api-troubleshooting.md`` §10.6); the CLI defaults to
``--wait`` and polls the job-status endpoint behind the scenes.  These
tests exercise:

* the default wait-and-poll happy path
* the ``--no-wait`` fire-and-forget path
* the ``--sync`` legacy escape hatch (``?sync=true`` on the server)
* JSON output mode
* file-not-found error handling
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbom_graph_cli.cli import main


_TERMINAL_SUMMARY = {
    "status": "ok",
    "record_id": "abc-123",
    "format": "cyclonedx",
    "projects_count": 1,
    "dependencies_count": 5,
    "defects_count": 2,
}


def test_ingest_success_default_waits(sample_sbom_file: str) -> None:
    """Default invocation forwards wait/sync defaults and prints the summary."""
    with patch("sbom_graph_cli.commands.ingest.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.ingest_sbom.return_value = _TERMINAL_SUMMARY
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(main, ["ingest", str(sample_sbom_file)])

        assert result.exit_code == 0, result.output
        mock_client.ingest_sbom.assert_called_once()
        _, kwargs = mock_client.ingest_sbom.call_args
        # The CLI must default to ``wait=True`` so legacy scripts keep
        # working without modification.
        assert kwargs["wait"] is True
        assert kwargs["sync"] is False
        assert "on_poll" in kwargs and callable(kwargs["on_poll"])
        assert "Record ID" in result.output
        assert "abc-123" in result.output


def test_ingest_no_wait_prints_async_envelope(sample_sbom_file: str) -> None:
    """``--no-wait`` surfaces the 202 envelope (job_id + status_url)."""
    envelope = {
        "status": "accepted",
        "record_id": "abc-123",
        "job_id": "job-xyz",
        "status_url": "/ingest/jobs/job-xyz",
        "format": "cyclonedx",
    }
    with patch("sbom_graph_cli.commands.ingest.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.ingest_sbom.return_value = envelope
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--no-wait", str(sample_sbom_file)]
        )

        assert result.exit_code == 0, result.output
        _, kwargs = mock_client.ingest_sbom.call_args
        assert kwargs["wait"] is False
        assert kwargs["sync"] is False
        # 202 envelope renderer must show the polling handle.
        assert "Job ID" in result.output
        assert "job-xyz" in result.output
        assert "/ingest/jobs/job-xyz" in result.output


def test_ingest_sync_flag_forwarded(sample_sbom_file: str) -> None:
    """``--sync`` flips the client to the legacy synchronous path."""
    with patch("sbom_graph_cli.commands.ingest.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.ingest_sbom.return_value = _TERMINAL_SUMMARY
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--sync", str(sample_sbom_file)]
        )

        assert result.exit_code == 0, result.output
        _, kwargs = mock_client.ingest_sbom.call_args
        assert kwargs["sync"] is True
        assert "Record ID" in result.output


def test_ingest_json_output(sample_sbom_file: str) -> None:
    """``--output json`` prints the raw summary dict, no spinner."""
    mock_result = {"status": "ok", "record_id": "x", "projects_count": 1}

    with patch("sbom_graph_cli.commands.ingest.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.ingest_sbom.return_value = mock_result
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--output", "json", "ingest", str(sample_sbom_file)],
        )

        assert result.exit_code == 0
        assert '"record_id": "x"' in result.output


def test_ingest_file_not_found() -> None:
    """ingest with missing file fails."""
    runner = CliRunner()
    result = runner.invoke(main, ["ingest", "/nonexistent.json"])
    assert result.exit_code != 0
