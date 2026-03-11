"""Tests for ingest command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbom_graph_cli.cli import main


def test_ingest_success(sample_sbom_file: str) -> None:
    """ingest prints summary in table format."""
    mock_result = {
        "status": "ok",
        "record_id": "abc-123",
        "format": "cyclonedx",
        "projects_count": 1,
        "dependencies_count": 5,
        "defects_count": 2,
    }

    with patch("sbom_graph_cli.commands.ingest.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.ingest_sbom.return_value = mock_result
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(main, ["ingest", str(sample_sbom_file)])

        assert result.exit_code == 0
        mock_client.ingest_sbom.assert_called_once_with(str(sample_sbom_file))
        assert "Record ID" in result.output
        assert "abc-123" in result.output


def test_ingest_json_output(sample_sbom_file: str) -> None:
    """ingest with --output json prints JSON."""
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
