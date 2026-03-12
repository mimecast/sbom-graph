"""Tests for export command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbom_graph_cli.cli import main


def test_export_success(tmp_path) -> None:
    """export saves report to file."""
    with patch("sbom_graph_cli.commands.export.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.export_report.return_value = b'{"data": []}'
        mock_cls.return_value = mock_client

        runner = CliRunner()
        out_file = str(tmp_path / "report.json")
        result = runner.invoke(
            main,
            [
                "export",
                "vulnerabilities",
                "--format",
                "json",
                "--output",
                out_file,
            ],
        )

        assert result.exit_code == 0
        mock_client.export_report.assert_called_once_with(
            "vulnerabilities", output_format="json",
        )
        with open(out_file, "rb") as f:
            assert f.read() == b'{"data": []}'


def test_export_stdout_json() -> None:
    """export with json format writes to stdout when no -o."""
    with patch("sbom_graph_cli.commands.export.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.export_report.return_value = b'{"data": []}'
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["export", "vulnerabilities", "--format", "json"],
        )

        assert result.exit_code == 0
        assert "data" in result.output


def test_export_excel_no_output_suggests_filename() -> None:
    """export excel without -o suggests filename and writes to stdout."""
    with patch("sbom_graph_cli.commands.export.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.export_report.return_value = b"xlsx-content"
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["export", "vulnerabilities", "--format", "excel"],
        )

        assert result.exit_code == 0
        assert "vulnerabilities.xlsx" in result.output
        assert "12 bytes" in result.output
