"""Tests for main CLI entry point."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from sbom_graph_cli.cli import _run, main
from sbom_graph_cli.utils import EXIT_ERROR, APIError


def test_main_help() -> None:
    """Main command shows help."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "sbom-graph" in result.output
    assert "ingest" in result.output
    assert "query" in result.output
    assert "policy" in result.output
    assert "export" in result.output


def test_main_api_url_option() -> None:
    """--api-url is accepted."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--api-url", "https://api.example.com", "ingest", "--help"],
    )
    assert result.exit_code == 0


def test_run_exits_on_api_error() -> None:
    """_run exits with EXIT_ERROR when APIError raised."""
    with patch("sbom_graph_cli.cli.main") as mock_main:
        mock_main.side_effect = APIError("Connection refused")

        with pytest.raises(SystemExit) as exc_info:
            _run()

        assert exc_info.value.code == EXIT_ERROR


def test_run_exits_130_on_keyboard_interrupt() -> None:
    """_run exits 130 on KeyboardInterrupt."""
    with patch("sbom_graph_cli.cli.main") as mock_main:
        mock_main.side_effect = KeyboardInterrupt()

        with pytest.raises(SystemExit) as exc_info:
            _run()

        assert exc_info.value.code == 130

