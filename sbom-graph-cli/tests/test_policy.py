"""Tests for policy command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbom_graph_cli.cli import main


def test_policy_annotate_bad() -> None:
    """policy annotate --type bad creates annotation."""
    with patch(
        "sbom_graph_cli.commands.policy.SBOMGraphClient"
    ) as mock_cls:
        mock_client = MagicMock()
        mock_client.annotate_policy.return_value = {
            "annotation_id": "uuid",
            "purl": "pkg:maven/org/foo@1.0",
            "type": "bad",
        }
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "policy",
                "annotate",
                "pkg:maven/org/foo@1.0",
                "--type",
                "bad",
                "--justification",
                "Security issue",
            ],
        )

        assert result.exit_code == 0
        mock_client.annotate_policy.assert_called_once_with(
            "pkg:maven/org/foo@1.0",
            "bad",
            "Security issue",
        )
        assert "bad" in result.output


def test_policy_annotate_invalid_purl() -> None:
    """policy annotate with invalid purl exits 2."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "policy", "annotate", "invalid",
            "--type", "bad",
            "--justification", "x",
        ],
    )
    assert result.exit_code == 2


def test_policy_annotate_missing_type() -> None:
    """policy annotate without --type exits 2."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "policy", "annotate",
            "pkg:maven/org/foo@1.0",
            "--justification", "x",
        ],
    )
    assert result.exit_code == 2


def test_policy_annotate_json_output() -> None:
    """policy annotate --output json prints JSON."""
    with patch(
        "sbom_graph_cli.commands.policy.SBOMGraphClient"
    ) as mock_cls:
        mock_client = MagicMock()
        mock_client.annotate_policy.return_value = {
            "annotation_id": "uuid",
            "type": "good",
        }
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--output",
                "json",
                "policy",
                "annotate",
                "pkg:maven/org/foo@1.0",
                "--type",
                "good",
                "--justification",
                "Approved",
            ],
        )

        assert result.exit_code == 0
        assert '"annotation_id"' in result.output
