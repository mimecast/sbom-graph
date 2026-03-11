"""Tests for query commands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbom_graph_cli.cli import main


def test_query_vulns_success() -> None:
    """query vulns prints table."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_vulnerabilities.return_value = [
            {"id": "CVE-2024-1", "severity": "HIGH", "cvss": 7.5, "title": "Test"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["query", "vulns", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert "CVE-2024-1" in result.output
        assert "HIGH" in result.output


def test_query_vulns_invalid_purl() -> None:
    """query vulns with invalid purl exits 2."""
    runner = CliRunner()
    result = runner.invoke(main, ["query", "vulns", "invalid"])
    assert result.exit_code == 2


def test_query_deps_success() -> None:
    """query deps prints table."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_dependencies.return_value = [
            {"depth": 1, "dependency_project": "bar", "dependency_version": "2.0"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["query", "deps", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert "bar" in result.output


def test_query_deps_json_output() -> None:
    """query deps --output json prints JSON."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_dependencies.return_value = [
            {"depth": 1, "dependency_project": "bar", "dependency_version": "2.0"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--output", "json", "query", "deps", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert '"dependencies"' in result.output


def test_query_patch_plan_success() -> None:
    """query patch-plan prints table."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_patch_plan.return_value = [
            {
                "priority": 1,
                "project_name": "foo",
                "version_name": "1.0",
                "is_direct": True,
                "dependant_count": 2,
                "recommended_action": "Upgrade",
            },
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["query", "patch-plan", "CVE-2024-1234"],
        )

        assert result.exit_code == 0
        assert "foo" in result.output
        assert "Upgrade" in result.output


def test_query_vulns_json_output() -> None:
    """query vulns --output json prints JSON."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_vulnerabilities.return_value = [
            {"id": "CVE-1", "severity": "HIGH"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--output", "json", "query", "vulns", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert '"vulnerabilities"' in result.output
        assert '"CVE-1"' in result.output


def test_query_deps_invalid_purl() -> None:
    """query deps with invalid purl exits 2."""
    runner = CliRunner()
    result = runner.invoke(main, ["query", "deps", "invalid"])
    assert result.exit_code == 2


def test_query_dependants_invalid_purl() -> None:
    """query dependants with invalid purl exits 2."""
    runner = CliRunner()
    result = runner.invoke(main, ["query", "dependants", "invalid"])
    assert result.exit_code == 2


def test_query_deps_no_dependencies_row() -> None:
    """query deps with (no dependencies) shows single row."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_dependencies.return_value = [
            {"dependency_project": "(no dependencies)"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["query", "deps", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert "(no dependencies)" in result.output


def test_query_dependants_success() -> None:
    """query dependants prints table."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_dependants.return_value = [
            {"project_name": "app-a", "version": "1.0", "partition": 2},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["query", "dependants", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert "app-a" in result.output


def test_query_dependants_json_output() -> None:
    """query dependants --output json prints JSON."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_dependants.return_value = [
            {"project_name": "app", "version": "1.0"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--output", "json", "query", "dependants", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert '"dependants"' in result.output


def test_query_patch_plan_json_output() -> None:
    """query patch-plan --output json prints JSON."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_patch_plan.return_value = [
            {"priority": 1, "project_name": "foo", "version_name": "2.0"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--output",
                "json",
                "query",
                "patch-plan",
                "CVE-2024-1234",
            ],
        )

        assert result.exit_code == 0
        assert '"patch_plan"' in result.output


def test_query_vulns_severity_styles() -> None:
    """query vulns renders severity styles (CRITICAL, MEDIUM, LOW, UNKNOWN)."""
    with patch("sbom_graph_cli.commands.query.SBOMGraphClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.get_vulnerabilities.return_value = [
            {"id": "CVE-1", "severity": "CRITICAL"},
            {"id": "CVE-2", "severity": "MEDIUM"},
            {"id": "CVE-3", "severity": "LOW"},
            {"id": "CVE-4", "severity": "UNKNOWN"},
        ]
        mock_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["query", "vulns", "pkg:maven/org/foo@1.0"],
        )

        assert result.exit_code == 0
        assert "CRITICAL" in result.output
        assert "MEDIUM" in result.output
        assert "LOW" in result.output
        assert "UNKNOWN" in result.output
