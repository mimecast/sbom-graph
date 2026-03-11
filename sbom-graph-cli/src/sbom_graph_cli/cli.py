"""Main Click group for sbom-graph CLI."""

from __future__ import annotations

import sys

import click

from sbom_graph_cli.commands import export, ingest, policy, query
from sbom_graph_cli.utils import EXIT_ERROR, APIError


@click.group()
@click.option(
    "--api-url",
    envvar="SBOM_GRAPH_API_URL",
    default="http://localhost:5000",
    help="Base URL of the sbom-graph API.",
)
@click.option(
    "--token",
    envvar="SBOM_GRAPH_TOKEN",
    default=None,
    help="API token for authentication.",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format: table (human-readable) or json (machine-parseable).",
)
@click.pass_context
def main(
    ctx: click.Context,
    api_url: str,
    token: str | None,
    output_format: str,
) -> None:
    """sbom-graph CLI: ingest SBOMs, query vulnerabilities, manage policy."""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url
    ctx.obj["token"] = token
    ctx.obj["output_format"] = output_format


# Register command groups and subcommands
main.add_command(ingest.ingest)
main.add_command(query.query)
main.add_command(policy.policy)
main.add_command(export.export)


def _run() -> None:
    """Entry point for the CLI script."""
    try:
        main()  # pylint: disable=no-value-for-parameter
    except APIError as e:
        click.echo(click.style(str(e), fg="red"), err=True)
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        click.echo(click.style("Interrupted", fg="yellow"), err=True)
        sys.exit(130)


# Entry point for console script
if __name__ == "__main__":
    _run()
