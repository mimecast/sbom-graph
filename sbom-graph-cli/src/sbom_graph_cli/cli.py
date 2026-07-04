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
    help="Base URL of the sbom-graph API (use https:// off localhost).",
)
@click.option(
    "--token",
    envvar="SBOM_GRAPH_TOKEN",
    default=None,
    help="API token (prefer the SBOM_GRAPH_TOKEN env var over --token).",
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

    # L3 (CWE-214): a token on the command line is visible to other local users
    # (ps / /proc); steer to the env var instead.
    token_src = ctx.get_parameter_source("token")
    if token and token_src == click.core.ParameterSource.COMMANDLINE:
        click.echo(
            "WARNING: passing --token on the command line exposes it in the process "
            "list; prefer the SBOM_GRAPH_TOKEN environment variable.",
            err=True,
        )
    # L4 (CWE-319): non-local http:// API URL sends the bearer token in cleartext.
    _local = any(h in api_url for h in ("localhost", "127.0.0.1", "[::1]"))
    if token and api_url.startswith("http://") and not _local:
        click.echo(
            "WARNING: API URL uses plaintext http://; the API token will be sent "
            "unencrypted. Use https://.",
            err=True,
        )


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
