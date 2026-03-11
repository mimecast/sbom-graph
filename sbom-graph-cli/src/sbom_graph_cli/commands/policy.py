"""Policy command: annotate packages."""

from __future__ import annotations

import json
import sys

import click

from sbom_graph_cli.client import SBOMGraphClient
from sbom_graph_cli.utils import EXIT_SUCCESS


@click.group("policy")
def policy() -> None:
    """Manage policy annotations (bad/good/hold)."""


@policy.command("annotate")
@click.argument("purl", type=str)
@click.option(
    "--type", "annotation_type",
    type=click.Choice(["bad", "good", "hold"]),
    required=True,
    help="Policy annotation type: bad (banned), good (approved), hold (deprecated).",
)
@click.option(
    "--justification",
    "-j",
    required=True,
    help="Justification for the annotation.",
)
@click.pass_context
def annotate(
    ctx: click.Context,
    purl: str,
    annotation_type: str,
    justification: str,
) -> None:
    """Create a policy annotation on a package.

    Use --type to specify bad (banned), good (approved), or hold (deprecated).
    """
    if not purl.startswith("pkg:"):
        click.echo(
            click.style(
                "PURL must start with 'pkg:'", fg="red"
            ),
            err=True,
        )
        sys.exit(2)

    annotation = annotation_type

    client = SBOMGraphClient(api_url=ctx.obj["api_url"], token=ctx.obj["token"])
    try:
        result = client.annotate_policy(purl, annotation, justification)
        if ctx.obj["output_format"] == "json":
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo(
                click.style(
                    f"Annotation created: {result.get('type', annotation)} on {purl}",
                    fg="green",
                )
            )
        sys.exit(EXIT_SUCCESS)
    finally:
        client.close()
