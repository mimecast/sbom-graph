"""Ingest command: upload SBOM files."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn
from rich.table import Table

from sbom_graph_cli.client import SBOMGraphClient


@click.command("ingest")
@click.argument("file", type=click.Path(exists=True, path_type=str))
@click.pass_context
def ingest(ctx: click.Context, file: str) -> None:
    """Upload a CycloneDX or SPDX SBOM file.

    Auto-detects format and prints a summary (projects, dependencies,
    defects, record_id).
    """
    api_url = ctx.obj["api_url"]
    token = ctx.obj["token"]
    output_format = ctx.obj["output_format"]

    client = SBOMGraphClient(api_url=api_url, token=token)
    try:
        if output_format == "json":
            result = client.ingest_sbom(file)
            click.echo(json.dumps(result, indent=2))
        else:
            with Progress(
                SpinnerColumn(),
                console=Console(),
                transient=True,
            ) as progress:
                task = progress.add_task("Uploading SBOM...", total=None)
                result = client.ingest_sbom(file)
                progress.update(task, completed=1)

            table = Table(title="Ingest Summary")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Record ID", result.get("record_id", "-"))
            table.add_row("Format", result.get("format", "cyclonedx"))
            table.add_row("Projects", str(result.get("projects_count", 0)))
            table.add_row("Dependencies", str(result.get("dependencies_count", 0)))
            table.add_row("Defects", str(result.get("defects_count", 0)))
            console = Console()
            console.print(table)
    finally:
        client.close()
