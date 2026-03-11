"""Export command: download reports."""

from __future__ import annotations

import sys

import click

from sbom_graph_cli.client import SBOMGraphClient


@click.command("export")
@click.argument("report_name", type=str)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "excel", "csv"]),
    default="json",
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(path_type=str),
    default=None,
    help="Write to file (default: stdout for json, else report filename).",
)
@click.pass_context
def export(
    ctx: click.Context,
    report_name: str,
    fmt: str,
    output_path: str | None,
) -> None:
    """Export a report.

    Report names: vulnerabilities, snapshots, projects, applications,
    incident-response/CVE-1234, etc.
    """
    client = SBOMGraphClient(api_url=ctx.obj["api_url"], token=ctx.obj["token"])
    try:
        content = client.export_report(report_name, output_format=fmt)
        if output_path:
            with open(output_path, "wb") as f:
                f.write(content)
            click.echo(click.style(f"Saved to {output_path}", fg="green"))
        else:
            if fmt == "json":
                sys.stdout.buffer.write(content)
            else:
                # For Excel/CSV, suggest a filename
                safe = report_name.replace("/", "_").replace(" ", "_")
                ext = "xlsx" if fmt == "excel" else "csv"
                fname = f"{safe}.{ext}"
                click.echo(
                    click.style(
                        f"Use -o {fname} to save {len(content)} bytes",
                        fg="yellow",
                    ),
                    err=True,
                )
                sys.stdout.buffer.write(content)
    finally:
        client.close()
