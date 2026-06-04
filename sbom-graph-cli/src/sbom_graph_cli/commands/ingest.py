"""Ingest command: upload SBOM files.

The server defaults to asynchronous ingestion (``202 Accepted`` + a
``job_id`` returned immediately, with the heavy parse-and-persist work
running on a dedicated Celery worker pool -- see
``docs/sbom-graph-api-troubleshooting.md`` §10.6 and
``docs/ingest-pipeline.md``).

For backwards-compatible scripting UX this command defaults to
``--wait`` -- the CLI polls the job-status endpoint until the worker
reaches a terminal state and prints the same summary the legacy
synchronous handler would have returned.  Two opt-out flags are
available:

* ``--no-wait``     -- print the ``202`` envelope (``job_id``,
                       ``status_url``) and exit ``0`` immediately.
                       Use for fire-and-forget CI/CD steps that don't
                       block on completion.
* ``--sync``        -- request the legacy synchronous server path
                       (``?sync=true``).  The API processes the SBOM
                       inline and returns ``201``.  Useful when the
                       dedicated ingest worker pool is disabled, or
                       for very small SBOMs in test scripts.
"""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sbom_graph_cli.client import SBOMGraphClient


def _render_async_envelope(envelope: dict) -> None:
    """Pretty-print the 202 envelope when ``--no-wait`` is set."""
    table = Table(title="Ingest Job Accepted")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Status", envelope.get("status", "accepted"))
    table.add_row("Record ID", envelope.get("record_id", "-"))
    table.add_row("Job ID", envelope.get("job_id", "-"))
    table.add_row("Status URL", envelope.get("status_url", "-"))
    if "format" in envelope:
        table.add_row("Format", envelope["format"])
    Console().print(table)


def _render_terminal_summary(result: dict) -> None:
    """Pretty-print the worker's terminal summary (same shape as legacy 201)."""
    table = Table(title="Ingest Summary")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Record ID", result.get("record_id", "-"))
    table.add_row("Format", result.get("format", "cyclonedx"))
    table.add_row("Projects", str(result.get("projects_count", 0)))
    table.add_row("Dependencies", str(result.get("dependencies_count", 0)))
    table.add_row("Defects", str(result.get("defects_count", 0)))
    Console().print(table)


@click.command("ingest")
@click.argument("file", type=click.Path(exists=True, path_type=str))
@click.option(
    "--wait/--no-wait",
    default=True,
    show_default=True,
    help=(
        "Wait for the async ingest job to finish before exiting.  "
        "With --no-wait the command returns immediately with a job id "
        "that can be polled via /ingest/jobs/<id>."
    ),
)
@click.option(
    "--sync",
    is_flag=True,
    default=False,
    help=(
        "Force the legacy synchronous server path (?sync=true).  "
        "The API processes the SBOM inline rather than enqueuing it.  "
        "Implies --wait."
    ),
)
@click.option(
    "--poll-interval",
    type=click.FloatRange(min=0.1, max=60.0),
    default=1.0,
    show_default=True,
    help="Seconds between job status polls when --wait is active.",
)
@click.option(
    "--poll-timeout",
    type=click.FloatRange(min=1.0, max=7200.0),
    default=600.0,
    show_default=True,
    help="Maximum seconds to wait for the ingest job to finish.",
)
@click.pass_context
def ingest(
    ctx: click.Context,
    file: str,
    wait: bool,
    sync: bool,
    poll_interval: float,
    poll_timeout: float,
) -> None:
    """Upload a CycloneDX or SPDX SBOM file.

    Auto-detects format and prints a summary (projects, dependencies,
    defects, record_id) once the worker finishes.
    """
    api_url = ctx.obj["api_url"]
    token = ctx.obj["token"]
    output_format = ctx.obj["output_format"]

    client = SBOMGraphClient(api_url=api_url, token=token)
    try:
        if output_format == "json":
            result = client.ingest_sbom(
                file,
                wait=wait,
                sync=sync,
                poll_interval=poll_interval,
                poll_timeout=poll_timeout,
            )
            click.echo(json.dumps(result, indent=2))
            return

        # Table output -- drive a spinner from the poll callback so the
        # user gets feedback while the worker is running.  The spinner
        # text reflects the most recent Celery state ("PENDING",
        # "STARTED", etc).
        if wait and not sync:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=Console(),
                transient=True,
            ) as progress:
                task = progress.add_task("Uploading SBOM (queued)...", total=None)

                def _on_poll(status: dict) -> None:
                    state = status.get("state", "unknown")
                    progress.update(task, description=f"Ingesting (state: {state})...")

                result = client.ingest_sbom(
                    file,
                    wait=True,
                    sync=False,
                    poll_interval=poll_interval,
                    poll_timeout=poll_timeout,
                    on_poll=_on_poll,
                )
                progress.update(task, completed=1)
            _render_terminal_summary(result)
            return

        # --no-wait OR --sync: no async polling spinner needed
        with Progress(
            SpinnerColumn(),
            console=Console(),
            transient=True,
        ) as progress:
            task = progress.add_task(
                "Uploading SBOM..." if sync else "Submitting SBOM...",
                total=None,
            )
            result = client.ingest_sbom(
                file,
                wait=wait,
                sync=sync,
                poll_interval=poll_interval,
                poll_timeout=poll_timeout,
            )
            progress.update(task, completed=1)

        if sync or result.get("status") == "ok":
            _render_terminal_summary(result)
        else:
            _render_async_envelope(result)
    finally:
        client.close()
