"""Query commands: vulns, deps, dependants, patch-plan."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from sbom_graph_cli.client import SBOMGraphClient


def _severity_style(severity: str) -> str:
    """Return rich style for severity badge."""
    s = (severity or "UNKNOWN").upper()
    if s == "CRITICAL":
        return "red bold"
    if s == "HIGH":
        return "orange1"
    if s == "MEDIUM":
        return "yellow1"
    if s == "LOW":
        return "blue"
    return "dim"


@click.group("query")
def query() -> None:
    """Query vulnerabilities, dependencies, and patch plans."""


@query.command("vulns")
@click.argument("purl", type=str)
@click.pass_context
def vulns(ctx: click.Context, purl: str) -> None:
    """List vulnerabilities for a package (by PURL)."""
    if not purl.startswith("pkg:"):
        click.echo(click.style("PURL must start with 'pkg:'", fg="red"), err=True)
        raise SystemExit(2)

    client = SBOMGraphClient(api_url=ctx.obj["api_url"], token=ctx.obj["token"])
    try:
        vulns_list = client.get_vulnerabilities(purl)
        if ctx.obj["output_format"] == "json":
            out = {"purl": purl, "vulnerabilities": vulns_list}
            click.echo(json.dumps(out, indent=2))
        else:
            table = Table(title=f"Vulnerabilities: {purl[:60]}...")
            table.add_column("ID", style="cyan")
            table.add_column("Severity", style="bold")
            table.add_column("CVSS", justify="right")
            table.add_column("Title", style="dim")
            for v in vulns_list:
                vid = v.get("id") or v.get("defect_id", "-")
                sev = v.get("severity", "UNKNOWN")
                cvss = v.get("cvss") or v.get("cvss_score", "-")
                if isinstance(cvss, (int, float)):
                    cvss = str(cvss)
                title = (v.get("title") or v.get("description") or "-")[:50]
                style = _severity_style(sev)
                table.add_row(vid, f"[{style}]{sev}[/]", str(cvss), title)
            Console().print(table)
    finally:
        client.close()


@query.command("deps")
@click.argument("purl", type=str)
@click.pass_context
def deps(ctx: click.Context, purl: str) -> None:
    """List dependencies (direct and transitive) for a package."""
    if not purl.startswith("pkg:"):
        click.echo(click.style("PURL must start with 'pkg:'", fg="red"), err=True)
        raise SystemExit(2)

    client = SBOMGraphClient(api_url=ctx.obj["api_url"], token=ctx.obj["token"])
    try:
        deps_list = client.get_dependencies(purl)
        if ctx.obj["output_format"] == "json":
            click.echo(json.dumps({"purl": purl, "dependencies": deps_list}, indent=2))
        else:
            table = Table(title=f"Dependencies: {purl[:60]}...")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Type", style="dim")
            for d in deps_list:
                if d.get("dependency_project") == "(no dependencies)":
                    table.add_row("(no dependencies)", "-", "-")
                    break
                pkg = d.get("dependency_project", d.get("project_name", "-"))
                ver = d.get("dependency_version", d.get("version", "-"))
                depth = d.get("depth", 1)
                dep_type = "direct" if depth == 1 else "transitive"
                table.add_row(pkg, ver, dep_type)
            Console().print(table)
    finally:
        client.close()


@query.command("dependants")
@click.argument("purl", type=str)
@click.pass_context
def dependants(ctx: click.Context, purl: str) -> None:
    """List dependants (reverse dependencies) for a package."""
    if not purl.startswith("pkg:"):
        click.echo(click.style("PURL must start with 'pkg:'", fg="red"), err=True)
        raise SystemExit(2)

    client = SBOMGraphClient(api_url=ctx.obj["api_url"], token=ctx.obj["token"])
    try:
        deps_list = client.get_dependants(purl)
        if ctx.obj["output_format"] == "json":
            click.echo(json.dumps({"purl": purl, "dependants": deps_list}, indent=2))
        else:
            table = Table(title=f"Dependants: {purl[:60]}...")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Partition", justify="right")
            for d in deps_list:
                pkg = d.get("project_name", d.get("project", "-"))
                ver = d.get("version", d.get("version_name", "-"))
                part = d.get("partition", d.get("max_partition", "-"))
                table.add_row(pkg, ver, str(part))
            Console().print(table)
    finally:
        client.close()


@query.command("patch-plan")
@click.argument("defect_id", type=str)
@click.pass_context
def patch_plan(ctx: click.Context, defect_id: str) -> None:
    """Show patch plan for a vulnerability (CVE/GHSA/OSV ID)."""
    client = SBOMGraphClient(api_url=ctx.obj["api_url"], token=ctx.obj["token"])
    try:
        plan = client.get_patch_plan(defect_id)
        if ctx.obj["output_format"] == "json":
            out = {"defect_id": defect_id, "patch_plan": plan}
            click.echo(json.dumps(out, indent=2))
        else:
            table = Table(title=f"Patch Plan: {defect_id}")
            table.add_column("Priority", style="cyan")
            table.add_column("Package", style="green")
            table.add_column("Version", style="dim")
            table.add_column("Direct?", justify="center")
            table.add_column("Dependants", justify="right")
            table.add_column("Action", style="yellow")
            for p in plan:
                prio = p.get("priority", p.get("level", "-"))
                pkg = p.get("project_name", p.get("package", "-"))
                ver = p.get("version_name", p.get("version", "-"))
                direct = "Yes" if p.get("is_direct", False) else "No"
                count = p.get("dependant_count", p.get("dependants", 0))
                action = p.get("recommended_action", p.get("action", "-"))
                table.add_row(str(prio), pkg, ver, direct, str(count), str(action))
            Console().print(table)
    finally:
        client.close()
