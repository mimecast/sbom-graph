# AGENTS.md — sbom-graph-cli

This document provides project-specific context for AI agents. It inherits all
standards from the root [`AGENTS.md`](../AGENTS.md) and adds CLI-specific
guidance.

## Project Overview

sbom-graph-cli is a command-line interface for the sbom-graph API. It enables
ingestion of SBOMs, querying vulnerabilities and dependencies, policy
annotation, and report export. Designed for scripting and CI/CD integration.

## Technology Stack

- **Framework**: Click
- **HTTP Client**: httpx
- **Output**: Rich (tables, progress, colour)
- **Package Manager**: uv

## Architecture

```
cli.py (main group)
├── commands/ingest.py   → POST /ingest/sbom
├── commands/query.py   → GET /api/v1/package/{purl}/vulns, reports
├── commands/policy.py  → POST /api/v1/policy/annotate
└── commands/export.py  → GET /reports/{name}?format=
```

- **client.py**: SBOMGraphClient wraps httpx; all API calls go through it.
- **utils.py**: APIError, exit codes (0=success, 1=policy violations, 2=error).

## Configuration

- `--api-url`: Base API URL (env: `SBOM_GRAPH_API_URL`, default: http://localhost:5000)
- `--token`: API token (env: `SBOM_GRAPH_TOKEN`)
- `--output table|json`: Output format for pipeline integration

## Adding New Commands

1. Create module in `commands/` (e.g. `commands/newcmd.py`).
2. Define Click command or group, use `@click.pass_context`.
3. Obtain `ctx.obj["api_url"]`, `ctx.obj["token"]`, `ctx.obj["output_format"]`.
4. Add client method in `client.py` if needed.
5. Register in `cli.py`: `main.add_command(newcmd.cmd)`.
6. Add tests in `tests/test_newcmd.py` using `CliRunner` and mocked transport.

## Testing

- Use `pytest` with `CliRunner` from Click.
- Mock HTTP via `httpx.MockTransport` or `respx` (if added).
- Test success, error, and `--output json` for each command.
