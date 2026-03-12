# sbom-graph-cli

Command-line interface for the [sbom-graph](../README.md) API. Ingest SBOMs,
query vulnerabilities and dependencies, manage policy annotations, and export
reports.

## Installation

From the monorepo root:

```bash
cd sbom-graph-cli
uv sync
```

Or install in development mode:

```bash
uv pip install -e .
```

## Usage

```bash
sbom-graph [--api-url URL] [--token TOKEN] [--output table|json] <command> [args]
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SBOM_GRAPH_API_URL` | Base URL of the sbom-graph API | `http://localhost:5000` |
| `SBOM_GRAPH_TOKEN` | API token for authentication | (none) |

### Commands

#### Ingest

```bash
sbom-graph ingest <file>
```

Upload a CycloneDX or SPDX SBOM file. Auto-detects format and prints a summary
(projects, dependencies, defects, record_id).

#### Query

```bash
sbom-graph query vulns <purl>
sbom-graph query deps <purl>
sbom-graph query dependants <purl>
sbom-graph query patch-plan <defect_id>
```

- **vulns**: List vulnerabilities for a package (by PURL).
- **deps**: List dependencies (direct and transitive).
- **dependants**: List dependants (reverse dependencies).
- **patch-plan**: Show patch plan for a vulnerability (CVE/GHSA/OSV ID).

#### Policy

```bash
sbom-graph policy annotate <purl> --type bad|good|hold --justification "reason"
```

Create a policy annotation (banned, approved, or deprecated) on a package.

#### Export

```bash
sbom-graph export <report_name> --format json|excel [--output FILE]
```

Export a report. Examples: `vulnerabilities`, `snapshots`, `projects`,
`incident-response/CVE-2024-1234`.

## CI/CD Integration

- **Exit codes**: 0 = success, 1 = policy violations, 2 = error.
- **`--output json`**: Machine-parseable output for pipelines.

Example:

```bash
export SBOM_GRAPH_API_URL=https://sbom.example.com
export SBOM_GRAPH_TOKEN=your-token
sbom-graph --output json query vulns pkg:maven/org/foo@1.0 | jq '.vulnerabilities | length'
```

## Development

```bash
uv sync
uv run pytest -v --tb=short
uv run ruff check src/ tests/
```
