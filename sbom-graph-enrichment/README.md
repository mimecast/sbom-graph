# sbom-graph-enrichment

Celery-based enrichment pipeline for the sbom-graph platform. Runs background
certifiers to enrich graph data with vulnerability, license, and scorecard
information.

## Architecture

The worker reuses FalkorDB's Redis instance as the Celery broker (database 1)
and result backend (database 2), avoiding additional infrastructure.

### Certifiers

| Certifier | Source | Finding Kind |
|-----------|--------|--------------|
| `osv` | [OSV.dev](https://osv.dev) | Vulnerability |
| `clearlydefined` | [ClearlyDefined](https://clearlydefined.io) | License |

## Development

```bash
# Install dependencies (from repo root)
cd sbom-graph-enrichment
uv sync

# Run worker locally (requires Redis)
celery -A sbom_graph_enrichment.celery_app worker --loglevel=info -Q enrichment

# Run beat scheduler
celery -A sbom_graph_enrichment.celery_app beat --loglevel=info

# Run tests
pytest
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FALKORDB_HOST` | `localhost` | Redis/FalkorDB host |
| `FALKORDB_PORT` | `6379` | Redis port |
| `FALKORDB_PASSWORD` | _(empty)_ | Redis password |
| `FALKORDB_GRAPH_NAME` | `acme-corp` | FalkorDB graph name |
| `CELERY_BROKER_DB` | `1` | Redis DB for Celery broker |
| `CELERY_RESULT_DB` | `2` | Redis DB for Celery results |
| `ENRICHMENT_INTERVAL` | `3600` | Seconds between full enrichment runs |
| `INTERNAL_PREFIXES` | _(empty)_ | Internal prefix rules (same as API) |
