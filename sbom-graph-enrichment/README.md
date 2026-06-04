# sbom-graph-enrichment

Celery-based enrichment pipeline for the sbom-graph platform. Runs background
certifiers to enrich graph data with vulnerability, license, scorecard, and
trust score information.

## Architecture

The worker reuses FalkorDB's Redis instance as the Celery broker (database 1)
and result backend (database 2), avoiding additional infrastructure.

### Certifiers

| Certifier | Source | Finding Kind |
|-----------|--------|--------------|
| `osv` | [OSV.dev](https://osv.dev) | Vulnerability |
| `clearlydefined` | [ClearlyDefined](https://clearlydefined.io) | License |
| `scorecard` | [OpenSSF Scorecard](https://scorecard.dev) | Security practices |
| `ossindex` | [Sonatype OSS Index](https://ossindex.sonatype.org) | Vulnerability |
| `depsdev` | [deps.dev](https://deps.dev) | Project health, scorecard, licenses, advisory count |
| `eol` | [endoflife.date](https://endoflife.date) | EOL |
| `source_repo` | [deps.dev](https://deps.dev) | Source repository |

### Trust score computation

The pipeline computes a composite trust score (0–10) for each package by
aggregating findings from OpenSSF Scorecard, OSV, Sonatype OSS Index, and
deps.dev. Scores are propagated through the dependency graph with configurable
alpha blending and depth attenuation. The `propagate_effective_scores` task runs
periodically to update inherited risk. When packages fall below
`TRUST_SCORE_ALERT_THRESHOLD` (default 4.0), the task logs WARNING-level alerts
with the top 20 at-risk packages.

### Persistence

Each certifier's findings are stored via dedicated persistence handlers in
`tasks.py`. The `depsdev` certifier stores advisory count, publication date,
default-version flag, and license data on `Version` nodes. If OpenSSF Scorecard
data is returned by deps.dev, a `Scorecard` node is created and linked via
`HAS_SCORECARD`. OSS-Fuzz status and deps.dev project keys are also persisted
on the `Version` node. The `source_repo` certifier creates `SourceRepository`
nodes linked via `FROM_REPO`.

## Marking packages as internal (`INTERNAL_PREFIXES`)

Use the environment variable **`INTERNAL_PREFIXES`** so packages that match
your organisation’s naming rules are treated as **internal** when this worker
talks to FalkorDB through `sbom-graph-model`’s `Persistence` layer (same rules as
the API ingest path and the SonaType release listener).

- **Format:** comma-separated `field:prefix` tokens (no spaces inside tokens).
- **Allowed `field` values:** `group`, `name`, `purl` (see
  `Persistence.parse_internal_prefixes()` in `sbom-graph-model`).
- **Semantics:** a package is internal if **any** configured field’s value
  **starts with** the given prefix (e.g. Maven `group` `com.acme` →
  `group:com.acme`).

**Examples:**

```bash
export INTERNAL_PREFIXES='group:com.acme,name:acme-'
export INTERNAL_PREFIXES='purl:pkg:maven/com.acme/'
```

**Kubernetes (umbrella chart):** set `global.internalPrefixes` in
`helm/charts/sbom-graph/values.yaml`. The chart maps that value to `INTERNAL_PREFIXES`
on the enrichment worker and beat (and on other components that need the same
rules).

**Related (API alignment):** `FALKORDB_INTERNAL_LABEL` must match the
sbom-graph-api setting (default `INTERNAL`). The scheduled task
`refresh_internal_centrality` updates `inDegree` / `outDegree` on
`Version:{label}` nodes. Use **`INTERNAL_PREFIXES`** so ingestion and
enrichment agree on which packages receive that secondary label.

## Development

```bash
# Install dependencies (from this directory)
cd sbom-graph-enrichment
uv sync

# Run worker locally (requires Redis / FalkorDB reachable as broker + graph)
celery -A sbom_graph_enrichment.celery_app worker --loglevel=info -Q enrichment

# Run beat scheduler (separate process)
celery -A sbom_graph_enrichment.celery_app beat --loglevel=info

# Run tests
pytest
```

## Docker

The image is a multi-stage **distroless-style** build: the runtime stage installs
only wheels (including `sbom-graph-enrichment` at a pinned version). The
**`PYTHON_PACKAGE_VERSION`** build argument must match `[project].version` in
this directory’s `pyproject.toml` (the same version published to your PyPI).

### From the monorepo root

The repo root `build-images.sh` script builds the `sbom-graph-model` wheel when
needed, reads the version from `sbom-graph-enrichment/pyproject.toml`, and
passes `--build-arg PYTHON_PACKAGE_VERSION=…`:

```bash
# From the repository root (sbom-graph/)
./build-images.sh sbom-graph-enrichment

# Custom image tag
./build-images.sh --enr-tag myregistry/sbom-graph-enrichment:1.2.3 sbom-graph-enrichment
```

### Manual `docker build`

Use **`sbom-graph-enrichment/`** as the build context (same as CI and
`build-images.sh`):

```bash
cd sbom-graph-enrichment
docker build -t sbom-graph-enrichment:latest -f Dockerfile \
  --build-arg "PYTHON_PACKAGE_VERSION=$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)" \
  .
```

### Run the container

The default command starts a **Celery worker** on queue `enrichment`. Point
**broker and graph** at the same Redis host (FalkorDB); broker/result DB indexes
default to `1` and `2`.

```bash
docker run --rm \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_PORT=6379 \
  -e FALKORDB_GRAPH_NAME=acme-corp \
  -e FALKORDB_PASSWORD= \
  -e INTERNAL_PREFIXES='group:com.acme' \
  sbom-graph-enrichment:latest
```

**Celery beat** (scheduler) uses the same image; override the container command,
for example:

```bash
docker run --rm \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_GRAPH_NAME=acme-corp \
  sbom-graph-enrichment:latest \
  -A sbom_graph_enrichment.celery_app beat --loglevel=info
```

TLS between Celery and Redis uses **`CELERY_REDIS_SSL=true`** plus the same
`FALKORDB_CACERTS` / optional client cert variables as in the table below.
FalkorDB **graph** connections from the worker use **`FALKORDB_SSL=true`** when
talking to the server over TLS (see `persistence_helpers.py`).

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| **`INTERNAL_PREFIXES`** | _(empty)_ | Comma-separated `field:prefix` pairs so matching packages are treated as internal (`group`, `name`, `purl`). See [above](#marking-packages-as-internal-internal_prefixes). |
| `FALKORDB_HOST` | `localhost` | Redis / FalkorDB host (Celery broker + graph) |
| `FALKORDB_PORT` | `6379` | Redis port |
| `FALKORDB_PASSWORD` | _(empty)_ | Redis password |
| `FALKORDB_GRAPH_NAME` | `acme-corp` | FalkorDB graph name |
| `FALKORDB_SSL` | `false` | Set `true` for TLS when opening the **graph** client to FalkorDB |
| `FALKORDB_CACERTS` | _(empty)_ | CA bundle path for graph client TLS (and Celery when `CELERY_REDIS_SSL=true`) |
| `FALKORDB_CLIENT_CERT` / `FALKORDB_CLIENT_KEY` | _(empty)_ | Optional mutual TLS client certificate paths |
| `CELERY_BROKER_DB` | `1` | Redis logical DB for the Celery broker |
| `CELERY_RESULT_DB` | `2` | Redis logical DB for Celery results |
| `CELERY_REDIS_SSL` | `false` | Set `true` for `rediss://` broker and result backend |
| `ENRICHMENT_INTERVAL` | `3600` | Seconds between scheduled full enrichment runs |
| `ENRICHMENT_SOURCES` | _(empty)_ | JSON array of certifier names to run (empty = all), e.g. `'["osv","clearlydefined"]'` |
| `ENRICHMENT_HTTP_TIMEOUT` | `30` | HTTP timeout (seconds) for outbound certifier requests |
| `TRUST_SCORE_ENABLED` | `true` | Enable trust score propagation beat task |
| `TRUST_SCORE_INTERVAL` | `7200` | Seconds between propagation runs |
| `TRUST_SCORE_ALPHA` | `0.4` | Blend weight (own vs inherited score) |
| `TRUST_SCORE_DECAY` | `0.8` | Depth attenuation for propagation |
| `TRUST_SCORE_MAX_DEPTH` | `20` | Maximum graph depth for propagation |
| `TRUST_SCORE_ALERT_THRESHOLD` | `4.0` | Direct scores below this trigger WARNING logs |
| `TRUST_SCORE_WEIGHT_SECURITY_PRACTICES` | `0.3` | Category weight (must sum to 1.0 with other weights) |
| `TRUST_SCORE_WEIGHT_VULNERABILITY_PROFILE` | `0.35` | Category weight |
| `TRUST_SCORE_WEIGHT_MAINTENANCE_HEALTH` | `0.2` | Category weight |
| `TRUST_SCORE_WEIGHT_SUPPLY_CHAIN_HYGIENE` | `0.15` | Category weight |
| `OSSINDEX_USER` / `OSSINDEX_TOKEN` | _(empty)_ | Optional Sonatype OSS Index credentials |

## Kubernetes

For production installs use the umbrella chart under `helm/charts/sbom-graph/`, which
deploys FalkorDB, the API, enrichment worker/beat, and shared settings such as
`global.internalPrefixes`. See `helm/charts/sbom-graph/values.yaml` for
`enrichment.*` and `global.internalPrefixes`.
