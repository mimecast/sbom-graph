# sbom-graph-enrichment Agent Guidance

## Project Overview
Celery-based asynchronous enrichment pipeline that queries external APIs to enrich package metadata stored in FalkorDB.

## Project Structure
```
src/sbom_graph_enrichment/
├── celery_app.py          # Celery configuration, beat schedule, log redaction
├── tasks.py               # Celery shared tasks (enrich_package, compute_trust_score, propagate_effective_scores, refresh_internal_centrality)
├── persistence_helpers.py # Per-worker Persistence and httpx.Client caching
└── certifiers/
    ├── base.py            # Abstract Certifier base, Finding dataclass, FindingKind enum
    ├── osv.py             # OSV.dev vulnerability certifier
    ├── license.py         # ClearlyDefined license certifier
    ├── scorecard.py       # OpenSSF Scorecard certifier
    ├── ossindex.py        # Sonatype OSS Index certifier
    ├── depsdev.py         # deps.dev project health certifier
    ├── eol.py             # endoflife.date EOL certifier
    ├── source_repo.py     # Source repository URL certifier (from deps.dev)
    └── trust_score.py     # Trust score calculator (compositor, not a Certifier)
tests/
├── conftest.py
├── test_certifiers.py
├── test_scorecard_certifier.py
├── test_ossindex_certifier.py
├── test_depsdev_certifier.py
├── test_trust_score_calculator.py
├── test_trust_score_tasks.py
├── test_tasks.py
├── test_celery_app.py
└── test_persistence_helpers.py
```

## Certifiers
| Certifier | FindingKind | Notes |
|-----------|-------------|-------|
| osv | VULNERABILITY | OSV.dev |
| clearlydefined | LICENSE | ClearlyDefined |
| scorecard | SCORECARD | OpenSSF Scorecard |
| ossindex | OSSINDEX | Sonatype OSS Index |
| depsdev | DEPSDEV | deps.dev project health, scorecard, licenses, advisory count; persists Version metadata + Scorecard nodes |
| eol | EOL | endoflife.date API, 30 req/min, maps PURL to product names |
| source_repo | SOURCE_REPO | deps.dev, 100 req/min, SSRF mitigation via host allowlist |

## Certifier Interface Pattern
Every certifier extends `Certifier` (from `base.py`) and implements:
- `name` property: short string identifier
- `enrich(purl, *, client)`: queries an external API, returns `list[Finding]`

A shared `httpx.Client` is passed in for connection pooling. Rate limiting is internal to each certifier using `_TokenBucket`.

## Adding a New Certifier
1. Create `certifiers/new_source.py` implementing the `Certifier` interface
2. Add a new `FindingKind` enum value in `base.py`
3. Register the certifier in `tasks.py` `_CERTIFIERS` dict
4. Add a `_persist_*` handler in `tasks.py` (e.g. `_persist_eol` stores EOL on Version nodes, `_persist_source_repo` creates/links SourceRepository nodes)
5. If the certifier contributes to trust scores, update `trust_score.py` category scoring
6. Add unit tests using `httpx.Response` mocking (see existing test files for pattern)

## Testing Patterns
- Mock `httpx.Client` with `MagicMock(spec=httpx.Client)`
- Mock `_bucket.acquire` to skip rate limiting in tests
- Use `_mock_response(status_code, json_data)` helper for building responses
- Propagation algorithm tests use pure-function `_propagate()` directly

## Trust Score Architecture
- `TrustScoreCalculator.compute()` is a compositor that consumes findings from all certifiers
- 4 categories with configurable weights sum to direct_score (0-10 scale)
- `propagate_effective_scores` task runs periodically to compute inherited risk
- Bottom-up graph traversal with alpha blending and decay attenuation
- Trust score drop alerting: when packages fall below `TRUST_SCORE_ALERT_THRESHOLD`, the task logs WARNING with top 20 at-risk packages

## Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| **INTERNAL_PREFIXES** | "" | Comma-separated `field:prefix` pairs (`group`, `name`, `purl`) so matching packages are treated as internal in FalkorDB; same format as API / release listener. Umbrella Helm: `global.internalPrefixes`. |
| FALKORDB_HOST | localhost | FalkorDB / Redis host |
| FALKORDB_PORT | 6379 | FalkorDB port |
| FALKORDB_GRAPH_NAME | acme-corp | Graph name |
| **FALKORDB_INTERNAL_LABEL** | INTERNAL | Secondary label on internal `Version` nodes; must match API. Used when refreshing stored degree centrality. Helm: `sbomGraphApi.falkordbInternalLabel`. |
| FALKORDB_PASSWORD | "" | FalkorDB password |
| FALKORDB_SSL | false | TLS for graph client (`persistence_helpers`) |
| FALKORDB_CACERTS | "" | CA path for graph TLS |
| CELERY_BROKER_DB | 1 | Redis DB for Celery broker |
| CELERY_RESULT_DB | 2 | Redis DB for Celery results |
| CELERY_REDIS_SSL | false | Use `rediss://` for broker and result backend |
| ENRICHMENT_INTERVAL | 3600 | Seconds between enrichment cycles |
| **CENTRALITY_REFRESH_ENABLED** | true | When true, Celery beat schedules `refresh_internal_centrality` |
| **CENTRALITY_REFRESH_INTERVAL** | 7200 | Seconds between centrality refresh runs (default 2 hours) |
| TRUST_SCORE_ENABLED | true | Enable trust score computation |
| TRUST_SCORE_INTERVAL | 7200 | Seconds between propagation runs |
| TRUST_SCORE_ALPHA | 0.4 | Blend weight (own vs inherited) |
| TRUST_SCORE_DECAY | 0.8 | Depth attenuation factor |
| TRUST_SCORE_MAX_DEPTH | 20 | Maximum traversal depth |
| OSSINDEX_USER | "" | Optional OSS Index username |
| OSSINDEX_TOKEN | "" | Optional OSS Index API token |
| ENRICHMENT_SOURCES | null | JSON list of certifier names to run (empty = all) |
| TRUST_SCORE_ALERT_THRESHOLD | 4.0 | Score below which packages trigger WARNING alerts |
