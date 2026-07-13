# Code Quality Report — sbom-graph monorepo

**Date:** 2026-06-29
**Scope:** non-test source (`*/src/`) across all five subprojects (sbom-graph-api,
sbom-graph-model, sbom-graph-enrichment, sbom-graph-cli, sonatype-lifecycle-release-listener).
**Companion:** security findings live in [`sast-scan-results.md`](./sast-scan-results.md). This
file is for **non-security** code-quality issues only.

This pass covered two specific requests — (1) misuse of `assert` for control flow, and
(2) imports not declared in the file header — plus incidental observations.

---

## 1. `assert` usage — ✅ FIXED (2026-06-29)

`assert` is stripped when Python runs under `-O`/`-OO`, so it must never carry runtime
control-flow, input validation, or any check whose disappearance would change behaviour. It also
raises a bare `AssertionError`, which is opaque to humans reading a traceback.

**Finding: four `assert` statements in non-test source (all sbom-graph-api); none validated
external input, but all were `-O`-fragile and unclear.** All four were **replaced with explicit
guards** that raise a descriptive exception. Verified: full API suite (1489) green, `ruff` clean,
and a repo-wide grep confirms **zero `assert` remain in any `*/src/`**.

| # | Location | Was | Now |
|---|----------|-----|-----|
| A1 | `exports/excel.py` | `assert ws is not None` (type-narrowing after `ws = wb.active`) | `if ws is None: raise RuntimeError("Failed to create Excel worksheet")` |
| A2 | `services/token_storage.py` `_get_session` | `assert self._session_factory is not None` | `if self._session_factory is None: raise RuntimeError("Database session factory is not initialised")` |
| A3 | `services/user_storage.py` `_get_session` | `assert self._session_factory is not None` | same explicit guard as A2 |
| A4 | `routes/reports/dependencies.py` (`latest` resolution path) | `assert latest_version is not None` | `if latest_version is None: raise RuntimeError("Latest version could not be resolved")` — **this one was missed by the first automated scan** and caught on a re-grep. |

**Convention recorded:** "Never use `assert` outside of test code" is now a mandatory Working
Agreement in the root [`AGENTS.md`](../AGENTS.md) (item 12) — explicit `raise` in `*/src/`, `assert`
permitted only under `tests/`.

**Other subprojects:** sbom-graph-model, sbom-graph-enrichment, sbom-graph-cli, and
sonatype-lifecycle-release-listener have **no** `assert` in non-test source.

---

## 2. Imports not in the file header — ✅ MOVED where safe

Audited all module-level vs. function-local imports. **16 inline import statements were moved to
their file headers** (verified: full test suites green — API 1489, model 471, enrichment 236 —
and `ruff` clean, so no cycles or breakage introduced). **7 were deliberately left inline** with
documented reasons (moving them would change behaviour or create a cycle).

### Moved to header (✅)
| File | Was inline in | Import(s) moved |
|------|---------------|-----------------|
| `sbom-graph-api/.../services/falkordb_service.py` | 8 methods | `import networkx as nx`, `from collections import deque`, `from datetime import UTC, datetime, timedelta` (×3 sites), `import uuid`, `from uuid import uuid4` — consolidated into the header |
| `sbom-graph-api/.../app.py` | `_is_api_request()` | `from flask import request` — was **redundant** (already imported at top); inline line deleted |
| `sbom-graph-api/.../utils/api_helpers.py` | `paginate_params()` | `from ...utils.validation import validate_int_param` |
| `sbom-graph-api/.../routes/auth.py` | `debug_tokens()` | `StoredToken` — folded into the existing top-level `from ...token_storage import get_token_storage` |
| `sbom-graph-api/.../routes/reports/vulnerabilities.py` | `incident_response_graph()` | `from ...visualizations.blast_radius import create_blast_radius_graph` |
| `sbom-graph-api/.../routes/reports/inventory.py` | `source_impact_graph()` | `from ...visualizations.source_impact import create_source_impact_graph` |
| `sbom-graph-model/.../persistence.py` | `create_policy_annotation()`, `create_vex_statement()` | `PolicyType`, `VexStatus` — folded into the existing top-level `from .model import (...)` |
| `sbom-graph-enrichment/.../celery_app.py` | module-level `try` block | `import json` (was `import json as _json` inside the `try`; alias dropped) |

Cycle-safety was verified for every cross-module move (the target module does not import the
source module): `visualizations/{blast_radius,source_impact}` do not import `routes/reports`;
`token_storage` does not import `routes/auth`; `validation` does not import `api_helpers`;
`model.py` does not import `persistence.py` (the header already imported `.model`).

### Left inline on purpose (kept)
| File | Reason kept |
|------|-------------|
| `sbom-graph-api/.../routes/ingest.py` (`_enqueue_async` → `celery_client`; `_run_vex_inline` → `sbom_graph_model.vex`) | Optional/soft dependency wrapped in `try/except` (Celery / VEX module may be absent in some deployments). Moving to the header would turn a graceful 503/fallback into an import-time crash. |
| `sbom-graph-api/.../routes/api_v1.py` (`trigger_enrichment` → `sbom_graph_enrichment.tasks`) | Optional cross-subproject dependency (`# type: ignore[import-not-found]`), `try/except`. Enrichment pipeline isn't installed in all environments. |
| `sbom-graph-enrichment/.../ingest_tasks.py` (`ingest_vex` → `sbom_graph_model.vex`) | Optional module wrapped in `try/except`. |
| `sbom-graph-api/.../schemas/definitions.py` (`from ...schemas.inbound import INBOUND_SCHEMA_INDEX`) | **Intentional circular-import break** — `inbound.py` imports `SCHEMA_VERSION` from `definitions.py` at module level; the lazy import inside a helper breaks the cycle (docstring documents this). Moving it would reintroduce the cycle. |
| `sbom-graph-api/.../utils/validation.py` (`get_safe_redirect_url` → `from flask import request, url_for`) | **Deliberate framework decoupling** — `validation.py` imports no Flask at module level so it stays importable as a pure validation utility; only this one redirect helper needs Flask. Promoting it would couple the whole module to the web framework. |
| `sbom-graph-api/.../app.py` (`ready()` → `falkordb_service`) | Health/readiness probe wrapped in a broad `try/except` for graceful degradation; keeping the import lazy preserves that resilience contract for the `/ready` endpoint. |

---

## 3. Memory / resource leaks — ✅ FIXED (2026-06-29)

A dedicated leak hunt across the long-running processes (Flask-under-gunicorn, Celery workers, the
webhook listener) found **four confirmed leaks**, all now fixed with regression tests. The
streaming/temp-file export path (`exports/streaming.py`) was specifically audited and is **clean**
(`mkstemp` fd closed immediately; temp file `unlink`ed and workbook `.close()`d on success, error,
and abandoned-iteration paths). PyVis visualisations build in-memory HTML only (no temp files).

| # | Location | Leak | Fix | Test |
|---|----------|------|-----|------|
| L1 | `routes/reports/_common.py` `_rate_state` | Per-client rate-limit dict grew unbounded (one entry per client address ever seen; only ever reset for existing keys, never evicted) — unbounded memory in each gunicorn worker. | Added periodic eviction of entries older than the window (`_cleanup_stale_rate_entries`, every `_RATE_CLEANUP_INTERVAL`), mirroring the correct `auth.py` `_login_attempts` pattern. | `test_reports_security_phase1.py::...test_stale_rate_entries_are_purged` |
| L2 | `services/token_storage.py` + `services/user_storage.py` (19 methods) | `session.close()` was called only on the happy path; any exception left the SQLAlchemy `Session` (and its checked-out connection) unclosed → `QueuePool` exhaustion + identity-map memory growth over time. | Wrapped each method's body in `with self._get_session() as session:` (SQLAlchemy 2.0 `Session` closes on exit, on every path); removed the 36 scattered manual `close()` calls. | Existing 1490-test API suite exercises all methods |
| L3 | `sbom-graph-enrichment/tasks.py` (`enrich_all_packages`, `propagate_effective_scores`) | Called `create_persistence()` per scheduled beat tick → a **new** FalkorDB/redis connection pool each run, never closed (`Persistence` had no `close`). | Switched both to the per-process `get_persistence()` singleton (one connection per worker, reused). | existing `test_tasks.py` (patches updated to `get_persistence`) |
| L4 | `sonatype-lifecycle-release-listener/app.py` (`process_release_scan`) | Each webhook built a fresh `CycloneDXHelper` **and** `VexHelper`, each opening a `Persistence` (FalkorDB) + a `requests.Session`, none ever closed → 2 connections + 2 sessions leaked per webhook. | Added `close()` to the helpers + `SonaTypeClient`, and a `try/finally` in `process_release_scan` that closes both helpers on success and error. | `test_app.py::TestResourceCleanup` (3 cases) |

**Supporting changes:**
- Added `Persistence.close()` + context-manager (`__enter__`/`__exit__`) to `sbom-graph-model` (`FalkorDB` exposes `close()`); used by L4 and the worker-shutdown handler. Tests in `test_persistence.py`.
- Added a Celery `worker_process_shutdown` handler (`_on_worker_process_shutdown`) that closes the per-worker `httpx.Client` and `Persistence` when a child is recycled (e.g. `--max-tasks-per-child`). Test in `test_persistence_helpers.py`.

**Verified NOT leaks** (checked, no change): `exports/streaming.py` temp-file/workbook lifecycle; PyVis `Network`/HTML (in-memory, GC'd); CLI HTTP clients (closed in `try/finally`); the API/enrichment `get_*` singletons (single cached objects, reused per process); `auth.py` `_login_attempts` (already has eviction); no unbounded `lru_cache`/`@cache` anywhere.

---

## 4. Incidental observations (no action required)

- **PEP 758 parenthesis-less `except` is used intentionally and is sound.**
  `sbom-graph-enrichment/.../celery_app.py` uses `except ValueError, TypeError:` (no parentheses).
  This is valid only on **Python 3.14+** (PEP 758) and correctly catches *both* exception types
  (verified empirically). All four 3.14-only subprojects declare `requires-python = ">=3.14,<4"`,
  so this is consistent — **not** a Python-2 remnant and not a bug. (Worth knowing: this syntax
  would be a `SyntaxError` on 3.11–3.13; the pinned `>=3.14` floor is what makes it safe. The CLI,
  which is `>=3.11`, does not use it.)
