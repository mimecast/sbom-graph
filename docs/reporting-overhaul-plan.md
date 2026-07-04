# SBOM-Graph Reporting: Pagination, Streaming Exports, Provenance Fields & New Reports

## Context

Reports OOM when pulling large result sets. Today **no report paginates** — every endpoint
runs `MATCH … LIMIT $limit` (default 10 000, max 100 000), materialises the entire result list
in memory, and then builds the **whole** Excel workbook (`wb.save(BytesIO)`) or JSON dict
(`jsonify(dict)`) in memory before responding (`services/falkordb_service.py`,
`exports/excel.py`, `exports/json_format.py`, `routes/reports/*`).

Separately, several data-quality issues surfaced:
- `/reports/applications` shows duplicate `(project_name, version)` rows with different
  `scan_id`/`public_id`. The report reads the **singular** `app.scan_id`/`app.public_id` per node,
  while ingestion actually maintains a `scan_ids[]` array on one merged node — so duplicate rows
  mean **multiple distinct graph nodes** exist for the same name+version.
- `/reports/projects` similarly shows duplicate `(project_name, version)` rows.
- The graph MERGE identity is `(name, project_name, project_group)` only
  (`sbom-graph-model/src/sbom_graph_model/persistence.py:629`). `purl` and `language` are **not**
  part of identity; `language` is **never ingested** at all (it can only be derived from the purl
  type). Different-purl components therefore collapse into one node, losing provenance.
- `/reports/non-semver-versions` misses versions like `99.99.99-main.16-SNAPSHOT` because
  `SEMVER_PATTERN` (`falkordb_service.py:55`) accepts them (parsed as `99.99.99` + prerelease
  `main.16` + a tolerated `-SNAPSHOT` suffix). These are branch-name / unreleased builds that
  should be flagged.
- There is no tabular report for the `/visualizations/bipartite/{project_name}` data, and no way
  to see which dependants keep up to date with a library’s latest / latest-1.

### Decisions captured from discussion
1. **Row identity (reports):** *first* just **add** `group`, `purl`, and a derived `language`
   column to `/reports/projects` and `/reports/applications` for visibility — do **not** collapse
   rows yet.
2. **Ingestion identity:** factor **purl** into the node MERGE key (provenance). `language` is not
   ingested, so derive it from the purl for display; it is **not** added to the MERGE key.
3. **Non-semver:** keep strict pass/fail, and **add** a "suspect / unreleased" flag — detect
   prerelease/SNAPSHOT builds (not released) and the branch-name-as-version pattern (many versions
   sharing the same `major.minor.patch` base, differing only in prerelease).
4. **Bipartite report:** classify the **dependency (target)** version — `is_latest` and
   `is_latest_or_prev` reflect whether the dependant is using the target library’s latest or
   latest/latest-1 version, so we can see who has good dependency hygiene.

---

## Implementation methodology (applies to every phase)

Per-phase, secure-development workflow with **TDD upfront**:
1. **`secure-privacy-by-design`** — classify requirements, abuse/counter-use cases, build the SRTM
   for the phase (esp. pagination DoS, resource-exhaustion, data exposure via new columns/purl).
2. **`security-architect`** — design the pagination/streaming layer, param contracts, and the new
   endpoints against SOLID / clean-architecture and the existing service/route patterns.
3. **`threat-modeling`** — STRIDE/LINDDUN over the new surface (unbounded `all=true`, `page_size`
   abuse, Cypher `SKIP/LIMIT` injection, purl handling, content-disposition/header injection).
4. **`software-test-engineer`** — write the **failing** test suite first (red): pagination math,
   `all=true` streaming bounds, security cases (limits enforced, params sanitised), then implement
   to green and confirm requirements coverage against the SRTM.

Artifacts land under the top-level `docs/` folder (phase SRTM + architecture + threat model),
tests under `sbom-graph-api/tests/`.

### Phase 1 — artifacts & status (updated 2026-06-26)
Secure-development workflow completed for Phase 1; implementation underway. All phase docs live in
the parent `docs/` folder alongside this plan:
- **secure-privacy-by-design** → `docs/phase1-pagination-security-privacy-analysis.md` (SRTM: FR-001..007, SEC-001..009, PRV-001..002, PERF-001..002, COMP-001..003; TA-001..020).
- **security-architect** → `docs/phase1-pagination-architecture.md` (central `render_paged_report` helper + generic `iterate_pages` generator; offset/`count_*` service methods; `exports/streaming.py`; bounded+streamed PyVis; ADR-001..005).
- **threat-modeling** → `docs/phase1-threat-model.md` (no Critical findings; Medium hardening: single-source filter helper, validated-int `SKIP` if FalkorDB rejects a parameterised one, `page_size+1` has-next on the heaviest reports, keyset for large exports).
- **TDD (red)** → `tests/test_pagination.py`, `tests/test_exports_streaming.py`, `tests/test_visualizations_streaming.py`, `tests/test_reports_security_phase1.py` (+ updated brittle assertions in `tests/test_routes_reports.py`). 43 failing as intended.

**Keystone security decisions (from the threat model):**
- **`all=true` is streaming-only** (T-1 / SEC-003): exports always stream the full set page-by-page
  via `iterate_pages`; HTML renders exactly one bounded page. **No buffered/unbounded path exists
  for any format/flag** — this is the invariant that fixes the OOM and must stay true (asserted by
  TA-008). `all=true` only lifts the *total* cap for UI navigation; `page_size` (≤1000) bounds every
  rendered page.
- **`internal_only` applied identically across page + count + stream** (T-4/T-6 / PRV-001): the
  `:INTERNAL` label filter is built once (single-source helper) and reused by the page query, the
  `count_*` query, and the streaming generator, so a filtered view can never leak non-internal
  components or counts (asserted by TA-016/TA-017).

**Scope decision (confirmed):** the two threat-model fast-follows are **IN Phase 1** — SEC-008
(per-identity rate limiting / 429 on report/export/visualization endpoints) and COMP-003 (structured
export access/audit logging at the `render_paged_report` choke point).

**Status (updated 2026-06-26):** Core + shared infra COMPLETE and verified — full suite **1477
passed, ruff clean**; the openpyxl write_only "I/O operation on closed file" unraisable-exception
flakiness is **robustly fixed** (finalise the write-only worksheet on the export error path;
verified green across repeated full-suite runs under `-W error::pytest.PytestUnraisableExceptionWarning`);
`SKIP $offset` confirmed **parameterised** on a live FalkorDB.

Rollout **COMPLETE and independently verified (2026-06-26)**. All report endpoints either:
- **paginate + stream** (page/page_size + `count_*`, filters/sort threaded to BOTH page and count):
  projects, applications, source-repos, snapshots, self-dependencies, **vulnerabilities**,
  **sbom-inventory**, **centrality**; and Python-post-processed lists (non-semver-versions,
  version-dependencies, multi-version-deps/sources) computed once → sliced for HTML → same list
  streamed for export (no O(n²)); or
- **export-stream** (HTML kept, Excel/JSON via `exports/streaming.py`): vulnerability-dependants,
  enrichment-coverage, dependants, incident-response, license-summary, coverage; plus the 6 graph
  **visualizations** bounded + chunk-streamed.

Only **genuinely-bounded aggregates** remain on the in-memory path (justified, no OOM risk):
license-dashboard JSON (category summary), source-impact (single-repo), risk-path-explorer
(≤50 paths).

**Independent verification (run by main, not the subagent):** Gate 1 `pytest -q -W
error::PytestUnraisableExceptionWarning` → **1477 passed, 0 failed/0 error** (x2); Gate 2 `ruff
check src tests` → clean; Gate 3 buffered-path grep → only the 3 bounded aggregates above; new
paged/count Cypher parses+runs on live FalkorDB; vulnerabilities filters confirmed threaded to page
AND count.

**license-conflicts gap CLOSED (2026-06-26):** HTML now paginates — the BFS-computed conflict list
is computed once, sliced for HTML (`conflicts[offset:offset+page_size]` + `build_page_view` +
`_pagination.html`), and the same single list streams for JSON. No buffered path remains.
Verified: full suite `-W error` → **1478 passed, 0 error**; ruff clean.

Phase 1 is functionally complete (OOM closed, pagination/streaming live, docs page overhauled,
deprecated `/exports` blueprint removed). **However, a post-rollout audit found an Excel feature
regression plus duplication that must be consolidated — see Phase 1.5 below — before this is
truly "done".**

---

## Phase 1.5 — Post-rollout consolidation (Excel feature regression + duplication)

> **STATUS: COMPLETE & independently verified (2026-06-26).** Full Excel parity restored via a new
> multi-sheet streaming writer (`stream_multi_sheet_workbook_response` + `SheetSpec` in
> `exports/streaming.py`): every migrated report regained its Summary sheet / multi-sheet layout /
> styled headers / formatting (10 `test_reports_excel_parity.py` tests open each xlsx and assert
> sheets + Summary). The 16 orphaned `create_*_excel` were deleted (`excel.py` 1541→~110 lines;
> only `create_source_impact_excel` survives); 5 orphaned `*_json` deleted; viz truncation banner
> deduped (bipartite reuses `_bounded`, `build_bounded_network` kept); timestamp unified via
> `utils/api_helpers.get_utc_timestamp` (`_ts`/`ts` now thin aliases); the `:INTERNAL` label bug
> fixed (4 sites now `(v:Version:INTERNAL)` via `get_node_label`, confirmed behavior-preserving).
> Gates: full suite `-W error` → **1453 passed, 0 error**; ruff clean. Not committed.



### Context
Two read-only audits (2026-06-26) of the streaming migration found:
1. **Excel feature regression (HIGH):** the rollout replaced 16 rich per-report Excel builders with
   the generic single-sheet `stream_workbook_response()`, silently dropping features across **every**
   migrated report — **Summary sheets** (aggregate stats, Top-10 rankings, severity/partition/reason
   breakdowns), **header styling**, **column auto-width**, **number/boolean formatting**, and for ~5
   reports **multi-sheet layouts** (2–3 sheets → 1). `create_source_impact_excel` still has all of it,
   proving these were dropped in migration, not deprecated by design. The 16 old builders therefore
   encode **lost features**, not just dead code — deleting them as-is would cement the regression.
2. **Duplication — each item checked for substitute FEATURE-PARITY before removal (2nd audit):**
   - **5 orphaned JSON formatters** — `projects_json`, `applications_json`, `snapshots_json`,
     `self_dependencies_json`, `vulnerabilities_json`. **Parity ✓ CONFIRMED**: the current
     `render_paged_report` JSON reproduces every top-level key, all `stats` keys, per-row fields and
     filename (vulnerabilities even *adds* `vex_coverage_pct`). → **Safe to delete now.**
   - **Timestamp helpers** — `_ts()` (json_format.py) + `ts()` (_common.py) + ~11 inline
     `datetime.now(UTC).isoformat()`. **Parity ✓ identical output.** → **Safe to unify now** (one util).
   - **Viz truncation banner** — `bipartite._inject_truncation_banner` is **byte-identical** to
     `_bounded.inject_truncation_banner` (only the param name differs). → **Safe to dedupe now**
     (bipartite imports the shared one). BUT `bipartite.build_bounded_network` (edge-iterator→Network)
     is **NOT** equivalent to `_bounded.bound_nodes_edges` (lists→lists) → **KEEP both**, do not merge.
   - **Hand-rolled `:INTERNAL` label (4 sites: lines ~3373/3405/3434/3784)** — **Parity ✗ NOT equivalent
     and a LATENT BUG.** `label = ":INTERNAL"|":Version"` → `(v:INTERNAL)` matches *any* INTERNAL node,
     whereas `get_node_label` → `(v:Version:INTERNAL)` matches only Version∧INTERNAL. (In practice INTERNAL
     is only applied to Version nodes, so result sets likely coincide today — but it's an unsafe
     inconsistency.) → **NOT a free cleanup:** confirm INTERNAL is Version-only, then align the 4 sites to
     `get_node_label()` as a deliberate **bug-fix** (with tests), not a silent merge.
   - Already consolidated (no action): `_page_clause` (SKIP/LIMIT) and `get_node_label` used uniformly
     elsewhere; `style_header_row`/`auto_adjust_column_widths` properly scoped within `excel.py`.

### Plan
**A. Restore Excel parity in the streaming path, then retire the old builders.**
- Extend `exports/streaming.py` so the streamed workbook (still write-only / constant-memory) supports:
  styled header row (WriteOnlyCell font/fill), preset column widths, number/bool formatting, an optional
  **Summary sheet**, and additional sheets. Summary stats stay cheap — accumulate in a single pass over
  the streamed rows, or run a small aggregate query.
- Port each report's summary/multi-sheet logic (which already lives in the old `create_*_excel`) into the
  route's streamed export via a small per-report "summary builder" callback.
- Once parity holds, **delete the 16 orphaned `create_*_excel` functions + their now-pointless unit
  tests**, keeping `create_source_impact_excel` (or migrate it to the enhanced streamer too for uniformity).
  Re-check whether `style_header_row`/`auto_adjust_column_widths`/pandas become unused afterward and remove
  if so.

**B. Parity-confirmed cleanups (zero behavior change — do regardless of scope):** delete the 5 orphaned
`*_json`; unify the timestamp helper + update ~13 call sites; dedupe the viz truncation banner (bipartite
imports `_bounded.inject_truncation_banner`) while KEEPING `build_bounded_network`.

**B2. Label semantics — bug-fix, NOT a free merge (decide separately):** the 4 hand-rolled `:INTERNAL`
sites match a different node set than `get_node_label()`. Verify whether any non-Version node ever carries
the INTERNAL label; if not (expected), align the 4 sites to `get_node_label()` as a tested bug-fix; if so,
this changes results and needs explicit sign-off. Either way it is NOT bundled into the zero-change cleanups.

**C. Centrality** is resolved as part of A (it regains its Summary sheet via the enhanced writer);
its HTML paging-vs-bounded question (see open decisions) is decided alongside.

### Open decision — scope of the parity restoration
- **Full parity:** rebuild summary sheets + multi-sheet layouts + styling + widths + formatting for all
  ~15 reports, matching the originals.
- **Pragmatic:** styling + column widths + a single Summary sheet everywhere; don't rebuild the few 2–3
  sheet layouts.
- **Accept simplification:** keep single-sheet streamed exports, document the trade-off, delete the 16
  builders as-is (explicitly signs off on the feature loss).

### Verification
After each step: full suite under `-W error::pytest.PytestUnraisableExceptionWarning` green; `ruff check
src tests` clean; for each report with a restored Summary, open the generated xlsx and assert sheet
names + a sample summary value; objective dead-code grep shows the removed builders/formatters gone;
new Excel built at constant memory (no full in-memory workbook).

## Phase 1 — Pagination + unlimited flag + streaming exports (cross-cutting, highest priority for OOM)

**Goal:** every report paginates; HTML always pages; an `all=true` flag lifts the cap; exports
always stream page-by-page so memory stays flat.

### 1a. Param parsing & validation
- `utils/validation.py`: add `validate_page(value)` (default 1, ≥1) and
  `validate_page_size(value, default=100, max=1000)` (reuse `validate_int_param`). Add an
  `MAX_PAGE_SIZE = 1000` constant. Keep `validate_limit` for back-compat.
- `routes/reports/_common.py`: add `parse_pagination()` → returns
  `(page, page_size, unlimited)` from `page`, `page_size`, `all` query params; and
  `offset = (page - 1) * page_size`.

### 1b. Service layer — paged queries + streaming generators
In `services/falkordb_service.py`, for each list-style method (`get_all_projects`,
`get_all_applications`, `get_all_vulnerabilities`, `get_all_trust_scores_for_report`,
`find_non_semver_versions`, `get_sbom_inventory`, …):
- Add an `offset: int = 0` param → Cypher `… ORDER BY … SKIP $offset LIMIT $limit`.
- Add a matching `count_*()` (lightweight `MATCH … RETURN count(*)`) for total/page-count.
- Add a generator `iter_*(page_size, …)` that loops `SKIP/LIMIT` and `yield`s rows page-by-page
  until a short page is returned. Generators back the streaming exports so the full set is never
  held in memory. Describe-once pattern; representative method to implement first:
  `get_all_projects` / `iter_all_projects` / `count_all_projects`.

### 1c. HTML paging UI
- `templates/table.html`: add a pagination control block below the table — Prev/Next links (built
  from current query params, swapping `page`), "Page X of Y (N total)", and a `page_size` selector.
  Driven by a new optional `pagination` template var; templates that don’t pass it are unaffected.
- Custom templates (centrality, vulnerabilities, trust_scores, etc.) get the same `pagination`
  partial included where applicable.

### 1d. Streaming exports (new module `exports/streaming.py`)
- **Excel:** `stream_workbook(headers, page_iter, sheet_title) -> Response`. Use
  `openpyxl.Workbook(write_only=True)` + `ws.append(row)` per row pulled from the generator, save
  to a `NamedTemporaryFile` in the scratch dir, and return via a streamed file response (so
  `getvalue()` never holds the whole file in RAM). Refactor `create_all_projects_excel` /
  `create_applications_excel` (`exports/excel.py`) to delegate to this.
- **JSON:** `stream_json_response(meta, page_iter, data_key="data") -> Response` using Flask
  `stream_with_context`, yielding the envelope `{"report_type":…,"generated_at":…,"data":[` then
  comma-joined row chunks per page, then `],"stats":{…}}`. Refactor `*_json` in
  `exports/json_format.py` to feed this.
- Exports **always** stream page-by-page (per requirement); `all=true` just removes the row cap.

### 1e. Apply to routes
Update report routes (`routes/reports/inventory.py`, `dependencies.py`, `vulnerabilities.py`,
`trust_scores.py`, `compliance.py`, `sbom_provenance.py`) to: parse pagination, pass `offset`/
`page_size` to the service for HTML, pass the `iter_*` generator to the streaming exporters, and
pass `pagination` to templates. Start with `/reports/projects` and `/reports/applications`, then
roll the same pattern across the rest.

---

### 1f. Visualizations — stream to avoid OOM
The visualization endpoints (`routes/visualizations.py`; `visualizations/bipartite.py`,
`blast_radius.py`, `dependants_graph.py`, `dependencies_graph.py`, `kpartite.py`,
`multi_layout.py`, `source_impact.py`) build a full PyVis `Network` and return
`net.generate_html()` as one in-memory string — large graphs OOM the same way reports do.
- Feed graph builders from the **paged generators** (1b) (e.g. `iter_*` over
  `get_direct_dependants` / dependency edges) instead of loading the whole result set at once.
- **Bound** node/edge counts with a validated cap and surface a "graph truncated at N nodes"
  notice when exceeded (avoids unbounded render-time blow-ups; log what was dropped).
- Return the generated HTML via a **streamed** Flask response (`stream_with_context`, chunked)
  rather than holding extra copies of the full string.
- Same treatment for the embedded report graphs (`/reports/source-impact/graph`,
  `/reports/incident-response/{id}/graph`).

## Phase 1.6 — HTML/JSON parity restoration (audit 2026-06-29)

> **STATUS: COMPLETE & independently verified (2026-06-29).** Restored full-set aggregate stats into
> HTML + JSON: trust-scores (Avg Direct/Effective Score + Low/Med/High distribution), sbom-inventory
> (By-Format/By-Source + JSON `count`), policy-violations (Total Affected Dependants) — via 3 new
> aggregate methods (`get_trust_scores_summary`, `get_sbom_inventory_summary`,
> `get_policy_violations_total_dependants`) using the same filters as page+count (NOT per-page). Kept
> sbom-coverage flat (deliberate) and rewrote `SBOM_COVERAGE_SCHEMA` to the flat shape (verified: flat
> validates, old nested rejected). 21 new tests (`test_phase16_restorations.py`). Labels match `git HEAD`.
> Gates: full suite `-W error` → **1482 passed, 0 error**; ruff clean. Not committed.



HTML + JSON parity audits (original `git HEAD` vs current, all uncommitted) found the streaming/
pagination migration also dropped some **aggregate stats** and changed two JSON shapes. Most reports
(columns, badges, drill-down links, toggles, custom templates, row fields) retained parity; the JSON
"streaming vs buffering" diffs are equivalent documents (NOT regressions). Confirmed gaps to fix:

**HTML stats dropped (restore via full-set aggregate, NOT per-page):**
- `/reports/trust-scores` — lost **Avg Direct Score, Avg Effective Score, Low/Med/High distribution**
  (now only Total / Min-Score / Sort-By).
- `/reports/sbom-inventory` — lost **By-Format and By-Source breakdown** stats (now only Total SBOMs).
- `/reports/policy-violations` — lost **Total Affected Dependants**.

**JSON shape changes:**
- `/reports/sbom-inventory` — dropped top-level **`count`**.
- `/reports/sbom-coverage` — original nested all under **`"coverage"`**; current promotes `projects`
  (array) + `stats` to top-level. **DECIDED (Case B, 2026-06-29): keep the flat shape** — it is
  consistent with every other report (verified: sbom-coverage was the lone schema burying both stats
  and its data array under a wrapper) — and **update `SBOM_COVERAGE_SCHEMA`** (definitions.py:2092) to
  match (top-level `stats` + `projects`, drop the required `coverage` wrapper) + add a schema-validation
  test. This is a deliberate, documented contract change.
- `/reports/trust-scores` JSON — stats come from the same source as its HTML, so restore there too.

**Confirmed NON-issues (de-noised):** vulnerabilities stats are full-set (`get_vulnerability_summary_stats`),
applications keeps `version_mode`, and the build_json_response→stream_json_response switches produce
equivalent JSON (licenses, dependants, multi-version-deps, vulnerability-dependants, etc.).

**Scope principle (user, 2026-06-29):** *no accidental changes, but keep deliberate improvements.*
Accidental drops → restore to parity; genuine improvements → keep + update schema/tests/docs.

**Plan (resolved per principle):**
- **Restore (accidental drops):** full-set aggregate stats fed into BOTH HTML stats block and JSON
  `stats` — trust-scores (avg direct, avg effective, low/med/high distribution), sbom-inventory
  (by-format / by-source breakdown), policy-violations (total affected dependants); re-add
  sbom-inventory top-level `count` (also required by its schema). Use a small aggregate query /
  single-pass accumulation (NOT per-page).
- **Keep + document (deliberate):** sbom-coverage flat JSON shape → update `SBOM_COVERAGE_SCHEMA` to
  the flat shape + schema-validation test.
- TDD per report (assert the specific stat keys present in HTML + JSON; schema validates). Verify:
  full suite `-W error`, ruff.

## Phase 2 — Provenance columns on projects & applications

**Status (2026-07-01): COMPLETE.** `purl_ecosystem` added; `get_all_projects` /
`get_all_applications` now return `project_group`, `package_url`, and derived `language`; Group /
PURL / Language columns wired into both reports' HTML/JSON/Excel; schemas + tests updated.
Rows are not collapsed. Full suite green, ruff clean.

- `utils/purl.py`: add `purl_ecosystem(purl: str | None) -> str` — parse the `pkg:<type>/…` prefix
  to a language/ecosystem label (maven→Java, npm→JavaScript, pypi→Python, golang→Go, nuget→.NET,
  gem→Ruby, cargo→Rust, composer→PHP, …; unknown→raw type or "").
- `falkordb_service.get_all_projects`: also return `v.project_group`, `v.package_url` (already
  selected) → add `project_group`, `package_url`, derived `language` to each row dict.
- `falkordb_service.get_all_applications`: also return `app.project_group`, `app.package_url` →
  add `project_group`, `package_url`, derived `language`.
- HTML (`inventory.py`): add **Group**, **PURL**, **Language** columns to both reports’ `headers`
  and row builders.
- JSON (`exports/json_format.py` `projects_json` / `applications_json`): add the three fields.
- Excel (`exports/excel.py` `create_all_projects_excel` / `create_applications_excel`): add the
  three columns.
- Rows are **not** collapsed in this phase — the new columns expose *why* duplicates exist.

---

## Phase 3 — Ingestion node identity (purl) + duplicate-node diagnostic

> Separate, higher-risk phase: touches the `sbom-graph-model` subproject and existing data.

**Status (2026-07-01): COMPLETE.** 3a — `package_url` added to the Version MERGE identity
(null/empty falls back to the name/project_name/project_group triplet); scan_ids back-fill matches
the same identity; `specification.md` documents identity + the no-auto-migration note. 3b — new
`find_duplicate_version_nodes` / `count_duplicate_version_nodes` service methods and
`/reports/duplicate-nodes` diagnostic report (HTML/JSON/Excel) surfacing provenance splits and
genuine duplicates. Model suite 478 green; API suite 1517 green; ruff clean.

### 3a. Add purl to the MERGE key
- `sbom-graph-model/src/sbom_graph_model/persistence.py:create_project_version`: add
  `package_url` to `main_fields` (the MERGE identity) alongside name/project_name/project_group.
  Components with the same name+version+group but different purl become **distinct** nodes
  (provenance preserved). Null/empty purls fall back to the existing triplet bucket (document this).
- Update the `scan_ids` MATCH (`persistence.py:657`) to also match on `package_url` so the array is
  appended to the correct node.
- Update `sbom-graph-model/specification.md` / `contracts.md` and `tests/test_persistence.py`.
- **Migration note:** existing merged nodes will **not** retroactively split — a re-ingest (or a
  one-off migration script) is required to materialise the new identity. Call this out; do not
  auto-migrate unless requested.

### 3b. Duplicate-node diagnostic report
- New `/reports/duplicate-nodes` (in `routes/reports/inventory.py` or `dependencies.py`): groups
  Version nodes by `(project_name, name)` and surfaces (a) groups spanning multiple
  `project_group`/`package_url` values (expected-but-noteworthy provenance splits) and
  (b) **genuine** duplicates — same `(project_name, name, project_group, package_url)` with
  `count > 1`, which should not happen. New service method `find_duplicate_version_nodes()`.
  Gives engineering visibility into the scale and nature of the duplication.

---

## Phase 4 — Suspect / unreleased version detection

**Status (2026-07-01): COMPLETE.** `parse_semver` promoted to a module-level helper (shared
`_split_semver`); added `_classify_version_release(version, base_counts)`. `find_non_semver_versions`
now also returns technically-SemVer-but-suspect versions (pre-release / SNAPSHOT / branch-name),
tagged `semver_compliant` / `released` / `reason`; clean releases are excluded. `SemVer Compliant`
and `Released` columns added to `/reports/non-semver-versions` (HTML/JSON/Excel); schema updated.

- `falkordb_service.py`: add `_classify_version_release(version, base_counts)`:
  - **Unreleased:** prerelease or SNAPSHOT/`-dev`/branch-style suffix present → `released = False`.
  - **Branch-name versioning:** within a project, the `major.minor.patch` base is shared by
    multiple versions that differ only in prerelease → reason "Suspected branch-name versioning".
  - Add a base-extractor (reuse the `parse_semver` logic in `get_latest_semver_version:582`).
- Extend `find_non_semver_versions` (or add a sibling fed into the same report) to also return
  technically-semver-but-suspect versions, tagged with `semver_compliant: bool`,
  `released: bool`, and `reason`. These rows currently pass `SEMVER_PATTERN` so are absent today.
- `/reports/non-semver-versions` route + JSON/Excel: add **SemVer Compliant**, **Released**, and
  keep **Reason** columns. (Title/wording stays the same report.)

---

## Phase 5 — Bipartite tabular report with latest / latest-1 classification

**Status (2026-07-01): COMPLETE.** New `/reports/bipartite/<project_name>` (+ `/purl/<path:purl>`
307 redirect) via `render_paged_report` (HTML/JSON/Excel). New
`get_target_version_recency(project_name, internal_only) -> (latest, prev)` (semver-aware ordering,
sorted fallback for non-semver). Per-row `is_latest` / `is_latest_or_prev`; `recency` filter
(`latest` / `latest_or_prev` / `not_latest_or_prev`). New `BIPARTITE_SCHEMA` registered. Also
hardened `render_paged_report` to sanitise Excel sheet titles (invalid `\ / * ? : [ ]` stripped),
fixing a recurring latent bug.

- New routes `/reports/bipartite/<project_name>` (+ `/reports/bipartite/purl/<path:purl>` redirect),
  mirroring the existing visualization route in `routes/visualizations.py` but returning
  HTML table / Excel / JSON, paginated & streamed (Phase 1 infra).
- Data: reuse `get_direct_dependants(project_name, internal_only)` (rows: `dependant_project`,
  `dependant_version`, `target_project`, `target_version`) and
  `get_all_versions_of_project(project_name)` to rank the **target** (dependency) versions.
- New service helper `get_target_version_recency(project_name, internal_only)` → `(latest, prev)`
  using semver-aware ordering (reuse `parse_semver`); for non-semver projects fall back to sorted
  order and note the classification is approximate.
- Per row compute: `is_latest = target_version == latest`,
  `is_latest_or_prev = target_version in {latest, prev}`.
- Columns: Target Project, **Target Version**, **Is Latest**, **Is Latest-or-(Latest-1)**,
  Dependant Project, Dependant Version. JSON/Excel include the two boolean columns the user asked
  for.
- Filter param `recency` ∈ {`latest`, `latest_or_prev`, `not_latest_or_prev`} to filter rows —
  the third value is the `!(latest or latest-1)` case for finding poor dependency hygiene.

---

## Phase 6 — Name / partial-name filtering

**Status (2026-07-01): COMPLETE (initial scope).** Case-insensitive `name` substring filter
implemented on `/reports/projects`, `/reports/applications` (Cypher
`WHERE toLower(project_name) CONTAINS toLower($name)` via a shared `_name_filter` helper on the
count + page queries), and the bipartite report (in-memory filter on `dependant_project`).
Validated with `validate_search_term`; threaded through Excel/JSON/pagination URLs and prefilled in
a new search box in `table.html` (shown via `show_name_search`).

**Status (2026-07-02): FAST-FOLLOW COMPLETE.** Same `name` filter now on `/reports/trust-scores`
and the per-project dependency reports (`/reports/version-dependencies`,
`/reports/dependants`, `/reports/multi-version-deps`). Trust-scores pushes the filter into Cypher
via a new `_name_predicate` helper (bare predicate AND-ed onto the existing
`WHERE t.<score> IS NOT NULL …`; `_name_filter` now delegates to it). The per-project dependency
reports filter in-memory on the listed dependant/dependency `project_name` with counts/stats
recomputed for consistency; multi-version-deps drops versions with no matching dependant, and a
name filter matching nothing renders an empty view (with the search box) rather than a 404.
Search boxes added to the custom `trust_scores.html` and `dependants.html` templates; download
URLs carry `name` via a new `name` param on `build_url_params` / `build_url_with_params`.

**Analysis (which reports benefit):** strongest value on **project/version inventory** reports —
`/reports/projects`, `/reports/applications`, the new **bipartite** report, `/reports/trust-scores`,
and the per-project dependency reports. `/reports/vulnerabilities` already has `defect_id_match`;
`/reports/sbom-inventory` already has `search`.

---

## Phase 7 — Reporting gaps for engineering (deliverable)

**Status (2026-07-02): COMPLETE.** Deliverable written to
[`sbom-graph-api/docs/reporting-gaps.md`](../sbom-graph-api/docs/reporting-gaps.md) — a living
document with one section per gap (what it is / why engineering wants it / what already exists to
build on / proposed shape), grounded in the real routes and service helpers. The gaps captured:
- **Dependency-freshness fleet report** — generalise Phase 5 across all libraries: who is on
  latest / latest-1 / stale, ranked by fan-in (good upgrade-campaign targeting).
- **Duplicate / provenance-integrity report** — Phase 3b, kept as an ongoing data-quality KPI.
- **Language / ecosystem breakdown** — counts per ecosystem (now that we derive `language`).
- **Unreleased-in-production report** — apps depending on SNAPSHOT/branch builds (Phase 4 signal).
- **Pagination metadata everywhere** — total counts/`X-Total-Count` header for API consumers.
- **purl-based identity rollout** — re-ingest/migration tracking after Phase 3a.

---

## Phase 8 — Aggregate materialization (dashboard memory ceiling)

**Status (2026-07-02): COMPLETE.** Audit of the named endpoints found only `get_license_risk_dashboard`
was an unbounded scan-all-to-aggregate — all others are already bounded (`get_trust_scores_heatmap`
`limit=200`, `get_trust_score_gaps` `limit=20`, `get_all_trust_scores_for_report` paged,
`get_application_risk_dashboard` `limit=100`, `get_license_summary` per-project depth-bounded BFS,
risk-propagation/incident graph-bounded). Refactored the license-dashboard: `get_license_risk_dashboard`
(built a full per-category `packages` list in memory) is replaced by `get_license_risk_stats` (grouped
Cypher computing each package's worst risk category in-query → fixed-size counts/percentages, no rows
buffered), `get_license_risk_rows` (paged, optional worst-category filter) and `count_license_risk_rows`.
JSON/Excel stream rows page-by-page via `iterate_pages`; the HTML dashboard shows exact counts/bars plus
a bounded per-category sample (100) with a "download for full list" note. JSON contract unchanged;
`X-Total-Count` emitted. Suite 1587 green; ruff + mypy clean.
**Caveat:** the new grouped Cypher (worst-category `CASE`, `trim/toLower`, `WITH DISTINCT`) has not been
run against a live FalkorDB — validate when an instance is available.

Streaming (Phase 1) removed the buffered serialized-string copy for dashboard downloads, but the
underlying services still fully materialize the aggregate in memory before streaming.

- **`get_license_risk_dashboard`** (license-dashboard JSON/Excel) — has no `limit`/`offset`: it
  must scan the entire result set to compute per-category percentages, so the full aggregate is
  held in memory regardless of streaming. Streaming only avoids the extra serialized-string copy,
  not the base materialization. On very large graphs this remains an OOM risk.
- **Goal:** compute category counts/percentages without materializing every row — e.g. a two-pass
  or grouped Cypher aggregation (counts first, then stream rows per category), or push the
  percentage math into the query so Python only streams flat rows.
- **Scope:** audit the other dashboard/aggregate endpoints (application-risk-dashboard,
  trust-score-heatmap/gaps, risk-propagation-graph, license-summary, incident-response) for the
  same "scan-all-to-aggregate" pattern and apply the same treatment where it applies.

---

## Critical files
- `services/falkordb_service.py` — paged queries, counts, generators, recency/version helpers,
  suspect-version classification, duplicate-node query (`SEMVER_PATTERN:55`,
  `get_all_projects:278`, `get_all_applications:343`, `find_non_semver_versions:1714`,
  `get_latest_semver_version:556`, `get_direct_dependants:455`).
- `routes/reports/_common.py` — `parse_pagination`, pagination response helpers.
- `routes/reports/inventory.py` — projects/applications columns + filtering + bipartite report.
- `routes/reports/dependencies.py` — non-semver report changes.
- `exports/streaming.py` (new), `exports/excel.py`, `exports/json_format.py` — streaming writers.
- `templates/table.html` — pagination controls + name search box.
- `utils/validation.py` — `validate_page`/`validate_page_size`.
- `utils/purl.py` — `purl_ecosystem`.
- `sbom-graph-model/src/sbom_graph_model/persistence.py` — MERGE key (Phase 3).

## Verification
- **Unit/integration tests:** extend `tests/test_routes_reports*.py`, `tests/test_exports*.py`,
  `tests/test_falkordb_service*.py`, `tests/test_json_format.py`, and (Phase 3)
  `sbom-graph-model/tests/test_persistence.py`. Add cases for: pagination math
  (page/offset/total), `all=true` streaming, new columns present in HTML/JSON/Excel,
  `99.99.99-main.16-SNAPSHOT` now flagged suspect/unreleased, bipartite `is_latest` /
  `is_latest_or_prev` correctness, and the `recency`/`name` filters. Run with
  `cd sbom-graph-api && pytest` (and `cd sbom-graph-model && pytest` for Phase 3).
- **Memory:** export a large `/reports/projects?format=excel&all=true` and confirm flat memory
  (write_only + temp-file streaming) vs. the current in-memory build.
- **Manual:** `curl` each changed report in html/json/excel with `page`, `page_size`, `all=true`,
  `name=`, and (bipartite) `recency=` params; confirm paging links and counts in the HTML UI.
