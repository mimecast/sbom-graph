# Reporting gaps for engineering

**Status:** living document — Phase 7 deliverable of the [reporting overhaul](../../docs/reporting-overhaul-plan.md).

Phases 1–6 of the overhaul delivered paginated/streamed reports, provenance columns, purl node
identity, suspect-version detection, the bipartite latest/latest-1 report, and name filtering. In
doing so they surfaced a set of reports and capabilities that engineering still wants but that do
**not** exist yet (or exist only as a single-project drill-down that should be generalised).

Each gap below records **what it is**, **why engineering wants it**, **what already exists** to
build on, and a **proposed shape**. Ordering is roughly by expected value, not effort.

**Implementation status (2026-07-02):** **all six gaps implemented.** The four net-new reports —
#1 dependency-freshness, #3 ecosystem-breakdown, #4 unreleased-in-prod, #6 purl-coverage — plus
#2 (duplicate-nodes KPI counters) and #5 (uniform `X-Total-Count` header). See each section for the
route / service / schema details. The new reports are unit-tested at the service/route boundary
with a mocked graph; their Cypher has not yet been exercised against a live FalkorDB (none was
available at implementation time).

---

## 1. Dependency-freshness fleet report

**Status: IMPLEMENTED (2026-07-02)** — `/reports/dependency-freshness` (HTML/JSON/Excel),
`FalkorDBService.get_dependency_freshness` / `count_dependency_freshness`,
schema `/schemas/dependency-freshness`.

**What:** A fleet-wide view of who is on `latest` / `latest-1` / stale for **every** dependency,
ranked by fan-in (how many projects depend on the library).

**Why:** Phase 5 answers "for *this one* project, who is behind?" (`/reports/bipartite/<project>`).
Engineering wants the inverse, aggregated across the estate: "which stale dependencies affect the
most consumers?" — the natural targeting list for an upgrade campaign.

**Exists today:**
- `get_target_version_recency(project_name, internal_only) -> (latest, prev)` — semver-aware
  latest/latest-1 ranking (`falkordb_service.py`), currently per-project.
- Per-row `is_latest` / `is_latest_or_prev` classification and the `recency` filter in the bipartite
  report (`routes/reports/dependencies.py`).
- Fan-in counting already exists for source-impact (`total_count`/`transitive_count` aggregation,
  `falkordb_service.py:~4967`).

**Proposed shape:** A new `/reports/dependency-freshness` (paged/streamed via `render_paged_report`)
with one row per dependency library: `Target Project`, `Latest`, `Latest-1`, `# Consumers`,
`# on Latest`, `# on Latest-1`, `# Stale`, `% Stale`. Sortable by fan-in and by `% Stale`; reuse
the `recency` classification per consumer edge. The main new work is generalising the recency
computation to run once per library over all dependants rather than per target project.

---

## 2. Duplicate / provenance-integrity report (ongoing KPI)

**Status: IMPLEMENTED (2026-07-02)** — `FalkorDBService.get_duplicate_node_stats()` computes the
KPI breakdown (`affected_groups`, `provenance_splits`, `genuine_duplicates`) in a single aggregation
query; `/reports/duplicate-nodes` now surfaces all three in its HTML/JSON/Excel stats block (schema
`/schemas/duplicate-nodes` updated). The counts are a stable JSON shape suitable for a dashboard tile
or time-series scrape. (Historical trending — periodic snapshots — remains out of scope here.)

**What:** Promote the Phase 3b duplicate-node diagnostic from a one-off check to an ongoing
data-quality KPI with trendable numbers.

**Why:** Phase 3a changed the Version MERGE identity to include `package_url`; existing merged nodes
were intentionally **not** retro-split (see migration note in the plan). The duplicate report is how
we watch provenance splits and genuine duplicates shrink as re-ingest happens — it needs to be
tracked over time, not just glanced at once.

**Exists today:**
- `/reports/duplicate-nodes` (`routes/reports/inventory.py:372`) with HTML/JSON/Excel, surfacing
  (a) provenance splits — same `(project_name, name)` across multiple `project_group`/`package_url`
  and (b) genuine duplicates — same full identity tuple with `count > 1`.
- `find_duplicate_version_nodes()` / `count_duplicate_version_nodes()` service methods.

**Gap:** No summary counters (total splits, total genuine duplicates) exposed as a stable JSON shape
suitable for a dashboard tile or time-series scrape, and no historical tracking. **Proposed:** add a
compact stats block to the JSON response (already the pattern used by other reports via
`stats_builder`) and, if trending is wanted, a lightweight periodic snapshot of the two counts.

---

## 3. Language / ecosystem breakdown

**Status: IMPLEMENTED (2026-07-02)** — `/reports/ecosystem-breakdown` (HTML/JSON/Excel),
`FalkorDBService.get_ecosystem_breakdown` / `count_ecosystems`,
schema `/schemas/ecosystem-breakdown`. The package type is extracted in-query and the counts are
aggregated in the database (grouped), so raw rows are never materialised.

**What:** Counts of components per ecosystem (npm, maven, pypi, golang, …).

**Why:** Now that ecosystem is derivable from the purl, engineering can see the shape of the estate
by language — useful for tooling decisions, scanner coverage, and prioritisation.

**Exists today:**
- `purl_ecosystem(purl)` helper (`utils/purl.py:38`).
- `language` is already derived onto project/application rows via `purl_ecosystem`
  (`falkordb_service.py:468`, `:601`), so the data is present per row but never aggregated.

**Gap:** No aggregate report. **Proposed:** `/reports/ecosystem-breakdown` — a grouped count
(`ecosystem`, `# components`, `# distinct projects`, `% of estate`). This is a pure aggregation
(a `GROUP BY` on the derived ecosystem), so it should follow the Phase 8 "aggregate without
materialising every row" guidance rather than paging raw rows.

---

## 4. Unreleased-in-production report

**Status: IMPLEMENTED (2026-07-02)** — `/reports/unreleased-in-prod` (HTML/JSON/Excel),
`FalkorDBService.get_unreleased_in_production` / `count_unreleased_in_production`,
schema `/schemas/unreleased-in-prod`.

**What:** Applications/projects that depend on SNAPSHOT / branch-build / pre-release versions in
production.

**Why:** Phase 4 gave us the signal (a version can be flagged unreleased); engineering wants it
turned around into a risk list: "which shipped apps are pulling non-released dependencies?"

**Exists today:**
- `_classify_version_release(version, base_counts)` and the extended `find_non_semver_versions`,
  which tag rows `semver_compliant` / `released` / `reason` (SNAPSHOT, `-dev`, branch-name, etc.).
- `/reports/non-semver-versions` (`routes/reports/dependencies.py:641`) already shows the
  **SemVer Compliant** / **Released** columns for the versions themselves.

**Gap:** The current report is version-centric (which versions look suspect), not consumer-centric
(which *applications* depend on an unreleased version). **Proposed:** `/reports/unreleased-in-prod`
that joins the `released = False` classification back to the dependant applications: `Application`,
`Dependency`, `Version`, `Reason`. Reuses the existing classifier plus the dependant traversal
(`get_direct_dependants`).

---

## 5. Pagination metadata everywhere (API consumers)

**Status: IMPLEMENTED (2026-07-02)** — every response from the `render_paged_report` choke point
(HTML, JSON, Excel) now carries an `X-Total-Count` header with the full result-set size
(`routes/reports/_common.py`, constant `TOTAL_COUNT_HEADER`). Chosen over a `total` field in the
JSON body because several report schemas set `additionalProperties: false` at the top level — a new
body field would make those responses violate their own published schema, whereas a header does not.

**What:** Expose total counts / page metadata to programmatic consumers, not just the HTML pager.

**Why:** HTML reports render a full pager (`build_page_view` computes `total`, `pages`, etc.), but a
script hitting the JSON endpoints has no reliable way to learn the total result size or page count
without walking every page.

**Exists today:**
- `build_page_view(req, total, ...)` computes `total`, page count, and links for HTML
  (`routes/reports/_common.py:143`).
- JSON exports stream a `{...meta, "data": [...], "stats": {...}}` document, and several reports put
  totals in `stats` — but inconsistently, and there is **no** `X-Total-Count` header.

**Gap:** No standard, uniform pagination metadata for API callers. **Proposed:** (a) emit an
`X-Total-Count` header on paged JSON responses, and/or (b) standardise a `pagination` block in the
JSON `meta` (`total`, `page`, `page_size`, `pages`). Best done as one change in the
`render_paged_report` / `stream_json_response` choke point so every report inherits it.

---

## 6. purl-based identity rollout tracking

**Status: IMPLEMENTED (2026-07-02)** — `/reports/purl-coverage` (HTML/JSON/Excel),
`FalkorDBService.get_purl_coverage`, schema `/schemas/purl-coverage`. Implemented as a small
standalone coverage report (with-purl vs fallback bucket + coverage %).

**What:** Visibility into how far the Phase 3a purl-identity change has propagated through the data
via re-ingest.

**Why:** Phase 3a deliberately did **not** auto-migrate existing nodes — the new
`package_url`-in-identity behaviour only materialises as components are re-ingested. Engineering
needs to know how much of the graph still predates the new identity so they can judge when the
duplicate/provenance numbers (gap #2) can be trusted as "clean".

**Exists today:**
- purl is on the Version MERGE identity and back-filled onto `scan_ids` (Phase 3a).
- The duplicate-nodes report (gap #2) is the closest existing signal.

**Gap:** No direct rollout metric. **Proposed:** a coverage counter — `# Version nodes with a
non-null/non-empty package_url` vs total (i.e. what fraction still sits in the fallback
name/project_name/project_group bucket). Surface it either as a stat on the duplicate-nodes report
or as a small `/reports/purl-coverage` tile. Pairs naturally with gap #2 as the "are we there yet?"
number for the identity migration.

---

## Cross-cutting note

Gaps #3 (ecosystem breakdown) and any future all-estate aggregate should be built against the
Phase 8 guidance (compute counts/percentages without materialising every row) rather than the
row-paging path, since they scan the whole graph to aggregate.
