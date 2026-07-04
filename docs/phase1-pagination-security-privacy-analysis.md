# Security and Privacy by Design Analysis: SBOM-Graph Reporting — Phase 1 (Pagination, Streaming Exports & Visualizations)

**Date:** 2026-06-26
**Version:** 1.0
**Frameworks:** STRIDE · LINDDUN · OWASP Top 10 · GDPR / Privacy by Design
**Regulatory scope:** GDPR (minimal — operator usernames only), CRA (assessed: out of scope), NIS2 (assessed: no new obligations)

---

## Executive Summary

Phase 1 adds real pagination (`page`/`page_size`), an unlimited `all=true` flag, page-by-page
streaming exports (Excel via openpyxl `write_only` + temp file, JSON via `stream_with_context`),
and streamed/bounded PyVis visualizations to the SBOM-graph reporting API. The primary motivation
is reliability: the current "load everything into memory, then build the whole workbook/dict"
design OOMs the process on large result sets — a self-inflicted **Denial of Service**.

The dominant risk class for this change is **resource exhaustion / DoS**, and ironically the new
`all=true` flag *re-introduces* the very failure mode we are fixing if it is implemented as
"remove the cap and buffer." The single most important design rule for this phase: **`all=true`
must stream end-to-end and never materialise the full result set** (constant memory), and
`page_size`/`offset` must be hard-bounded server-side.

The second risk class is **information disclosure via authorization-filter bypass**: the
`internal_only` label filter is the only thing separating "all nodes" from "internal-only" views.
Pagination, generators, and count queries must apply the *same* label filter on every page and in
every count — a divergence between the page query and the count query, or an unfiltered generator,
would leak internal component inventory.

Privacy exposure is **low**: reports contain software supply-chain metadata (project/component
names, versions, purls, licenses, vulnerabilities, trust scores, source-repo URLs, scan/public
IDs), not personal data. The only personal data in the system is operator usernames (handled by
the pre-existing auth layer, unchanged here).

**Top priorities for engineering:**
1. **Stream `all=true`** (constant memory) — never buffer; this is the whole point of the phase.
2. **Hard-bound `page_size` (≤1000) and `offset`** server-side; parameterise `SKIP/LIMIT` (`$offset`,`$limit`) — no string interpolation.
3. **Cap visualization node/edge counts** with an explicit "truncated at N" notice; stream the HTML.
4. **Apply `internal_only` consistently** across page query, count query, and streaming generator.
5. **Secure temp-file handling** for Excel streaming (scratch dir, unique name, 0600, guaranteed cleanup) + **rate-limit/audit** the expensive report & export endpoints (currently neither exists).

---

## 1. Assumptions and Context

Answers to intake questions (derived from the codebase during planning; flagged where assumed):

1. **What is being built?** A reliability/scalability change to an internal SBOM-graph reporting
   API: server-side pagination, an unlimited streaming mode, memory-safe Excel/JSON exports, and
   bounded streamed graph visualizations. No change to *what* data is returned, only *how* it is
   paged/streamed.
2. **Actors.** Authenticated internal users (session via LDAP/local login) and API-token consumers
   (`@auth_required`); admins; the FalkorDB graph backend; background enrichment workers (not in
   scope). All report endpoints require authentication today.
3. **Data handled.** Software supply-chain metadata: component/project/application names, versions,
   purls, group ids, licenses, vulnerabilities (CVE/GHSA), trust scores, source-repo URLs,
   `scan_id`/`public_id`/`app_id`. **Not personal data.** Operator usernames exist only in the
   auth/token layer (unchanged). Source-repo URLs and internal app identifiers are
   **confidential business data** (internal architecture), not PII.
4. **Deployment.** Kubernetes (Helm charts present), internal/private network, single-tenant
   (one organisation), multi-user. *Assumption:* not exposed to the public internet.
5. **Compliance.** Internal tooling. GDPR footprint minimal (usernames). The tool itself *supports*
   the org's CRA/SBOM obligations for other products but is not a placed-on-market product.
6. **Sold/distributed in the EU?** No — internal hosted service, not placed on the EU market.
7. **Downloadable/embedded software component?** No — purely a hosted internal service.

**CRA applicability:** **Out of scope.** Internal hosted service, not placed on the EU market, no
downloadable/embedded element. (Flag for compliance to confirm; revisit if the product is ever
externalised.)
**NIS2 applicability:** Mimecast may be an "important/essential entity," but this internal tool
generates **no new** NIS2 obligations; it contributes positively to supply-chain security posture.
**PSTI:** Not applicable (not a consumer connectable device).

---

## 2. Requirements Classification and Gap Analysis

### Original requirements (from the plan)

| ID | Requirement | Type |
|----|-------------|------|
| FR-001 | `page` & `page_size` query params on every report; server-side paging for HTML | FR |
| FR-002 | `all=true` flag returns the full result set (cap lifted) | FR |
| FR-003 | Excel export streams page-by-page (openpyxl `write_only` + temp file) | FR |
| FR-004 | JSON export streams page-by-page (`stream_with_context`) | FR |
| FR-005 | HTML paging UI: Prev/Next, "Page X of Y (N total)", `page_size` selector | FR |
| FR-006 | Visualizations fed from paged generators, bounded node/edge count, streamed HTML | FR |
| FR-007 | Backward compatibility — existing `limit` behaviour preserved | FR |
| PERF-001 | Flat/constant memory regardless of result size (incl. `all=true`) | PERF |

### Gaps found (become `[NEW]` requirements in §7)

- **SEC — input bounds:** `page_size` and `offset` upper bounds; behaviour on invalid/negative/overflow input. *(SEC-001/002)*
- **SEC — `all=true` cannot OOM:** the unlimited mode must be *streaming-only*, never buffered. *(SEC-003)*
- **SEC — query construction:** paging values must be parameterised, never interpolated, in Cypher. *(SEC-004)*
- **SEC — visualization bound:** node/edge cap to prevent render/memory blow-up. *(SEC-005)*
- **SEC — temp-file safety:** secure creation, permissions, and guaranteed cleanup of streamed Excel temp files. *(SEC-006)*
- **SEC — auth on streamed responses:** auth enforced *before* the generator starts; mid-stream errors must not leak internals. *(SEC-007, SEC-010)*
- **SEC — rate limiting:** **no rate limiting exists** on report/export endpoints today (only login). Expensive endpoints (large pages, `all=true`, big graphs) are unthrottled. *(SEC-008)*
- **SEC — count-query cost:** total-count queries must apply the same filters and be bounded. *(SEC-009)*
- **PRV/SEC — filter consistency:** `internal_only` (and any future authz filter) applied identically to page query, count query, and generator. *(PRV-001)*
- **COMP — access/audit logging:** **no access/export audit logging exists**; exports of the full internal inventory are not recorded (non-repudiation gap). *(COMP-003)*
- **PERF — deep-offset degradation:** large `SKIP` offsets degrade; note keyset/cursor pagination as a future option. *(PERF-002)*

---

## 3. Use Cases

```
UC-001: Page through a report in the browser
Actor: Authenticated user
Goal: View a large report one page at a time without loading everything
Preconditions: User authenticated; report endpoint exists
Main Flow:
  1. User opens /reports/<name>?page=1&page_size=100
  2. API validates paging params, applies internal_only/authz filter
  3. Service runs MATCH ... ORDER BY ... SKIP $offset LIMIT $limit + count query
  4. HTML renders the page with Prev/Next and "Page X of Y (N total)"
Postconditions: One bounded page returned; memory proportional to page_size
Data involved: Read-only supply-chain metadata
Trust boundary crossings: Client → API (auth); API → FalkorDB (parameterised query)
```

```
UC-002: Export an entire report (unlimited) without OOMing the service
Actor: Authenticated user / API-token consumer
Goal: Download the full report as Excel or JSON
Preconditions: Authenticated
Main Flow:
  1. GET /reports/<name>?format=excel&all=true (or format=json)
  2. API authorises, then opens a streaming response
  3. Service generator yields pages (SKIP/LIMIT loop); exporter writes each page out
     (openpyxl write_only → temp file; or JSON chunks via stream_with_context)
  4. Response streamed to client; temp file cleaned up afterwards
Postconditions: Full data delivered; server memory stays flat
Data involved: Full report dataset (read-only)
Trust boundary crossings: Client → API (auth); API → FalkorDB; API → temp filesystem (Excel)
```

```
UC-003: Render a bounded, streamed graph visualization
Actor: Authenticated user
Goal: View a dependency/bipartite/blast-radius graph without OOMing on huge graphs
Preconditions: Authenticated
Main Flow:
  1. GET /visualizations/<type>/<project>
  2. API authorises; service yields edges/nodes from paged generator up to the cap
  3. PyVis builds the network; if cap exceeded, a "truncated at N nodes" notice is included
  4. Generated HTML streamed to client (chunked)
Postconditions: Bounded graph rendered; truncation surfaced and logged
Data involved: Read-only graph metadata
Trust boundary crossings: Client → API (auth); API → FalkorDB
```

---

## 4. Threat Analysis

### 4.1 Security Threats (STRIDE)

```
ST-001: Unbounded all=true buffers the full result set → OOM (re-introduces the bug)
STRIDE: Denial of Service
Affected: UC-002
Description: If all=true is implemented as "remove LIMIT and build the workbook/dict in memory,"
  a large graph exhausts memory and crashes the worker — the exact failure this phase fixes.
Attack vector: Any authenticated user requests all=true on the largest report/export.
Likelihood: High (trivial, single request) · Impact: High (process crash, multi-user outage)
```

```
ST-002: Oversized page_size or deep offset exhausts memory / CPU
STRIDE: Denial of Service
Affected: UC-001
Description: page_size=10_000_000 or offset=2_000_000_000 forces a huge SKIP/LIMIT, large result
  buffer, or expensive scan.
Attack vector: Crafted query params.
Likelihood: High · Impact: Medium–High
```

```
ST-003: Cypher injection via paging params
STRIDE: Tampering / Elevation
Affected: UC-001, UC-002
Description: If page/page_size/offset are string-interpolated into the Cypher (e.g.
  f"SKIP {offset}"), an attacker could break out of the clause.
Attack vector: Non-numeric/crafted page params.
Likelihood: Low (codebase parameterises elsewhere) · Impact: High (data tampering/exfiltration)
```

```
ST-004: Huge graph visualization exhausts memory / render time
STRIDE: Denial of Service
Affected: UC-003
Description: A project with tens of thousands of dependants builds an enormous PyVis Network and
  one giant HTML string.
Attack vector: Request a visualization for a high-fan-in node.
Likelihood: Medium · Impact: High
```

```
ST-005: Temp-file mishandling for streamed Excel
STRIDE: Information Disclosure / DoS
Affected: UC-002
Description: World-readable temp files, predictable names (symlink race), or files left undeleted
  fill the disk or leak exported inventory to other local processes.
Attack vector: Local co-tenant process / disk fill via repeated exports.
Likelihood: Low–Medium · Impact: Medium
```

```
ST-006: internal_only filter bypass via inconsistent paging/count
STRIDE: Information Disclosure
Affected: UC-001, UC-002
Description: If the page query filters on :INTERNAL but the count query or the streaming generator
  does not, internal-only consumers see counts/rows for non-internal components.
Attack vector: Internal-scoped user paging/exporting; or a refactor that drifts the two queries.
Likelihood: Medium · Impact: Medium–High (confidential inventory disclosure)
```

```
ST-007: Mid-stream error leaks stack trace / partial sensitive data
STRIDE: Information Disclosure
Affected: UC-002
Description: An exception after headers are sent could append a stack trace into the streamed
  JSON/Excel, or emit malformed/partial data interpreted as complete.
Likelihood: Medium · Impact: Low–Medium
```

```
ST-008: No rate limiting on expensive endpoints
STRIDE: Denial of Service
Affected: UC-001/002/003
Description: Report, export, and visualization endpoints have no throttle; repeated all=true /
  large-graph requests saturate FalkorDB and workers.
Likelihood: Medium · Impact: Medium–High
```

```
ST-009: Repudiation — full-inventory exports are not logged
STRIDE: Repudiation
Affected: UC-002
Description: A user can export the entire internal component/vuln inventory with no audit record.
Likelihood: Medium · Impact: Medium
```

### 4.2 Privacy Threats (LINDDUN)

```
PT-001: Non-compliance / Disclosure — bulk export of confidential supply-chain inventory
LINDDUN: Disclosure of information / Non-compliance
Affected: UC-002
Description: all=true makes it trivial to exfiltrate the complete internal software inventory
  (apps, internal repo URLs, versions). This is confidential business data, not PII, but the bulk
  egress + lack of logging is a data-governance concern.
Affected data: Internal component/app inventory, source-repo URLs
Affected subjects: The organisation (not individuals)
Likelihood: Medium · Impact: Medium
GDPR relevance: Minimal (no PII); governed by internal confidentiality, not GDPR.
```

> LINDDUN coverage is intentionally light: the reporting datasets contain no personal data.
> Operator usernames are confined to the unchanged auth layer and out of scope for this phase.

---

## 5. Abuse Cases

### 5.1 Security Abuse Cases

```
SAC-001: OOM via all=true (buffered implementation)
Linked threat: ST-001 · Attacker: External authenticated (or careless user)
Goal: Crash the service / cause an outage
Attack Flow:
  1. Authenticate (valid token/session)
  2. GET the largest report with format=excel&all=true
  3. If the implementation buffers, the worker's memory spikes and OOM-kills
Impact: Multi-user outage, dropped in-flight requests
OWASP: A04:2021 – Insecure Design / A05 – Security Misconfiguration
```

```
SAC-002: Resource exhaustion via crafted paging params
Linked threat: ST-002 · Attacker: External authenticated
Goal: Degrade or crash the service
Attack Flow:
  1. Request page_size=99999999 (or many parallel deep-offset requests)
  2. Server allocates/scans far beyond a reasonable page
Impact: Latency spikes, memory pressure, DB load
OWASP: A04:2021 – Insecure Design
```

```
SAC-003: Cypher injection through page params
Linked threat: ST-003 · Attacker: External authenticated
Goal: Read/alter data outside the intended scope
Attack Flow:
  1. Supply a non-numeric/crafted page/page_size value
  2. If interpolated into Cypher, alter the query
Impact: Data exfiltration/tampering
OWASP: A03:2021 – Injection
```

```
SAC-004: Visualization graph bomb
Linked threat: ST-004 · Attacker: External authenticated
Goal: Exhaust memory/CPU via a giant graph render
Attack Flow:
  1. Request a visualization for a node with massive fan-in/out
  2. Unbounded PyVis network + HTML string blows up memory
Impact: Worker OOM / long render stall
OWASP: A04:2021 – Insecure Design
```

```
SAC-005: Internal inventory disclosure via filter drift
Linked threat: ST-006 · Attacker: Internal-scoped user (or exploited refactor)
Goal: See non-internal components they shouldn't
Attack Flow:
  1. Page/export with internal_only semantics
  2. Count or generator query omits the :INTERNAL filter → leaks rows/counts
Impact: Confidential inventory disclosure
OWASP: A01:2021 – Broken Access Control
```

### 5.2 Privacy Abuse Cases

```
PAC-001: Untracked bulk egress of confidential inventory
Linked threat: PT-001 · Actor: Authenticated user / compromised token
Scenario: An actor exports the entire internal SBOM inventory via all=true with no audit trail,
  enabling reconnaissance of the org's internal software estate.
Affected subjects: The organisation
PbD principle violated: Visibility and Transparency; End-to-end Security
Regulatory exposure: Internal confidentiality / data-governance (not GDPR-bearing)
```

---

## 6. Counter-Use Cases

### 6.1 Security Use Cases (Countermeasures)

```
SUC-001: Streaming-only unlimited mode
Mitigates: SAC-001
Control: Implement all=true exclusively over the page generator + streaming writers; the response
  body is produced incrementally (openpyxl write_only → temp file; JSON via stream_with_context).
  No code path buffers the full dataset for any format/flag combination.
Implementation: exports/streaming.py; iter_*() generators in falkordb_service.py.
ASVS: §12.x resource handling
Residual risk: Sustained streaming still loads FalkorDB — addressed by SUC-008 (rate limit).
```

```
SUC-002: Hard server-side bounds on paging input
Mitigates: SAC-002
Control: validate_page (≥1, default 1) and validate_page_size (1..MAX_PAGE_SIZE=1000, default 100);
  cap offset; invalid/overflow → default. Reuse validate_int_param.
Implementation: utils/validation.py; parse_pagination() in routes/reports/_common.py.
ASVS: §5.1 input validation
Residual risk: Deep valid offsets still cost — see PERF-002 / future keyset paging.
```

```
SUC-003: Parameterised paging in Cypher
Mitigates: SAC-003
Control: Always pass $offset/$limit as query parameters to execute_query; never f-string them.
  Validation guarantees ints, so even a regression cannot inject.
Implementation: falkordb_service.py paged methods.
ASVS: §5.3 output encoding / query parameterisation
Residual risk: None if both validation and parameterisation hold (defence in depth).
```

```
SUC-004: Visualization node/edge cap + truncation notice
Mitigates: SAC-004
Control: Validated MAX_GRAPH_NODES/EDGES cap; pull edges from the paged generator up to the cap;
  when exceeded, stop, render a visible "graph truncated at N" banner, and log the drop count.
Implementation: visualizations/*.py + routes/visualizations.py.
Residual risk: Cap must be tuned; default conservatively.
```

```
SUC-005: Secure temp-file handling for streamed Excel
Mitigates: SAC-005 (ST-005)
Control: Create temp files in the configured scratch dir via tempfile.NamedTemporaryFile
  (mode 0600, unpredictable name), stream with the file handle open, and delete in a finally/
  context-manager even on error.
ASVS: §12.4 file storage
Residual risk: Disk pressure under heavy concurrency — bounded by SUC-008.
```

```
SUC-006: Authorise before streaming; safe mid-stream errors
Mitigates: ST-007, SAC-001 partials
Control: @auth_required runs before the generator starts (Flask already evaluates the decorator
  before the view returns the streaming Response). Wrap the generator so an internal error logs
  server-side and terminates the stream without appending stack traces; never emit a 200 with a
  half-written body presented as complete (set headers/format so truncation is detectable).
ASVS: §7.x error handling
Residual risk: Client must treat a truncated stream as failure (documented).
```

```
SUC-007: Consistent authz/internal_only filtering across page, count, and generator
Mitigates: SAC-005
Control: Build the label filter once (get_node_label/internal_label) and reuse it in the page
  query, the count_*() query, and the iter_*() generator. Add tests asserting count == rows for a
  filtered fixture, and that internal_only never returns non-internal nodes.
ASVS: §4.x access control
Residual risk: Future filters must follow the same single-source pattern.
```

```
SUC-008: Rate limit + bound concurrency on report/export/visualization endpoints
Mitigates: SAC-001, SAC-002, SAC-004, ST-008
Control: Apply a per-identity rate limit to the heavy endpoints (reuse/extend the existing
  in-memory limiter pattern from auth.py, or introduce a shared limiter). Optionally cap concurrent
  all=true streams per identity.
ASVS: §11.x business-logic / anti-automation
Residual risk: In-memory limiter is per-process; a shared store (Redis/FalkorDB) is a follow-up.
Note: May be scoped as a fast-follow if it expands Phase 1 too far — flag to product owner.
```

```
SUC-009: Bounded, filtered count queries
Mitigates: ST-006 cost, ST-002
Control: count_*() uses MATCH ... RETURN count(*) with the same filter; FalkorDB counts are
  acceptable. If counts prove expensive on the largest labels, fall back to "has next page"
  detection (fetch page_size+1) and omit the absolute total.
Residual risk: None significant.
```

### 6.2 Privacy Use Cases (Privacy Controls)

```
PUC-001: Audit-log report access and bulk exports
Mitigates: PAC-001 (ST-009)
Control: Emit a structured access log (identity, endpoint, format, all=true, row/byte count,
  timestamp) for report and export requests. No audit logging exists today.
PbD principle: Visibility and Transparency
Implementation: a small logging hook in routes/reports/_common.py (or a decorator).
GDPR: N/A (no PII) — internal data-governance control.
Residual risk: Log retention/rotation handled by platform logging.
```

```
PUC-002: No new data exposure; preserve existing scope
Mitigates: PT-001
Control: Pagination/streaming returns exactly the columns/rows the non-paged report returned —
  no additional fields. internal_only semantics preserved per SUC-007.
PbD principle: Privacy as the Default
Residual risk: Phase 2 adds columns (purl/group/language) — re-assess there.
```

---

## 7. Refined Requirements

**Functional (FR)** — original FR-001..FR-007, PERF-001 retained verbatim from §2.

**Security (SEC)**
- **SEC-001 [NEW — SUC-002]:** `page_size` validated to 1..1000 (default 100); invalid/oversized → default.
- **SEC-002 [NEW — SUC-002]:** `page` validated ≥1 (default 1); `offset=(page-1)*page_size` capped; invalid → default.
- **SEC-003 [NEW — SUC-001]:** `all=true` is streaming-only; **no** code path buffers the full result set for any format.
- **SEC-004 [NEW — SUC-003]:** paging values passed as Cypher parameters (`$offset`,`$limit`); never string-interpolated.
- **SEC-005 [NEW — SUC-004]:** visualizations cap node/edge counts (validated max) and surface + log truncation.
- **SEC-006 [NEW — SUC-005]:** streamed-Excel temp files created securely (scratch dir, 0600, unique) and always cleaned up.
- **SEC-007 [NEW — SUC-006]:** authorization enforced before streaming begins; mid-stream errors don't leak internals or present partial data as complete.
- **SEC-008 [NEW — SUC-008]:** rate limiting / concurrency bound on report, export, and visualization endpoints. *(Candidate fast-follow.)*
- **SEC-009 [NEW — SUC-009]:** count queries apply the same filters and are bounded (or use page_size+1 has-next detection).

**Privacy (PRV)**
- **PRV-001 [NEW — SUC-007]:** `internal_only`/authz filter applied identically across page query, count query, and generator.
- **PRV-002 [NEW — PUC-002]:** no new columns/rows vs. the non-paged report.

**Performance (PERF)**
- PERF-001 (original): constant memory regardless of result size, including `all=true`.
- **PERF-002 [NEW]:** document deep-offset degradation; keyset/cursor pagination noted as future work.

**Compliance (COMP)**
- **COMP-001:** CRA assessed **out of scope** (recorded for traceability).
- **COMP-002:** NIS2 assessed — **no new obligations** (recorded).
- **COMP-003 [NEW — PUC-001]:** access/audit logging for report access and bulk exports (non-repudiation). *(Candidate fast-follow.)*

---

## 8. Security Requirements Traceability Matrix

| Req ID | Requirement (brief) | Type | Use Case | Threat / Abuse | Control | Test ID | Test Description | Priority |
|--------|--------------------|------|----------|----------------|---------|---------|------------------|----------|
| FR-001 | page/page_size paging | FR | UC-001 | — | SUC-002 | TA-001 | Page N returns rows [offset, offset+page_size); ordering stable | High |
| FR-002 | all=true full set | FR | UC-002 | ST-001 | SUC-001 | TA-002 | all=true returns every row across pages | High |
| FR-003 | streaming Excel | FR | UC-002 | ST-001 | SUC-001/005 | TA-003 | Excel built via write_only+temp file; opens; row count correct | High |
| FR-004 | streaming JSON | FR | UC-002 | ST-001 | SUC-001 | TA-004 | JSON streamed; valid envelope; full data | High |
| FR-005 | HTML paging UI | FR | UC-001 | — | — | TA-005 | Prev/Next, "Page X of Y (N total)", page_size selector render | Medium |
| FR-006 | viz paged+bounded+streamed | FR | UC-003 | ST-004 | SUC-004 | TA-006 | Graph capped; truncation notice; streamed response | High |
| FR-007 | back-compat limit | FR | UC-001 | — | — | TA-007 | Legacy limit param still honoured | Medium |
| PERF-001 | constant memory | PERF | UC-002 | ST-001 | SUC-001 | TA-008 | Peak memory flat across 10x dataset growth (all=true) | Critical |
| SEC-001 | page_size ≤1000 | SEC | UC-001 | ST-002/SAC-002 | SUC-002 | TA-009 | page_size>max and negative → default; boundary 1000/1001 | Critical |
| SEC-002 | page≥1, offset cap | SEC | UC-001 | ST-002 | SUC-002 | TA-010 | page=0/-1/abc → default; offset overflow handled | High |
| SEC-003 | streaming-only all | SEC | UC-002 | ST-001/SAC-001 | SUC-001 | TA-008 | No buffered path; generator drives all formats | Critical |
| SEC-004 | parameterised SKIP/LIMIT | SEC | UC-001/002 | ST-003/SAC-003 | SUC-003 | TA-011 | Injection-style params rejected; query uses $params | Critical |
| SEC-005 | viz node cap | SEC | UC-003 | ST-004/SAC-004 | SUC-004 | TA-012 | >cap nodes truncated + notice + logged | High |
| SEC-006 | temp-file safety | SEC | UC-002 | ST-005 | SUC-005 | TA-013 | Temp file 0600, unique, deleted on success and on error | High |
| SEC-007 | auth-before-stream / safe errors | SEC | UC-002 | ST-007/SAC-001 | SUC-006 | TA-014 | Unauthed gets 401 before stream; mid-stream error → no stack, detectable truncation | High |
| SEC-008 | rate limit heavy endpoints | SEC | UC-001/002/003 | ST-008 | SUC-008 | TA-015 | Nth rapid request throttled (429) | Medium |
| SEC-009 | filtered bounded counts | SEC | UC-001 | ST-006 | SUC-009 | TA-016 | count == rows for fixture; same filter applied | High |
| PRV-001 | consistent internal_only | PRV | UC-001/002 | ST-006/SAC-005 | SUC-007 | TA-017 | internal_only never returns non-internal across pages+count+stream | High |
| PRV-002 | no new exposure | PRV | UC-001/002 | PT-001 | PUC-002 | TA-018 | Paged columns == non-paged columns | Medium |
| PERF-002 | deep-offset documented | PERF | UC-001 | — | — | TA-019 | Deep offset returns correct page (perf note only) | Low |
| COMP-003 | access/export audit log | COMP | UC-002 | ST-009/PAC-001 | PUC-001 | TA-020 | Export emits structured access-log record | Medium |

---

## 9. Test Artifacts

### 9.1 Functional Security Tests
```
TA-001: Pagination math — page slicing
Requirement(s): FR-001, SEC-002 · Unit/Integration
Scenario: Given 250 rows, page_size=100: page 1→rows 0-99, page 2→100-199, page 3→200-249, page 4→empty.
Expected: Correct slice + stable ORDER BY; total=250, pages=3. · Automation: High
```
```
TA-002/TA-004: all=true completeness (JSON)
Requirement(s): FR-002, FR-004, SEC-003 · Integration
Scenario: all=true streams every row; assemble stream and compare to full fixture; envelope valid JSON.
Expected: Set equality with fixture; well-formed streamed JSON. · Automation: High
```
```
TA-003: Streaming Excel correctness
Requirement(s): FR-003 · Integration
Scenario: Export all=true Excel; reopen with openpyxl; assert header + row count + sample values.
Expected: Valid xlsx, write_only path used, temp file gone afterwards. · Automation: High
```
```
TA-005: HTML paging controls
Requirement(s): FR-005 · Integration (template)
Scenario: Render page 2 of 5; assert Prev/Next hrefs carry params, "Page 2 of 5 (N total)", selector present.
Expected: Correct links/labels. · Automation: High
```
```
TA-006/TA-012: Visualization cap + truncation + stream
Requirement(s): FR-006, SEC-005 · Integration
Scenario: Fixture exceeding MAX_GRAPH_NODES; assert node count == cap, truncation banner present, log emitted, response streamed.
Expected: Bounded graph + visible/ logged truncation. · Automation: High
```
```
TA-007: Backward compatibility
Requirement(s): FR-007 · Integration
Scenario: Legacy ?limit=50 still returns ≤50 rows. Expected: unchanged behaviour. · Automation: High
```
```
TA-008: Constant memory under growth
Requirement(s): PERF-001, SEC-003 · Integration/perf
Scenario: Run all=true export against 1x and 10x fixtures; assert peak RSS does not scale with dataset size (tracemalloc/peak check or generator-call assertion that no full list is built).
Expected: Flat memory; service builds at most one page at a time. · Automation: Medium
```
```
TA-016: Count matches rows with same filter
Requirement(s): SEC-009 · Unit/Integration
Scenario: count_*() vs len(all rows) for filtered + unfiltered fixtures. Expected: equal. · Automation: High
```
```
TA-018: No new exposure
Requirement(s): PRV-002 · Integration
Scenario: Compare column set of paged vs pre-existing report output. Expected: identical. · Automation: High
```

### 9.2 Security Attack Tests
```
TA-009: page_size abuse
Abuse case: SAC-002 · Automated
Scenario: page_size in {0,-1,1001,99999999,"abc","1e9"} → clamped to default/max; boundary 1000 ok, 1001 → default/clamp.
Expected: No oversized allocation; bounded rows. · Tools: pytest param matrix
```
```
TA-010: page/offset abuse
Abuse case: SAC-002 · Automated
Scenario: page in {0,-5,"abc", huge}; assert default/clamped, no overflow error. Expected: graceful. 
```
```
TA-011: Cypher injection via paging
Abuse case: SAC-003 · Automated
Scenario: page/page_size carrying Cypher metacharacters; assert validation rejects → default, and query uses $params (inspect/parameter assertion).
Expected: No injection; parameterised. · Tools: pytest + query spy
```
```
TA-013: Temp-file safety
Requirement(s): SEC-006 · Automated
Scenario: During Excel stream, assert temp file in scratch dir, mode 0600; after success AND after an injected mid-write error, assert file removed.
Expected: Secure perms + guaranteed cleanup. 
```
```
TA-014: Auth-before-stream & safe mid-stream error
Abuse case: ST-007 · Automated
Scenario: (a) unauthenticated request → 401 before any body; (b) inject exception mid-generator → response terminates without stack trace, truncation detectable.
Expected: No partial-as-complete; no info leak. 
```
```
TA-015: Rate limiting (if SEC-008 in scope)
Abuse case: SAC-001/002 · Automated
Scenario: Rapid repeated all=true requests → throttled (429) after threshold.
Expected: Throttle engaged. 
```

### 9.3 Privacy Verification Tests
```
TA-017: internal_only consistency across page/count/stream
Requirement(s): PRV-001 · Automated
Scenario: Fixture with internal + non-internal nodes; internal_only=true across all pages, the count, and the stream returns ONLY internal nodes; counts agree.
Expected: Zero non-internal leakage. · Automation: High
```
```
TA-020: Access/export audit log (if COMP-003 in scope)
Requirement(s): COMP-003 · Automated
Scenario: Trigger an export; assert a structured access-log record (identity, endpoint, format, all flag, count, ts) is emitted.
Expected: Record present and complete. 
```

### 9.4 Penetration Testing Scenarios
```
TA-PEN-001: Resource-exhaustion sweep
Scope: /reports/* and /visualizations/* (paging, all=true, large graphs)
Objectives: Trigger OOM/latency collapse via paging params, all=true, and graph bombs; confirm
  streaming + caps + (if present) rate limits hold.
Key abuse cases: SAC-001, SAC-002, SAC-004
Out of scope: Auth bypass (covered by existing auth tests), Phase 2 column changes.
```

---

## Appendix E: Regulatory Compliance Summary

| Regulation | Applicability | Rationale | COMP reqs |
|-----------|---------------|-----------|-----------|
| **GDPR** | Minimal | Reporting data is supply-chain metadata, not PII; only operator usernames exist (unchanged auth layer) | — |
| **CRA** | **Out of scope** | Internal hosted service; not placed on EU market; no downloadable/embedded element. (Confirm with compliance; revisit if externalised) | COMP-001 (record) |
| **NIS2** | No new obligations | Internal tool; supports (does not undermine) supply-chain security posture | COMP-002 (record) |
| **PSTI** | N/A | Not a consumer connectable device | — |
| **Internal data-governance** | Applies | Bulk export of confidential inventory should be logged | COMP-003 |

*(Appendices A–D: standard STRIDE / LINDDUN / OWASP Top 10 (2021) / GDPR PbD references — omitted here for brevity; frameworks applied inline above.)*
```

---

### Handoff note for the next steps
- **security-architect** should design: `parse_pagination()` contract, the `validate_page/validate_page_size` bounds (MAX_PAGE_SIZE=1000), the `iter_*()/count_*()` service interface, `exports/streaming.py` (write_only Excel + temp file lifecycle, `stream_with_context` JSON), and the visualization cap/stream — all enforcing SEC-001..SEC-009 and PRV-001.
- **threat-modeling** should validate ST-001..ST-009 against the chosen design (esp. that *no* buffered path survives for `all=true`).
- **software-test-engineer** should implement TA-001..TA-020 as **failing** tests first (red), prioritising the Critical/High rows of the SRTM. SEC-008/COMP-003 (rate limit + audit log) may be flagged as fast-follow if they over-expand Phase 1.
