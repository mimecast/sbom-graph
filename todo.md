# SBOM-Graph Feature Roadmap

Gap analysis against [GUAC](https://github.com/guacsec/guac) (Graph for
Understanding Artifact Composition), the OpenSSF incubating project for
software supply chain metadata aggregation.

> **How to read this document:** Numbered items in the summary are
> high-level initiatives. Each has a detailed sub-section below with
> concrete tasks spanning the graph model, API, UI/visualizations, and
> automation/CI-CD integration.

---

## Summary

### Tier 1 -- Security-Critical Gaps

| # | Initiative | Why It Matters |
|---|-----------|----------------|
| 1 | [Vulnerability Enrichment](#1-vulnerability-enrichment) | SBOMs only contain vulnerabilities known at scan time. Continuous enrichment from OSV/NVD catches new CVEs as they are published. |
| 2 | [License Tracking and Compliance](#2-license-tracking-and-compliance) | No license data is currently extracted or stored. Organisations need licence compliance reporting to avoid legal risk. |
| 3 | [VEX Support](#3-vex-support) | Vulnerability Exploitability eXchange documents communicate whether a vulnerability actually affects a product. Without VEX, every CVE looks like a fire drill. |
| 4 | [Patch Planning and Blast Radius](#4-patch-planning-and-blast-radius) | When a zero-day hits, responders need to know which projects are affected and in what order to patch. GUAC's "frontier-level" patch plan is the gold standard. |
| 5 | [Policy Annotations](#5-policy-annotations-certifybadcertifygood) | The ability to mark packages or versions as approved/denied drives binary-authorisation and supply-chain policy enforcement. |

### Tier 2 -- Breadth and Interoperability

| # | Initiative | Why It Matters |
|---|-----------|----------------|
| 6 | [SPDX SBOM Support](#6-spdx-sbom-support) | SPDX is the other dominant SBOM standard (ISO/IEC 5962:2021). Many tools and regulators require it. |
| 7 | [Source Repository Tracking](#7-source-repository-tracking) | Linking packages to their source repos enables provenance checks, scorecard lookups, and incident attribution. |
| 8 | [Supply-Chain Trust Score](#8-supply-chain-trust-score-composite-security-rating) | **IMPLEMENTED.** A composite trust score combining OpenSSF Scorecard, OSV, Sonatype OSS Index, and deps.dev provides evidence-based risk ratings across all forges and ecosystems, with inherited risk propagation through the dependency graph. |
| 9 | [End-of-Life Tracking](#9-end-of-life-tracking) | Detecting EOL packages prevents reliance on unmaintained software that will never receive patches. |
| 10 | [SBOM Provenance Tracking](#10-sbom-provenance-tracking) | Tracking where an SBOM came from, when it was ingested, and what tool produced it creates an auditable chain of custody. |

### Tier 3 -- Automation and Developer Experience

| # | Initiative | Why It Matters |
|---|-----------|----------------|
| 11 | [Enrichment Pipeline](#11-enrichment-pipeline) | An async worker that watches for new packages and fetches additional metadata (vulns, licences, scorecards) without blocking ingestion. |
| 12 | [CLI Tooling](#12-cli-tooling) | A command-line interface for ingestion, querying, and policy management enables scripting and CI/CD integration. |
| 13 | [Programmatic Security API](#13-programmatic-security-api) | REST endpoints purpose-built for CI/CD gates: "is this purl vulnerable?", "what is the blast radius of this CVE?". |
| 14 | [SBOM Comparison and Diff](#14-sbom-comparison-and-diff) | Comparing two SBOMs (or two versions of the same project) surfaces added/removed/changed dependencies between releases. |
| 15 | [Package Identity Normalisation](#15-package-identity-normalisation) | Different SBOMs can refer to the same package with different purls or hashes. Normalisation prevents duplicates and enables cross-SBOM correlation. |

---

## Detailed Tasks

---

### 1. Vulnerability Enrichment

GUAC's OSV certifier watches for new packages and automatically queries
[OSV.dev](https://osv.dev) for known vulnerabilities, keeping the graph
current even when no new SBOM is ingested. sbom-graph currently only
stores vulnerabilities that were present in the SBOM at ingestion time.

#### 1.1 Graph Model

- [x] Design a `VulnerabilitySource` node (or property on `Defect`) to
  record where vulnerability data came from (SBOM, OSV, NVD, Snyk, etc.)
  and when it was last refreshed.
- [x] Add `last_enriched_at` timestamp to `Defect` nodes.
- [ ] Add `CVSS v4` support alongside existing CVSS fields.
- [x] Add `aliases` list to `Defect` to link CVE / GHSA / OSV IDs for
  the same vulnerability.

#### 1.2 API

- [x] `POST /enrich/vulnerabilities` -- trigger an on-demand enrichment
  run for all (or specified) packages.
- [x] `GET /reports/vulnerability-freshness` -- report showing packages
  whose vulnerability data is older than a configurable threshold.
- [x] `GET /api/v1/package/{purl}/vulns` -- programmatic endpoint
  returning vulnerabilities for a purl including transitive dependencies
  (mirrors GUAC's REST API).

#### 1.3 UI / Visualizations

- [x] Add a "last scanned" column to the vulnerabilities report.
- [x] Add a dashboard widget showing enrichment coverage (% of packages
  with recent vulnerability data vs stale/never-scanned).
- [x] Colour-code vulnerability nodes in dependency visualizations by
  severity (critical=red, high=orange, medium=yellow, low=blue).

#### 1.4 Automation

- [x] Background worker (Celery or APScheduler) that periodically queries
  OSV for all packages in the graph.
- [x] Configurable enrichment interval via Helm values
  (`enrichment.interval`, `enrichment.sources`).
- [ ] Webhook/callback on new vulnerability discovery (post to Slack,
  PagerDuty, or generic HTTP endpoint).

---

### 2. License Tracking and Compliance

GUAC integrates with [ClearlyDefined](https://clearlydefined.io) to
attach declared and discovered licence information to every package.
sbom-graph currently ignores the `licenses` field in CycloneDX components.

#### 2.1 Graph Model

- [x] Add `License` node with properties: `id` (SPDX expression),
  `name`, `url`, `source` (declared / discovered).
- [x] Add `HAS_LICENSE` edge from `Version` to `License`.
- [x] Add `license_risk` property to `License` (permissive, weak-copyleft,
  strong-copyleft, proprietary, unknown).

#### 2.2 API

- [x] `GET /reports/licenses` -- all licences in use across the graph,
  grouped by risk category.
- [x] `GET /reports/license-conflicts` -- flag projects that mix
  incompatible licences in their dependency tree.
- [x] `GET /reports/license-summary/{project}/{version}` -- licence
  bill of materials for a single project version.
- [x] `GET /api/v1/package/{purl}/licenses` -- programmatic licence
  lookup by purl.

#### 2.3 UI / Visualizations

- [x] Add licence columns to the "All Projects" and "Applications" reports.
- [x] Licence compliance dashboard with counts by risk category and
  drill-down to affected projects.
- [x] Colour-code dependency graph nodes by licence risk (green=permissive,
  yellow=weak-copyleft, red=strong-copyleft/unknown).

#### 2.4 Automation

- [x] Extract `licenses` from CycloneDX `component.licenses[]` during
  SBOM ingestion in `CycloneDXProcessor`.
- [x] Background enrichment worker querying ClearlyDefined for packages
  missing licence data.
- [ ] CI/CD gate endpoint: `GET /api/v1/package/{purl}/license-check`
  returns pass/fail against a configurable policy.

---

### 3. VEX Support

GUAC supports [OpenVEX](https://openvex.dev) and
[CSAF VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
documents to communicate whether a vulnerability actually affects a product.
Without VEX, vulnerability reports are noisy with false positives.

#### 3.1 Graph Model

- [x] Add `VexStatement` node with properties: `status`
  (not_affected, affected, fixed, under_investigation),
  `justification`, `impact_statement`, `action_statement`,
  `source_document`, `timestamp`.
- [x] Add `HAS_VEX` edge from `Version` to `VexStatement`.
- [x] Add `REFERS_TO` edge from `VexStatement` to `Defect`.

#### 3.2 API

- [x] `POST /ingest/vex` -- upload an OpenVEX or CSAF VEX document.
- [x] `GET /reports/vulnerabilities` -- add `vex_status` column showing
  the most recent VEX determination for each vulnerability.
- [x] `GET /reports/vex-coverage` -- report showing which vulnerabilities
  have VEX statements and which are unreviewed.
- [x] `GET /api/v1/package/{purl}/vex` -- programmatic VEX status lookup.

#### 3.3 UI / Visualizations

- [x] Filter vulnerabilities report by VEX status (show only "affected",
  hide "not_affected", highlight "under_investigation").
- [x] Badge/icon on vulnerability nodes in visualizations indicating
  VEX status.
- [x] VEX coverage percentage on the vulnerability dashboard.

#### 3.4 Automation

- [ ] Support VEX document ingestion via the Sonatype webhook listener
  (if Sonatype publishes VEX data alongside SBOMs).
- [ ] Auto-generate VEX "not_affected" stubs for vulnerabilities that
  don't match the project's dependency tree (component not present).

---

### 4. Patch Planning and Blast Radius

GUAC's `guacone query patch` computes frontier levels showing what to
patch first when a vulnerability is discovered. sbom-graph has dependant
reports with partition levels but lacks a purpose-built patch planning
workflow.

#### 4.1 Graph Model

- [x] Add `PointOfContact` node with properties: `email`, `team`,
  `slack_channel`, linked to `Version` nodes via `CONTACT_FOR` edge.
- [ ] Ensure `DEPENDENCY_VERSION` edges support weight/priority for
  future patch-order optimisation.

#### 4.2 API

- [x] `GET /api/v1/patch-plan/{defect_id}` -- given a vulnerability,
  return:
  - Frontier levels (level 0 = the vulnerable package itself,
    level 1 = direct dependants, level N = transitive dependants).
  - Affected project count per frontier.
  - Points of contact per frontier.
- [x] `GET /api/v1/blast-radius/{purl}` -- given a purl, return all
  projects affected (directly and transitively) with depth and path.
- [x] `GET /api/v1/patch-plan/{defect_id}?format=json` -- machine-readable
  output for ticketing system integration.

#### 4.3 UI / Visualizations

- [x] "Incident Response" page: enter a CVE/GHSA/OSV ID or purl, get a
  visual blast radius graph with frontier levels colour-coded by depth.
- [x] Patch plan table showing each frontier level, affected projects,
  recommended patch order, and contacts.
- [x] "What-if" simulation: if I patch package X to version Y, which
  frontier levels are resolved?

#### 4.4 Automation

- [ ] Webhook trigger: when a new critical vulnerability is enriched,
  automatically compute the patch plan and post it to a configured
  notification channel.
- [ ] CI/CD endpoint: `POST /api/v1/patch-plan/evaluate` -- accepts a
  proposed dependency update and returns which vulnerabilities it resolves.

---

### 5. Policy Annotations (CertifyBad/CertifyGood)

GUAC allows marking any package, source, or artifact as "bad" (compromised,
deprecated, banned) or "good" (approved, reviewed) with a justification.
This drives supply-chain policy and binary authorisation.

#### 5.1 Graph Model

- [x] Add `PolicyAnnotation` node with properties: `type`
  (bad / good / hold), `justification`, `created_by`, `created_at`,
  `expires_at`.
- [x] Add `HAS_POLICY` edge from `Version` to `PolicyAnnotation`.
- [x] Index on `PolicyAnnotation.type` for fast "list all bad packages"
  queries.

#### 5.2 API

- [x] `POST /api/v1/policy/annotate` -- create a CertifyBad or
  CertifyGood annotation for a purl or version.
- [x] `DELETE /api/v1/policy/annotate/{id}` -- revoke an annotation.
- [x] `GET /reports/policy-violations` -- all packages with "bad"
  annotations and their dependants.
- [x] `GET /api/v1/package/{purl}/policy` -- check if a purl has any
  active policy annotations.

#### 5.3 UI / Visualizations

- [x] Admin page to manage policy annotations (add/remove/search).
- [x] Badge/icon on report rows and graph nodes for annotated packages.
- [x] Policy violations dashboard showing banned packages still in use
  and which projects depend on them.

#### 5.4 Automation

- [x] CI/CD gate: `GET /api/v1/policy/check?purl=...` returns
  pass/fail/hold for a given package.
- [ ] Bulk import of annotations from a YAML/JSON policy file.
- [ ] Auto-annotate packages flagged by Sonatype Lifecycle as
  "policy violation".

---

### 6. SPDX SBOM Support

GUAC supports both CycloneDX and SPDX. SPDX is an ISO standard
(ISO/IEC 5962:2021) and many tools produce only SPDX output.

#### 6.1 Graph Model

- [x] No model changes required -- the `Version`, `Defect`,
  `DEPENDENCY_VERSION`, and `VERSION_DEFECT` schema is format-agnostic.
- [x] Add `sbom_format` property to `Version` nodes to record whether
  the data came from CycloneDX or SPDX.

#### 6.2 API

- [x] `POST /ingest/spdx` -- accept an SPDX 2.3 JSON document.
- [x] Reuse the same response schema as `/ingest/cyclonedx`.

#### 6.3 sbom-graph-model

- [x] Add `SPDXProcessor` class in `sbom_graph_model.spdx` module.
- [x] Map SPDX `packages` to `Version` nodes.
- [x] Map SPDX `relationships` (DEPENDS_ON, DEPENDENCY_OF) to
  `DEPENDENCY_VERSION` edges.
- [x] Extract external references for purl, source repo, and licence.
- [x] Map SPDX `vulnerabilities` (if present, SPDX 2.3+) to `Defect`
  nodes.
- [x] Comprehensive unit tests with sample SPDX documents.

#### 6.4 UI / Automation

- [x] Update the ingest page/docs to indicate both CycloneDX and SPDX
  are accepted.
- [x] Auto-detect format (CycloneDX vs SPDX) in a unified
  `POST /ingest/sbom` endpoint based on document structure.

---

### 7. Source Repository Tracking

GUAC's `hasSrcAt` predicate links packages to their source repository.
This enables provenance verification, scorecard lookups, and incident
attribution (e.g., "this GitHub repo was compromised, which packages
are affected?").

#### 7.1 Graph Model

- [x] Add `SourceRepository` node with properties: `vcs_type`
  (git, svn), `namespace` (github.com, gitlab.com), `name` (repo path),
  `url`, `tag`, `commit`.
- [x] Add `HAS_SOURCE` edge from `Version` to `SourceRepository`.

#### 7.2 API

- [x] `GET /reports/source-repos` -- list all tracked source repos with
  linked package counts.
- [x] `GET /api/v1/source/{repo_url}/packages` -- given a repo URL,
  return all packages sourced from it.
- [x] `GET /api/v1/source/{repo_url}/vulnerabilities` -- given a repo,
  return all vulnerabilities in packages sourced from it.

#### 7.3 UI / Visualizations

- [x] Clickable source repo links in project/version reports.
- [x] "Source Impact" visualization: given a compromised repo, show all
  affected packages and their dependants.

#### 7.4 Automation

- [x] Extract `externalReferences` with type `vcs` from CycloneDX
  components during ingestion.
- [x] Enrichment worker that queries deps.dev or GitHub API to discover
  source repos for packages missing this data.

---

### 8. Supply-Chain Trust Score (Composite Security Rating)

Single-source scores give an incomplete picture. OpenSSF Scorecard is the
most comprehensive open-source tool for composite security trust ratings,
covering vulnerability response and project best practices, but has
**limited coverage** -- it does not score Apache projects hosted on SVN,
Bitbucket-hosted projects, GitLab-hosted projects, or projects on other
forges. The OSV Database and Sonatype OSS Index provide deeper insights
into vulnerability frequency, severity, and remediation timelines.
Combining these sources with [deps.dev](https://deps.dev) (Google's
dependency metadata service) enables proactive, evidence-based decisions
about component usage and risk management.

The goal is to build a **composite trust score** (0 -- 10) for every
package in the graph by aggregating data from four sources:

| Source | What It Provides | Coverage Gaps |
|--------|-----------------|---------------|
| [OpenSSF Scorecard](https://scorecard.dev) | 18+ security-practice checks (branch protection, CI, code review, dependency pinning, SAST, fuzzing, etc.) | GitHub-only; no SVN, Bitbucket, GitLab, SourceHut, etc. |
| [OSV Database](https://osv.dev) | Vulnerability count, severity distribution, mean-time-to-fix, exposure windows | Advisory coverage varies by ecosystem; no best-practice signals |
| [Sonatype OSS Index](https://ossindex.sonatype.org) | Proprietary vulnerability intelligence, component age, remediation guidance | Requires API key; free tier rate-limited |
| [deps.dev](https://deps.dev) | Project health, advisory counts, scorecard data, activity signals; REST API | Coverage depends on package registry presence |

#### 8.0 Composite Score Calculation

The score is computed across four categories. Each category draws from
one or more data sources and is normalised to a 0 -- 10 scale.

**Categories and default weights:**

| Category | Weight | Primary Sources | Fallback Sources |
|----------|--------|----------------|-----------------|
| Security Practices | 30% | OpenSSF Scorecard | deps.dev |
| Vulnerability Profile | 35% | OSV, Sonatype OSS Index | (either alone) |
| Maintenance Health | 20% | OpenSSF Scorecard, deps.dev | deps.dev alone |
| Supply-Chain Hygiene | 15% | OpenSSF Scorecard (pinned-deps, SAST, signed-releases) | deps.dev |

**Per-category scoring:**

1. **Security Practices** (0 -- 10): When OpenSSF Scorecard is available,
   use the mean of: `Branch-Protection`, `Code-Review`,
   `Token-Permissions`, `Dangerous-Workflow`, `SAST`, `Fuzzing` checks
   (each 0 -- 10). When Scorecard is unavailable (non-GitHub project),
   fall back to the deps.dev project data.
2. **Vulnerability Profile** (0 -- 10): Combine signals from OSV and
   Sonatype OSS Index:
   - `vuln_count_score = max(0, 10 - (open_critical * 3 + open_high * 1.5 + open_medium * 0.5))`
   - `remediation_score = 10 * (fixed_vulns / total_vulns)` (capped at 10)
   - `mttr_score = max(0, 10 - (mean_days_to_fix / 30))` (0 if MTTR > 300 days)
   - Category score = weighted mean: `vuln_count_score * 0.4 + remediation_score * 0.3 + mttr_score * 0.3`
3. **Maintenance Health** (0 -- 10): When Scorecard is available, use the
   mean of: `Maintained`, `Contributors`, `Recent-Activity` checks. When
   unavailable, use deps.dev project activity data.
   When both are available, take the mean.
4. **Supply-Chain Hygiene** (0 -- 10): When Scorecard is available, use
   the mean of: `Pinned-Dependencies`, `Signed-Releases`, `Packaging`,
   `CI-Tests` checks. Fall back to deps.dev project data covering
   similar ground.

**Direct composite score (per-package):**

```
direct_score(v) = Σ(category_score_i × weight_i)
```

When a data source is unavailable for a category, the remaining sources
are re-weighted proportionally within that category. A **confidence
level** (0 -- 1) is reported alongside the composite score:

```
confidence = sources_available / total_possible_sources
```

A score with `confidence < 0.5` is flagged as "low confidence" in
reports. Weights are configurable via Helm values
(`trustScore.weights.securityPractices`, etc.) to allow organisations to
tune the formula to their risk appetite.

#### 8.0.1 Inherited Risk Propagation

A package's *direct score* only tells part of the story. The **real
risk** of using a component includes the risk inherited from everything
it depends on -- a library scoring 9/10 that depends on a library
scoring 2/10 is far riskier than its own score suggests. Since the
dependency graph already captures these relationships, the trust score
system leverages it to compute an **effective score** that reflects the
aggregate risk of a package *and all of its transitive dependencies*.

**Effective Trust Score:**

```
effective_score(v) = α × direct_score(v) + (1 - α) × inherited_score(v)
```

Where:
- `α` (default **0.4**) controls the balance between a package's own
  score and the risk it inherits. A lower α means inherited risk
  dominates; a higher α puts more emphasis on the package itself.
- `direct_score(v)` = the per-package composite from Section 8.0.
- `inherited_score(v)` = aggregated effective score from dependencies.

**Inherited score computation:**

```
inherited_score(v) = Σ(w_i × effective_score(dep_i)) / Σ(w_i)
```

Where `dep_i` are the direct dependencies of `v`, and `w_i` is the
weight assigned to each. Since `effective_score(dep_i)` itself includes
that dependency's inherited score, risk propagates recursively from
leaf nodes all the way to the top-level application -- a critical
vulnerability buried five levels deep will attenuate but still visibly
degrade the application's effective score.

**Depth attenuation:** Direct dependencies matter more than deeply
transitive ones. A decay factor `δ` (default **0.8**) reduces the
influence of each dependency level:

```
w_i = δ^(depth_i - 1)
```

At depth 1 (direct), weight = 1.0. At depth 2, weight = 0.8. At
depth 5, weight ≈ 0.41. This prevents a minor leaf-node issue from
disproportionately dragging down a deeply-layered application, while
still making it visible.

**Computation strategy:** Scores are computed **bottom-up** via reverse
topological order (leaf packages first, applications last). Leaf
packages with no dependencies have `effective_score = direct_score`.
Each subsequent level incorporates children that are already resolved.
Cycles (rare but possible in real dependency graphs) are broken by
capping iteration and using the direct score as the fallback.

**Minimum-path score ("weakest link"):** In addition to the weighted
effective score, the system tracks the **minimum direct score** found
on any path from an application to a leaf node. This single number
answers: *"What is the worst individual component in my entire supply
chain?"* It is stored alongside the effective score for quick filtering.

**Application-level aggregate score:** For nodes of type `application`,
the effective score *is* the aggregate supply-chain risk rating -- it
naturally incorporates the scores of every direct and transitive
dependency, weighted by distance and breadth. This enables:
- Ranking applications by overall supply-chain health.
- Comparing applications: *"App A has effective 7.2 with 300 deps;
  App B has effective 4.1 with 50 deps -- App B has higher per-dep
  risk."*
- Tracking application health over time as dependencies are updated.

**Risk hotspot detection:** By walking the dependency graph from a
low-scoring application downward, the system identifies **risk paths**
-- the specific chains of dependencies contributing most to the score
degradation. The contribution of each dependency is:

```
contribution(dep, app) = (10 - effective_score(dep)) × w_dep × fan_in(dep, app)
```

Where `fan_in(dep, app)` is the number of distinct paths from `app` to
`dep` (a dependency reachable through many paths has higher impact).
Sorting by contribution highlights the most impactful remediation
targets: *"Upgrading library X from 3.1 to 3.2 would improve 12
applications' effective scores."*

**Positive propagation:** Crucially, risk propagation works in both
directions. When a low-scoring dependency is patched and its score
rises, the improvement propagates upward through the graph
automatically on the next scoring run. This creates a measurable
feedback loop: security teams can quantify the ROI of upgrading a
specific library by the number of applications whose effective score
improves and by how much.

#### 8.1 Graph Model

- [x] Add `TrustScore` node with properties:
  - `direct_score` (float 0 -- 10): per-package composite from 8.0.
  - `effective_score` (float 0 -- 10): direct + inherited risk.
  - `inherited_score` (float 0 -- 10): aggregated score from deps.
  - `min_path_score` (float 0 -- 10): lowest direct score on any
    dependency path ("weakest link").
  - `confidence` (float 0 -- 1): data source coverage.
  - `dep_count` (int): total direct + transitive dependency count used
    in the inherited calculation.
  - `security_practices_score`, `vulnerability_profile_score`,
    `maintenance_health_score`, `supply_chain_hygiene_score` (all float
    0 -- 10): per-category breakdowns for the direct score.
  - `sources_used` (list of source names).
  - `scored_at` (ISO timestamp).
  - `scorecard_raw` (JSON, nullable), `fosstars_raw` (JSON, nullable).
- [x] Add `HAS_TRUST_SCORE` edge from `Version` to `TrustScore`.
- [x] If `SourceRepository` nodes exist (initiative 7), add a
  `HAS_TRUST_SCORE` edge from `SourceRepository` to `TrustScore` as
  well, enabling both package-level and repo-level scoring.
- [x] Index on `TrustScore.effective_score` for fast "lowest-scored
  packages" queries.
- [x] Index on `TrustScore.min_path_score` for fast "weakest link"
  queries.

#### 8.2 API

- [x] `GET /reports/trust-scores` -- all packages with direct score,
  effective score, inherited score, and min-path score. Sortable by any
  score column (ascending = riskiest first), filterable by confidence
  level, category, and node type (application vs library).
- [x] `GET /api/v1/package/{purl}/trust-score` -- full trust score
  breakdown for a single package: direct score with per-category detail,
  effective score, inherited score, min-path score, confidence, and
  dependency count.
- [x] `GET /api/v1/package/{purl}/trust-score/risk-path` -- the top N
  dependency chains contributing most to score degradation. Each path
  includes the chain of packages (with their individual scores) and the
  cumulative contribution value. Answers: *"Why is this package's
  effective score low, and which dependencies should I fix first?"*
- [x] `GET /api/v1/application/{purl}/supply-chain-risk` -- aggregate
  risk view for an application: effective score, weakest-link package
  (min-path), top risk contributors (by contribution formula), score
  breakdown by dependency depth tier (direct, transitive 1-2 hops,
  transitive 3+ hops).
- [x] `GET /reports/trust-score-gaps` -- packages missing one or more
  data sources, prioritised by dependency frequency (most-depended-on
  packages with low confidence first).
- [x] `GET /api/v1/analysis/trust-score-distribution` -- histogram of
  effective scores (not just direct) across the entire graph for
  portfolio-level risk assessment. Include separate distributions for
  applications vs libraries.
- [x] `GET /api/v1/analysis/risk-propagation-impact?purl={purl}&new_score={score}`
  -- "what-if" simulation: given a hypothetical score change for a
  single package, return the list of applications whose effective score
  would change and by how much. Enables prioritised remediation:
  *"Fixing this one library improves 15 applications by an average of
  1.2 points."*

#### 8.3 UI / Visualizations

- [x] Trust score columns in project and application reports showing
  both **direct score** and **effective score** with colour coding
  (green >= 7, yellow 4 -- 6.9, red < 4). Delta indicator when the
  effective score differs significantly from the direct score
  (shows inherited risk at a glance).
- [x] Confidence badge alongside the score (full circle = high
  confidence, half circle = partial, outline = low confidence).
- [x] Trust score heatmap: grid of packages vs score categories,
  colour-coded by individual category scores.
- [x] **Risk propagation graph**: dependency graph where nodes are
  sized by dependency fan-in (how many things depend on them) and
  colour-coded by effective trust score. Edges coloured to show risk
  flow: red edges where a low-scoring dependency is degrading its
  parent's effective score. Clicking a node highlights all paths to
  applications it affects.
- [x] **Application risk dashboard**: for each application, show the
  effective score, a sparkline of effective score over time, and a
  "risk decomposition" bar showing what percentage of inherited risk
  comes from direct dependencies vs transitive tiers (1-2 hops,
  3+ hops).
- [x] **Risk path explorer**: drill into a specific application to see
  the ordered list of dependency chains dragging down its effective
  score. Each chain shows the package names, their individual scores,
  and the calculated contribution. One-click link to each package's
  detail page.
- [x] "Risk Outliers" dashboard widget: packages with effective
  score < 4 that are dependencies of >= 3 applications.
- [x] **What-if simulator**: UI widget where users select a package,
  enter a hypothetical new score, and see real-time projected changes
  to all affected applications' effective scores (calls the
  `risk-propagation-impact` API).

#### 8.4 Automation

- [x] **Trust Score Certifier** in the enrichment pipeline that
  orchestrates calls to all four data sources and computes the direct
  composite score. Runs as a Celery task alongside the existing OSV
  and License certifiers.
- [x] **Effective Score Propagation Task**: a separate Celery task
  (triggered after the Trust Score Certifier completes a batch, or on
  a schedule) that performs the bottom-up graph traversal to compute
  `effective_score`, `inherited_score`, and `min_path_score` for all
  packages. Uses reverse topological ordering for efficiency; only
  recomputes subtrees where a direct score has changed since the last
  run.
- [x] Configurable scoring parameters via Helm values:
  - `trustScore.enabled`, `trustScore.interval`,
    `trustScore.sources: [scorecard, osv, sonatype, fosstars]`,
    `trustScore.weights.*` (category weights).
  - `trustScore.propagation.alpha` (default 0.4): own-score vs
    inherited-score balance.
  - `trustScore.propagation.decay` (default 0.8): per-depth
    attenuation factor.
  - `trustScore.propagation.maxDepth` (default 20): depth cutoff to
    limit traversal in very deep graphs.
- [x] CI/CD gate: `GET /api/v1/package/{purl}/trust-check` returns
  pass/fail against a configurable minimum **effective score** threshold
  (not just direct score). This catches cases where a package itself
  looks fine but its dependencies are risky.
- [x] Alert when a package's **effective score** drops below a
  configurable threshold, including the top risk contributors that
  caused the drop (e.g., *"App X effective score dropped from 7.5 to
  4.1 because dependency Y's direct score fell to 1.3 due to 2 new
  critical CVEs"*).
- [x] **Remediation priority queue**: automatically rank packages by
  remediation leverage -- the number of applications whose effective
  score would improve if that package were upgraded, multiplied by the
  average improvement. Exposes this via
  `GET /api/v1/analysis/remediation-priorities`.

---

### 9. End-of-Life Tracking

GUAC's EOL certifier checks packages against
[endoflife.date](https://endoflife.date) to detect dependencies that have
reached end-of-life and will no longer receive security patches.

#### 9.1 Graph Model

- [ ] Add `eol_date`, `is_eol`, `lts_until` properties to `Version`
  nodes (or a separate `EOLStatus` node if metadata is rich).

#### 9.2 API

- [ ] `GET /reports/eol` -- all packages at or approaching EOL, with
  dates and affected dependants.
- [ ] `GET /api/v1/package/{purl}/eol` -- EOL status for a specific purl.

#### 9.3 UI / Visualizations

- [ ] EOL column in project and application reports.
- [ ] EOL warning badge on dependency graph nodes.
- [ ] Dashboard widget: "X packages are past EOL, Y approaching EOL
  within 6 months".

#### 9.4 Automation

- [ ] Background worker querying endoflife.date API for all packages.
- [ ] Configurable lead-time alerts (warn N months before EOL).

---

### 10. SBOM Provenance Tracking

GUAC's `hasSBOM` predicate records where an SBOM was stored, what tool
produced it, and when. This creates an auditable chain of custody and
helps answer "what do I know and not know about my supply chain?".

#### 10.1 Graph Model

- [x] Add `SBOMRecord` node with properties: `format` (cyclonedx, spdx),
  `tool_name`, `tool_version`, `serial_number`, `ingested_at`,
  `source` (webhook, api_upload, cli), `document_hash`.
- [x] Add `PRODUCED_BY_SBOM` edge from `Version` to `SBOMRecord`.

#### 10.2 API

- [x] `GET /reports/sbom-inventory` -- all ingested SBOMs with metadata
  (tool, date, format, component count).
- [x] `GET /api/v1/sbom/{id}` -- retrieve SBOM metadata by ID.
- [x] `GET /reports/coverage` -- "known/unknown" report showing which
  projects have recent SBOMs and which are stale or missing.

#### 10.3 UI / Visualizations

- [x] SBOM inventory table with search and filter by tool, date, format.
- [x] Coverage dashboard: donut chart showing % of projects with fresh
  SBOMs vs stale vs never-scanned.

#### 10.4 Automation

- [x] Store SBOM metadata on every ingestion (CycloneDX and SPDX).
- [ ] Alert when a project's SBOM is older than a configurable threshold.

---

### 11. Enrichment Pipeline

GUAC's architecture uses an async ingestion pipeline with collectors,
ingestors, and certifiers communicating via NATS. sbom-graph currently
processes SBOMs synchronously during ingestion with no post-ingestion
enrichment.

#### 11.1 Architecture

- [x] Choose a task queue (Celery + Redis, or APScheduler for simpler
  deployments).
- [x] Define enrichment task interface: `enrich(purl) -> list[Finding]`.
- [x] Implement "certifier" pattern: pluggable enrichment modules that
  run against new or existing packages.

#### 11.2 Enrichment Modules

- [x] **OSV Certifier**: query OSV.dev for vulnerabilities.
- [x] **License Certifier**: query ClearlyDefined for licence data.
- [x] **Trust Score Certifier**: composite scoring from OpenSSF Scorecard,
  OSV, Sonatype OSS Index, and deps.dev (see [initiative 8](#8-supply-chain-trust-score-composite-security-rating)).
- [x] **EOL Certifier**: query endoflife.date for EOL status.
- [x] **Deps.dev Certifier**: query deps.dev for additional dependency
  and source metadata.
- [x] **Source Repository Certifier**: query deps.dev for source
  repository URLs with SSRF mitigation via host allowlist.

#### 11.3 Helm / Deployment

- [x] Add enrichment worker Deployment to the umbrella Helm chart.
- [x] Add `enrichment.enabled`, `enrichment.interval`,
  `enrichment.sources[]` to `values.yaml`.
- [x] Add Redis (or reuse FalkorDB's Redis protocol) for task queue.

#### 11.4 Observability

- [ ] Enrichment run history API:
  `GET /api/v1/enrichment/status` -- last run time, success/failure,
  packages processed.
- [ ] Prometheus metrics for enrichment (packages_enriched_total,
  enrichment_errors_total, enrichment_duration_seconds).

---

### 12. CLI Tooling

GUAC provides `guacone` for ingestion, querying, and policy management.
sbom-graph has no CLI -- all interaction is through the web UI or direct
API calls.

#### 12.1 CLI Framework

- [x] Create `sbom-graph-cli` package (Click or Typer framework).
- [x] Distribute via PyPI (`pip install sbom-graph-cli`).
- [x] Support `--api-url`, `--token` for remote API access.

#### 12.2 Commands

- [x] `sbom-graph ingest <file>` -- upload CycloneDX or SPDX file.
- [x] `sbom-graph query vulns <purl>` -- list vulnerabilities for a purl.
- [x] `sbom-graph query deps <purl>` -- list dependencies (direct and
  transitive).
- [x] `sbom-graph query dependants <purl>` -- list dependants.
- [x] `sbom-graph query patch-plan <defect_id>` -- compute and display
  a patch plan with frontier levels.
- [x] `sbom-graph policy annotate <purl> --type bad|good|hold --justification "reason"` --
  create policy annotation.
- [x] `sbom-graph export <report_name> --format json|excel|csv` --
  export a report.

#### 12.3 CI/CD Integration

- [x] Exit codes: 0 = clean, 1 = policy violations found, 2 = error.
- [x] `--output json` for machine-parseable output.
- [x] Example GitHub Actions workflow in documentation.
- [x] Example GitLab CI pipeline in documentation.

---

### 13. Programmatic Security API

GUAC provides REST endpoints (`/v0/package/{purl}/vulns`,
`/v0/package/{purl}/dependencies`, `/analysis/dependencies`) designed for
programmatic consumption. sbom-graph's API is report-oriented (HTML-first
with optional JSON/Excel).

#### 13.1 API Endpoints

- [x] `GET /api/v1/package/{purl}` -- resolve a purl and return all
  known metadata (versions, vulnerabilities, licences, scorecard,
  policy annotations).
- [x] `GET /api/v1/package/{purl}/vulns?include_dependencies=true` --
  vulnerabilities for a package and optionally its transitive
  dependencies.
- [x] `GET /api/v1/package/{purl}/dependencies` -- dependency tree
  (direct and transitive).
- [x] `GET /api/v1/package/{purl}/dependants` -- reverse dependency tree.
- [x] `GET /api/v1/analysis/critical-dependencies?sort=frequency|scorecard`
  -- most depended-on packages or lowest-scorecard packages.
- [x] `GET /api/v1/analysis/risk-summary` -- aggregate risk metrics
  (total vulns by severity, licence risk distribution, EOL count,
  policy violations).

#### 13.2 Design

- [x] Version the API under `/api/v1/` prefix.
- [x] Consistent JSON response envelope: `{data, pagination, meta}`.
- [x] Pagination via cursor or offset/limit.
- [x] OpenAPI 3.1 spec auto-generated from route definitions.

#### 13.3 Authentication

- [ ] Support API token authentication (bearer tokens) alongside the
  existing JWT session auth for programmatic access.

---

### 14. SBOM Comparison and Diff

Neither GUAC nor sbom-graph currently offers SBOM diff, but it is a
high-value feature for release management: "what changed in the
dependency tree between version A and version B?"

#### 14.1 API

- [ ] `GET /api/v1/diff/{project}?from={version_a}&to={version_b}` --
  return added, removed, and changed dependencies between two versions.
- [ ] `GET /api/v1/diff/{project}?from={version_a}&to={version_b}&include_vulns=true`
  -- include vulnerability diff (new vulns introduced, vulns resolved).

#### 14.2 UI / Visualizations

- [ ] "Compare Versions" page: select two versions of a project and see
  a side-by-side diff table.
- [ ] Diff visualization: dependency graph with added nodes in green,
  removed nodes in red, unchanged in grey.
- [ ] "Release Risk" summary: new vulnerability count, new licence
  risk, new EOL dependencies introduced in the newer version.

#### 14.3 Automation

- [ ] CI/CD endpoint: `POST /api/v1/diff/evaluate` -- accepts two
  SBOMs (before/after) and returns the diff with a pass/fail verdict
  against configured policy (e.g., "no new critical vulns").

---

### 15. Package Identity Normalisation

GUAC uses `pkgEquals` and `hashEquals` predicates to assert that
different identifiers refer to the same package or artifact. sbom-graph
relies solely on the `(name, project_name, project_group)` tuple,
which can lead to duplicates when different SBOMs use different naming
conventions for the same library.

#### 15.1 Graph Model

- [ ] Add `Artifact` node with `algorithm` and `digest` properties,
  linked to `Version` via `HAS_ARTIFACT` edge.
- [ ] Add `EQUIVALENT_TO` edge between `Version` nodes that represent
  the same package under different identifiers.
- [ ] Add `HASH_EQUAL` edge between `Artifact` nodes with the same
  content but different hash algorithms.

#### 15.2 API

- [ ] `POST /api/v1/identity/assert-equal` -- declare two purls or
  hashes as equivalent.
- [ ] `GET /api/v1/identity/resolve/{purl}` -- return the canonical
  purl and all known aliases.

#### 15.3 Automation

- [ ] During ingestion, attempt to match incoming packages against
  existing graph nodes using purl normalisation rules (case folding,
  qualifier ordering).
- [ ] Enrichment worker that queries deps.dev to discover alternative
  purls and hashes for known packages.

#### 15.4 UI

- [ ] "Package Aliases" column in project reports.
- [ ] Merge duplicate nodes in visualizations when equivalence is known.

---

## Priority and Sequencing

Recommended implementation order based on dependencies and impact:

```
Phase 1 (Foundation)
├── 1. Vulnerability Enrichment
├── 2. License Tracking
└── 11. Enrichment Pipeline (enables 1, 2, 8, 9)

Phase 2 (Incident Response)
├── 4. Patch Planning and Blast Radius
├── 5. Policy Annotations
└── 3. VEX Support

Phase 3 (Breadth)
├── 6. SPDX Support
├── 7. Source Repository Tracking
├── 8. Supply-Chain Trust Score
└── 9. End-of-Life Tracking

Phase 4 (Developer Experience)
├── 12. CLI Tooling
├── 13. Programmatic Security API
├── 10. SBOM Provenance Tracking
├── 14. SBOM Comparison and Diff
└── 15. Package Identity Normalisation
```

Items within a phase can be parallelised. The enrichment pipeline (11)
is listed in Phase 1 because it is the foundation for vulnerability
enrichment (1), licence enrichment (2), scorecard (8), and EOL (9).

### 16 Threat Model Findings

At line 72 of sbom-graph-api/threat-model.md, the mitigation status is marked as 'ACCEPTED' but the risk severity is 'Critical'. This indicates a critical security risk (brute force attacks on login) that has been accepted without application-level rate limiting. While network-level rate limiting is mentioned, relying solely on external controls for a critical risk creates a significant vulnerability if those controls fail or are misconfigured. Consider implementing basic application-level rate limiting using in-memory storage for single-worker deployments or documenting this as a deployment blocker until network controls are verified.

| 2 | Brute force on `/auth/login` | S | User credentials | High | High | **Critical** | **ACCEPTED** | SameSite=Lax cookies and session-based auth reduce automated attack surface. Network-level rate limiting expected at ingress controller / WAF. Application-level rate limiting deferred to future sprint (requires Redis or shared state for multi-worker). |

#### 16.1 Threat Model Update

- [x] The above should be changed to:

> | 2 | Brute force on `/auth/login` | S | User credentials | High | High | **Critical** | **MITIGATION REQUIRED** | SameSite=Lax cookies and session-based auth reduce automated attack surface. Network-level rate limiting at the ingress controller / WAF is a documented deployment requirement and must be verified before production. Application-level rate limiting will be added in a future sprint for defense in depth (requires Redis or shared state for multi-worker). |

The residual risk section lists 'No application-level rate limiting on login' as Critical severity but accepts it as a residual risk. This is inconsistent with security best practices. Even basic in-memory rate limiting (per worker) would provide defense-in-depth against brute force attacks. The justification mentions monitoring/alerting but detection after compromise is less effective than prevention. Consider implementing at least basic per-IP rate limiting in-memory as an interim measure until distributed rate limiting is available.

line 149 of sbom-graph-api/threat-model.md
| No application-level rate limiting on login | Critical | Network-level rate limiting at ingress/WAF is the expected control. Application-level limiting requires shared state (Redis) across Gunicorn workers and is deferred. Monitoring/alerting on failed login attempts provides detection. |

#### 16.2 Rate Limiting

- [x] Implement according to Guideline above, so that the "No application-level rate limiting on login" it is mitigated by basic in-memory per-IP login rate limiting in each Gunicorn worker (defense-in-depth) and network-level rate limiting at ingress/WAF. Retain the monitoring/alerting on failed login attempts which provide additional detection coverage.