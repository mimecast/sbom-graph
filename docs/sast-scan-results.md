# SAST Scan Results — sbom-graph monorepo

**Date:** 2026-06-29
**Operating mode:** A — first-pass scan (all subprojects)
**Scanner:** ai-sast-scanner (static analysis, source→sink, per-finding triage)
**Metabase:** none found — **cross-repo taint was NOT analysed** (each subproject scanned in isolation).
**Anti-fabrication:** every HIGH finding's cited `file:line` was re-opened and confirmed PRESENT in the working tree before inclusion. No fabricated paths/lines.

## Scope (5 Python subprojects, ~31k LOC)
| Subproject | Role |
|---|---|
| `sbom-graph-api` | Flask API over FalkorDB; JWT/LDAP auth, ingestion, exports, PyVis visualizations (~23k LOC) |
| `sbom-graph-model` | CycloneDX/SPDX parsing + FalkorDB persistence |
| `sbom-graph-enrichment` | Celery workers calling external APIs (OSS Index, deps.dev, OSV, Scorecard, ClearlyDefined) |
| `sbom-graph-cli` | httpx CLI client |
| `sonatype-lifecycle-release-listener` | Flask webhook listener → ingestion |

## Executive summary
Overall posture is **above average**: Cypher is parameterised throughout (values are `$params`; labels are allowlist-validated), Jinja autoescaping is on, there is no `eval`/`exec`/`pickle`/`yaml.load`/`subprocess` and no XML parsing (no XXE), no `verify=False` anywhere, HMAC uses constant-time compare, and SSRF was specifically looked for and **not** found (external API hosts are hardcoded; the API never fetches user-supplied URLs).

No **CRITICAL** findings. The material risks are: **(1)** a stored-XSS sink in the graph visualizations fed by ingested SBOM data; **(2)** ~~the release-listener webhook ships unauthenticated by default~~ — **corrected 2026-06-29: this was largely a false positive; the umbrella Helm chart auto-generates + wires `WEBHOOK_SECRET`, so the canonical deployment is authenticated** (residual: standalone chart wiring + app fail-open); **(3)** a cross-user token-metadata disclosure on an over-permissive debug endpoint; and **(4)** an ingestion-DoS from unguarded dict access while parsing attacker-supplied SBOMs. A cluster of MEDIUM hardening gaps (CSP, CSRF-on-API, LDAP/FalkorDB TLS enforcement, rate-limiter proxy trust, SBOM size caps) should follow.

---

## Top 5 must-fix now
> **Remediation status (2026-06-29): #1, #3, #4, #5 FIXED & tested (suites green, ruff clean). #2 OUTSTANDING.**

1. ✅ **FIXED — [HIGH] Stored XSS in PyVis tooltips** — `visualizations/kpartite.py:120` `format_properties_for_tooltip` now HTML-escapes key+value (`markupsafe.escape`); covers `dependants_graph.py` (shared fn). Test: `tests/test_security.py::TestXSSPrevention::test_tooltip_properties_are_html_escaped`.
2. ⬇️ **DOWNGRADED (re-checked 2026-06-29) — Webhook unauthenticated by default** — **mostly a FALSE POSITIVE.** The umbrella chart `helm/charts/sbom-graph/` auto-generates `WEBHOOK_SECRET` and wires it into the listener, so the canonical deployment IS authenticated. ✅ Residuals now fixed (2026-06-29): the *standalone* listener chart auto-generates + wires the secret, and the app **fails closed** (503) when the env is unset. See H2.
3. ✅ **FIXED — [HIGH] Cross-user token-metadata disclosure** — `routes/auth.py:673` `/auth/tokens/debug` changed `@auth_required` → `@admin_required`.
4. ✅ **FIXED — [HIGH] Ingestion DoS via unguarded SBOM parsing** — `sbom-graph-model/.../cyclonedx/processor.py` `parse_defect_from_cyclone_dx` now uses `.get()` defaults, tolerates 0/1/many ratings (uses first, warns), skips entries with no id; call site filters `None`. Tests: `test_cyclonedx_processor.py` (`test_multiple_ratings_uses_first_without_raising`, `test_missing_ratings_does_not_raise`, `test_missing_id_is_skipped`).
5. ✅ **FIXED — [MEDIUM] ClearlyDefined path traversal** — `sbom-graph-enrichment/.../certifiers/license.py` now normalizes each PURL-derived path segment via `_cd_segment` = `quote(unquote(x), safe="")` (decode-then-encode: neutralizes `/`+`..`, avoids double-encoding `%40` scopes). Tests: `test_certifiers.py` (`test_path_traversal_in_version_is_neutralised`, `test_already_encoded_scope_not_double_encoded`).

*(Correction 2026-06-29: #2 was downgraded after verifying the umbrella chart auto-generates and wires `WEBHOOK_SECRET` — the canonical deployment is authenticated. The residual standalone-chart / fail-open items were subsequently fixed: standalone chart now wires the secret, and the app fails closed. See H2.)*

---

## HIGH

### H1 — Stored XSS via unescaped node properties in PyVis tooltip · CONFIRMED · ✅ FIXED (2026-06-29)
- **Location:** `sbom-graph-api/src/sbom_graph_api/visualizations/kpartite.py:120-136` (`format_properties_for_tooltip`), used at `:334` and `dependants_graph.py:215`. **Evidence: PRESENT.**
- **Description:** Other fields are `escape()`d, but `format_properties_for_tooltip` builds `f"{key}: {value_str}"` with no escaping and assigns it to the PyVis `title=`, which vis.js renders as HTML. Node properties (name, description, purl, repo_url, tool names) come from attacker-influenceable SBOMs.
- **Attack:** Upload a CycloneDX component whose `name`/`description` is `<img src=x onerror="fetch('/auth/tokens',{credentials:'include'})...">`; an analyst hovering the node in the k-partite/dependants graph executes it. No CSP to contain it (see M2).
- **Impact:** Session/token theft, admin takeover of authenticated viewers.
- **Remediation:** `markupsafe.escape()` both key and value (and list/dict serialisations) in `format_properties_for_tooltip`.
- **CWE-79 / OWASP A03.** Trust boundary: ingested SBOM → rendered HTML.

### H2 — Release-listener webhook unauthenticated by default · ⬇️ DOWNGRADED → mostly FALSE-POSITIVE (re-checked 2026-06-29) · ✅ RESIDUALS FIXED (2026-06-29)
- **Correction:** the original HIGH ("the Helm chart never wires `WEBHOOK_SECRET`") was based on the *standalone* listener chart only. The **umbrella chart `helm/charts/sbom-graph/` — the canonical full-stack deployment — DOES secure it**: `templates/webhook-secret.yaml` auto-generates a random 64-char secret on first install (reused on upgrade, or `.Values.releaseListener.webhookSecret`), and `templates/sonatype-lifecycle-release-listener-deployment.yaml:47-51` wires it as `WEBHOOK_SECRET` via `secretKeyRef`. So the webhook **is authenticated by default** in the recommended deployment.
- **Residual (genuine but narrower) issues — both now fixed:**
  1. **[MEDIUM] Standalone chart omits the wiring** — ✅ FIXED (2026-06-29): `sonatype-lifecycle-release-listener/helm/.../templates/secret.yaml` now auto-generates `webhook-secret` (explicit `secrets.webhookSecret` wins; otherwise reused-on-upgrade via `lookup`, else `randAlphaNum 64`) and `deployment.yaml` wires it as `WEBHOOK_SECRET` via `secretKeyRef` (key configurable via `secrets.existingSecretWebhookKey`). Verified with `helm template` (auto-gen / explicit / existingSecret paths) + `helm lint`.
  2. **[LOW→FIXED] App now fails closed** — ✅ FIXED (2026-06-29): `app.py` `/webhook` handler returns **503** when `WEBHOOK_SECRET` is unset (was warn-and-continue), and startup logs an **error** that all requests will be rejected. A non-Helm deploy (docker run, bespoke manifest, direct `app.run`) can no longer accidentally process webhooks unauthenticated. Regression-proofed by `test_missing_secret_fails_closed`; the existing webhook test-suite was migrated to an auto-signing test client so all 61 tests pass under the now-required signature.
- **CWE-306 / OWASP A07.** *(HMAC-SHA1 + `hmac.compare_digest` remain fine.)*

### H3 — Cross-user token metadata disclosure on `/auth/tokens/debug` · CONFIRMED · ✅ FIXED (2026-06-29)
- **Location:** `sbom-graph-api/src/sbom_graph_api/routes/auth.py:673-720` (`debug_tokens`). **Evidence: PRESENT** (`@auth_required`, `db_session.query(StoredToken).all()`).
- **Description:** Any authenticated user gets **all** users' token metadata (username, token name, timestamps, revocation state). Raw token values are not returned, but it enables cross-user enumeration. Bypasses the per-identity scoping used everywhere else.
- **Remediation:** `@admin_required`, scope to the caller, or delete the endpoint / gate on `app.debug`.
- **CWE-200/285 / OWASP A01.**

### H4 — Ingestion DoS via unguarded dict access parsing attacker SBOMs · CONFIRMED · ✅ FIXED (2026-06-29)
- **Location:** `sbom-graph-model/src/sbom_graph_model/cyclonedx/processor.py:306-320` (`parse_defect_from_cyclone_dx`); call site `:403`. **Evidence: PRESENT.**
- **Description:** Bare subscripts `['id']`, `['source']['name']`, `['ratings']`, `['ratings'][0]['severity']` on attacker-controlled vuln entries; a missing/empty key raises `KeyError`/`IndexError` inside a dict comprehension, aborting the entire SBOM ingest. (Also: `>1 ratings` raises `ValueError` — modern multi-rating SBOMs from Trivy/Syft trigger it.) Reachable via the unauthenticated webhook (H2).
- **Remediation:** `.get()` with defaults; skip-and-warn per-vuln; tolerate multiple ratings.
- **CWE-755/400 / OWASP A05.**

---

## MEDIUM

### M1 — `FALKORDB_INTERNAL_LABEL` interpolated into Cypher without validation · CONFIRMED (operator-controlled) · ✅ FIXED (2026-06-29: `FalkorDBConfig.__post_init__` rejects labels not matching `^[A-Za-z_][A-Za-z0-9_]*$`; test in `test_config.py`)
`sbom-graph-api/.../services/falkordb_service.py:2113` (`internal_filter = f" AND '{internal_label}' IN labels(dependant)"`) and ~16 `f"Version:{self.internal_label}"` label sites. The value is an env var, not attacker-HTTP input, so exploitability needs deployment/CI compromise — but a bad value injects/corrupts Cypher across many queries. **Fix:** validate against `^[A-Z][A-Z0-9_]*$` at startup; refuse to boot otherwise. CWE-943/A03.

### M2 — No Content-Security-Policy header · CONFIRMED · ✅ FIXED (2026-06-29: CSP added in `_set_security_headers`; test in `test_app.py`)
`sbom-graph-api/.../app.py:140-154` sets X-Content-Type-Options/X-Frame-Options/Referrer-Policy/Permissions-Policy but **no CSP**. Removes the defence-in-depth layer for H1. Add a CSP (PyVis `cdn_resources="in_line"` needs `script-src 'unsafe-inline'` or switch to local+SRI). CWE-1021/A05.

### M3 — Insecure default secrets accepted in debug mode · CONFIRMED · ✅ FIXED (2026-06-29)
`app.py:62-73` rejects the three `*-change-in-production` defaults (`FLASK_SECRET_KEY`, `JWT_SECRET_KEY`, `TOKEN_DB_ENCRYPTION_KEY`) when `config.debug is False`. **Re-checked (2026-06-29): these three ARE auto-provisioned by the Helm charts** — the umbrella chart (`templates/sbom-graph-api-secret.yaml`) generates each via `randAlphaNum` **and reuses any existing cluster value via `lookup`**, so the canonical deployment never ships a default and **upgrades never overwrite live keys**. Since a removed env var falls back to the `*-change-in-production` placeholder, the non-debug guard already **fails closed on removal** in production.
- **Real residual (now fixed):** the **standalone API chart** (`sbom-graph-api/helm/.../templates/secret.yaml`) regenerated all three on **every** `helm upgrade` with **no `lookup`** — and `secrets.create` defaults to `false`, so the *default* install hit that path. This silently rotated `JWT_SECRET_KEY` (invalidating sessions) and, critically, `TOKEN_DB_ENCRYPTION_KEY` (making tokens already encrypted at rest undecryptable) on every upgrade. **✅ FIXED:** rewrote the template to compute each key as *explicit value → existing-cluster value via `lookup` → fresh `randAlphaNum`*, mirroring the umbrella chart, so existing values are preserved and never overwritten. Verified with `helm template` (generate / explicit-wins / falkordb-password paths) + `helm lint`.
- Debug-mode local dev still accepts the placeholder defaults **by design** (no secret needed to run locally); production is unaffected. CWE-321/798/CWE-323 (key reuse/overwrite).

### M4 — JWT cookie CSRF protection disabled for the JSON API · CONFIRMED
`app.py:84` `JWT_COOKIE_CSRF_PROTECT=False` and `api_v1` is `csrf.exempt`; state-changing `/api/v1/...` mutations rely only on `SameSite=Lax` (partial). **Fix:** re-enable double-submit, or require `Authorization: Bearer` (CSRF-safe) for mutations. CWE-352/A01.

### M5 — LDAP TLS not enforced (warn-only) · CONFIRMED · ✅ FIXED (2026-06-29: `create_app` raises in non-debug when LDAP enabled without TLS; test in `test_app.py`)
`app.py:65-69` + `config.py:193` (`LDAP_USE_SSL` defaults false). Enabled-LDAP-without-TLS sends bind credentials in cleartext; code only warns. **Fix:** refuse startup when `LDAP_ENABLED && !LDAP_USE_SSL`. CWE-319/A02.

### M6 — `policy_admin_page` (GET `/admin/policies`) only `@auth_required` · CONFIRMED · ✅ FIXED (2026-06-29: changed to `@admin_required`; dropped now-unused import)
`routes/admin.py:30-71` — POST/DELETE are `@admin_required` but the read page (all policy annotations, justifications, annotator identities) is any-authenticated. **Fix:** `@admin_required`. CWE-285/200/A01.

### M7 — Rate limiters key on `request.remote_addr` without `ProxyFix` · CONFIRMED · ✅ FIXED (2026-06-29: `ProxyFix` applied, `TRUSTED_PROXY_HOPS` configurable; test in `test_app.py`)
`routes/auth.py:91` + `routes/reports/_common.py:153`. Behind K8s ingress all clients share the proxy IP → legit users blocked + attackers bypass per-IP limits via multiple egress IPs. **Fix:** `ProxyFix(x_for=1,...)` with a trusted-proxy count. CWE-307/A07.

### M8 — ClearlyDefined path traversal via unencoded PURL fields · CONFIRMED · ✅ FIXED (2026-06-29)
`sbom-graph-enrichment/.../certifiers/license.py:172` (`f"{ptype}/{provider}/{ns}/{name}/{version}"`, also `_golang_purl_to_coordinates:139`). Host is fixed (not SSRF), but `..` in PURL fields redirects the request path (empirically demonstrated with httpx). PURL is from ingested SBOMs. **Fix:** `quote(..., safe="")` each component (deps.dev/source_repo already do). CWE-22/A01.

### M9 — `ssl_check_hostname=False` for IPv4 FalkorDB · CONFIRMED · ✅ FIXED (2026-06-29: enforced mTLS when hostname check is off)
`sbom-graph-model/.../persistence.py:158-172`. When `FALKORDB_HOST` is an IPv4 literal + TLS on, hostname verification is disabled → MitM on the cluster network can present any CA-trusted cert (issued for any name). **✅ FIXED:** the constructor now **requires mutual TLS** in this mode — if `ssl_certfile`/`ssl_keyfile` (`FALKORDB_CLIENT_CERT`/`FALKORDB_CLIENT_KEY`, already wired by the Helm enrichment env helper) are absent it raises `ValueError` rather than silently disabling verification, so the channel stays mutually authenticated by the client certificate. (DNS-named hosts — the normal K8s case — are unaffected; hostname verification stays on.) Tests: positive (mTLS → `ssl_check_hostname=False`) + negative (no client cert → raises) in `test_persistence.py`. CWE-297/A02.

### M10 — Unbounded SBOM size (component/package cardinality) · CONFIRMED · ✅ FIXED (2026-06-29: `MAX_SBOM_ENTRIES=100k` cap in both CycloneDX & SPDX validators; tests added)
`cyclonedx/processor.py:386-406`, `spdx/processor.py:290-317` — no cap on `components`/`packages`; a huge SBOM → millions of MERGE round-trips (volumetric DoS, no creds needed via H2). **Fix:** `MAX_COMPONENTS` cap post-validation + upstream request-body size limit. CWE-400/A05.

### M11 — Freetext license name → log injection / unbounded stored value · CONFIRMED · ✅ FIXED (2026-06-29: `Persistence.create_license` sanitizes spdx_id+name via `_clean_license_text` (strip CR/LF/tab, truncate 255) — single choke point covering CycloneDX+SPDX+the log line; tests in `test_persistence.py`)
`cyclonedx/processor.py:249-255` + `persistence.py:1381` logs raw SBOM-derived `spdx_id` (Cypher use is parameterised → no first-order injection, but newline → CRLF log injection; no length cap). **Fix:** strip CR/LF + truncate before store/log. CWE-117/20.

### M12 — Listener logging silently degrades to DEBUG in production · CONFIRMED · ✅ FIXED (2026-06-29: logging.conf → stdout/stderr StreamHandlers, INFO fallback, gunicorn umask 0o022; test in `test_app.py`)
`app.py:48-51` fallback `basicConfig(level=DEBUG)`; `logging.conf` uses `FileHandler` to `/app` but the container is `readOnlyRootFilesystem: true` → `fileConfig` raises → DEBUG fallback in prod (tracebacks/Sonatype URLs/app-ids in logs). `gunicorn.conf.py:27` `umask=0`. **Fix:** INFO fallback, `StreamHandler` to stdout, `umask=0o022`. CWE-532/A09.

---

## LOW
- **L1** ✅ FIXED (2026-06-29) LDAP **DN** not escaped (`ldap_service.py:82`) though the search **filter** was (`:174`). **Fix:** the username is now run through `ldap3.utils.dn.escape_rdn` before being interpolated into the bind DN, so DN special chars (`,` `=` `+` …) are escaped and can't alter the DN structure. Test in `test_ldap_service.py`. CWE-90.
- **L2** ⬇️ **DOWNGRADED → low/non-issue for data integrity (re-checked 2026-06-29).** Webhook **no replay protection** — a captured signed payload is replayable. But the listener path is **synchronous** (no Celery queue to dedup on; `handle_webhook` → `process_release_scan` → direct persist), and the persistence layer is **idempotent**: Version/Defect/Dependency nodes use `MERGE`, and `scan_ids` is appended only via `WHERE NOT $scan_id IN coalesce(p.scan_ids, [])`. So a replayed identical webhook **re-requests the same data from Sonatype and converges to the same graph state — it does not duplicate or corrupt core data** (the reporter's intuition was correct). **Residual (data-hygiene only) — ✅ FIXED (2026-06-29):** `SBOMRecord` nodes were `MERGE`d on a fresh `uuid4()` per ingest (`app.py` `record_id`), so each replay added a new `SBOMRecord` + `PRODUCED_BY_SBOM` edge — provenance/audit accumulation that could inflate SBOM-record counts (no dependency/vuln corruption). **Fix:** the listener now derives `record_id` **deterministically** from the SBOM content + app — `uuid5(NAMESPACE_URL, "sbom:{public_app_id}:{document_hash}")` — so a re-delivered webhook with identical content `MERGE`s the same `SBOMRecord` node and edges (idempotent, no accumulation); changed content ⇒ new record. UUID format preserved; no model-layer change (model already `MERGE`s on `record_id`). Tests in `test_app.py::TestSbomRecordIdempotency`. **Scope note:** the authenticated **API** ingest path (`routes/ingest.py`) keeps its random `record_id` deliberately — there it doubles as the async **job id** (returned/tracked), and API uploads are explicit (not auto-retried like the Nexus webhook), so content-addressing would collide job ids. CWE-294.
- **L3** ✅ FIXED (2026-06-29) CLI `--token` visible in process list (`cli.py`); now warns when the token is passed on the command line (vs the `SBOM_GRAPH_TOKEN` env var) + help text steers to the env var. CWE-214.
- **L4** ✅ FIXED (2026-06-29) CLI plaintext base URL (`cli.py`); now warns when a non-local `http://` API URL is used with a token (cleartext bearer). CWE-319.
- **L5** ✅ FIXED (2026-06-29) Enrichment accepted **unauthenticated FalkorDB** (empty `FALKORDB_PASSWORD`) with warn-only (`persistence_helpers.py:51`). Re-checked: the **Helm charts auto-provision `FALKORDB_PASSWORD`** (umbrella `falkordb-secret.yaml` generates it via `randAlphaNum` **with `lookup` reuse**, wired into every enrichment worker via the `sbom-graph.enrichment.env` helper), so an empty value in a real deployment means it was **removed**. **Fix:** `create_persistence` now **fails closed** — raises `RuntimeError` on empty password — with an explicit `FALKORDB_ALLOW_NO_AUTH=true` opt-in for local auth-less dev. This stops a removed/missing password from silently downgrading to an unauthenticated connection. Tests added in `test_persistence_helpers.py`. CWE-306.
- **L6** Enrichment source-repo allowlist permits arbitrary `*.github.com` subdomains (`certifiers/source_repo.py:85`); stored only (no fetch today). Tighten to exact hosts. CWE-184.
- **L7** ✅ FIXED (2026-06-29) `cast(LiteralString, f"...{qlit_prop}...{validated}...")` pattern in `apply_internal_label` (`persistence.py`) — safe today (allowlisted) but trained an unsafe Cypher-construction pattern. **Fix:** replaced the f-string with a fully-literal per-field query lookup table (`_INTERNAL_LABEL_BACKFILL_BY_FIELD`); the column name now comes from the literal template (no interpolation) and the only substitution is the allowlist-validated, backtick-quoted label. Removed the now-dead `INTERNAL_RULE_FIELD_TO_VERSION_PROPERTY` constant. Behavior unchanged (existing `apply_internal_label` tests still pass). CWE-89 (pattern risk).
- **L8** ✅ FIXED (2026-06-29) VEX `@id`/`name` stored as `defect_id` with no format validation (`vex.py`); could forge VEX→Defect links (false "not_affected") against arbitrary identifiers. **Fix:** `_process_statement` now validates the id against a recognised vulnerability-id scheme (`_VULN_ID_RE`: CVE / GHSA, case-insensitive); non-matching ids are skipped and logged, and `linked_vulns` stays accurate. Tests in `test_vex.py::TestVulnIdValidation`. CWE-20/290.
- **L9** ✅ FIXED (2026-06-29) `_SAFE_IDENTIFIER_RE` allows hyphens; the allowlisted `Machine-Learning-Model` type was interpolated **unquoted** as a Cypher label (`persistence.py` create_project_version) — a latent *runtime* syntax error (not injection) that broke ingestion of ML-model components. **Fix:** the `project_type` (and the internal-label backfill label) are now **backtick-quoted** (`` n:Version:`{project_type}` ``), so any allowlisted hyphenated label is valid Cypher. The regex stays as-is (hyphens are intended in the allowlist). Test asserts the backtick-quoted label in the MERGE. CWE-20.
- **L10** ✅ FIXED (2026-06-29) DEBUG-level query/param logging in `persistence.py` — the 4 MERGE debug logs now emit `param_keys` (sorted key names) instead of raw param values, removing the CRLF/log-injection + sensitive-value exposure. CWE-117/532.
- **L11** Dev-server entrypoint binds `0.0.0.0` with `FLASK_DEBUG`-gated debugger (`sonatype-lifecycle-release-listener/.../app.py` `app.run(debug=debug_mode, host="0.0.0.0", port=5000)`; same pattern in `sbom-graph-api/.../app.py`). **Secure by default** — `debug` reads `FLASK_DEBUG` defaulting to `"false"`, and the block is the `__main__` dev entrypoint (production runs under gunicorn). Residual is operational only: if `FLASK_DEBUG=true` were ever set on a reachable deployment, the Werkzeug debugger console is RCE. **Recommendation:** hard-pin `FLASK_DEBUG` off in deployment manifests and keep production on the WSGI server (never `app.run`). CWE-215. *(Surfaced by the Haddix sweep below; left as documented operational guidance, not a code change.)*

## INFO / hygiene
- SHA-1 for `app_id` derivation (`enrichment/ingest_tasks.py:65`) — non-security identifier, `# nosec` annotated; prefer SHA-256. CWE-328.
- No length bounds on SBOM-derived node properties (purl/description/repo) — cap before persist. (model)
- `*-change-in-production` default secret strings present in `config.py` — **value-content-capped to INFO** (self-declared placeholders; startup guard rejects them in non-debug).

---

## Haddix "AI Code Security Anti-Patterns" sweep (2026-06-29)

Targeted pass against the AI-codegen anti-pattern catalogue (Jason Haddix), focused on the
categories **not** already covered by the findings above. Result: the codebase is clean against
these patterns — no new CONFIRMED findings. Recorded here for audit completeness.

| # | Anti-pattern (CWE) | Result |
|---|--------------------|--------|
| 1 | Insecure randomness for security values (CWE-330) | **NOT FOUND** — no `random` module use for tokens/ids/secrets; identifiers use `uuid.uuid4()`; webhook record-ids are content-derived `uuid5`. |
| 2 | Weak hashing for security (CWE-327/328) | **Acceptable** — 3× SHA-1: 2 derive a non-security `app_id` (matches Sonatype's scheme; `# nosec`), 1 is HMAC-SHA1 webhook verification (algorithm mandated by Sonatype; uses constant-time `hmac.compare_digest`). Optional clarity nit: add `usedforsecurity=False` to the `app_id` SHA-1 calls. Already tracked under INFO. |
| 3 | Command injection / unsafe deserialization (CWE-78) | **NOT FOUND** — no `shell=True`, `os.system`, `os.popen`, `eval`, `exec`, `pickle.loads`, or unsafe `yaml.load`. |
| 4 | ReDoS (CWE-1333) | **NOT FOUND** — all regexes (PURL, SemVer, vuln-id, IPv4, redis-URL scrub) are linear; no nested quantifiers / catastrophic backtracking on user/SBOM input. |
| 5 | Mass assignment (CWE-915) | **NOT FOUND** — ingest validates against an explicit JSON schema then reads named fields; no `Model(**request.json)` or wholesale `setattr` over request keys. |
| 6 | Insecure temp files (CWE-377) | **NOT FOUND** — `exports/streaming.py` uses `tempfile.mkstemp` (atomic, 0600), cleaned up on success and error; no `mktemp`, no manual `/tmp` paths. |
| 7 | Open/permissive CORS (CWE-346) | **NOT FOUND** — no flask-cors / manual `Access-Control-Allow-Origin` anywhere. |
| 8 | Unrestricted file upload / unsafe file write (CWE-434/22/732) | **NOT FOUND** — SBOMs parsed in-memory (not persisted by attacker-supplied name); the only file writes are the CLI `-o` output (local user) and the `mkstemp` export path; no `os.chmod` with broad perms; path-traversal already covered/mitigated. |
| 9 | Debug / verbose error exposure (CWE-209/215) | **Mostly clean** — error responses return generic messages + a reference id (no stack traces / `traceback.format_exc()` to clients). One conditional operational item: `FLASK_DEBUG`-gated `app.run(debug=...)` on `0.0.0.0` (secure default `false`) — see **L11**. |

Patterns already covered and FIXED in earlier rounds (not re-listed): hardcoded-secret defaults
(M3), Cypher/SQL injection (parameterised), XSS (H1 + autoescape), LDAP filter+DN injection (L1),
security headers/CSP (M2), JWT secret handling, rate limiting, webhook auth fail-closed (H2).

## Verified mitigated / non-findings (looked for, not present)
- **Cypher injection from HTTP params** — MITIGATED: all values are `$params` (`execute_query`→`ro_query`); only allowlisted labels/sort fragments and `int`-cast `SKIP/LIMIT` are interpolated.
- **SSRF (attacker-controlled host)** — NOT PRESENT: API never fetches user URLs (`repo_url` is stored only); all enrichment hosts are hardcoded constants.
- **Open redirect** — MITIGATED (`get_safe_redirect_url`, `validation.py:789`).
- **Path traversal (API)** — MITIGATED: schema/record/project names allowlist-validated; `sanitize_content_disposition`; no `send_file(user_input)`/`open(user_input)`.
- **IDOR on token ops** — MITIGATED (identity-scoped) — *except* H3.
- **Template XSS** — MITIGATED: Jinja autoescape on; no `| safe`/`Markup()` with user data (the gap is the PyVis path H1).
- **TLS `verify=False`** — none anywhere (api, enrichment, cli, listener).
- **Insecure deserialization** — none (`eval`/`exec`/`pickle`/`yaml.load`/`marshal`/`subprocess` all absent).
- **XXE** — N/A: CycloneDX & SPDX parse **JSON only**; no XML parser.
- **Webhook HMAC-SHA1 + comparison** — FALSE-POSITIVE: HMAC-SHA1 is sound as a MAC; `hmac.compare_digest` is constant-time; secret from env. (The gap is optionality — H2.)
- **CLI** — no `verify=False`, token not persisted/logged; `--api-url`/`report_name` are acceptable for a local CLI trust model.
- **Listener `app.run(debug=...)`** — DEV-ONLY: `__main__` block, never run under the Gunicorn entrypoint; `FLASK_DEBUG` defaults false.

---

## Per-subproject posture (updated 2026-06-29 to reflect remediation)
- **sbom-graph-api** — strong baseline (validation layer, parameterised Cypher, autoescape, login rate-limit, open-redirect/path-traversal defences). **Fixed:** PyVis stored-XSS (H1), debug-endpoint authz (H3), `FALKORDB_INTERNAL_LABEL` validation (M1), LDAP-TLS fail-closed (M5), policy-page authz (M6), **CSP (M2)**, **ProxyFix for real client IP (M7)**, **standalone-chart secret regeneration / overwrite-on-upgrade (M3)**, **LDAP-DN escaping (L1)**. **Remaining:** API CSRF for `api_v1` (M4). Posture: good and improving — main open item is M4.
- **sbom-graph-model** — Cypher posture excellent, no XXE surface. **Fixed:** untrusted-SBOM parsing DoS (H4), **SBOM size caps (M10)**, license-text sanitisation (M11), **DEBUG param-logging (L10)**, **enforced mTLS when IPv4 hostname check is off (M9)**, **dynamic-Cypher pattern → literal lookup table (L7)**, **VEX-id format validation (L8)**, **backtick-quoted hyphenated type label (L9)**. **Remaining:** none of note. Posture: robust against malicious SBOMs now.
- **sbom-graph-enrichment** — good SSRF awareness (fixed hosts, `quote()`, timeouts, no `verify=False`). **Fixed:** ClearlyDefined path-traversal (M8 — `_cd_segment` decode-then-encode), **unauth-FalkorDB fail-closed (L5)**. **Remaining:** allowlist tightness (L6), the dead Scorecard certifier (functional, trust-score blind spot). Posture: SSRF surface clean.
- **sbom-graph-cli** — clean for its trust model. **Fixed:** `--token` process-list warning (L3), plaintext-`http://` warning (L4); also repaired pre-existing breakage that left the test suite unrunnable (an `IndentationError` in `commands/ingest.py` and `tests/conftest.py`, and a missing pytest `pythonpath`) — the CLI suite now runs (49 tests). Posture: clean.
- **sonatype-lifecycle-release-listener** — sound crypto (constant-time HMAC, CA-bundle TLS, strong input regex); the **umbrella chart authenticates the webhook by default** (auto-generated + wired `WEBHOOK_SECRET`), so H2 was downgraded. **Fixed:** prod-DEBUG logging collision + world-writable umask (M12); the *standalone* listener chart now auto-generates and wires the webhook secret (H2 MEDIUM residual); the app now **fails closed** — `/webhook` returns 503 when `WEBHOOK_SECRET` is unset (H2 LOW residual); ingestion is now **replay-idempotent** — `SBOMRecord` `record_id` is content-derived (`uuid5` of `public_app_id`+`document_hash`), so re-delivered webhooks no longer accumulate duplicate provenance nodes/edges (L2). **Remaining:** none of note (core graph was already idempotent). Posture: solid; no high- or medium-severity open items.

## Appendix — out of SAST scope / follow-ups
- **SCA / dependencies:** not assessed here (no metabase, no lockfile audit run). Recommend a dependency/CVE scan of each `pyproject.toml` + a container-image scan; the project's own SBOM tooling could dogfood this.
- **Correctness bug found incidentally (not security) — ✅ FIXED (2026-06-29):** `sbom-graph-cli/.../commands/ingest.py` had a real **`IndentationError`** (broken `with Progress(...)` block) so the CLI `ingest` command did not import; `tests/conftest.py` had another `IndentationError`; and the CLI pytest config lacked `pythonpath=["src"]`, so the whole CLI test suite was unrunnable. All three repaired — CLI suite now runs (49 passed). *(Pre-existing import-sort lint `I001` remains in untouched `client.py` / `test_ingest.py` — left as-is, out of scope.)*
- **Cross-repo taint** (SBOM field → graph → enrichment → re-render) was not analysed (no metabase). The H1/M8/M11 findings share one root taint source (ingested SBOM fields); a metabase pass would strengthen confidence on second-order flows.
