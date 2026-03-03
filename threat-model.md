# Threat Model: SBOM Graph System

## Summary

SBOM Graph is a multi-component system for ingesting CycloneDX and SPDX SBOMs, storing dependency relationships and source repository provenance in a graph database (FalkorDB), enriching packages with vulnerability and license data from external sources, and providing interactive visualizations and reports. The system consists of:

- **sonatype-lifecycle-release-listener**: Webhook receiver that fetches SBOMs from SonaType and writes to FalkorDB
- **sbom-graph-api**: Web application for viewing reports and visualizations (read path) and authenticated CycloneDX/SPDX SBOM ingestion (write paths via `POST /ingest/cyclonedx`, `POST /ingest/spdx`, `POST /ingest/sbom`)
- **sbom-graph-enrichment**: Celery-based asynchronous pipeline that queries OSV.dev and ClearlyDefined APIs to enrich packages with vulnerability and license metadata, and also queries OpenSSF Scorecard, Sonatype OSS Index, and deps.dev APIs for trust score computation; uses a per-worker-process `httpx.Client` for connection-pooled HTTPS and a cached `Persistence` instance for FalkorDB access
- **FalkorDB**: Graph database storing dependency data (Redis protocol); Redis instance also serves as Celery broker and result backend for the enrichment pipeline
- **sbom-graph-model**: Shared library for SBOM parsing and persistence

This document covers **cross-component and infrastructure-level threats**. Component-specific findings are detailed in:
- [`sbom-graph-api/threat-model.md`](sbom-graph-api/threat-model.md)
- [`sonatype-lifecycle-release-listener/threat-model.md`](sonatype-lifecycle-release-listener/threat-model.md)
- [`sbom-graph-model/threat-model.md`](sbom-graph-model/threat-model.md)

The most critical system-level risks are: the **unauthenticated write path** (sonatype-lifecycle-release-listener webhook), **TLS inconsistencies** across the deployment, and **missing secrets** in the umbrella Helm chart that leave components misconfigured by default.

## System Architecture

```
                    +-----------------+
                    | SonaType IQ     |
                    | Server          |
                    +--------+--------+
                             |
                  Webhook POST (untrusted)
                             |
+----------------------------v-------------------------------+
| Kubernetes Cluster                                         |
|                                                            |
|  +-------------------+         +------------------------+  |
|  | Ingress / LB      |         | Release Listener (SLC) |  |
|  | (TLS termination) +---------+ (Flask, port 8000)     |  |
|  +--------+----------+         | - No auth on /webhook  |  |
|           |                    | - SonaType creds       |  |
|           |                    +----------+-------------+  |
|           |                               |                |
|  +--------v----------+         +---------v--------------+  |
|  | SBOM Graph API |         | FalkorDB               |  |
|  | (Flask, port 8000) |-------->| (Redis protocol, 6379) |  |
|  | - JWT/LDAP auth   |         | - Optional TLS         |  |
|  | - Session mgmt    |         | - Optional password    |  |
|  | - Read graph      |         | - PVC persistence      |  |
|  | - Ingest SBOMs    |         |                        |  |
|  +-------------------+         +-------------------------+  |
|                                         ^                  |
|  +-------------------+                  |                  |
|  | Init Data Job     +------------------+                  |
|  | (Helm hook)       |                                     |
|  +-------------------+                                     |
+------------------------------------------------------------+
       ^
       | HTTPS
+------+------+
| Browser /   |
| API Client  |
+--------------+
```

## Assets

| Asset | Component | Sensitivity |
|-------|-----------|-------------|
| Flask SECRET_KEY | sbom-graph-api | **Critical** -- signs session cookies |
| JWT_SECRET_KEY | sbom-graph-api | **Critical** -- signs all JWT tokens |
| TOKEN_DB_ENCRYPTION_KEY | sbom-graph-api | **Critical** -- Fernet key for token encryption |
| SonaType API credentials | sonatype-lifecycle-release-listener | **Critical** -- access to all SBOMs |
| FalkorDB password | All components | **High** -- database access |
| LDAP bind password | sbom-graph-api | **High** -- directory service credential |
| TLS private keys | FalkorDB, sbom-graph-api | **High** -- server identity |
| Graph data | FalkorDB | **High** -- dependency metadata, vulnerability data, organizational structure |
| User credentials / tokens | sbom-graph-api SQLite DB | **High** -- authentication material |
| Self-signed CA key | FalkorDB init container | **Medium** -- trust anchor for demo TLS |
| OSS Index API credentials (OSSINDEX_USER/OSSINDEX_TOKEN) | sbom-graph-enrichment | **Medium** -- optional API key for higher rate limits |

## Trust Boundaries

| Boundary | Crossing | Protocol |
|----------|----------|----------|
| Internet -> Cluster | Webhook from SonaType | HTTPS (ingress), HTTP (internal) |
| Internet -> Cluster | User browser | HTTPS (ingress) |
| Cluster -> Internet | SBOM fetch from SonaType API | HTTPS |
| Cluster -> LDAP | User authentication | LDAP/LDAPS |
| App -> FalkorDB | Graph reads/writes | Redis protocol (+/- TLS) |
| Enrichment Worker -> FalkorDB | Graph reads/writes (cached connection per worker) | Redis protocol (+/- TLS) |
| Enrichment Worker -> OSV API | Vulnerability queries | HTTPS (connection-pooled httpx.Client) |
| Enrichment Worker -> ClearlyDefined API | License queries | HTTPS (connection-pooled httpx.Client) |
| Enrichment Worker -> Scorecard API | Scorecard queries | HTTPS (connection-pooled httpx.Client) |
| Enrichment Worker -> OSS Index API | Vulnerability queries | HTTPS (connection-pooled httpx.Client) |
| Enrichment Worker -> deps.dev API | Package metadata queries | HTTPS (connection-pooled httpx.Client) |
| Enrichment Beat -> Redis | Task scheduling | Redis protocol |
| Init Job -> FalkorDB | Demo data load | Redis protocol |

## System-Level Threat Analysis (STRIPED)

### Cross-Component Threats

| # | Threat | STRIPED | Components | Likelihood | Impact | Risk | Status | Detail |
|---|--------|---------|------------|------------|--------|------|--------|--------|
| S1 | Graph data poisoning via unauthenticated webhook | S, T | sonatype-lifecycle-release-listener -> FalkorDB -> sbom-graph-api | **High** | **Critical** | **Critical** | **OPEN** | An attacker can POST crafted webhook payloads to the sonatype-lifecycle-release-listener, triggering SBOM ingestion of arbitrary data. Poisoned graph data propagates to all reports and visualizations shown to users, potentially hiding real vulnerabilities or creating false ones. This is the highest-priority system risk. |
| S2 | FalkorDB password not set by default | S, E | All components -> FalkorDB | **High** | **High** | **Critical** | **MITIGATED** | The umbrella chart defaults `falkordb.password` to `""` but the `falkordb-secret.yaml` template auto-generates a 32-character random password when no explicit value or existing Secret is found. All deployments (FalkorDB, sbom-graph-api, release-listener, enrichment worker/beat) inject `FALKORDB_PASSWORD` from this Secret via `secretKeyRef`. The enrichment `persistence_helpers.py` logs a warning if the env var is empty (local development without Helm). Residual: operators who deploy outside Helm must set the password manually. |
| S3 | TLS configuration mismatch between components | I | sbom-graph-api <-> FalkorDB | **High** | **Medium** | **High** | **OPEN** | FalkorDB is deployed with TLS by default (`tls.enabled: true`, non-TLS port disabled). However, `FalkorDBService` in sbom-graph-api does not pass `ssl` or `ssl_ca_certs` when connecting. The umbrella chart sets `TLS_ENABLED` but this controls the sbom-graph-api HTTP server TLS, not the FalkorDB client connection. sbom-graph-api will fail to connect to a TLS-only FalkorDB, or if TLS is disabled to work around this, traffic is unencrypted. |
| S4 | Umbrella chart missing critical sbom-graph-api secrets | I, E | sbom-graph-api | **High** | **Critical** | **Critical** | **OPEN** | The umbrella chart does not set `FLASK_SECRET_KEY`, `JWT_SECRET_KEY`, `TOKEN_DB_ENCRYPTION_KEY`, or `AUTH_ENABLED`. sbom-graph-api has a guard that rejects insecure defaults when `FLASK_DEBUG=false`, but the chart also does not set `FLASK_DEBUG`. The resulting behavior depends on image defaults and is non-deterministic. If auth is disabled (the default), all reports and visualizations are publicly accessible within the cluster. |
| S5 | No NetworkPolicy restricting FalkorDB access | E | FalkorDB | **Medium** | **High** | **High** | **PARTIALLY MITIGATED** | The umbrella chart now includes an opt-in NetworkPolicy for the enrichment worker and beat pods (`enrichment.networkPolicy.enabled`). When enabled, enrichment egress is restricted to: DNS (port 53), FalkorDB/Redis (port 6379, by pod selector), and external HTTPS (port 443, excluding RFC 1918 ranges). Residual: FalkorDB ingress is not yet restricted — any pod in the namespace can still connect on 6379. A FalkorDB-specific NetworkPolicy should be added to complete the control. |
| S6 | Self-signed TLS CA not distributed to clients | I | FalkorDB -> sonatype-lifecycle-release-listener, sbom-graph-api | **High** | **Medium** | **High** | **OPEN** | When TLS is auto-generated via the init container, the self-signed CA certificate is stored in an emptyDir volume on the FalkorDB pod. Neither the sonatype-lifecycle-release-listener nor sbom-graph-api deployments mount this volume or receive the CA cert. Clients cannot verify the FalkorDB server certificate, resulting in connection failures or requiring TLS verification to be disabled. |
| S7 | SonaType credentials not provisioned by umbrella chart | I | sonatype-lifecycle-release-listener -> SonaType | **High** | **Medium** | **Medium** | **OPEN** | The umbrella chart does not set `SONATYPE_HOST`, `SONATYPE_USERNAME`, or `SONATYPE_PASSWORD` for the sonatype-lifecycle-release-listener. Webhook processing will fail at runtime when attempting to fetch SBOMs. This is a deployment correctness issue that may lead operators to pass credentials via insecure means (e.g., plain env vars in overrides). |
| S8 | Init data job bypasses TLS and auth | T, E | init-data-job -> FalkorDB | **Medium** | **Medium** | **Medium** | **PARTIALLY MITIGATED** | The `init-data-job.yaml` does not set `FALKORDB_CACERTS` or pass TLS parameters to `populate_acme_corp.py`. The readiness check uses a Python TCP connect (reusing the application image, no BusyBox dependency), which will succeed on the TLS port but does not verify the certificate. The job also does not receive the FalkorDB password if `falkordb.password` is set after the initial deployment. |
| S9 | No ingress defined in umbrella chart | I, D | sbom-graph-api, sonatype-lifecycle-release-listener | **Low** | **Medium** | **Low** | **ACCEPTED** | Services are ClusterIP-only. External access requires operators to configure ingress separately. This is by design (separation of concerns) but means there is no default TLS termination, rate limiting, or WAF protection documented in the chart. |
| S10 | Demo data loaded in production | I | init-data-job -> FalkorDB | **Low** | **Low** | **Low** | **OPEN** | `initData.enabled` defaults to `true`. The demo data (Acme Corp) will be loaded into production deployments unless explicitly disabled, cluttering the graph with synthetic data. |
| S11 | Graph poisoning via SBOM ingest API | S, T | sbom-graph-api -> FalkorDB | **Low** | **High** | **Medium** | **MITIGATED** | `POST /ingest/cyclonedx` accepts CycloneDX SBOMs and writes to FalkorDB. Mitigated by: JWT authentication (`@auth_required`), CycloneDX structural validation (`CycloneDXValidationError`), parameterized Cypher queries and label allowlists in `sbom-graph-model`, and `MAX_CONTENT_LENGTH` (50 MB) to prevent oversized payloads. Residual risk: an authenticated user can still inject misleading (but structurally valid) SBOM data. |
| S12 | Denial of service via oversized SBOM upload | D | sbom-graph-api | **Medium** | **Medium** | **Medium** | **MITIGATED** | Large CycloneDX payloads could exhaust memory or CPU during parsing. Mitigated by Flask `MAX_CONTENT_LENGTH` (50 MB), Gunicorn worker timeouts, and Kubernetes resource limits. |
| S13 | Information disclosure in SBOM processing errors | I | sbom-graph-api | **Low** | **Low** | **Low** | **MITIGATED** | SBOM processing errors could leak internal paths or database details. Mitigated by generic error messages for 500 responses (only `CycloneDXValidationError` details are returned to the client at 422). |
| S14 | Mass assignment via extra JSON fields in ingest request | T | sbom-graph-api | **Low** | **Medium** | **Low** | **MITIGATED** | Attacker could include extra fields (e.g., `role`, `is_admin`) in the ingest JSON body. Mitigated by explicit field extraction: only `sbom`, `app_id`, `public_app_id`, and `project_url` are read from the request body. |
| S15 | Enrichment worker SSRF via crafted purl | S, T | sbom-graph-enrichment -> OSV/ClearlyDefined | **Low** | **Medium** | **Low** | **MITIGATED** | A malicious purl stored in the graph could cause the enrichment worker to construct requests to unintended hosts. Mitigated by: (1) hardcoded API base URLs in certifiers (`OSV_API_URL`, `CLEARLY_DEFINED_API`) — purl only populates the URL path, (2) `_purl_to_coordinates` rejects unknown package types via `provider_map` allowlist, (3) 30 s `httpx.Client` timeout prevents slow-loris, (4) opt-in NetworkPolicy restricts egress to port 443 on public IPs only. Design decision documented in `certifiers/license.py` module docstring. |
| S16 | Enrichment worker DoS via unbounded fan-out | D | sbom-graph-enrichment | **Medium** | **Medium** | **Medium** | **MITIGATED** | `enrich_all_packages` dispatches a task per purl in the graph. For very large graphs (100K+ packages) this could overwhelm the Redis broker. Mitigated by batched dispatch (`_DISPATCH_BATCH_SIZE = 500`), Celery `worker_prefetch_multiplier=1`, `task_acks_late=True`, and `result_expires=86400` to prevent indefinite Redis key accumulation. |
| S17 | Graph poisoning via compromised external API response | T | OSV/ClearlyDefined -> sbom-graph-enrichment -> FalkorDB | **Low** | **High** | **Medium** | **PARTIALLY MITIGATED** | If OSV.dev or ClearlyDefined returns malicious data, it is persisted to the graph. Mitigated by: HTTPS transport validation, explicit field extraction from API responses (only expected keys), and `LicenseRiskCategory.from_str()` validation. Residual risk: structurally valid but semantically misleading data cannot be detected. |
| S18 | Redis password exposure in Celery broker URL | I | sbom-graph-enrichment | **Medium** | **Medium** | **Medium** | **PARTIALLY MITIGATED** | The Redis password is embedded in the Celery broker URL string. Celery's standard Redis transport requires this — `broker_transport_options` only supports password separation for Redis Sentinel, which is not used here. Mitigated by: a `_RedactSecretsFilter` logging filter on `celery` and `kombu` loggers that replaces `redis://:password@` patterns with `redis://:*****@` in all log messages, tuple args, and dict args. Residual: password remains in the process-internal URL string and may appear in core dumps, tracebacks printed to stderr, or debugger inspection. |

| S19 | Policy annotation abuse (CertifyGood on vulnerable package) | T, E | sbom-graph-api | **Medium** | **High** | **Medium** | **PARTIALLY MITIGATED** | `POST /api/v1/policy/annotate` allows any authenticated user to create "good" annotations on known-vulnerable packages, bypassing CI/CD policy gates. Mitigated by: JWT authentication required, `created_by` audit field on every annotation, justification required, package existence verified before annotation. Residual: no role-based access control (all authenticated users can annotate), no approval workflow, annotations do not expire unless `expires_at` is set. |
| S20 | On-demand enrichment abuse | D | sbom-graph-api -> sbom-graph-enrichment | **Medium** | **Medium** | **Medium** | **MITIGATED** | `POST /api/v1/enrich/vulnerabilities` allows authenticated users to trigger enrichment for up to 1000 purls per request, or fan-out for all packages. Mitigated by: JWT authentication, maximum 1000 purls per request, purl format validation, batched dispatch in the fan-out task, Celery rate limiting in the OSV certifier. |
| S21 | Blast radius / patch plan information disclosure | I | sbom-graph-api | **Low** | **Medium** | **Low** | **MITIGATED** | `GET /api/v1/patch-plan/{defect_id}` and `GET /api/v1/blast-radius/{purl}` reveal the full dependency tree, team contacts, and organisational structure. Mitigated by: JWT authentication, `max_depth` capped at 50, `internal_only` filter available, `MAX_TRANSITIVE_NODES` safety cap prevents unbounded traversal. Residual: authenticated users see the full internal dependency graph which may be sensitive in multi-tenant scenarios. |
| S22 | VEX statement injection (false "not_affected") | T, E | sbom-graph-api | **Medium** | **High** | **Medium** | **PARTIALLY MITIGATED** | `POST /ingest/vex` allows authenticated users to upload VEX documents that mark vulnerabilities as "not_affected", potentially suppressing legitimate vulnerability findings in reports. Mitigated by: JWT authentication, `VexStatus.from_str()` validation (only 4 allowed statuses), `source_document` audit trail, `timestamp` field, statements linked to existing Defect/Version nodes only. Residual: no approval workflow, no role-based restriction on VEX uploads, a single malicious VEX document can suppress multiple findings. |
| S23 | Contact information exposure via PointOfContact nodes | I | sbom-graph-api | **Low** | **Low** | **Low** | **MITIGATED** | `POST /api/v1/contacts` stores email addresses and team/Slack channel info. `GET /api/v1/patch-plan` returns this data in responses. Mitigated by: JWT authentication on both endpoints, email format validation, length limits, package existence verification before linking. |
| S24 | SPDX document poisoning via malformed packages | T, D | sbom-graph-api | **Medium** | **Medium** | **Medium** | **MITIGATED** | `POST /ingest/spdx` and `POST /ingest/sbom` accept SPDX documents that may contain crafted package names, PURLs, or relationship data. An attacker with valid JWT credentials could inject misleading dependency data, create phantom packages, or establish false dependency relationships. Mitigated by: `SPDXValidationError` structural validation before processing, JWT authentication, 50 MB `MAX_CONTENT_LENGTH`, SPDX format detection requires `spdxVersion` field, MERGE semantics prevent duplicate nodes, `sbom_format` property provides provenance tracking. Residual: semantically valid but misleading SPDX data (e.g. false dependency claims) cannot be detected automatically. |
| S25 | Source repository URL tampering | T, I | sbom-graph-api, sbom-graph-model | **Medium** | **Medium** | **Medium** | **PARTIALLY MITIGATED** | SBOM documents (CycloneDX `externalReferences` or SPDX `downloadLocation`) provide source repository URLs that are persisted as `SourceRepository` nodes and queried via `GET /api/v1/source/packages` and `GET /api/v1/source/vulnerabilities`. An attacker could upload SBOMs with false VCS URLs, associating packages with repositories they don't belong to. This could mislead incident responders querying "which packages come from this compromised repo?". Mitigated by: JWT authentication, URL stored as-is (no SSRF -- URLs are data, not fetched server-side), `repo_url` query parameter validated for length (max 2048), MERGE on URL deduplicates. Residual: no verification that a purl actually originates from the claimed repository; trust is placed in the SBOM producer. |
| S26 | Format auto-detection bypass in unified endpoint | S, T | sbom-graph-api | **Low** | **Medium** | **Low** | **MITIGATED** | `POST /ingest/sbom` auto-detects format from document structure. An attacker could craft a document that passes CycloneDX detection but contains SPDX-style payloads (or vice versa), potentially bypassing format-specific validation. Mitigated by: detection checks `bomFormat == "CycloneDX"` or `spdxVersion` presence; each processor then applies its own full structural validation; unrecognised documents are rejected with 400. |
| S27 | Trust score data poisoning via compromised external APIs | T | Scorecard/OSS Index/deps.dev -> sbom-graph-enrichment -> FalkorDB | **Low** | **High** | **Medium** | **PARTIALLY MITIGATED** | If any of the four external APIs (Scorecard, OSV, OSS Index, deps.dev) return manipulated data, the trust score for affected packages will be incorrect, potentially causing safe packages to appear risky or risky packages to appear safe. This is more impactful than S17 because trust scores feed into CI/CD gate decisions. Mitigated by: HTTPS transport, explicit field extraction, multiple independent data sources (cross-validation), configurable weights, confidence score indicating data source coverage. Residual: structurally valid but semantically misleading data from a compromised API cannot be detected. |
| S28 | Denial-of-service via Scorecard/deps.dev API rate exhaustion | D | sbom-graph-enrichment | **Medium** | **Medium** | **Medium** | **MITIGATED** | The trust score computation queries up to 4 external APIs per package. For large graphs (100K+ packages), this could generate millions of API calls, exhausting rate limits and potentially triggering IP bans. Mitigated by: per-certifier token-bucket rate limiting (30 req/min Scorecard, 60/120 req/min OSS Index, 150 req/min deps.dev), batched dispatch, configurable TRUST_SCORE_INTERVAL (default 7200s). |
| S29 | Misleading effective scores from manipulated dependency graphs | T | sbom-graph-enrichment propagation task -> FalkorDB | **Low** | **High** | **Medium** | **PARTIALLY MITIGATED** | An attacker who can inject false dependency edges (via poisoned SBOMs -- see S1, S11, S24) could manipulate the inherited risk propagation, artificially raising or lowering effective scores for target packages. A single low-scoring fake dependency could drag down an entire application's effective score (denial of service on the trust metric), or a fake high-scoring dependency could mask inherited risk. Mitigated by: SBOM ingestion authentication (S11), alpha blending limits pure inheritance influence, min_path_score exposes the weakest link regardless of blending, SBOM format validation. Residual: authenticated users can still inject misleading dependency data. |
| S30 | OSS Index credential leakage | I | sbom-graph-enrichment | **Low** | **Medium** | **Low** | **MITIGATED** | OSSINDEX_USER and OSSINDEX_TOKEN are passed as environment variables from a Kubernetes Secret. If leaked, an attacker could use the credentials for their own OSS Index queries (limited blast radius -- read-only API). Mitigated by: credentials stored in Kubernetes Secret (not Helm values by default), optional (system works without auth), read-only API access, Secret template gated on non-empty user value. |

### Data Flow Threats

| # | Threat | STRIPED | Data Flow | Likelihood | Impact | Risk | Status | Detail |
|---|--------|---------|-----------|------------|--------|------|--------|--------|
| D1 | SBOM tampering in transit (SonaType -> sonatype-lifecycle-release-listener) | T | External HTTPS | **Low** | **High** | **Low** | **MITIGATED** | SonaType API requests use HTTPS with CA verification (`session.verify = cacerts`). Man-in-the-middle attacks are mitigated by TLS. |
| D2 | Graph data read without authorization | I | FalkorDB -> sbom-graph-api | **Medium** | **Medium** | **Medium** | **OPEN** | When `AUTH_ENABLED=false` (default), any user with network access to sbom-graph-api can read the full dependency graph including internal project names, vulnerability data, and organizational structure. |
| D3 | FalkorDB data at rest unencrypted | I | FalkorDB PVC | **Low** | **Medium** | **Low** | **ACCEPTED** | FalkorDB stores data on the PVC without encryption. Kubernetes StorageClass encryption (e.g., encrypted EBS) is the expected control. |
| D4 | Credential exposure in Helm values | I | Helm deployment | **Medium** | **High** | **Medium** | **OPEN** | Passwords set directly in `values.yaml` (e.g., `falkordb.password`, `secrets.sonatypePassword`) are stored in plaintext in Helm release secrets and may appear in CI/CD logs, version control, or `helm get values` output. |

### Infrastructure Threats

| # | Threat | STRIPED | Layer | Likelihood | Impact | Risk | Status | Detail |
|---|--------|---------|-------|------------|--------|------|--------|--------|
| I1 | Init container runs as root | E | FalkorDB pod | **Low** | **Medium** | **Low** | **ACCEPTED** | The TLS generation init container (`generate-tls`) runs as `runAsUser: 0` because `openssl` and `chmod` require root for key file permissions. It runs only once during pod startup and has `allowPrivilegeEscalation: false` and all capabilities dropped. The blast radius is limited to the emptyDir volume. |
| I2 | Alpine init image not pinned by digest | T | Init containers | **Medium** | **Medium** | **Medium** | **OPEN** | `alpine:3.20` is referenced by tag, not SHA digest. A compromised registry or tag mutation could inject malicious code into the TLS init container, which has access to the TLS volume. The BusyBox dependency was removed; the init-data job now reuses the application image for the readiness check. |
| I3 | FalkorDB image uses `latest` tag | T | FalkorDB | **Medium** | **High** | **Medium** | **OPEN** | `falkordb.image.tag: latest` in the umbrella chart values means deployments are non-reproducible and could pull a compromised or breaking version. |
| I4 | No PodDisruptionBudget | D | All components | **Low** | **Medium** | **Low** | **OPEN** | The umbrella chart does not define PDBs. Node drains can take down all replicas simultaneously. |
| I5 | Token database on emptyDir | I | sbom-graph-api | **Medium** | **Medium** | **Medium** | **OPEN** | The umbrella chart's sbom-graph-api deployment mounts only `/tmp` as emptyDir. `TOKEN_DB_PATH` defaults to `/data/tokens.db` but no `/data` volume is mounted. User accounts and API tokens will be lost on every pod restart. |

## Security Controls Summary

### Controls Present

| Control | Component | Effectiveness |
|---------|-----------|---------------|
| Parameterized Cypher queries | sbom-graph-model | **Strong** -- prevents injection |
| Node label allowlist | sbom-graph-model | **Strong** -- prevents arbitrary labels |
| CycloneDX structure validation | sbom-graph-model | **Moderate** -- validates required fields |
| Safe identifier regex | sbom-graph-model | **Strong** -- defense-in-depth for label injection |
| SSL default True | sbom-graph-model | **Moderate** -- secure default but caller can override |
| Null guards on all persistence methods | sbom-graph-model | **Moderate** -- prevents NoneType crashes |
| Input validation (regex, length, allowlist) | sbom-graph-api | **Strong** -- covers all route params |
| PBKDF2-SHA256 (600K iterations) | sbom-graph-api | **Strong** -- password hashing |
| Fernet token encryption | sbom-graph-api | **Strong** -- tokens encrypted at rest |
| JWT with configurable expiry | sbom-graph-api | **Moderate** -- depends on secret strength |
| CSRF protection (Flask-WTF) | sbom-graph-api | **Strong** -- all forms protected |
| Security headers | sbom-graph-api | **Moderate** -- X-Frame-Options, nosniff, etc. |
| Open redirect prevention | sbom-graph-api | **Strong** -- strict URL validation |
| JWT auth on ingest endpoint | sbom-graph-api | **Strong** -- `@auth_required` on `POST /ingest/cyclonedx` |
| Request body size limit | sbom-graph-api | **Moderate** -- `MAX_CONTENT_LENGTH` = 50 MB |
| Explicit field extraction (ingest) | sbom-graph-api | **Strong** -- only `sbom`, `app_id`, `public_app_id`, `project_url` read |
| Generic error messages (ingest) | sbom-graph-api | **Moderate** -- 500 responses hide internal details |
| Insecure default rejection | sbom-graph-api | **Strong** -- fails fast on weak secrets |
| TLS to SonaType API | sonatype-lifecycle-release-listener | **Strong** -- CA-verified HTTPS |
| TLS to FalkorDB | sonatype-lifecycle-release-listener | **Moderate** -- ssl=True but CA path issues |
| Distroless containers | All apps | **Strong** -- minimal attack surface |
| Non-root execution | All components | **Strong** -- UID 65532 |
| Read-only root filesystem | All containers | **Strong** -- prevents runtime modification |
| Dropped capabilities | All containers | **Strong** -- `ALL` dropped |
| Kubernetes Secrets for credentials | Helm charts | **Moderate** -- base64, not encrypted by default |
| Redis URL log redaction | sbom-graph-enrichment | **Strong** -- `_RedactSecretsFilter` on celery/kombu loggers |
| NetworkPolicy (opt-in) | Helm chart (enrichment) | **Strong** -- restricts egress to DNS, FalkorDB, HTTPS only |
| SSRF-safe certifier design | sbom-graph-enrichment | **Strong** -- hardcoded hosts, path-only purl interpolation |
| Auto-generated FalkorDB password | Helm chart | **Strong** -- `falkordb-secret.yaml` generates 32-char random password |
| Empty password startup warning | sbom-graph-enrichment | **Moderate** -- warns when FALKORDB_PASSWORD env var is empty |
| JWT auth on policy/enrichment endpoints | sbom-graph-api | **Strong** -- all write endpoints require `@auth_required` |
| Policy annotation input validation | sbom-graph-api | **Strong** -- type allowlist, purl format, length limits, package existence check |
| Enrichment request size limit | sbom-graph-api | **Strong** -- max 1000 purls per enrichment request |
| Policy annotation audit trail | sbom-graph-api | **Moderate** -- `created_by`, `created_at` on every annotation |
| Vulnerability enrichment metadata | sbom-graph-enrichment | **Moderate** -- `last_enriched_at`, `enrichment_source`, `aliases` tracked |
| JWT auth on patch-plan/blast-radius/contacts/VEX endpoints | sbom-graph-api | **Strong** -- all new endpoints require `@auth_required` |
| Patch plan max_depth cap (50) | sbom-graph-api | **Strong** -- prevents unbounded BFS traversal |
| VEX status validation | sbom-graph-model | **Strong** -- `VexStatus.from_str()` rejects invalid statuses |
| VEX source_document audit trail | sbom-graph-model | **Moderate** -- links statements to source documents for traceability |
| Contact email format validation | sbom-graph-api | **Strong** -- email must contain `@`, length limited to 254 chars |
| OpenVEX document structure validation | sbom-graph-model | **Moderate** -- `VexProcessor._validate_document()` checks for required fields |
| Trust score rate limiting (per-certifier token buckets) | sbom-graph-enrichment | **Strong** -- prevents API rate exhaustion |
| Trust score multi-source cross-validation | sbom-graph-enrichment | **Moderate** -- confidence score indicates data coverage |
| Trust score CI/CD gate | sbom-graph-api | **Strong** -- configurable min_score and min_confidence thresholds |
| OSS Index credentials in Kubernetes Secret | Helm chart | **Strong** -- gated on non-empty user value |

### Controls Missing

| Missing Control | Impact | Components |
|----------------|--------|------------|
| Webhook authentication | Critical | sonatype-lifecycle-release-listener |
| FalkorDB ingress NetworkPolicy | High | Umbrella chart |
| TLS CA distribution | High | Umbrella chart |
| Application secrets provisioning | Critical | Umbrella chart -> sbom-graph-api |
| Rate limiting | Medium | sonatype-lifecycle-release-listener, sbom-graph-api |
| Structured audit logging | Medium | sonatype-lifecycle-release-listener |
| Request size limits | Medium | sonatype-lifecycle-release-listener |
| Image digest pinning | Medium | Umbrella chart |

## Recommendations

### Critical Priority (Block Production Deployment)

| # | Finding | Recommendation | Effort |
|---|---------|----------------|--------|
| S1 | Unauthenticated webhook | Add HMAC signature verification or API key authentication to `/webhook`. Create a Kubernetes Secret for the shared secret and inject it via the Helm chart. | Medium |
| S2 | FalkorDB runs without password | Change the umbrella chart to **require** `falkordb.password` (fail template rendering if empty) or auto-generate a random password stored in a Secret. | Low |
| S4 | sbom-graph-api secrets not set | Add required env vars to the umbrella chart's sbom-graph-api deployment: `FLASK_SECRET_KEY`, `JWT_SECRET_KEY`, `TOKEN_DB_ENCRYPTION_KEY`, `AUTH_ENABLED`. Use a Kubernetes Secret with generated values or require them in `values.yaml`. | Medium |

### High Priority (Implement Before First Users)

| # | Finding | Recommendation | Effort |
|---|---------|----------------|--------|
| S3 | TLS mismatch sbom-graph-api <-> FalkorDB | Either: (a) add `ssl`/`ssl_ca_certs` parameters to `FalkorDBService` and pass the CA cert, or (b) disable FalkorDB TLS and rely on NetworkPolicy for in-cluster traffic isolation. Document the chosen approach. | Medium |
| S5 | No NetworkPolicy | Add a NetworkPolicy to the umbrella chart that restricts FalkorDB ingress to only the sbom-graph-api and sonatype-lifecycle-release-listener pods (by label selector). | Low |
| S6 | Self-signed CA not distributed | When using self-signed TLS, store the generated CA cert in a Kubernetes Secret (via an init Job) and mount it in both the sonatype-lifecycle-release-listener and sbom-graph-api deployments. Alternatively, use cert-manager for automated certificate lifecycle. | Medium |
| I5 | Token DB on emptyDir | Add a PVC mount for `/data` in the sbom-graph-api deployment so that user accounts and API tokens persist across restarts. | Low |

### Medium Priority (Next Sprint)

| # | Finding | Recommendation | Effort |
|---|---------|----------------|--------|
| S7 | SonaType creds not provisioned | Add SonaType configuration to the umbrella chart's `values.yaml` with `existingSecret` support, and document the required setup. | Low |
| S8 | Init job bypasses TLS/auth | Pass `FALKORDB_CACERTS` and `FALKORDB_PASSWORD` to the init job. The readiness check now uses a Python TCP connect (BusyBox removed), but still needs CA cert for full TLS verification. | Low |
| D2 | Graph data readable without auth | Set `AUTH_ENABLED=true` by default in the umbrella chart, or at minimum document that auth is disabled by default and the implications. | Low |
| D4 | Credentials in Helm values | Document that production deployments should use `existingSecret` references rather than inline passwords. Add `.gitignore` patterns for custom values files. | Low |
| I2 | Alpine image not pinned by digest | Pin `alpine` init container image by SHA256 digest. BusyBox dependency has been removed. | Low |
| I3 | FalkorDB `latest` tag | Pin FalkorDB to a specific version tag (e.g., `v4.2.1`). | Low |
| S10 | Demo data in production | Change `initData.enabled` to default `false`, or gate it on a `global.demoMode` flag. | Low |

### Low Priority (Hardening)

| Finding | Recommendation |
|---------|----------------|
| No PodDisruptionBudget | Add PDBs for sbom-graph-api and sonatype-lifecycle-release-listener (minAvailable: 1). |
| `umask = 0` in sonatype-lifecycle-release-listener gunicorn | Set to `0o077`. |
| Unused `flask-jwt-extended` in sonatype-lifecycle-release-listener | Remove from `pyproject.toml`. |
| No resource quotas | Consider adding a ResourceQuota to the namespace to prevent runaway resource consumption. |
| Error messages expose internals (sonatype-lifecycle-release-listener) | Replace `str(e)` with generic messages and correlation IDs. |

## Deployment Security Checklist

Before deploying to production, verify:

- [x] `falkordb.password` is auto-generated if not set (32-char random)
- [ ] `FLASK_SECRET_KEY` is set (min 32 bytes, cryptographically random)
- [ ] `JWT_SECRET_KEY` is set (min 32 bytes, cryptographically random)
- [ ] `TOKEN_DB_ENCRYPTION_KEY` is set (min 32 bytes)
- [ ] `AUTH_ENABLED=true` is set for sbom-graph-api
- [ ] Webhook authentication is configured for sonatype-lifecycle-release-listener
- [ ] `SONATYPE_HOST`, `SONATYPE_USERNAME`, `SONATYPE_PASSWORD` are configured
- [ ] FalkorDB TLS CA is distributed to all client pods
- [ ] `enrichment.trustScore.enabled` is set appropriately
- [ ] `OSSINDEX_USER`/`OSSINDEX_TOKEN` are provisioned (optional, for higher rate limits)
- [ ] Trust score propagation interval is set (`TRUST_SCORE_INTERVAL`)
- [ ] `enrichment.networkPolicy.enabled` is set to `true` (requires CNI support)
- [ ] NetworkPolicy restricts FalkorDB access to authorized pods only
- [ ] All images are pinned to specific versions (not `latest`)
- [ ] `initData.enabled` is set to `false` for production
- [ ] LDAP is configured with `LDAP_USE_SSL=true`
- [ ] Ingress is configured with TLS termination and rate limiting
- [ ] A PVC is mounted at `/data` for the sbom-graph-api deployment
- [ ] Helm values containing secrets are not committed to version control

## Third-Party Component Assessment

| Component | Version | CVEs (2yr) | Maintenance | License | Risk |
|-----------|---------|------------|-------------|---------|------|
| FalkorDB (server) | latest | 0 | Active | SSPLv1 (strong copyleft) | **High** -- SSPL requires that if FalkorDB is offered as part of a service to external users, the **entire service stack** must be open-sourced under SSPL. Internal use is exempt. This project's MIT licence does not conflict (FalkorDB is a separate service, not linked), but deployers must understand the constraint: internal deployment is unrestricted; external-facing service deployment requires a commercial FalkorDB licence. See README "Licensing" section. |
| FalkorDB (Python client) | 1.x | 0 | Active | MIT | Low |
| Flask | 3.x | 0 | Very active | BSD-3 | Low |
| Gunicorn | 23.x | 0 | Active | MIT | Low |
| Flask-JWT-Extended | 4.x | 0 | Active | MIT | Low |
| Flask-WTF | 1.x | 0 | Active | BSD-3 | Low |
| ldap3 | 2.x | 1 (low) | Active | LGPL-3 (weak copyleft) | **Accepted** -- LGPL-3 is weak copyleft; safe for use as an unmodified import but requires licence notice and the ability for users to replace the library. Alternatives (`bonsai` MIT, `python-ldap` PSF) are C extensions requiring `libldap2` system libraries, which are incompatible with distroless containers without fragile `.so` copying. The pure-Python nature of ldap3 is essential for the distroless security posture. Accepted trade-off: LGPL-3 compliance obligations vs. container security and maintainability. Review with legal if organisation prohibits all copyleft. |
| requests | 2.x | 0 | Very active | Apache-2 | Low |
| httpx | 0.x | 0 | Active | BSD-3 | Low (already in enrichment, now used by 3 additional certifiers) |
| cryptography | 44.x | 2 (patched) | Very active | Apache-2/BSD | Low |
| Alpine (init) | 3.20 | Varies | Active | MIT | Low |

All primary dependencies are actively maintained with no unpatched critical vulnerabilities. The main supply chain risk is the unpinned Alpine init container image and the FalkorDB `latest` tag. BusyBox was removed as a dependency; the init-data job now reuses the application image.

## Risk Heat Map

```
              Low Impact    Medium Impact    High Impact    Critical Impact
            +-------------+----------------+--------------+----------------+
 High       |             | S7, S10        | S3, S6       | S1, S4         |
 Likelihood |             |                |              |                |
            +-------------+----------------+--------------+----------------+
 Medium     |             | D4,I2,I3,S8   | D2, I5, S5   |                |
 Likelihood |             | S12,S16,S20    | S19,S22      |                |
            |             | S24,S25,S28    |              |                |
            +-------------+----------------+--------------+----------------+
 Low        | I4,S13,S23  | I1,D3,S9,S14  | S11,S17,S27,S29 |                |
 Likelihood | S26         | S15,S21,S30    |                |                |
            +-------------+----------------+--------------+----------------+

 Mitigated (removed from heat map): S2, S18
```

## Residual Risk (After Mitigations)

| Risk | Severity | Justification |
|------|----------|---------------|
| SonaType credential exposure in process memory | Medium | Inherent to the architecture. Short-lived per request. Distroless prevents memory dumps. |
| FalkorDB data at rest unencrypted | Low | Kubernetes StorageClass encryption is the expected control. |
| Large SBOM resource consumption | Low | Gunicorn timeouts and Kubernetes resource limits provide backstops. |
| Transitive dependency vulnerabilities | Medium | Lockfile pinning and CI/CD scanning mitigate. |
| Self-signed TLS weaker than CA-issued | Low | Acceptable for demo/internal use. Production should use proper PKI. |
| Enrichment external API data integrity | Medium | OSV/ClearlyDefined data is trusted after transport validation. Structurally valid but semantically wrong data cannot be detected automatically. |
| Trust score external API data integrity | Medium | Multiple independent sources provide cross-validation. Confidence score alerts when coverage is low. Structurally valid manipulated data remains undetectable. |
| SBOM source repository provenance | Medium | Source repository URLs from SBOMs are stored as-is. No verification that packages actually originate from claimed repositories. Trust is placed in the SBOM producer (build tool, CI pipeline). |
| Redis password in Celery broker URL | Low | Log redaction filter prevents exposure in Celery/Kombu log output. Password remains in process memory (inherent to Celery's Redis transport). |

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-02-28 | AI-assisted threat model | Added trust score threats S27-S30 (data poisoning, rate exhaustion, dependency graph manipulation, OSS Index credential leakage). Updated Summary, Assets, Trust Boundaries, Security Controls, Risk Heat Map, Residual Risk, Deployment Checklist, Third-Party Assessment. |
| 2026-03-01 | AI-assisted threat model | Initial system-level STRIPED analysis |
| 2026-02-28 | AI-assisted threat model | Added enrichment pipeline data flows and threats (S15-S18) |
| 2026-02-28 | AI-assisted threat model | Mitigated S18 (Redis URL log redaction filter), S2 (auto-generated FalkorDB password + startup warning), partially mitigated S5 (enrichment NetworkPolicy). Documented SSRF design decision (S15). Added enrichment controls to Security Controls Summary. |
| 2026-02-28 | AI-assisted threat model | Added S19 (policy annotation abuse) and S20 (on-demand enrichment abuse) for vulnerability enrichment and policy annotation features. Added controls: JWT auth on new endpoints, policy input validation, enrichment request size limit, annotation audit trail, enrichment metadata tracking. |
| 2026-02-28 | AI-assisted threat model | Added S21 (blast radius info disclosure), S22 (VEX statement injection), S23 (contact info exposure) for patch planning and VEX support features. Added controls: max_depth cap, VEX status validation, source_document audit trail, email format validation, OpenVEX document validation. |
| 2026-02-28 | AI-assisted threat model | Added S24 (SPDX document poisoning), S25 (source repository URL tampering), S26 (format auto-detection bypass) for SPDX SBOM support and source repository tracking features. Added controls: SPDXValidationError structural validation, sbom_format provenance tracking, repo_url length validation, format-specific processor dispatch. |
