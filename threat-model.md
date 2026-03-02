# Threat Model: SBOM Graph System

## Summary

SBOM Graph is a three-component system for ingesting CycloneDX SBOMs, storing dependency relationships in a graph database (FalkorDB), and providing interactive visualizations and reports. The system consists of:

- **sonatype-lifecycle-release-listener**: Webhook receiver that fetches SBOMs from SonaType and writes to FalkorDB
- **sbom-graph-api**: Web application for viewing reports and visualizations (read path)
- **FalkorDB**: Graph database storing dependency data (Redis protocol)
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
|  | - Read-only graph |         | - PVC persistence      |  |
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

## Trust Boundaries

| Boundary | Crossing | Protocol |
|----------|----------|----------|
| Internet -> Cluster | Webhook from SonaType | HTTPS (ingress), HTTP (internal) |
| Internet -> Cluster | User browser | HTTPS (ingress) |
| Cluster -> Internet | SBOM fetch from SonaType API | HTTPS |
| Cluster -> LDAP | User authentication | LDAP/LDAPS |
| App -> FalkorDB | Graph reads/writes | Redis protocol (+/- TLS) |
| Init Job -> FalkorDB | Demo data load | Redis protocol |

## System-Level Threat Analysis (STRIPED)

### Cross-Component Threats

| # | Threat | STRIPED | Components | Likelihood | Impact | Risk | Status | Detail |
|---|--------|---------|------------|------------|--------|------|--------|--------|
| S1 | Graph data poisoning via unauthenticated webhook | S, T | sonatype-lifecycle-release-listener -> FalkorDB -> sbom-graph-api | **High** | **Critical** | **Critical** | **OPEN** | An attacker can POST crafted webhook payloads to the sonatype-lifecycle-release-listener, triggering SBOM ingestion of arbitrary data. Poisoned graph data propagates to all reports and visualizations shown to users, potentially hiding real vulnerabilities or creating false ones. This is the highest-priority system risk. |
| S2 | FalkorDB password not set by default | S, E | All components -> FalkorDB | **High** | **High** | **Critical** | **OPEN** | The umbrella chart defaults `falkordb.password` to `""`. When empty, no `FALKORDB_PASSWORD` env var is injected and no Kubernetes Secret is created. FalkorDB runs without authentication, allowing any pod in the namespace (or any pod that can reach the ClusterIP) to read/write the graph. |
| S3 | TLS configuration mismatch between components | I | sbom-graph-api <-> FalkorDB | **High** | **Medium** | **High** | **OPEN** | FalkorDB is deployed with TLS by default (`tls.enabled: true`, non-TLS port disabled). However, `FalkorDBService` in sbom-graph-api does not pass `ssl` or `ssl_ca_certs` when connecting. The umbrella chart sets `TLS_ENABLED` but this controls the sbom-graph-api HTTP server TLS, not the FalkorDB client connection. sbom-graph-api will fail to connect to a TLS-only FalkorDB, or if TLS is disabled to work around this, traffic is unencrypted. |
| S4 | Umbrella chart missing critical sbom-graph-api secrets | I, E | sbom-graph-api | **High** | **Critical** | **Critical** | **OPEN** | The umbrella chart does not set `FLASK_SECRET_KEY`, `JWT_SECRET_KEY`, `TOKEN_DB_ENCRYPTION_KEY`, or `AUTH_ENABLED`. sbom-graph-api has a guard that rejects insecure defaults when `FLASK_DEBUG=false`, but the chart also does not set `FLASK_DEBUG`. The resulting behavior depends on image defaults and is non-deterministic. If auth is disabled (the default), all reports and visualizations are publicly accessible within the cluster. |
| S5 | No NetworkPolicy restricting FalkorDB access | E | FalkorDB | **Medium** | **High** | **High** | **OPEN** | The umbrella chart does not include a Kubernetes NetworkPolicy. Any pod in the namespace (or cluster, depending on CNI defaults) can connect to the FalkorDB ClusterIP on port 6379. Combined with S2 (no password), this allows arbitrary graph manipulation. |
| S6 | Self-signed TLS CA not distributed to clients | I | FalkorDB -> sonatype-lifecycle-release-listener, sbom-graph-api | **High** | **Medium** | **High** | **OPEN** | When TLS is auto-generated via the init container, the self-signed CA certificate is stored in an emptyDir volume on the FalkorDB pod. Neither the sonatype-lifecycle-release-listener nor sbom-graph-api deployments mount this volume or receive the CA cert. Clients cannot verify the FalkorDB server certificate, resulting in connection failures or requiring TLS verification to be disabled. |
| S7 | SonaType credentials not provisioned by umbrella chart | I | sonatype-lifecycle-release-listener -> SonaType | **High** | **Medium** | **Medium** | **OPEN** | The umbrella chart does not set `SONATYPE_HOST`, `SONATYPE_USERNAME`, or `SONATYPE_PASSWORD` for the sonatype-lifecycle-release-listener. Webhook processing will fail at runtime when attempting to fetch SBOMs. This is a deployment correctness issue that may lead operators to pass credentials via insecure means (e.g., plain env vars in overrides). |
| S8 | Init data job bypasses TLS and auth | T, E | init-data-job -> FalkorDB | **Medium** | **Medium** | **Medium** | **OPEN** | The `init-data-job.yaml` does not set `FALKORDB_CACERTS` or pass TLS parameters to `populate_acme_corp.py`. It uses `nc -z` (plain TCP) for the readiness check, which will fail against a TLS-only FalkorDB port. The job also does not receive the FalkorDB password if `falkordb.password` is set after the initial deployment. |
| S9 | No ingress defined in umbrella chart | I, D | sbom-graph-api, sonatype-lifecycle-release-listener | **Low** | **Medium** | **Low** | **ACCEPTED** | Services are ClusterIP-only. External access requires operators to configure ingress separately. This is by design (separation of concerns) but means there is no default TLS termination, rate limiting, or WAF protection documented in the chart. |
| S10 | Demo data loaded in production | I | init-data-job -> FalkorDB | **Low** | **Low** | **Low** | **OPEN** | `initData.enabled` defaults to `true`. The demo data (Acme Corp) will be loaded into production deployments unless explicitly disabled, cluttering the graph with synthetic data. |

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
| I2 | Alpine and BusyBox images not pinned by digest | T | Init containers | **Medium** | **Medium** | **Medium** | **OPEN** | `alpine:3.20` and `busybox:1.36` are referenced by tag, not SHA digest. A compromised registry or tag mutation could inject malicious code into the init containers, which have access to the TLS volume and FalkorDB connectivity. |
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
| Insecure default rejection | sbom-graph-api | **Strong** -- fails fast on weak secrets |
| TLS to SonaType API | sonatype-lifecycle-release-listener | **Strong** -- CA-verified HTTPS |
| TLS to FalkorDB | sonatype-lifecycle-release-listener | **Moderate** -- ssl=True but CA path issues |
| Distroless containers | All apps | **Strong** -- minimal attack surface |
| Non-root execution | All components | **Strong** -- UID 65532 |
| Read-only root filesystem | All containers | **Strong** -- prevents runtime modification |
| Dropped capabilities | All containers | **Strong** -- `ALL` dropped |
| Kubernetes Secrets for credentials | Helm charts | **Moderate** -- base64, not encrypted by default |

### Controls Missing

| Missing Control | Impact | Components |
|----------------|--------|------------|
| Webhook authentication | Critical | sonatype-lifecycle-release-listener |
| FalkorDB password enforcement | Critical | Umbrella chart |
| NetworkPolicy | High | Umbrella chart |
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
| S8 | Init job bypasses TLS/auth | Pass `FALKORDB_CACERTS` and `FALKORDB_PASSWORD` to the init job. Replace `nc -z` with a Redis-protocol PING that works over TLS. | Low |
| D2 | Graph data readable without auth | Set `AUTH_ENABLED=true` by default in the umbrella chart, or at minimum document that auth is disabled by default and the implications. | Low |
| D4 | Credentials in Helm values | Document that production deployments should use `existingSecret` references rather than inline passwords. Add `.gitignore` patterns for custom values files. | Low |
| I2 | Images not pinned by digest | Pin `alpine` and `busybox` init container images by SHA256 digest. | Low |
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

- [ ] `falkordb.password` is set to a strong random value
- [ ] `FLASK_SECRET_KEY` is set (min 32 bytes, cryptographically random)
- [ ] `JWT_SECRET_KEY` is set (min 32 bytes, cryptographically random)
- [ ] `TOKEN_DB_ENCRYPTION_KEY` is set (min 32 bytes)
- [ ] `AUTH_ENABLED=true` is set for sbom-graph-api
- [ ] Webhook authentication is configured for sonatype-lifecycle-release-listener
- [ ] `SONATYPE_HOST`, `SONATYPE_USERNAME`, `SONATYPE_PASSWORD` are configured
- [ ] FalkorDB TLS CA is distributed to all client pods
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
| FalkorDB | latest | 0 | Active | Server-Side PL | Low |
| Flask | 3.x | 0 | Very active | BSD-3 | Low |
| Gunicorn | 23.x | 0 | Active | MIT | Low |
| Flask-JWT-Extended | 4.x | 0 | Active | MIT | Low |
| Flask-WTF | 1.x | 0 | Active | BSD-3 | Low |
| ldap3 | 2.x | 1 (low) | Active | LGPL-3 | Low |
| requests | 2.x | 0 | Very active | Apache-2 | Low |
| cryptography | 44.x | 2 (patched) | Very active | Apache-2/BSD | Low |
| Alpine (init) | 3.20 | Varies | Active | MIT | Low |
| BusyBox (init) | 1.36 | Varies | Active | GPL-2 | Low |

All primary dependencies are actively maintained with no unpatched critical vulnerabilities. The main supply chain risk is unpinned init container images (Alpine, BusyBox) and the FalkorDB `latest` tag.

## Risk Heat Map

```
              Low Impact    Medium Impact    High Impact    Critical Impact
            +-------------+----------------+--------------+----------------+
 High       |             | S7, S10        | S3, S5, S6   | S1, S2, S4     |
 Likelihood |             |                |              |                |
            +-------------+----------------+--------------+----------------+
 Medium     |             | D4, I2, I3, S8 | D2, I5       |                |
 Likelihood |             |                |              |                |
            +-------------+----------------+--------------+----------------+
 Low        | I4          | I1, D3, S9     |              |                |
 Likelihood |             |                |              |                |
            +-------------+----------------+--------------+----------------+
```

## Residual Risk (After Mitigations)

| Risk | Severity | Justification |
|------|----------|---------------|
| SonaType credential exposure in process memory | Medium | Inherent to the architecture. Short-lived per request. Distroless prevents memory dumps. |
| FalkorDB data at rest unencrypted | Low | Kubernetes StorageClass encryption is the expected control. |
| Large SBOM resource consumption | Low | Gunicorn timeouts and Kubernetes resource limits provide backstops. |
| Transitive dependency vulnerabilities | Medium | Lockfile pinning and CI/CD scanning mitigate. |
| Self-signed TLS weaker than CA-issued | Low | Acceptable for demo/internal use. Production should use proper PKI. |

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-03-01 | AI-assisted threat model | Initial system-level STRIPED analysis |
