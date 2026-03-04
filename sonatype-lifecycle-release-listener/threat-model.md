# Threat Model: Sonatype Lifecycle Release Listener

## Summary

The sonatype-lifecycle-release-listener is a Flask microservice that receives webhook notifications from SonaType IQ Server, fetches CycloneDX SBOMs via the SonaType API, and persists dependency graph data to FalkorDB. It acts as a write-path bridge between an external CI/CD system and the internal graph database.

The primary risks center on the **unauthenticated webhook endpoint**, **SSRF potential through unvalidated input**, and **information disclosure in error responses**. The service handles SonaType API credentials and FalkorDB passwords, making credential management a critical concern.

## Assets and Trust Boundaries

### Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| SonaType API credentials | `SONATYPE_USERNAME`, `SONATYPE_PASSWORD` env vars | **Critical** -- read access to all SBOMs |
| FalkorDB password | `FALKORDB_PASSWORD` env var | **High** -- write access to dependency graph |
| CA certificate bundles | `/app/certs/ca_bundle.pem` | **High** -- TLS trust anchor |
| FalkorDB graph data | Remote Redis-protocol DB (write path) | **High** -- integrity of dependency data |
| SonaType SBOM data | Fetched via HTTPS, transient | **Medium** -- dependency metadata |
| Webhook payloads | In-memory during processing | **Low** -- event metadata |

### Entry Points

| Entry Point | Protocol | Auth Required |
|-------------|----------|---------------|
| `/webhook` (POST) | HTTP | **None** |
| `/health` (GET) | HTTP | None |

### Trust Boundaries

```
+--------------------------------------------------------------------+
| Kubernetes Cluster                                                  |
|                                                                     |
|  +--------------------+     +--------------------------------+      |
|  | Ingress / LB       |---->| Release Listener Pod           |      |
|  | (external traffic) |     | +----------------------------+ |      |
|  +--------------------+     | | Gunicorn + Flask App       | |      |
|                              | | (non-root, port 8000)     | |      |
|  +--------------------+     | +--------+-------------------+ |      |
|  | SonaType IQ Server |<----+          |                     |      |
|  | (external HTTPS)   |     |          | Redis protocol      |      |
|  +--------------------+     | +--------v-------------------+ |      |
|                              | | FalkorDB (ClusterIP:6379) | |      |
|                              | +----------------------------+ |      |
|                              +--------------------------------+      |
+--------------------------------------------------------------------+
       ^
       | Webhook POST (untrusted)
+------+------+
| SonaType IQ |
| Server      |
+--------------+
```

**Trust boundary crossings:**
1. **External -> Cluster**: Webhook POST from SonaType (or any caller) crosses the cluster boundary
2. **Cluster -> External**: HTTPS request to SonaType API to fetch SBOMs
3. **App -> FalkorDB**: Write operations to the graph database via Redis protocol

## Threat Analysis (STRIPED)

| # | Threat | STRIPED | Asset | Likelihood | Impact | Risk | Status | Detail |
|---|--------|---------|-------|------------|--------|------|--------|--------|
| 1 | Unauthenticated webhook ingestion | S, T | Graph data integrity | **High** | **High** | **Critical** | **OPEN** | `/webhook` accepts POST from any caller with no authentication, HMAC signature, API key, or IP allowlist. An attacker can trigger arbitrary SBOM ingestion or poison the graph with crafted payloads. |
| 2 | SSRF via `app_id` in SonaType API URL | S, T | SonaType credentials, internal network | **Medium** | **High** | **High** | **OPEN** | `app_id` from the webhook payload is interpolated directly into the SonaType API URL (`f"{self.api_url}cycloneDx/{version}/{app_id}/stages/{stage_id}/"`). A crafted `app_id` containing path traversal characters (e.g., `../../admin/`) could redirect the authenticated request to unintended SonaType endpoints, leaking the Basic Auth credentials. |
| 3 | Internal error details leaked to callers | I | Server internals | **Medium** | **Medium** | **Medium** | **OPEN** | `str(e)` from `NotFound` and `RedisError` exceptions is returned directly in the JSON response body (line 138: `{'error': str(e)}`). This can expose FalkorDB hostnames, SonaType API URLs, connection details, and internal file paths. |
| 4 | No request size limit on webhook | D | Application availability | **Medium** | **Medium** | **Medium** | **OPEN** | No `MAX_CONTENT_LENGTH` is configured on the Flask app. An attacker can POST an arbitrarily large JSON body, exhausting memory across all Gunicorn workers. |
| 5 | No rate limiting on webhook | D | Application availability, SonaType API | **Medium** | **Medium** | **Medium** | **OPEN** | Unlimited requests to `/webhook` can trigger unbounded SonaType API calls and FalkorDB writes, potentially causing resource exhaustion or SonaType rate-limit lockout. |
| 6 | SonaType credentials in memory across requests | I | SonaType API credentials | **Low** | **High** | **Medium** | **ACCEPTED** | `SonaTypeClient` stores credentials as instance attributes. A new `CycloneHelper` (and therefore new `SonaTypeClient`) is created per webhook request, so credentials are short-lived. However, they remain in the process address space. This is inherent to the architecture. |
| 7 | FalkorDB connection without TLS in umbrella chart | I | FalkorDB password, graph data | **Medium** | **Medium** | **Medium** | **OPEN** | The umbrella chart's `sonatype-lifecycle-release-listener-deployment.yaml` does not set `FALKORDB_CACERTS` or mount TLS certificates. Although `Persistence` defaults to `ssl=True`, the missing CA cert path will cause TLS verification to use system defaults, which may not include the self-signed CA generated by the umbrella chart's init container. |
| 8 | No webhook payload schema validation | T | Graph data integrity | **Medium** | **Medium** | **Medium** | **OPEN** | Beyond checking for `applicationEvaluation`, `stage`, `id`, and `publicId`, no JSON schema validation is performed. Malformed or oversized nested structures pass through to the CycloneDX processor. |
| 9 | No audit logging for webhook actions | R | Compliance, forensics | **Medium** | **Low** | **Low** | **OPEN** | Webhook processing is logged at INFO level with `message.get('id')`, but there is no structured audit trail (who sent the webhook, source IP, payload hash). Actions cannot be reliably attributed or investigated. |
| 10 | `FLASK_DEBUG` can be enabled in production | I, E | Server internals | **Low** | **High** | **Medium** | **OPEN** | `FLASK_DEBUG` defaults to `false`, but there is no guard preventing it from being set to `true` in production (unlike `sbom-graph-api` which rejects insecure defaults). Debug mode exposes the Werkzeug debugger with code execution capability. |
| 11 | No input sanitization on `app_id` / `public_id` | T | SonaType API, logs | **Medium** | **Medium** | **Medium** | **OPEN** | `app_id` and `public_id` extracted from the webhook are used in API URLs and log messages without validation against expected format (UUID hex strings). This enables log injection via newline characters and URL manipulation. |
| 12 | CycloneDX SBOM processing resource consumption | D | Application availability | **Low** | **Medium** | **Low** | **ACCEPTED** | Very large SBOMs (thousands of components) can consume significant CPU/memory during graph traversal and persistence. Gunicorn timeout (120s) provides a backstop. |
| 13 | Credential exposure if CA cert missing | I | SonaType credentials | **Low** | **High** | **Medium** | **OPEN** | If `SONATYPE_CACERTS` points to a non-existent file, `requests.Session.verify` will fail. However, if `verify` is set to a path that doesn't exist, `requests` raises an error rather than falling back to unverified. The error message could leak the path. If misconfigured to `verify=False`, credentials would be sent over unverified TLS. |
| 14 | New `Persistence` and `SonaTypeClient` per request | D | Application performance | **Medium** | **Low** | **Low** | **OPEN** | Each webhook request creates a new `CycloneHelper`, which opens a new FalkorDB connection and `requests.Session`. Under high webhook volume, this can exhaust FalkorDB connection limits and increase latency. |

## Security Controls in Place

### Positive Controls
- **Parameterized Cypher queries**: `sbom-graph-model` uses `$param` syntax for all graph writes, preventing Cypher injection
- **Node label allowlist**: `ALLOWED_PROJECT_TYPES` and `_SAFE_IDENTIFIER_RE` in `persistence.py` validate labels before interpolation
- **CycloneDX structure validation**: `_validate_cyclonedx_structure()` checks for required SBOM fields before processing
- **TLS to SonaType**: `requests.Session.verify` is set to a CA bundle path; HTTPS enforced for API calls
- **TLS to FalkorDB**: `Persistence` constructor defaults to `ssl=True`
- **Distroless container**: Minimal attack surface, no shell, no package manager
- **Non-root execution**: UID 65532 (daemon), read-only root filesystem
- **Kubernetes security context**: `allowPrivilegeEscalation: false`, `capabilities.drop: ALL`, `runAsNonRoot: true`
- **Secrets via Kubernetes Secrets**: SonaType and FalkorDB credentials injected via `secretKeyRef`
- **Health check endpoint**: `/health` returns simple JSON, no sensitive data

### Missing Controls
- No webhook authentication (HMAC, API key, mTLS, or IP allowlist)
- No request body size limit
- No rate limiting
- No structured audit logging
- No input validation on webhook payload fields (`app_id`, `public_id`)
- No JSON schema validation on webhook body
- No guard against debug mode in production
- Error responses contain internal exception messages

## Third-Party Component Assessment

| Criterion | Flask 3.x | Gunicorn 23.x | requests 2.x | sbom-graph-model | FalkorDB client |
|-----------|-----------|---------------|--------------|-------------------|-----------------|
| CVEs (last 2yr) | 0 | 0 | 0 | 0 (internal) | 0 |
| Last release | 2025 | 2024 | 2025 | Internal | 2024 |
| Maintenance | Very active | Active | Very active | Internal | Active |
| License | BSD-3 | MIT | Apache-2 | Internal | MIT |
| **Risk** | Low | Low | Low | Low | Low |

**Note**: `flask-jwt-extended` is listed as a dependency in `pyproject.toml` but is not used in the sonatype-lifecycle-release-listener code. It should be removed to reduce attack surface.

## Recommendations

### Critical (Implement Before Production)

| # | Finding | Recommendation |
|---|---------|----------------|
| 1 | Unauthenticated webhook | Implement HMAC signature verification using a shared secret. SonaType IQ supports webhook signatures. Alternatively, require an API key in a custom header validated against a Kubernetes Secret. |
| 2 | SSRF via `app_id` | Validate `app_id` against a strict regex (e.g., `^[a-f0-9]{32}$` for SonaType internal IDs). URL-encode path segments when constructing the API URL. |
| 10 | Debug mode unguarded | Add a startup check that rejects `FLASK_DEBUG=true` when a production indicator is present (e.g., `APP_ENV=production`), or remove the debug mode toggle entirely since Gunicorn ignores it. |

### High (Implement in Next Sprint)

| # | Finding | Recommendation |
|---|---------|----------------|
| 3 | Error detail leakage | Replace `str(e)` in error responses with generic messages. Log the full exception server-side with a correlation ID. Return only the correlation ID to the caller. |
| 4 | No request size limit | Set `app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024` (1 MB) to reject oversized payloads before JSON parsing. |
| 7 | FalkorDB TLS in umbrella chart | Mount the TLS CA certificate in the sonatype-lifecycle-release-listener deployment and set `FALKORDB_CACERTS` to the mount path. |
| 11 | Input sanitization | Validate `app_id` and `public_id` format before use. Strip or reject control characters (newlines, null bytes) to prevent log injection. |

### Medium (Plan for Future)

| # | Finding | Recommendation |
|---|---------|----------------|
| 5 | No rate limiting | Implement rate limiting via ingress annotations (e.g., `nginx.ingress.kubernetes.io/limit-rps`) or an API gateway. |
| 8 | No schema validation | Add JSON schema validation for the webhook payload to reject unexpected structures early. |
| 9 | No audit logging | Add structured audit log entries for each webhook: source IP, payload hash, `app_id`, `public_id`, processing result, duration. |
| 14 | Connection per request | Implement connection pooling for FalkorDB (reuse `Persistence` instance across requests) and reuse `requests.Session` for the SonaType client. |

### Low (Housekeeping)

| Finding | Recommendation |
|---------|----------------|
| Unused `flask-jwt-extended` dependency | Remove from `pyproject.toml` to reduce attack surface and image size. |
| `gunicorn.conf.py` SSL commented out | Either remove the commented SSL lines or document that TLS termination is handled by ingress. |
| `umask = 0` in gunicorn config | Set to `0o077` to ensure files created at runtime have restrictive permissions. |

## Residual Risk

| Risk | Severity | Justification |
|------|----------|---------------|
| SonaType credentials in process memory | Medium | Inherent to the architecture. Credentials are short-lived per request. Container memory is not swapped (distroless). Kubernetes Secrets provide at-rest encryption. |
| Large SBOM resource consumption | Low | Gunicorn worker timeout (120s) and `max-requests` recycling provide backstops. Kubernetes resource limits prevent cluster-wide impact. |
| Transitive dependency vulnerabilities | Medium | Lockfile pinning, CI/CD scanning (Snyk/SonaType), and automated patch PRs mitigate. |

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-03-01 | AI-assisted threat model | Initial STRIPED analysis |
