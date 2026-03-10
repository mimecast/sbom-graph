# Threat Model: SBOM Graph API

## Summary

SBOM Graph API is an internal Flask application that visualizes software dependency graphs from FalkorDB for Application Security reporting. It handles authentication (LDAP or local), JWT token management, and graph queries.

The primary risks identified were around credential management (hardcoded defaults), the FalkorDB connection (Redis protocol), and the authentication subsystem. All critical and high findings have been mitigated. The remaining residual risks are medium or low severity and are accepted with documented justification.

## Assets and Trust Boundaries

### Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Flask SECRET_KEY | Environment variable | **Critical** -- signs session cookies |
| JWT_SECRET_KEY | Environment variable | **Critical** -- signs all JWT tokens |
| TOKEN_DB_ENCRYPTION_KEY | Environment variable | **Critical** -- Fernet key for token encryption at rest |
| LDAP bind password | Environment variable | **High** -- service account credential |
| FalkorDB password | Environment variable | **High** -- database credential |
| SQLite token/user database | `/data/tokens.db` | **High** -- encrypted JWT tokens, password hashes |
| User password hashes | SQLite DB | **High** -- PBKDF2-SHA256, 600K iterations |
| TLS private key | `/certs/server.key` | **High** -- server identity |
| Graph data (FalkorDB) | Remote Redis-protocol DB | **Medium** -- dependency metadata, vulnerability data |
| Session cookies | Browser | **Medium** -- authentication state |

### Entry Points

| Entry Point | Protocol | Auth Required |
|-------------|----------|---------------|
| `/auth/login` (POST) | HTTPS | No (login endpoint) |
| `/auth/refresh` (POST) | HTTPS | JWT refresh token |
| `/reports/*` (GET) | HTTPS | Session or JWT |
| `/visualizations/*` (GET) | HTTPS | Session or JWT |
| `/auth/admin/*` (POST) | HTTPS | Session + admin role |
| `/auth/tokens/*` (POST) | HTTPS | Session or JWT |
| `/health`, `/ready` (GET) | HTTP/HTTPS | No |
| `/schemas/*` (GET) | HTTPS | Session or JWT |

### Trust Boundaries

```
+--------------------------------------------------------------+
| Kubernetes Cluster                                           |
|  +--------------------+    +-----------------------------+   |
|  | Ingress Controller |----> SBOM Graph API Pod       |   |
|  | (TLS termination)  |    | +-------------------------+ |   |
|  +--------------------+    | | Gunicorn + Flask App    | |   |
|                            | | (non-root, port 8080)  | |   |
|  +--------------------+    | +-----------+-------------+ |   |
|  | LDAP Server        |<---+             |               |   |
|  | (corporate AD)     |    | +-----------v-------------+ |   |
|  +--------------------+    | | /data/tokens.db         | |   |
|                            | | (PVC, encrypted)        | |   |
|  +--------------------+    | +-------------------------+ |   |
|  | FalkorDB           |<---+                             |   |
|  | (Redis protocol)   |    +-----------------------------+   |
|  +--------------------+                                      |
+--------------------------------------------------------------+
         ^
         | HTTPS
+---------+---------+
|  Browser / API    |
|  Client           |
+-------------------+
```

## Threat Analysis

| # | Threat | STRIDE | Asset | Likelihood | Impact | Risk | Status | Mitigation |
|---|--------|--------|-------|------------|--------|------|--------|------------|
| 1 | Default secret keys used in production | S, T | SECRET_KEY, JWT_SECRET_KEY, TOKEN_DB_ENCRYPTION_KEY | Medium | High | **High** | **MITIGATED** | `app.py` raises `RuntimeError` at startup if any secret matches a known default when `FLASK_DEBUG=false`. See `_INSECURE_DEFAULT_SECRETS`. |
| 2 | Brute force on `/auth/login` | S | User credentials | High | High | **Critical** | **ACCEPTED** | SameSite=Lax cookies and session-based auth reduce automated attack surface. Network-level rate limiting expected at ingress controller / WAF. Application-level rate limiting deferred to future sprint (requires Redis or shared state for multi-worker). |
| 3 | FalkorDB connection unencrypted | I | Graph data, credentials | Medium | Medium | **Medium** | **ACCEPTED** | Both pods deployed on same private network. Kubernetes NetworkPolicy restricts FalkorDB port access. Documented as deployment requirement. |
| 4 | LDAP connection without SSL | I | LDAP credentials, user info | Medium | High | **High** | **MITIGATED** | `app.py` logs a WARNING at startup when `LDAP_ENABLED=true` and `LDAP_USE_SSL=false`. Operators are alerted to misconfiguration. `LDAP_USE_SSL` config option available for enabling TLS. |
| 5 | Session fixation after login | S | Session cookie | Low | High | **Medium** | **MITIGATED** | Flask regenerates session ID on `session.permanent = True` and session data changes. `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE=Lax`, `SESSION_COOKIE_SECURE` tied to TLS config. |
| 6 | Cypher injection via user input | T | FalkorDB graph data | Low | High | **Medium** | **MITIGATED** | All user inputs validated with `[A-Za-z0-9._+-]` regex before use in queries. Parameterized queries via `$param` syntax. Route-level validation returns 400 on invalid input. See `utils/validation.py`. |
| 7 | XSS via project/version names in HTML | T | Browser session | Low | Medium | **Low** | **MITIGATED** | Jinja2 auto-escapes template variables. Visualization modules use `markupsafe.escape()`. Input validation rejects special characters at entry. |
| 8 | CSRF on state-changing form submissions | T | User session, admin actions | Low | High | **Low** | **MITIGATED** | Flask-WTF `CSRFProtect` enabled globally. All 13 forms include `csrf_token()` hidden field. JSON API requests auto-exempted. CSRF error handler returns user-friendly message. |
| 9 | Open redirect via `next` parameter | S | User trust | Low | Medium | **Low** | **MITIGATED** | `is_safe_redirect_url()` validates `next` parameter. Rejects `//`, `\`, `@`, protocol-relative, CRLF, null bytes. Only relative paths with single leading `/` accepted. |
| 10 | JWT token theft from SQLite database | I | Stored JWT tokens | Low | High | **Medium** | **MITIGATED** | Tokens encrypted with Fernet (AES-128-CBC + HMAC-SHA256). Lookup uses SHA-256 hash. Encryption key from environment variable. Container runs non-root. DB directory permissions 0o700. |
| 11 | Local user password hash brute force | I | User passwords | Low | High | **Low** | **MITIGATED** | PBKDF2-SHA256 with 600,000 iterations and 32-byte random salt. Constant-time comparison via `secrets.compare_digest()`. |
| 12 | Sensitive data in error responses | I | Server internals | Low | Medium | **Low** | **MITIGATED** | Generic error messages returned to users. `/ready` endpoint sanitized to return only "Database connection failed" (full error logged server-side). Stack traces never exposed. |
| 13 | DoS via deep graph traversal | D | Application availability | Medium | Medium | **Medium** | **MITIGATED** | `DEFAULT_MAX_DEPTH=50`, `MAX_TRANSITIVE_NODES=50000`. Iterative BFS with cycle detection. Gunicorn timeout 300s. `max-requests=1000` recycles workers. |
| 14 | Token/user database file permission exposure | I | tokens.db | Low | High | **Low** | **MITIGATED** | Directory created with `mode=0o700`. Container runs as non-root UID 65532. PVC mounted at `/data`. |
| 15 | Elevation of privilege via mass assignment | E | Admin status | Low | High | **Low** | **MITIGATED** | `admin_required` decorator on all admin endpoints. `is_admin` set from LDAP group membership or local user record, never from request data. All POST endpoints validate request bodies against JSON Schema (Draft-07) with `additionalProperties: false`, rejecting unexpected fields before processing. |
| 16 | Log injection via user-controlled data | T | Audit trail integrity | Low | Low | **Low** | **MITIGATED** | Username and group names removed from LDAP log messages. Only counts and exception messages logged. |
| 17 | Dependency supply chain compromise | T | Application integrity | Low | Critical | **Medium** | **MITIGATED** | `uv.lock` pins exact versions. Internal Nexus registry. Snyk and SonaType SCA scanning in CI/CD pipeline. |
| 18 | Container escape / privilege escalation | E | Kubernetes node | Low | Critical | **Low** | **MITIGATED** | Distroless base image. Non-root user. Helm chart includes `securityContext`. PodDisruptionBudget configured. |
| 19 | Missing security response headers | I | Browser security | Low | Medium | **Low** | **MITIGATED** | `after_request` handler adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`. |
| 20 | Content-Disposition header injection via schema_name | T | Browser, response headers | Low | Medium | **Low** | **MITIGATED** | `schema_name` path parameter validated with `validate_schema_name()`; Content-Disposition header sanitized via `sanitize_content_disposition()` before use. |
| 21 | ValueError/DoS from unvalidated query parameters | D, T | Application availability | Medium | Medium | **Medium** | **MITIGATED** | All `max_depth`, `limit`, `min_score`, `min_confidence` use `validate_int_param()`/`validate_float_param()` with bounds and NaN/Inf rejection. Boolean and URL params use `validate_boolean()` and `validate_url()`. Admin `username` path params use `validate_username()`; `expires_days` and `description` bounded. |

## Security Controls Summary

### Authentication & Authorization
- **Dual auth**: LDAP (corporate) or local user accounts with PBKDF2-SHA256 password hashing
- **JWT tokens**: HS256, configurable expiry, stored encrypted (Fernet) in SQLite
- **Session management**: HttpOnly, SameSite=Lax, Secure (when TLS enabled), 8-hour lifetime
- **RBAC**: `auth_required` and `admin_required` decorators, LDAP group-based admin assignment
- **CSRF**: Flask-WTF global protection, auto-exempt for JSON API, explicit exempt for JWT-only endpoints

### Input Validation
- **Project/version names**: `[A-Za-z0-9._+-]` regex, max length 256/128
- **Defect IDs**: `[A-Za-z0-9._-]` regex, max length 128
- **Annotation IDs**: UUID v4 pattern via `validate_annotation_id()`
- **Schema names**: Lowercase alphanumeric + hyphens via `validate_schema_name()`; Content-Disposition header sanitized with `sanitize_content_disposition()` to prevent header injection
- **Admin usernames**: Alphanumeric, hyphens, underscores, dots, @ via `validate_username()`
- **URLs** (e.g. `repo_url`): Must be http:// or https:// with valid host via `validate_url()`
- **CSS dimensions**: Allowlist pattern, max value 10000
- **Formats**: Strict allowlist (`html`, `excel`, `json`)
- **Layouts**: Strict allowlist (`spring`, `radial`, `shell`, `bfs`, `circular`)
- **Numeric params**: `validate_int_param()`/`validate_float_param()` with bounds, NaN/Inf rejection (max_depth, limit, min_score, min_confidence, expires_days)
- **Boolean params**: `validate_boolean()` for internal_only, include_dependencies, longest_only
- **Redirect URLs**: Single leading `/`, no `//`, `\`, `@`, CRLF, null bytes
- **Inbound JSON bodies**: All POST endpoints validated against JSON Schema (Draft-07) via `validate_json_body()`; schemas enforce required fields, type constraints, string length limits, enum values, pattern matching (e.g., `^pkg:` for purls), and `additionalProperties: false` to prevent mass assignment

### Transport & Cryptography
- **TLS**: Configurable via environment (Gunicorn SSL context, Ingress termination)
- **Token encryption**: Fernet (AES-128-CBC + HMAC-SHA256), key derived from SHA-256 of config key
- **Password hashing**: PBKDF2-SHA256, 600,000 iterations, 32-byte random salt

### Infrastructure
- **Container**: Distroless Python image, non-root (UID 65532), read-only root FS option
- **Kubernetes**: SecurityContext, PDB, HPA, resource limits, PVC for persistent data
- **CI/CD**: Snyk SAST, SonaType SCA, Bandit static analysis, Ruff linting, 85%+ test coverage

### Logging & Error Handling
- **No user data in logs**: Username, group names, and other user-controlled values excluded
- **Generic error messages**: Internal details logged server-side, generic messages to users
- **Startup validation**: Rejects insecure default secrets, warns on LDAP without SSL

## Third-Party Component Assessment

| Criterion | Flask-WTF | Flask-JWT-Extended | ldap3 | FalkorDB client | cryptography |
|-----------|-----------|--------------------|----|-----------------|--------------|
| CVEs (last 2yr) | 0 | 0 | 1 (low) | 0 | 2 (patched) |
| Last release | 2024 | 2024 | 2024 | 2024 | 2025 |
| Contributors | 50+ | 30+ | 10+ | 20+ | 200+ |
| License | BSD-3 | MIT | LGPL-3 | MIT | Apache-2/BSD |
| Maintenance | Active | Active | Active | Active | Very active |
| **Risk** | Low | Low | Low | Low | Low |

All dependencies are actively maintained with established user bases and compatible licenses. No critical unpatched vulnerabilities.

## Residual Risk

| Risk | Severity | Justification |
|------|----------|---------------|
| No application-level rate limiting on login | Critical | Network-level rate limiting at ingress/WAF is the expected control. Application-level limiting requires shared state (Redis) across Gunicorn workers and is deferred. Monitoring/alerting on failed login attempts provides detection. |
| FalkorDB unencrypted in-cluster traffic | Medium | Accepted if both pods share a private network with Kubernetes NetworkPolicy restricting access to the FalkorDB port. |
| TOKEN_DB_ENCRYPTION_KEY compromise exposes tokens | Medium | Fernet provides defense-in-depth. Token expiration (default 90 days) limits exposure window. Key rotation would require re-encrypting all tokens. |
| Transitive dependency vulnerabilities | Medium | Mitigated by lockfile pinning, Snyk/SonaType scanning, and automated security patch PRs. |

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-02-28 | AI-assisted threat model | Initial threat model with STRIDE analysis |
| 2026-02-28 | Implementation | Mitigated findings #1, #4, #12, #19 via code changes |
| 2026-03-10 | Parameter validation hardening | Added threats #20 (Content-Disposition header injection), #21 (unvalidated query params); expanded Input Validation controls with new validators and sanitizers |
