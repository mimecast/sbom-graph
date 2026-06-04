# AGENTS.md - AI Agent Instructions for SBOM Graph API

This document provides instructions and context for AI agents working on this codebase.

## Working Agreements

- All agents must operate in Privacy mode and use only approved models.
- Each code-generating agent must use a different model and focus area.
- All code must be well-architected, elegant, maintainable, and thoroughly documented.
- Cognitive complexity should be minimized; rationale for complex logic must be documented.
- All public APIs and methods must be commented and included in documentation.

## Agent Roles

### CodeGenAlpha

- Model: composer-1.5
- Focus: Maintainability, documentation, and clarity.
- Responsibilities: Generate code from specification, prioritize readability and extensibility.

### CodeGenBeta

- Model: claude-4.5-opus-high
- Focus: Performance and cognitive simplicity.
- Responsibilities: Generate code from specification, optimize for speed and resource usage.

### CodeGenGamma

- Model: gpt-5.3-codex
- Focus: Security and architectural elegance.
- Responsibilities: Generate code from specification, ensure secure patterns and robust design.

### Orchestrator

- Model: gpt-5.3-codex
- Responsibilities:  
  - Review and critique all codegen outputs.  
  - Aggregate the best, most secure, performant, and elegant aspects into a single solution.  
  - Document all integration decisions and rationale.

### TestingAgent

- Model: gpt-5.2
- Responsibilities:  
  - Write and run tests.  
  - Validate correctness and code coverage.  
  - Report and escalate test failures.

### PerformanceAgent

- Model: gpt-5.3-codex
- Responsibilities:  
  - Benchmark and profile code.  
  - Suggest and implement optimizations.

### SecurityAgent

- Model: claude-4.5-opus-high
- Responsibilities:  
  - Perform SAST and SCA scans at all workflow stages.  
  - Flag vulnerabilities and enforce remediation.  
  - Block progression if critical issues are found.

## Workflow Coordination

- CodeGen agents work in parallel.
- SecurityAgent, TestingAgent, and PerformanceAgent intervene at defined workflow points.
- Orchestrator aggregates and finalizes the solution, with all agents providing evidence and reports.
- All agents must communicate findings in Markdown, using clear section headers and evidence appendices.

## Quality Gates

- No solution may progress unless all tests pass and no critical security issues remain.
- Performance regressions must be addressed before finalization.
- All code must meet maintainability and documentation standards.

## Escalation Procedures

- If an agent cannot resolve an issue, escalate to Orchestrator for arbitration.
- Orchestrator may request additional input or rework from any agent as needed.

## Project Overview

SBOM Graph API is a Flask application that provides data visualizations of graph data structures stored in FalkorDB. It is part of the Application Security reporting infrastructure.

## Technology Stack

- **Language**: Python 3.12+
- **Package Manager**: uv (not Poetry)
- **Web Framework**: Flask with gunicorn
- **Database**: FalkorDB (Redis-compatible graph database)
- **Token Storage**: SQLite with Fernet encryption
- **Authentication**: Flask-JWT-Extended, Flask-Login, ldap3
- **Encryption**: cryptography (Fernet)
- **Validation**: jsonschema (Draft-07 JSON Schema validation for inbound payloads)
- **Visualization**: PyVis, NetworkX
- **Excel Generation**: openpyxl, pandas
- **Container**: Distroless Python image
- **Orchestration**: Kubernetes with Helm

## Key Architecture Decisions

### Configuration Guidelines

- All configuration comes from environment variables (optional `*_FILE` paths for secrets mounted as files)
- Use `config.py` for configuration management
- FalkorDB credentials should come from Kubernetes secrets in production
- Default values support local development
- The `FALKORDB_INTERNAL_LABEL` environment variable specifies the node label used for internal projects (default: `INTERNAL`). This label is used by the `internal_only` filter in reports and visualizations

### Service Layer

- `falkordb_service.py` provides all database interactions
- `ldap_service.py` handles LDAP authentication
- `token_storage.py` provides encrypted JWT token storage
- Uses singleton pattern for service instances
- Supports dependency injection for testing

### Authentication & Security

- Authentication is optional and controlled by `AUTH_ENABLED` environment variable
- When enabled, all endpoints (except `/health`, `/ready`) require authentication
- Supports two authentication methods:
  - **Session-based**: Users log in via `/auth/login` with LDAP credentials
  - **JWT tokens**: API clients use tokens in `Authorization: Bearer <token>` header
- JWT tokens are stored in an encrypted SQLite database (Fernet encryption)
- LDAP integration supports user DN templates, group membership checks, and SSL
- TLS can be enabled for secure HTTPS connections

### SBOM Ingest Pipeline (Async by Default)

The four ingest endpoints (`POST /ingest/cyclonedx`, `/ingest/spdx`,
`/ingest/sbom`, `/ingest/vex`) **default to asynchronous** processing:

- The Flask handler validates the request body (size, JSON Schema,
  format autodetect for `/ingest/sbom`), allocates a deterministic
  `record_id`, and then calls
  `celery_app.send_task("sbom_graph_enrichment.ingest_tasks.<task>",
   queue="ingest")`.
- The handler returns `202 Accepted` with body
  `{"status": "accepted", "record_id", "job_id", "status_url", "format"}`
  and a `Location: /ingest/jobs/<job_id>` header.
- The task runs on the dedicated `enrichment-ingest-worker` pool (see
  `helm/charts/sbom-graph/templates/enrichment-ingest-worker-deployment.yaml`)
  which consumes **only** the `ingest` queue with
  `--prefetch-multiplier=1` to bound per-task memory.
- `GET /ingest/jobs/<job_id>` validates the UUID shape, looks up the
  Celery `AsyncResult`, and returns
  `{"job_id", "state", "terminal", "result"?}`. The `result` dict in
  the terminal SUCCESS case is byte-for-byte the legacy synchronous
  summary (`projects_count`, `dependencies_count`, `defects_count`, …).

**Synchronous escape hatch**: `POST /ingest/<endpoint>?sync=true` (or
`?sync=1`/`?sync=yes`) runs the same `process_*` helpers inline and
returns the legacy `201 Created` with the summary directly. Use only
for very small SBOMs in test scripts or when the dedicated ingest pool
is intentionally disabled (`enrichment.ingest.enabled: false`).

**Security**:
- The `/ingest/jobs/<id>` handler **must** validate `<id>` as a UUID
  before passing it to `AsyncResult` — without that, an attacker could
  probe arbitrary keys in the result-backend Redis namespace
  (CWE-22 / CWE-200).
- Worker tasks catch their own validation exceptions and return a
  sanitised `{"status": "error", "error": "<message>"}` dict from
  `state: SUCCESS`. An actual `state: FAILURE` returns the static
  string `"Ingest job failed; see server logs"` (CWE-209) — the raw
  exception is never sent to the client.
- The 50 MB `MAX_SBOM_SIZE` body cap is enforced **before** the Celery
  `send_task` call, so oversize bodies never enter the broker.

**Failure handling**:
- When the API container cannot import `sbom_graph_enrichment.celery_app`
  the async path returns `503 Ingest pipeline not available`. The
  synchronous `?sync=true` path continues to work because it only
  needs the `sbom_graph_model` package (already a hard dependency).
- The dedicated worker pool can be disabled by setting
  `enrichment.ingest.enabled: false` or `replicas: 0` in
  `values.yaml`. The main enrichment pool will **not** automatically
  pick up the `ingest` queue — that's the priority guarantee.

**Module layout**:
- `src/sbom_graph_api/routes/ingest.py` — Flask handlers, validation,
  enqueue, and `?sync=true` inline path.
- `sbom-graph-enrichment/src/sbom_graph_enrichment/ingest_tasks.py` —
  Celery tasks invoked by the worker.
- Both call the same `process_cyclonedx` / `process_spdx` helpers and
  `sbom_graph_model.Persistence` plumbing.

**Reference**: [`docs/ingest-pipeline.md`](../docs/ingest-pipeline.md)
is the authoritative operator and integrator guide (topology, sizing,
HTTP contract, threat model, troubleshooting). Required reading
before changing the queue topology, worker concurrency, the
`?sync=true` flag semantics, or the job-status response shape.

### Visualization Modules

- K-partite visualization uses longest-path partitioning algorithm
- PyVis generates self-contained HTML with inline JavaScript
- Hierarchical layouts are configured via PyVis options
- **Cycle Handling**: Both visualizations and reports remove cycles using `nx.simple_cycles()` before computing partitions to prevent infinite loops

### API Design

- RESTful endpoints with clear URL structure
- Visualizations return complete HTML pages
- Reports support HTML, Excel, and JSON output formats
- JSON Schema definitions available for all report/export types
- Health/ready endpoints for Kubernetes probes
- **JSON response standardization**: Programmatic API v1 endpoints use `utils/api_helpers.py` (`api_response()`, `paginate_params()`, `make_pagination()`) for consistent envelope `{data, pagination?, meta}`
- **SBOM provenance tracking**: Ingestion endpoints (`/ingest/cyclonedx`, `/ingest/spdx`, `/ingest/sbom`) create SBOM records (document hash, tool info, ingested_at) linked to all ingested versions; responses include `record_id` for audit trails and provenance lookups
- **Asynchronous SBOM ingest**: `POST /ingest/*` returns `202 Accepted` by default and enqueues the parse-and-persist work onto a dedicated Celery `ingest` queue consumed only by the `enrichment-ingest-worker` pool. Clients poll `GET /ingest/jobs/<job_id>` for the worker's terminal summary. A `?sync=true` query flag preserves the legacy `201 Created` inline path for callers that need to block. See [`docs/ingest-pipeline.md`](../docs/ingest-pipeline.md) for the full contract and operational reference.

### UI Features

- **Internal Only Toggle**: All report and export HTML pages include a toggle switch to filter between "All projects" and "Internal Only" views
- **Dynamic Download Links**: Excel and JSON download links automatically update when the internal_only toggle changes
- **Interactive API Documentation**: The root endpoint (`/`) provides interactive forms to test all endpoints with parameter inputs
- **Direct Links**: Endpoints without required parameters have clickable links in the API docs
- **Frozen Table Headers**: All report tables have sticky headers that remain visible while scrolling through data (max-height: 70vh)

### Input Validation & Security

- All user inputs are validated using `utils/validation.py`
- **Inbound JSON payloads** on all POST endpoints are validated against JSON Schema (Draft-07) using the `validate_json_body()` utility in `utils/validation.py`
- Inbound schemas are defined in `schemas/inbound.py` and registered in the global `SCHEMA_INDEX`
- Schemas enforce `additionalProperties: false` to prevent mass assignment
- CSS dimensions are validated with allowlist patterns
- Format parameters are limited to allowed values (html, excel, json)
- Boolean parameters use strict validation
- URL parameters are properly encoded

**Validation utilities** (`utils/validation.py`): `validate_project_name`, `validate_version_name`, `validate_defect_id`, `validate_annotation_id` (UUID v4), `validate_schema_name` (lowercase alphanumeric + hyphens), `validate_username` (alphanumeric, hyphens, underscores, dots, @), `validate_url` (http/https with valid host), `validate_float_param` (safe float parsing with NaN/Inf/bounds), `validate_int_param` (safe integer parsing with bounds), `validate_max_depth`, `validate_limit`, `validate_boolean`, `validate_format`, `validate_layout`, `validate_css_dimension`, `validate_project_group`, `validate_json_body`, `validate_sort_param`, `validate_sort_order` (centralized sort validation used across routes), `sanitize_content_disposition` (prevents header injection in Content-Disposition). All path parameters, query parameters, and headers that accept user input are validated before use; raw `int()`/`float()` casts have been replaced with bounded validators to prevent crashes and NaN/Inf acceptance.

### HTML Templates

- Templates are stored in `src/sbom_graph_api/templates/` as separate HTML files
- `table.html` - Generic table report template with download links and toggles
- `dependants.html` - Specialized template for dependants report with expandable paths
- `export.html` - Export landing page template with preview table
- `api_docs.html` - Interactive API documentation page
- `enrichment_coverage.html` - Enrichment coverage dashboard with progress bars
- `license_dashboard.html` - License compliance dashboard with risk distribution
- `vulnerabilities.html` - Vulnerability report with VEX status column and filter
- `trust_scores.html` - Trust score report with colour-coded scores
- `trust_score_gaps.html` - Trust score gaps report with recommendations
- `trust_score_heatmap.html` - Trust score heatmap grid by category
- `risk_propagation_graph.html` - Risk propagation network (vis.js)
- `application_risk_dashboard.html` - Per-application supply-chain risk
- `risk_path_explorer.html` - Dependency risk path drill-down
- `risk_outliers.html` - Low-score, high-fan-in packages
- `whatif_simulator.html` - What-if risk propagation simulator
- `sbom_inventory.html` - SBOM inventory table with search and filters
- `sbom_coverage.html` - SBOM coverage dashboard with status distribution
- `source_impact.html` - Source repository impact report with graph
- `policy_admin.html` - Policy annotation admin page
- `incident_response.html` - Incident response with blast radius and patch plan
- Templates use Jinja2 syntax and are loaded via Flask's `render_template()`

## Code Organization

```Plaintext
src/sbom_graph_api/
├── app.py                    # Application factory - entry point
├── config.py                 # Environment-based configuration
├── wsgi.py                   # WSGI entry for gunicorn
├── routes/                   # Flask blueprints
│   ├── admin.py              # Policy annotation admin endpoints
│   ├── api_v1.py             # Programmatic JSON API (v1)
│   ├── auth.py               # Authentication & user management
│   ├── ingest.py             # SBOM ingestion (CycloneDX, SPDX)
│   ├── visualizations.py     # Graph visualization endpoints
│   ├── exports.py            # Excel/JSON download endpoints
│   ├── schemas.py            # JSON Schema endpoints
│   └── reports/              # Report sub-package
│       ├── __init__.py       # Report blueprint registration
│       ├── _common.py        # Shared report helpers
│       ├── compliance.py     # License compliance & dashboard
│       ├── inventory.py      # Project/app/source repo reports
│       ├── sbom_provenance.py # SBOM inventory & coverage
│       ├── trust_scores.py   # Trust scores, gaps, heatmap, risk dashboards
│       └── vulnerabilities.py # Vulnerability & incident reports
├── services/                 # Business logic layer
│   ├── falkordb_service.py   # Database operations
│   ├── ldap_service.py       # LDAP authentication
│   ├── token_storage.py      # Encrypted JWT token storage
│   └── user_storage.py       # Local user storage with password hashing
├── schemas/                  # JSON Schema definitions
│   ├── __init__.py
│   ├── definitions.py        # Output report schema definitions & SCHEMA_INDEX
│   └── inbound.py            # Inbound request body schemas
├── visualizations/           # Visualization generators
│   ├── kpartite.py           # K-partite dependency graphs
│   ├── bipartite.py          # Bi-partite version/dependant graphs
│   ├── dependencies_graph.py # Spring-layout dependency graphs
│   ├── dependants_graph.py   # Reverse dependency graphs
│   └── source_impact.py      # Source repo impact graphs
├── exports/                  # Export generators
│   ├── excel.py              # Excel file generation
│   └── json_format.py        # JSON export formatters
├── templates/                # Jinja2 HTML templates (20+ files)
├── static/css/               # Stylesheets
│   └── report.css            # Shared report styles
└── utils/                    # Utility modules
    ├── api_helpers.py        # api_response(), paginate_params(), make_pagination() for consistent JSON envelope
    └── validation.py         # Input validation & sanitisation

# Project root
gunicorn.conf.py              # Gunicorn config (TLS, workers, timeouts)
Dockerfile                    # Container build definition
pyproject.toml                # Python project configuration
```

## FalkorDB Graph Schema

The graph database uses the following node and relationship structure:

### Nodes

- **Version**: Represents a specific version of a project
  - `project_name`: String - the project identifier
  - `name`: String - the version string (e.g., "1.0.0", "2.1.0-SNAPSHOT")
  - `scan_id`: String - unique identifier for application scans
  - `scan_ids`: Array - list of scan IDs where this node appears
  - May have additional label `INTERNAL` for internal libraries

### Relationships

- **DEPENDS_ON** (or similar): Points from a Version to its dependencies

### Common Query Parameters

- **internal_only**: Filter to show only internal-labeled nodes (label configurable via `FALKORDB_INTERNAL_LABEL`)
- **project_group**: For project_name disambiguation when multiple versions share the same name (e.g., `com.acme`)
- **max_depth**: Limit traversal depth for transitive queries
- **limit**: Maximum number of results to return
- **format**: Output format (html, excel, json)

### Special Version Values

- **latest**: For version-dependencies endpoint, resolves to the highest SemVer version
  - Only available if ALL versions of the project are SemVer compliant
  - Returns 400 error with non-compliant versions list if project fails SemVer check
  - Use `/reports/non-semver-versions` to identify non-compliant versions

### Scan ID Filtering

- Application nodes have a single `scan_id` property
- Library nodes have `scan_ids` list (from all app scans that include them)
- Transitive queries use scan_id intersection to ensure accurate results
- **Visualizations skip scan_id filtering** by default (`skip_scan_filter=True`) to show raw graph structure
- Reports use scan_id filtering to ensure dependants are actually using the specific version
- The `get_transitive_dependants()` method accepts a `skip_scan_filter` parameter:
  - `False` (default): Filters by scan_id to ensure accurate version usage
  - `True`: Shows all structural dependants regardless of scan_id (used by visualizations)

## Authentication System

### Configuration

Authentication is controlled by the `AUTH_ENABLED` environment variable. When enabled:

- All endpoints require authentication except `/health` and `/ready`
- Users can authenticate via LDAP (when `LDAP_ENABLED=true`) or local users (when LDAP disabled)
- Configuration classes in `config.py`: `TLSConfig`, `JWTConfig`, `LDAPConfig`, `DatabaseConfig`

### Login Rate Limiting

`POST /auth/login` is protected by in-memory per-IP rate limiting: 10 attempts per 15 minutes per Gunicorn worker. When exceeded, returns `429 Too Many Requests` with `Retry-After` header. Limits are per-worker (not shared across workers).

### Authentication Endpoints (`routes/auth.py`)

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/auth/login` | GET/POST | Login page and authentication |
| `/auth/logout` | GET | Logout and clear session |
| `/auth/refresh` | POST | Refresh JWT access token |
| `/auth/change-password` | GET/POST | Change password (local auth only) |
| `/auth/change-password-required` | GET/POST | Forced password change after temp password |
| `/auth/tokens` | GET | List user's API tokens |
| `/auth/tokens/create` | GET/POST | Create new API token |
| `/auth/tokens/{id}` | GET | Get token details |
| `/auth/tokens/{id}/revoke` | POST | Revoke a token |
| `/auth/status` | GET | Check authentication status |

### Admin Endpoints (Local Auth Only)

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/admin/policies` | GET | Policy annotation admin page (search, filter, add/remove) |
| `/admin/policies` | POST | Add policy annotation (admin only, CSRF protected) |
| `/admin/policies/<purl>` | DELETE | Remove policy annotation (admin only, AJAX) |
| `/auth/admin/users` | GET | User management page |
| `/auth/admin/users/create` | GET/POST | Create new user |
| `/auth/admin/users/{username}/toggle-admin` | POST | Toggle admin status |
| `/auth/admin/users/{username}/toggle-active` | POST | Enable/disable user |
| `/auth/admin/users/{username}/reset-password` | POST | Reset user password |
| `/auth/admin/users/{username}/delete` | POST | Delete user |

### LDAP Service (`services/ldap_service.py`)

- Authenticates users against an LDAP directory
- Supports user DN templates, SSL, and group-based authorization
- Uses `ldap3` library for LDAP operations
- Returns `LDAPUser` dataclass with username, DN, email, display_name, groups, is_admin

#### LDAP Group-Based Authorization

When `LDAP_REQUIRE_GROUP_MEMBERSHIP=true`:

- Users must be a member of at least one group in `LDAP_ADMIN_GROUPS` or `LDAP_USER_GROUPS`
- `LDAP_ADMIN_GROUPS`: Comma-separated list of groups that grant admin access
- `LDAP_USER_GROUPS`: Comma-separated list of groups that grant regular user access
- Groups from `memberOf` attribute are parsed to extract CN from full DNs
- `LDAPUser.is_admin` is set based on membership in admin groups
- Legacy: `LDAP_ALLOWED_GROUPS` and `LDAP_REQUIRED_GROUP` still supported for backward compatibility

### Local User Storage Service (`services/user_storage.py`)

- Used when LDAP is disabled (`LDAP_ENABLED=false`)
- Stores users in SQLite database (same database as tokens)
- Password hashing: PBKDF2-SHA256 with 600,000 iterations and random salt
- First user becomes admin automatically (bootstrap)
- Admin features: create users, reset passwords, grant/revoke admin, enable/disable accounts
- Users with `must_change_password=True` are forced to change password on login

### Token Storage Service (`services/token_storage.py`)

- Stores JWT tokens in SQLite database with Fernet encryption
- Token values are hashed (SHA-256) for lookup, encrypted for storage
- Supports token listing, retrieval, revocation, and cleanup
- Uses SQLAlchemy ORM with `StoredToken` model

### TLS Configuration

- TLS is enabled via `TLS_ENABLED=true`
- Certificates are mounted at `/certs` volume
- Gunicorn can use SSL context when TLS is enabled
- JWT cookies are secure (HTTPS-only) when TLS is enabled
- For development: Generate self-signed certificates using openssl:

  ```bash
  openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -sha256 -days 365 -nodes -subj "/CN=localhost"
  ```

### Adding Authentication to Endpoints

Use the `@auth_required` decorator from `routes/auth.py`:

```python
from sbom_graph_api.routes.auth import auth_required

@bp.route("/my-endpoint")
@auth_required
def my_endpoint():
    # Endpoint requires authentication when AUTH_ENABLED=true
    pass
```

### Adding Admin-Only Endpoints

Use the `@admin_required` decorator from `routes/auth.py`:

```python
from sbom_graph_api.routes.auth import admin_required

@bp.route("/admin-only")
@admin_required
def admin_only():
    # Endpoint requires admin privileges
    pass
```

## Development Guidelines

### Documentation Requirements (Mandatory)

**IMPORTANT**: For ALL code changes, the following documentation MUST be updated:

1. **AGENTS.md** - Update this file when:
   - Adding/modifying endpoints, services, or visualizations
   - Adding new requirements or guidelines
   - Changing architecture or patterns
   - Adding troubleshooting information
   - Modifying security practices
   - Any change that affects how AI agents should work with the codebase

2. **README.md** - Update when:
   - Adding/modifying user-facing features or endpoints
   - Changing installation or deployment procedures
   - Modifying configuration options
   - Adding new dependencies

3. **app.py API docs** - Update when:
   - Adding/modifying any endpoint (add interactive forms/links)

This is a mandatory step before completing any task. Failing to update documentation leaves the codebase inconsistent and makes future maintenance harder.

### Code Style Requirements

- All Python code MUST be PEP8 compliant
- Use `ruff check` and `ruff format` to verify and fix style issues
- Maximum line length: 88 characters (ruff default)
- Use type hints for function parameters and return values
- Use docstrings for all public functions and classes

### Adding New Endpoints

1. Create route in appropriate blueprint (`routes/`)
2. Use validation utilities from `utils/validation.py`
3. For POST endpoints that accept JSON bodies, define an inbound JSON Schema in `schemas/inbound.py` and use `validate_json_body()` for request validation
4. Add service methods if needed (`services/falkordb_service.py`)
5. Add visualization/export logic if needed
6. Add output JSON Schema in `schemas/definitions.py` (for report endpoints)
7. Update the index documentation in `app.py`
8. Update `README.md` and `AGENTS.md`

### Adding New Visualizations

1. Create module in `visualizations/`
2. Use PyVis Network for graph rendering
3. Return HTML string from function
4. Support `internal_only` parameter for filtering
5. Validate CSS dimensions using `validate_css_dimension()`
6. Add route in `routes/visualizations.py`
7. Update `README.md` and `AGENTS.md`

### Adding New Reports

1. Add query method to `falkordb_service.py` with `internal_only` support
2. Add JSON Schema in `schemas/definitions.py`
3. Add Excel export function to `exports/excel.py`
4. Add route to `routes/reports.py`
5. Follow existing pattern for HTML/Excel/JSON triple output
6. Use `build_url_with_params()` for consistent URL construction
7. Pass `internal_only=internal_only` to `render_template_string()` for toggle support
8. Add interactive form to API docs in `app.py`
9. Update `README.md` and `AGENTS.md`

### HTML Template Requirements

When creating new report or export endpoints with HTML views:

1. Pass `internal_only` parameter to template for toggle state
2. Use `TABLE_TEMPLATE` or `EXPORT_TEMPLATE` which include the toggle switch
3. Download links (Excel, JSON) must include current filter state
4. Stats should NOT include "Filter" text (toggle shows current state)
5. Test toggle functionality reloads page with correct parameter

### Security Considerations

- Always use parameterized queries for Cypher
- Validate and sanitize all user input using `utils/validation.py`
- Use `validate_project_name()` for any project/version names used in URLs
- Use `url_for()` for generating internal redirect URLs (prevents open redirects)
- Use secrets for sensitive configuration
- Run as non-root in containers
- Apply `# nosec` comments only for intentional security exceptions
- **REQUIRED**: Run Snyk code scan (`snyk_code_scan` via MCP) before completing any task
- **REQUIRED**: Run Bandit scans for additional static analysis
- Run SonaType IQ scans (`scan_dependencies` via MCP) when dependencies change

## Testing

### Running Tests

```bash
uv sync --extra dev
uv run pytest tests/ -v
```

### Test Coverage

```bash
uv run pytest tests/ --cov=src/sbom_graph_api --cov-report=term-missing
```

### Security Testing

```bash
# Bandit static analysis
uv run bandit -r src/ -c pyproject.toml

# Ruff linting
uv run ruff check src/

# Snyk Code SAST (via MCP)
# Use the snyk_code_scan tool from Snyk MCP server
# REQUIRED: Run before declaring any task with significant code changes complete
```

### Snyk Security Scanning (Required)

**IMPORTANT**: Before completing any task that involves significant code changes:

1. Run `snyk_code_scan` via MCP on the `src/` directory
2. Review any security issues found (Medium severity or higher)
3. Fix security issues in newly introduced or modified code
4. Re-scan to verify fixes are effective and no new issues introduced
5. Repeat until no security issues remain

This is a mandatory step for all code changes to ensure security best practices.

### SonaType IQ SCA Scanning

SonaType IQ is used for Software Composition Analysis (SCA) to scan dependencies for known vulnerabilities.

**Via MCP Server:**

```yaml
# Use the scan_dependencies tool from SonaType MCP server
server: user-SonaType
tool: scan_dependencies
arguments:
  project_path: <path to project>
  app_id: "sbom-graph-api"
```

**Important:** The project uses `uv` for dependency management with `uv.lock`. Since Nexus IQ CLI doesn't natively support `uv.lock` format, a `requirements.txt` file must be generated first:

```bash
# Generate requirements.txt from uv.lock for SCA scanning
uv export --no-hashes --no-editable > requirements.txt
```

This is handled automatically in the CI/CD pipeline (Jenkinsfile). The `requirements.txt` is in `.gitignore` since it's generated.

**When to run SonaType scans:**

- When adding or updating dependencies in `pyproject.toml`
- Before major releases
- When investigating vulnerability reports

### Unit Tests

- Use pytest with fixtures
- Mock FalkorDBService for route tests
- Test configuration loading
- Test input validation utilities

### Integration Tests

- Require running FalkorDB instance
- Test actual graph queries

## Deployment

### Local Development

```bash
uv sync
uv run python -m sbom_graph_api.app
```

### Docker Build

Build context must be this subproject directory (or use `build-images.sh sbom-graph-api` from the monorepo root).

```bash
# From sbom-graph-api/
docker build -t sbom-graph-api:latest -f Dockerfile \
  --build-arg "PYTHON_PACKAGE_VERSION=$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)" \
  .
```

### Kubernetes

```bash
helm install sbom-graph-api ./helm/sbom-graph-api -f values-production.yaml
```

## Common Tasks

### Adding a New Report

1. Add query method to `falkordb_service.py` with `internal_only` support
2. Add JSON Schema to `schemas/definitions.py`
3. Add Excel export function to `exports/excel.py`
4. Add route to `routes/reports.py` with format handling
5. Use `build_url_with_params()` for download links
6. Follow existing pattern for HTML/Excel/JSON dual output

### Modifying Graph Visualizations

1. Visualization modules use PyVis options for layout
2. Colors are defined in `PARTITION_COLORS` constant
3. Tooltips are generated from node properties
4. Always validate CSS dimensions from user input

### Updating Configuration

1. Add new environment variable to `config.py`
2. Update Helm chart `values.yaml` and `deployment.yaml`
3. Document in `README.md`

## Available Endpoints

### Visualizations

- `/visualizations/kpartite/{project}/{version}` - K-partite dependency graph (hierarchical)
- `/visualizations/kpartite/purl/<path:purl>` - Same, using Package URL
- `/visualizations/bipartite/{project}` - Bi-partite version/dependant graph
- `/visualizations/bipartite/purl/<path:purl>` - Same, using purl
- `/visualizations/dependants/{project}/{version}` - Full dependants graph (hierarchical)
- `/visualizations/dependants/purl/<path:purl>` - Same, using purl
- `/visualizations/dependencies/{project}/{version}` - Dependencies with multiple layouts and cycle detection
- `/visualizations/dependencies/purl/<path:purl>` - Same, using purl
- `/visualizations/dependants-multi/{project}/{version}` - Dependants with multiple layouts and cycle detection
- `/visualizations/dependants-multi/purl/<path:purl>` - Same, using purl

#### Multi-Layout Visualizations

The `/visualizations/dependencies` and `/visualizations/dependants-multi` endpoints support multiple layout types via the `layout` query parameter:

- `spring` - Force-directed (ForceAtlas2) - best for cyclic graphs (default for dependencies)
- `radial` - Radial tree with concentric circles (default for dependants-multi)
- `shell` - Nodes grouped in shells by depth
- `bfs` - BFS tree (hierarchical) - traditional dependency tree
- `circular` - Nodes arranged in a circle

These visualizations include an interactive layout switcher UI, allowing users to change layouts without reloading.

### Reports

- `/reports/projects` - All projects with versions
- `/reports/applications` - All applications with versions (supports `latest_only` parameter)
- `/reports/vulnerabilities` - All vulnerabilities ordered by severity with affected versions
- `/reports/vulnerability-dependants/{defect_id}` - Dependants affected by a specific vulnerability, ordered by partition
- `/reports/incident-response/{defect_id}` - Incident response page with blast radius graph and patch plan table
- `/reports/centrality` - Centrality metrics (inDegree/outDegree) for internal libraries with drill-down links
- `/reports/snapshots` - SNAPSHOT dependencies
- `/reports/self-dependencies` - Self-referential dependencies
- `/reports/multi-version-deps/{project}` - Library version adoption (who uses what version)
- `/reports/multi-version-sources/{project}/{version}` - Diamond dependency conflicts
- `/reports/non-semver-versions` - Non-SemVer versions
- `/reports/version-dependencies/{project}/{version}` - Transitive dependencies (what a version depends on at all depths, supports 'latest')
- `/reports/version-dependencies/purl/<path:purl>` - Same, using purl
- `/reports/dependants/{project}/{version}` - Dependants with partitions and paths (longest_only=true by default for vulnerability prioritization)
- `/reports/dependants/purl/<path:purl>` - Same, using purl
- `/reports/multi-version-deps/purl/<path:purl>` - Library version adoption, using purl
- `/reports/multi-version-sources/purl/<path:purl>` - Diamond dependency conflicts, using purl
- `/reports/trust-scores` - Trust score report
- `/reports/trust-score-gaps` - Trust score gaps (low confidence)
- `/reports/trust-score-heatmap` - Trust score heatmap by category
- `/reports/risk-propagation-graph` - Risk propagation network (vis.js)
- `/reports/application-risk-dashboard` - Per-application supply-chain risk
- `/reports/risk-path-explorer/<path:purl>` - Dependency risk path explorer
- `/reports/risk-outliers` - Low-score, high-fan-in packages
- `/reports/whatif-simulator` - What-if risk propagation simulator

#### Centrality Report

The `/reports/centrality` endpoint shows inDegree and outDegree for all internal libraries:

- **inDegree**: Number of projects that depend on this library (popularity/importance)
- **outDegree**: Number of dependencies this library has (complexity/risk)
- Sortable by inDegree, outDegree, project_name, or version_name
- Each row has drill-down links:
  - inDegree links to dependants-multi visualization (radial layout)
  - outDegree has two links: internal-only dependencies and all dependencies

### Programmatic API v1 (JWT required)

All return JSON envelope `{data, pagination?, meta}`:

**Package metadata:**
- `GET /api/v1/package/<path:purl>` - Comprehensive package metadata (vulns, licenses, trust score, policy, VEX)
- `GET /api/v1/package/<path:purl>/vulns` - Vulnerabilities (optional `include_dependencies`)
- `GET /api/v1/package/<path:purl>/licenses` - Licenses
- `GET /api/v1/package/<path:purl>/vex` - VEX statements
- `GET /api/v1/package/<path:purl>/dependencies` - Paginated dependency tree (max_depth, offset, limit)
- `GET /api/v1/package/<path:purl>/dependants` - Paginated reverse dependency tree (max_depth, offset, limit)
- `GET /api/v1/package/<path:purl>/policy` - Policy check for CI/CD gate

**Trust score:**
- `GET /api/v1/package/<path:purl>/trust-score` - Trust score breakdown
- `GET /api/v1/package/<path:purl>/trust-score/risk-path` - Risk propagation path
- `GET /api/v1/package/<path:purl>/trust-check` - CI/CD gate: pass/fail against min effective score and confidence
- `GET /api/v1/application/<path:purl>/supply-chain-risk` - Application supply-chain risk summary

**Analysis:**
- `GET /api/v1/analysis/critical-dependencies` - Critical dependencies sorted by fan_in or trust_score
- `GET /api/v1/analysis/risk-summary` - Aggregate risk metrics (vuln counts by severity, license risk, policy violations)
- `GET /api/v1/analysis/trust-score-distribution` - Trust score histogram
- `GET /api/v1/analysis/remediation-priorities` - Packages ranked by remediation leverage
- `GET /api/v1/analysis/risk-propagation-impact` - What-if simulation for score change propagation

**Source repository:**
- `GET /api/v1/source/packages` - Packages from a source repository URL
- `GET /api/v1/source/vulnerabilities` - Vulnerabilities from a source repository URL

**Incident response:**
- `GET /api/v1/blast-radius/<path:purl>` - Blast radius for compromised package
- `GET /api/v1/patch-plan/<path:defect_id>` - Patch plan for a vulnerability
- `GET /api/v1/sbom/<record_id>` - SBOM record metadata

**POST endpoints (JSON Schema validated):**
- `POST /api/v1/enrich/vulnerabilities` - Trigger enrichment (`enrichment-request` schema)
- `POST /api/v1/policy/annotate` - Create policy annotation (`policy-annotation` schema)
- `DELETE /api/v1/policy/annotate/<id>` - Delete policy annotation
- `POST /api/v1/contacts` - Create point of contact (`contact-create` schema)
- `POST /api/v1/patch-plan/evaluate` - Evaluate patch plan (`patch-plan-evaluate` schema)
- `POST /api/v1/vex/auto-stub` - Auto-generate VEX stubs (`vex-auto-stub` schema)

**Specification:**
- `GET /api/v1/openapi.json` - OpenAPI 3.1 specification

### Exports (Deprecated)

- `/exports/dependencies/{project}` - Redirects to `/reports/version-dependencies/{project}`

### JSON Schemas

- `/schemas/` - List all available schemas
- `/schemas/{schema_name}` - Get specific schema

## Troubleshooting

### Gunicorn Worker Timeout Issues

- **WORKER TIMEOUT errors**: Usually caused by expensive graph operations
  - Use `gthread` worker class (not sync) for better concurrency
  - Increase `--timeout` to 300+ seconds for deep graph queries
  - Ensure cycle removal uses DFS-based algorithm (not `nx.simple_cycles()`)
- **"Error handling request (no URI read)"**: Worker died before reading request
  - Often caused by memory exhaustion or signal kills
  - Check container memory limits (need ~300MB per worker)
  - Use `--max-requests 1000` to recycle workers periodically
- **Timeouts with no active requests**: Usually health check related
  - Check Kubernetes probe `timeoutSeconds` settings
  - Use `--keep-alive 5` to handle load balancer connections

### FalkorDB Connection Issues

- Check `FALKORDB_HOST` and `FALKORDB_PORT` environment variables
- Verify network connectivity to FalkorDB
- Check `/ready` endpoint for connection status

### Visualization Not Rendering

- PyVis requires complete HTML output
- Check browser console for JavaScript errors
- Verify nodes and edges are being returned from queries

### Excel Generation Errors

- Ensure openpyxl is installed
- Check for None values in data
- Verify pandas DataFrame creation

### JSON Schema Validation Errors

- Schemas use Draft-07 standard
- **Output schemas**: Check `report_type` or `export_type` const values; verify required fields are present in response
- **Inbound schemas**: All POST endpoints validate request bodies against JSON Schema before processing; validation errors return 400 with a list of human-readable error messages; schemas are defined in `schemas/inbound.py`

### Dependants Report - Partition and Paths

- **Partition**: The LONGEST path (number of edges) from target to a dependant, calculated using proper DAG longest-path algorithm
- **Max Path Edges**: Number of edges in the longest path from that dependant back to the target (should match partition)
- **longest_only Parameter**: Default `true` - shows only longest paths (best for vulnerability prioritization). Set to `false` to see up to 50 alternative paths per dependant.
- **Path Ordering**: Paths are sorted by length descending (longest paths first)
- **Path Cutoff**: Uses `partition + 2` as cutoff since partition IS the longest path length
- **Default Max Depth**: 50 levels (configurable via `max_depth` query parameter)
- The graph is treated as a DAG; cycles are removed before computation
- **Partition Algorithm**: Uses BFS-ordered dynamic programming for correct longest path calculation

### Graph Cycles

- Cycles in the dependency graph can cause infinite loops during traversal
- **IMPORTANT**: Do NOT use `nx.simple_cycles()` - it has exponential complexity and causes Gunicorn worker timeouts on large graphs
- Instead, use DFS-based back-edge removal which is O(V+E)
- Both visualizations and reports use `remove_cycles_dfs()` helper function
- Cycle edges are removed before partition calculation and path finding
- Use `/reports/self-dependencies` to identify self-referential dependencies
- Use `find_cycles()` and `find_direct_cycles()` service methods for cycle analysis (use sparingly on large graphs)

## Demo Data (ACME Corp Graph)

A demonstration graph `acme_corp` is available via `scripts/populate_acme_corp.py` for testing and demos.

### Graph Configuration for ACME Corp

```bash
export FALKORDB_GRAPH_NAME=acme_corp
export FALKORDB_INTERNAL_LABEL=INTERNAL
```

### Understanding Multi-Version Reports

Two different reports for analyzing library versions:

| Report | Endpoint | Use Case |
| ------ | -------- | -------- |
| **Multi-Version Deps** | `/reports/multi-version-deps/{library}` | "Who uses what version across the org?" |
| **Multi-Version Sources** | `/reports/multi-version-sources/{project}/{version}` | "Does this project have diamond dependency conflicts?" |

### Multi-Version Dependencies Demo (Library Adoption)

Shows all versions of a library and which projects use each version.

**Demo Libraries:**

| Library | Demo URL |
| ------- | -------- |
| `jackson-databind` | `/reports/multi-version-deps/jackson-databind` |
| `slf4j-api` | `/reports/multi-version-deps/slf4j-api` |
| `guava` | `/reports/multi-version-deps/guava` |

### Multi-Version Sources Demo Libraries (Diamond Dependencies)

Shows version conflicts within a specific project's dependency tree:

| Library:Version | Conflict On | Demo URL |
| --------------- | ----------- | -------- |
| `acme-kafka:2.0.0` | `acme-events` | `/reports/multi-version-sources/acme-kafka/2.0.0` |
| `acme-data-pipeline:2.0.0` | `acme-connection-pool` | `/reports/multi-version-sources/acme-data-pipeline/2.0.0` |
| `acme-web-common:2.0.0` | `acme-logging` | `/reports/multi-version-sources/acme-web-common/2.0.0` |

**Diamond paths in acme-kafka:2.0.0:**

- `acme-kafka -> acme-serialization 2.0.0 -> acme-events 1.1.0` (pinned for stability)
- `acme-kafka -> acme-schema-registry 2.0.0 -> acme-events 2.0.0` (uses latest)

### Cyclic Dependencies Demo (Self-Referential Libraries)

The graph includes self-referential libraries that create simple cycles:

| Library | Cycle Type |
| ------- | ---------- |
| `acme-plugin-loader:1.0.0` | Depends on itself |
| `acme-plugin-loader:1.1.0` | Depends on itself |
| `acme-module-registry:1.0.0` | Depends on itself |

**Demo Applications:**

| Application | Cycles | Visualization URL |
| ----------- | ------ | ----------------- |
| `extensible-platform:1.0.0` | Both (best demo) | `/visualizations/dependencies/extensible-platform/1.0.0` |
| `plugin-manager:1.0.0` | `acme-plugin-loader` | `/visualizations/dependencies/plugin-manager/1.0.0` |
| `module-loader:1.0.0` | `acme-module-registry` | `/visualizations/dependencies/module-loader/1.0.0` |

**Visualization Features:**

- Multiple layouts available (spring, radial, shell, bfs, circular)
- Interactive layout switcher UI in top-right corner
- Cycle edges highlighted in red with dashed lines
- Nodes in cycles have thick red borders
- Interactive: pan, zoom, drag nodes

**Self-Dependencies Report:**

```Plaintext
/reports/self-dependencies
```

### Other Special Cases in ACME Corp Graph

- **SNAPSHOT versions**: Apps and libraries with `-SNAPSHOT` suffixes
- **Non-semver versions**: Calendar-based, prefix-based, build-based versions
- **Release using SNAPSHOTs**: `quick-prototype`, `demo-app` (bad practice demos)
