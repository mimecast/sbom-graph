# SBOM Graph API

A Flask application for visualizing graph data structures from FalkorDB, providing insights into dependency relationships, SNAPSHOT dependencies, and self-dependency detection.

## Features

- **K-Partite Dependency Visualization**: Hierarchical visualization of transitive dependencies with color-coded partition levels
- **Bi-Partite Graph**: Shows project versions and their direct dependants in a two-column layout
- **Dependants Graph**: Full reverse dependency tree from a library back to leaf applications
- **Excel Exports**: Download dependency data as Excel spreadsheets
- **JSON Exports**: Download dependency data as JSON with documented schemas
- **Reports**: HTML tables, Excel exports, and JSON exports for:
  - All projects with versions
  - SNAPSHOT dependencies
  - Self-dependency detection
  - Multi-version dependency source tracking
  - Non-SemVer version detection
  - Transitive dependencies (what a version depends on)
  - Dependants with partition levels and paths
- **Interactive UI Features**:
  - Internal Only Toggle: Filter views between all projects and INTERNAL-labeled only
  - Dynamic download links that respect current filter state
  - Interactive API documentation with forms to test all endpoints
  - Frozen table headers: Headers stay visible while scrolling through data

## Quick Start

### Prerequisites

- Python 3.14+
- [uv](https://github.com/astral-sh/uv) package manager
- FalkorDB instance (default: localhost:6379)

### Local Development

1. Install dependencies:

```bash
uv sync
```

2. Set environment variables (optional, defaults shown):

```bash
export FALKORDB_HOST=localhost
export FALKORDB_PORT=6379
export FALKORDB_GRAPH_NAME=acme_corp
export FLASK_DEBUG=true
```

3. Run the development server:

```bash
# Single-threaded Flask dev server (requires ~512MB, development only)
uv run python -m sbom_graph_api.app
```

Or with gunicorn (production-like, see Memory Configuration section):

```bash
# Light development (2 workers, requires ~1GB available memory)
uv run gunicorn \
  --bind 0.0.0.0:8080 \
  --workers 2 \
  --threads 2 \
  --worker-class gthread \
  --timeout 300 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  sbom_graph_api.wsgi:app

# Production-like (4 workers, requires ~2GB available memory for 1GB FalkorDB)
uv run gunicorn \
  --bind 0.0.0.0:8080 \
  --workers 4 \
  --threads 2 \
  --worker-class gthread \
  --timeout 300 \
  --graceful-timeout 30 \
  --keep-alive 5 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  sbom_graph_api.wsgi:app
```

> **Note**: Local development uses system-available memory. Memory limits are only
> enforced in containerized environments (Docker `--memory`, Kubernetes `resources.limits`).
> Ensure your development machine has sufficient RAM for the worker configuration.

4. Access the API at http://localhost:8080

The root endpoint (`/`) provides interactive API documentation with:
- Clickable links for endpoints without required parameters
- Forms to test endpoints with path parameters and query options
- Complete parameter reference table

## Memory Configuration

### Gunicorn Memory Requirements

For graph visualizations with FalkorDB, memory requirements depend on:
- **Base worker memory**: ~100MB per worker (Python + Flask)
- **Visualization processing**: ~100-200MB per heavy request (up to 50K nodes)
- **Peak per worker**: ~300MB under heavy load

### Memory Sizing Formula

```
Recommended Memory = (workers × 300MB) + 200MB overhead
```

| Workers | Minimum Memory | Recommended Memory | Use Case |
|---------|----------------|-------------------|----------|
| 1 | 400MB | 512Mi | Development only |
| 2 | 700MB | 1Gi | Light production |
| 4 | 1.4GB | 2Gi | Normal production (1GB FalkorDB) |
| 6 | 2GB | 3Gi | Heavy use / larger FalkorDB |

### Scaling for FalkorDB Size

For FalkorDB databases larger than 1GB, increase memory proportionally:
- **1GB FalkorDB**: 2Gi with 4 workers (default)
- **2GB FalkorDB**: 3Gi with 4-6 workers
- **5GB+ FalkorDB**: 4Gi+ with 6+ workers

### Gunicorn Command-Line Options

```bash
gunicorn \
  --bind 0.0.0.0:8080 \        # Bind address
  --workers 4 \                 # Number of worker processes
  --threads 2 \                 # Threads per worker
  --worker-class gthread \      # Threaded worker (better for graph ops)
  --timeout 300 \               # Request timeout (5 min for deep graphs)
  --graceful-timeout 30 \       # Shutdown grace period
  --keep-alive 5 \              # Keep connections alive
  --max-requests 1000 \         # Recycle workers (prevents memory leaks)
  --max-requests-jitter 50 \    # Randomize recycling
  sbom_graph_api.wsgi:app
```

## API Endpoints

### Visualization Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /visualizations/kpartite/{project_name}/{version}` | K-partite visualization of transitive dependencies |
| `GET /visualizations/kpartite/purl/<path:purl>` | Same as above, using Package URL (purl) instead of project/version |
| `GET /visualizations/bipartite/{project_name}` | Bi-partite graph of project versions and dependants |
| `GET /visualizations/bipartite/purl/<path:purl>` | Same as above, using purl |
| `GET /visualizations/dependants/{project_name}/{version}` | Full dependants graph to leaf nodes (hierarchical layout) |
| `GET /visualizations/dependants/purl/<path:purl>` | Same as above, using purl |
| `GET /visualizations/dependencies/{project_name}/{version}` | Dependencies graph with cycle detection and multiple layouts |
| `GET /visualizations/dependencies/purl/<path:purl>` | Same as above, using purl |
| `GET /visualizations/dependants-multi/{project_name}/{version}` | Dependants graph with cycle detection and multiple layouts |
| `GET /visualizations/dependants-multi/purl/<path:purl>` | Same as above, using purl |

#### Query Parameters for Visualizations

| Parameter | Description | Default |
|-----------|-------------|---------|
| `layout` | Layout algorithm: `spring`, `radial`, `shell`, `bfs`, `circular` | `spring` (dependencies) or `radial` (dependants-multi) |
| `max_depth` | Maximum depth to traverse (1-100) | unlimited |
| `internal_only` | Set to `true` to show only INTERNAL-labeled nodes | `false` |
| `project_group` | For project_name disambiguation when multiple versions share the same name (e.g., `com.acme`) | (none) |
| `height` | Visualization height (validated CSS dimension) | `100vh` |
| `width` | Visualization width (validated CSS dimension) | `100vw` |

#### Available Layout Types

| Layout | Description | Best For |
|--------|-------------|----------|
| `spring` | Force-directed (ForceAtlas2) | Cyclic graphs, exploratory analysis |
| `radial` | Radial tree with concentric circles | Dependants visualization, hierarchies |
| `shell` | Nodes grouped in shells by depth | Clear depth visualization |
| `bfs` | BFS tree (hierarchical) | Traditional dependency trees |
| `circular` | Nodes arranged in a circle | Overview of connectivity |

All multi-layout visualizations include an interactive layout switcher in the top-right corner, allowing users to switch layouts without reloading the page. Cycle edges are highlighted in red with dashed lines, and nodes involved in cycles have red borders.

#### Visualization vs Report Filtering

**Visualizations** skip scan_id filtering to show the complete structural graph. This means:
- All nodes that have a dependency relationship are shown
- Useful for understanding the full dependency structure

**Reports** use scan_id filtering to ensure dependants are actually using the specific version through a common application scan path. This provides more accurate results for analysis but may show fewer relationships than the visualization.

### Export Endpoints (Deprecated)

The export endpoints are deprecated and redirect to the new report endpoints:

| Endpoint | Redirects To |
|----------|--------------|
| `GET /exports/dependencies/{project_name}` | `/reports/version-dependencies/{project_name}` |

### Report Endpoints

All report endpoints support multiple output formats via the `format` query parameter:
- `html` (default): Interactive HTML table with download links
- `excel`: Download as Excel spreadsheet
- `json`: Download as JSON with schema-compliant structure

| Endpoint | Description |
|----------|-------------|
| `GET /reports/projects` | Table view of all projects with versions |
| `GET /reports/applications` | Table view of all applications with versions |
| `GET /reports/vulnerabilities` | All vulnerabilities ordered by severity |
| `GET /reports/vulnerability-dependants/{defect_id}` | Dependants affected by a vulnerability |
| `GET /reports/centrality` | Centrality metrics (inDegree/outDegree) for internal libraries |
| `GET /reports/snapshots` | Applications with SNAPSHOT dependencies |
| `GET /reports/self-dependencies` | Nodes that depend on themselves |
| `GET /reports/multi-version-deps/{project_name}` | All versions of a library and who uses each (version adoption) |
| `GET /reports/multi-version-sources/{project_name}/{version}` | Version conflicts within a project's dependency tree (diamond deps) |
| `GET /reports/non-semver-versions` | Versions not following SemVer naming convention |
| `GET /reports/version-dependencies/{project_name}/{version}` | Transitive dependencies for a version (what it depends on at all depths) |
| `GET /reports/version-dependencies/purl/<path:purl>` | Same as above, using purl |
| `GET /reports/dependants/{project_name}/{version}` | Dependants with partition levels and dependency paths |
| `GET /reports/dependants/purl/<path:purl>` | Same as above, using purl |
| `GET /reports/multi-version-deps/purl/<path:purl>` | Library version adoption, using purl |
| `GET /reports/multi-version-sources/purl/<path:purl>` | Diamond dependency conflicts, using purl |

#### Special Version Values

For `/reports/version-dependencies/{project_name}/{version}`:
- Use `latest` to get the highest SemVer version automatically
- **Note**: `latest` only works if ALL versions of the project follow SemVer naming convention
- If any version fails SemVer validation, a 400 error is returned with the non-compliant versions

#### Query Parameters for Reports

| Parameter | Description | Default |
|-----------|-------------|---------|
| `format` | Output format - `html`, `excel`, or `json` | `html` |
| `limit` | Maximum number of results (for `/reports/projects` and `/reports/applications`) | `10000` |
| `internal_only` | Set to `true` for internal-labeled nodes only | `false` |
| `project_group` | For project_name disambiguation when multiple versions share the same name (e.g., `com.acme`) | (none) |
| `latest_only` | For `/reports/applications`: show only the latest version per application | `false` |
| `max_depth` | Maximum traversal depth (for multi-version and dependants reports) | `50` |
| `longest_only` | For dependants report: show only longest paths (for vulnerability prioritization) | `true` |

### JSON Schema Endpoints

All JSON outputs conform to documented JSON Schema specifications. Schemas are available at:

| Endpoint | Description |
|----------|-------------|
| `GET /schemas/` | List all available JSON schemas |
| `GET /schemas/{schema_name}` | Get a specific JSON schema |

#### Available Schemas

| Schema Name | Description | Report Endpoint |
|-------------|-------------|-----------------|
| `projects` | All projects with versions | `/reports/projects` |
| `applications` | All applications with versions | `/reports/applications` |
| `vulnerabilities` | All vulnerabilities with affected versions | `/reports/vulnerabilities` |
| `vulnerability-dependants` | Dependants affected by a vulnerability | `/reports/vulnerability-dependants/{defect_id}` |
| `snapshots` | SNAPSHOT dependencies | `/reports/snapshots` |
| `self-dependencies` | Self-referencing nodes | `/reports/self-dependencies` |
| `multi-version-deps` | Library version adoption | `/reports/multi-version-deps/{project}` |
| `multi-version-sources` | Diamond dependency analysis | `/reports/multi-version-sources/{project}/{version}` |
| `non-semver-versions` | Non-SemVer version detection | `/reports/non-semver-versions` |
| `version-dependencies` | Version dependency export | `/exports/dependencies/{project}` |
| `dependants` | Dependants with partitions and paths | `/reports/dependants/{project}/{version}` |

#### Example: Fetching JSON with Schema Validation

```bash
# Get the JSON schema
curl http://localhost:8080/schemas/projects > projects.schema.json

# Get the report data in JSON format
curl "http://localhost:8080/reports/projects?format=json" > projects.json

# Validate using a JSON Schema validator (e.g., ajv-cli)
npx ajv validate -s projects.schema.json -d projects.json
```

### SBOM Ingestion Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /ingest/cyclonedx` | Upload and process a CycloneDX SBOM |

#### POST /ingest/cyclonedx

Accepts a CycloneDX SBOM as a JSON body and persists the parsed projects,
dependencies, and defects to the graph database via the `sbom-graph-model`
library. Requires JWT authentication.

**Request** (`Content-Type: application/json`):

```json
{
  "sbom": { "bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": { "..." }, "..." },
  "app_id": "optional-custom-app-id",
  "public_app_id": "optional-public-identifier",
  "project_url": "https://github.com/org/repo"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `sbom` | Yes | A complete CycloneDX JSON document |
| `app_id` | No | Custom application ID. Defaults to SHA-1 of `metadata.component.name` |
| `public_app_id` | No | Public application identifier. Defaults to `metadata.component.name` |
| `project_url` | No | URL of the source repository |

**Response** (`201 Created`):

```json
{
  "status": "ok",
  "app_id": "a1b2c3...",
  "public_app_id": "my-application",
  "projects_count": 42,
  "dependencies_count": 87,
  "defects_count": 3
}
```

**Error Responses**:

| Status | Condition |
|--------|-----------|
| `400` | Missing or invalid request body, missing `sbom` field |
| `415` | Content-Type is not `application/json` |
| `422` | CycloneDX structural validation failed |
| `500` | Unexpected processing error |

**Example**:

```bash
curl -X POST http://localhost:8080/ingest/cyclonedx \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt-token>" \
  -d '{"sbom": <cyclonedx-json>}'
```

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness probe |
| `GET /ready` | Readiness probe (checks FalkorDB connectivity) |

## Configuration

The application is configured via environment variables:

### Flask Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_HOST` | Host to bind to | `0.0.0.0` |
| `FLASK_PORT` | Port to listen on | `8080` |
| `FLASK_DEBUG` | Enable debug mode | `false` |
| `FLASK_SECRET_KEY` | Secret key for sessions | `dev-secret-key-change-in-production` |

### FalkorDB Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `FALKORDB_HOST` | FalkorDB hostname | `localhost` |
| `FALKORDB_PORT` | FalkorDB port | `6379` |
| `FALKORDB_PASSWORD` | FalkorDB password | (none) |
| `FALKORDB_GRAPH_NAME` | Graph name to query | `acme_corp` |
| `FALKORDB_SOCKET_TIMEOUT` | Socket read/write timeout (seconds) | `30.0` |
| `FALKORDB_CONNECT_TIMEOUT` | Connection establishment timeout (seconds) | `10.0` |
| `FALKORDB_INTERNAL_LABEL` | Node label for internal projects (used by internal_only filter) | `INTERNAL` |

### TLS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TLS_ENABLED` | Enable TLS/SSL | `false` |
| `TLS_CERT_FILE` | Path to TLS certificate file | (none) |
| `TLS_KEY_FILE` | Path to TLS private key file | (none) |
| `TLS_CA_FILE` | Path to CA certificate file (optional) | (none) |

See [TLS Setup](#tls-setup) for detailed configuration instructions.

### Authentication Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_ENABLED` | Enable authentication requirement | `false` |
| `JWT_SECRET_KEY` | Secret key for JWT token signing | `jwt-secret-key-change-in-production` |
| `JWT_ACCESS_TOKEN_EXPIRES_HOURS` | Access token validity (hours) | `1` |
| `JWT_REFRESH_TOKEN_EXPIRES_DAYS` | Refresh token validity (days) | `30` |
| `JWT_ALGORITHM` | JWT signing algorithm | `HS256` |
| `JWT_TOKEN_LOCATION` | Where to look for tokens (comma-separated) | `headers,cookies` |

### LDAP Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `LDAP_ENABLED` | Enable LDAP authentication | `false` |
| `LDAP_SERVER` | LDAP server hostname | `localhost` |
| `LDAP_PORT` | LDAP server port | `389` |
| `LDAP_USE_SSL` | Use SSL for LDAP connection | `false` |
| `LDAP_BASE_DN` | Base DN for LDAP searches | `dc=example,dc=com` |
| `LDAP_USER_DN_TEMPLATE` | Template for user DN (use `{username}`) | `uid={username},ou=users,dc=example,dc=com` |
| `LDAP_BIND_DN` | DN for LDAP bind (for searches) | (none) |
| `LDAP_BIND_PASSWORD` | Password for LDAP bind | (none) |
| `LDAP_SEARCH_FILTER` | LDAP search filter (use `{username}`) | `(uid={username})` |
| `LDAP_GROUP_SEARCH_BASE` | Base DN for group searches (required for group auth) | (none) |
| `LDAP_ADMIN_GROUPS` | Comma-separated list of groups that grant admin access | (none) |
| `LDAP_USER_GROUPS` | Comma-separated list of groups that grant regular user access | (none) |
| `LDAP_ALLOWED_GROUPS` | Legacy: combined allowed groups (use admin/user groups instead) | (none) |
| `LDAP_REQUIRED_GROUP` | Legacy: single required group (deprecated) | (none) |
| `LDAP_REQUIRE_GROUP_MEMBERSHIP` | Set to `true` to enforce group membership checks | `false` |

#### LDAP Group-Based Authorization

To restrict access and grant admin privileges based on LDAP group membership:

1. Set `LDAP_GROUP_SEARCH_BASE` to the DN where groups are located
2. Set `LDAP_REQUIRE_GROUP_MEMBERSHIP=true` to enable group checks
3. Configure admin and user groups:
   - `LDAP_ADMIN_GROUPS`: Users in these groups get admin privileges
   - `LDAP_USER_GROUPS`: Users in these groups get regular access
   - Users must be in at least one of the configured groups to log in

Example configuration:
```bash
export LDAP_ENABLED=true
export LDAP_SERVER=ldap.example.com
export LDAP_BASE_DN="dc=example,dc=com"
export LDAP_USER_DN_TEMPLATE="uid={username},ou=users,dc=example,dc=com"
export LDAP_GROUP_SEARCH_BASE="ou=groups,dc=example,dc=com"
export LDAP_REQUIRE_GROUP_MEMBERSHIP=true
export LDAP_ADMIN_GROUPS="appsec-admins,security-leads"
export LDAP_USER_GROUPS="appsec-users,developers,security-team"
```

**Group matching:**
- Groups can be specified as CN names (e.g., `appsec-admins`)
- Full DNs in `memberOf` attributes are automatically parsed to extract the CN
- Users in admin groups automatically get admin privileges in the application
- Users must be in at least one admin or user group to log in

### Token Storage Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TOKEN_DB_PATH` | Path to SQLite token database | `/data/tokens.db` |
| `TOKEN_DB_ENCRYPTION_KEY` | Encryption key for token storage | `db-encryption-key-change-in-production` |

## Authentication

When `AUTH_ENABLED=true`, all endpoints (except `/health` and `/ready`) require authentication.

### Authentication Methods

1. **LDAP Authentication** (when `LDAP_ENABLED=true`): Users log in via `/auth/login` with LDAP credentials
2. **Local Authentication** (when `LDAP_ENABLED=false`): Users are stored in the local SQLite database
3. **JWT Token (API)**: API clients use JWT tokens in the `Authorization: Bearer <token>` header

### Local Authentication

When LDAP is disabled, the application uses local user storage:

- **First User Bootstrap**: The first user to log in automatically becomes an admin
- **Temporary Passwords**: New users receive a temporary password and must change it on first login
- **Password Hashing**: Passwords are hashed using PBKDF2-SHA256 with 600,000 iterations

### Authentication Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /auth/login` | Login page |
| `POST /auth/login` | Authenticate with username/password |
| `GET /auth/logout` | Clear session and cookies |
| `POST /auth/refresh` | Refresh access token |
| `GET /auth/change-password` | Password change page (local auth only) |
| `GET /auth/tokens` | List user's API tokens |
| `GET /auth/tokens/create` | Create new API token page |
| `POST /auth/tokens/create` | Create new API token |
| `GET /auth/tokens/{id}` | Get token details |
| `POST /auth/tokens/{id}/revoke` | Revoke a token |
| `GET /auth/status` | Check authentication status |

### Admin Endpoints (Local Auth Only)

| Endpoint | Description |
|----------|-------------|
| `GET /auth/admin/users` | User management page |
| `GET /auth/admin/users/create` | Create new user form |
| `POST /auth/admin/users/create` | Create new user |
| `POST /auth/admin/users/{username}/toggle-admin` | Grant/revoke admin status |
| `POST /auth/admin/users/{username}/toggle-active` | Enable/disable account |
| `POST /auth/admin/users/{username}/reset-password` | Reset user password |
| `POST /auth/admin/users/{username}/delete` | Delete user account |

### Creating API Tokens

1. Log in at `/auth/login`
2. Navigate to `/auth/tokens/create`
3. Enter a token name and optional expiration
4. Copy the generated token (it will only be shown once)
5. Use the token in API requests: `Authorization: Bearer <token>`

## Docker

### Build

The Dockerfile must be built from the **repository root** because it references
paths relative to the monorepo. Use the build script provided in the repo root:

```bash
# From the repository root (sbom-graph/)
./build-images.sh sbom-graph-api

# Or with a custom tag
./build-images.sh --adv-tag myrepo/sbom-graph-api:v1

# Or directly with docker build
docker build -t sbom-graph-api:latest -f sbom-graph-api/Dockerfile .
```

### Run

```bash
# Basic run (uses default 4 workers, requires ~2GB memory)
docker run -p 8080:8080 \
  --memory=2g \
  --memory-swap=2g \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_PORT=6379 \
  sbom-graph-api:latest
```

### Run with Authentication Enabled

```bash
docker run -p 8080:8080 \
  --memory=2g \
  -v appsec-data-volume:/data \
  -e FALKORDB_HOST=host.docker.internal \
  -e AUTH_ENABLED=true \
  -e LDAP_ENABLED=true \
  -e LDAP_SERVER=ldap.example.com \
  -e LDAP_BASE_DN=dc=example,dc=com \
  -e JWT_SECRET_KEY=your-secure-jwt-secret \
  -e TOKEN_DB_ENCRYPTION_KEY=your-secure-db-encryption-key \
  sbom-graph-api:latest
```

### Run with TLS

```bash
docker run -p 8443:8443 \
  --memory=2g \
  -v /path/to/certs:/certs:ro \
  -v appsec-data-volume:/data \
  -e TLS_ENABLED=true \
  -e TLS_CERT_FILE=/certs/server.crt \
  -e TLS_KEY_FILE=/certs/server.key \
  -e FALKORDB_HOST=host.docker.internal \
  sbom-graph-api:latest

```

### Run with Custom Worker Configuration

```bash
# Light configuration (2 workers, 1GB memory)
docker run -p 8080:8080 \
  --memory=1g \
  --memory-swap=1g \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_PORT=6379 \
  sbom-graph-api:latest \
  --bind 0.0.0.0:8080 --workers 2 --threads 2 --worker-class gthread \
  --timeout 300 --max-requests 1000 --max-requests-jitter 50 sbom_graph_api.wsgi:app

# Heavy configuration (6 workers, 3GB memory)
docker run -p 8080:8080 \
  --memory=3g \
  --memory-swap=3g \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_PORT=6379 \
  sbom-graph-api:latest \
  --bind 0.0.0.0:8080 --workers 6 --threads 2 --worker-class gthread \
  --timeout 300 --max-requests 1000 --max-requests-jitter 50 sbom_graph_api.wsgi:app
```

### Docker Volumes

| Volume | Purpose |
|--------|---------|
| `/data` | Persistent token storage database |
| `/certs` | TLS certificates (optional) |

## TLS Setup

### Development (Self-Signed Certificates)

For local development, generate self-signed certificates using OpenSSL:

```bash
# Create certs directory
mkdir -p certs

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -sha256 -days 365 -nodes \
  -subj "/C=GB/ST=London/L=London/O=Development/OU=AppSec/CN=localhost"

# Copy cert as CA cert (for self-signed)
cp certs/server.crt certs/ca.crt
```

This creates:
- `certs/server.key` - Private key (keep secure, never commit to git)
- `certs/server.crt` - Public certificate
- `certs/ca.crt` - CA certificate (same as server cert for self-signed)

### Running with TLS in Development (Gunicorn)

Set the environment variables and run:

```bash
# Set TLS environment variables
export TLS_ENABLED=true
export TLS_CERT_FILE="$(pwd)/certs/server.crt"
export TLS_KEY_FILE="$(pwd)/certs/server.key"
export TLS_CA_FILE="$(pwd)/certs/ca.crt"

# Run with Flask development server (reads env vars automatically)
uv run python -m sbom_graph_api.app

# Or run with gunicorn using the config file (reads TLS env vars)
uv run gunicorn -c gunicorn.conf.py sbom_graph_api.wsgi:app

# Or run with gunicorn using explicit command-line options
uv run gunicorn \
  --bind 0.0.0.0:8443 \
  --certfile=certs/server.crt \
  --keyfile=certs/server.key \
  --workers 2 \
  sbom_graph_api.wsgi:app
```

The gunicorn config file (`gunicorn.conf.py`) automatically:
- Reads TLS settings from environment variables
- Switches to port 8443 when TLS is enabled
- Configures worker processes and timeouts

Access the application at `https://localhost:8443`. Your browser will warn about the self-signed certificate - this is expected in development.

### Running with TLS in Docker

Mount your certificates directory and set environment variables:

```bash
docker run -p 8443:8443 \
  --memory=2g \
  -v "$(pwd)/certs:/certs:ro" \
  -v appsec-data-volume:/data \
  -e TLS_ENABLED=true \
  -e TLS_CERT_FILE=/certs/server.crt \
  -e TLS_KEY_FILE=/certs/server.key \
  -e TLS_CA_FILE=/certs/ca.crt \
  -e FALKORDB_HOST=host.docker.internal \
  sbom-graph-api:latest
```

### Production TLS (Real Certificates)

For production, use certificates from a trusted Certificate Authority:

1. **Obtain certificates** from your CA (Let's Encrypt, DigiCert, etc.)
2. **Store securely** in Kubernetes secrets or a secrets manager
3. **Mount in container** at `/certs` volume

Example with Kubernetes:

```yaml
# Create secret from certificate files
kubectl create secret tls appsec-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key

# Reference in Helm values
config:
  tls:
    enabled: true
    existingSecret: appsec-tls
```

### Certificate Requirements

| File | Format | Description |
|------|--------|-------------|
| Certificate | PEM | Server certificate (may include chain) |
| Private Key | PEM | Private key (unencrypted or PKCS#8) |
| CA Certificate | PEM | CA certificate chain (optional) |

**Security Notes:**
- Never commit private keys to version control
- Use file permissions `600` for private keys
- Rotate certificates before expiration
- In production, use certificates from trusted CAs

## Kubernetes Deployment

A Helm chart is provided in `helm/sbom-graph-api/`.

### Install

```bash
helm install sbom-graph-api ./helm/sbom-graph-api \
  --set config.falkordb.host=falkordb-service \
  --set config.falkordb.existingSecret=falkordb-credentials
```

### Install with Authentication

```bash
helm install sbom-graph-api ./helm/sbom-graph-api \
  --set config.falkordb.host=falkordb-service \
  --set config.auth.enabled=true \
  --set config.auth.ldap.enabled=true \
  --set config.auth.ldap.server=ldap.example.com \
  --set config.auth.ldap.baseDn="dc=example,dc=com" \
  --set config.auth.ldap.existingSecret=ldap-credentials \
  --set config.auth.jwt.existingSecret=jwt-secrets \
  --set config.tokenStorage.existingSecret=token-db-secrets \
  --set persistence.enabled=true
```

### Configuration via values.yaml

Key configuration options:

```yaml
config:
  falkordb:
    host: "falkordb"
    port: "6379"
    graphName: "acme_corp"
    existingSecret: "falkordb-secret"  # Kubernetes secret for password
    secretKey: "password"              # Key within the secret
  
  # TLS configuration
  tls:
    enabled: false
    existingSecret: ""  # Secret containing tls.crt, tls.key, ca.crt
  
  # Authentication configuration
  auth:
    enabled: false
    jwt:
      accessTokenExpiresHours: "1"
      refreshTokenExpiresDays: "30"
      existingSecret: ""  # Secret containing jwt-secret key
    ldap:
      enabled: false
      server: ""
      port: "389"
      useSsl: "false"
      baseDn: ""
      userDnTemplate: "uid={username},ou=users,dc=example,dc=com"
      existingSecret: ""  # Secret containing bind-dn and bind-password
  
  # Token storage configuration
  tokenStorage:
    existingSecret: ""  # Secret containing encryption-key

# Secrets to be created (alternative to existingSecret)
secrets:
  create: false
  flaskSecretKey: ""
  jwtSecretKey: ""
  tokenDbEncryptionKey: ""
  falkordbPassword: ""
  ldapBindDn: ""
  ldapBindPassword: ""

# Persistent storage for token database
persistence:
  enabled: false
  existingClaim: ""
  storageClass: ""
  size: 1Gi
  mountPath: /data

# Memory sizing for 1GB FalkorDB (see Memory Configuration section)
resources:
  limits:
    cpu: "1"
    memory: 2Gi       # 4 workers × 300MB + overhead
  requests:
    cpu: 250m
    memory: 1Gi

# Gunicorn worker configuration
gunicorn:
  workers: 4          # Adjust based on memory: (memory - 200MB) / 300MB
  threads: 2          # Threads per worker
  workerClass: gthread  # Threaded worker (better for graph ops)
  timeout: 300        # Request timeout (5 min for deep graphs)
  gracefulTimeout: 30 # Shutdown grace period
  keepAlive: 5        # Keep connections alive
  maxRequests: 1000   # Recycle workers to prevent memory leaks
  maxRequestsJitter: 50

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
```

## Project Structure

```
sbom-graph-api/
├── src/
│   └── sbom_graph_api/
│       ├── __init__.py
│       ├── app.py              # Flask application factory
│       ├── config.py           # Configuration management
│       ├── wsgi.py             # WSGI entry point
│       ├── routes/
│       │   ├── auth.py         # Authentication endpoints
│       │   ├── ingest.py       # SBOM ingestion (CycloneDX upload)
│       │   ├── visualizations.py
│       │   ├── exports.py
│       │   ├── reports.py
│       │   └── schemas.py      # JSON Schema endpoints
│       ├── schemas/
│       │   ├── __init__.py
│       │   └── definitions.py  # JSON Schema definitions
│       ├── services/
│       │   ├── falkordb_service.py
│       │   ├── ldap_service.py # LDAP authentication
│       │   └── token_storage.py # Encrypted token storage
│       ├── templates/
│       │   ├── api_docs.html   # API documentation page
│       │   ├── login.html      # Login page
│       │   ├── tokens.html     # Token management page
│       │   ├── create_token.html # Token creation page
│       │   ├── table.html      # Generic table template
│       │   ├── dependants.html # Dependants report template
│       │   └── export.html     # Export page template
│       ├── visualizations/
│       │   ├── kpartite.py
│       │   ├── bipartite.py
│       │   └── dependants_graph.py
│       ├── exports/
│       │   └── excel.py
│       └── utils/
│           └── validation.py   # Input validation & sanitization
├── helm/
│   └── sbom-graph-api/      # Helm chart
├── tests/
├── Dockerfile
├── pyproject.toml
└── README.md
```

## Development

### Running Tests

```bash
uv sync --extra dev
uv run pytest
```

### Test Coverage

```bash
uv run pytest --cov=src/sbom_graph_api --cov-report=term-missing
```

### Code Formatting

```bash
uv run ruff check --fix .
uv run ruff format .
```

### Security Testing

```bash
# Bandit static security analysis (SAST)
uv run bandit -r src/ -c pyproject.toml

# Snyk Code analysis (SAST)
snyk code test --severity-threshold=medium

# Snyk SCA (requires requirements.txt - see below)
uv export --no-hashes --no-editable > requirements.txt
snyk test --file=requirements.txt

# Ruff linting
uv run ruff check src/
```

#### SonaType IQ (SCA) Scanning

The project uses `uv` for dependency management with `uv.lock`. Since Nexus IQ CLI doesn't natively support `uv.lock` format, the CI/CD pipeline generates a `requirements.txt` file for SCA scanning:

```bash
# Generate requirements.txt from uv.lock
uv export --no-hashes --no-editable > requirements.txt
```

This is done automatically in the Jenkinsfile's "Generate requirements.txt" stage before the build. The `requirements.txt` file is added to `.gitignore` since it's generated.

**Manual SonaType IQ scan:**
```bash
java -jar nexus-iq-cli.jar \
  -i "sbom-graph-api" \
  -s YOUR_IQ_SERVER_URL \
  -a YOUR_AUTH_TOKEN \
  -t build \
  .
```

### Demo Data (ACME Corp Graph)

A demonstration graph named `acme_corp` can be populated for testing and experimentation:

```bash
uv run python scripts/populate_acme_corp.py
```

Set `FALKORDB_GRAPH_NAME=acme_corp` and `FALKORDB_INTERNAL_LABEL=INTERNAL` to use this graph.

#### Understanding Multi-Version Reports

The application provides **two different reports** for analyzing multiple versions of libraries. These serve different but complementary purposes:

| Report | Endpoint | Input | Question Answered |
|--------|----------|-------|-------------------|
| **Multi-Version Dependencies** | `/reports/multi-version-deps/{library}` | Library name only | "Who uses what version of this library across the org?" |
| **Multi-Version Sources** | `/reports/multi-version-sources/{project}/{version}` | Project + Version | "Does this project have version conflicts in its dependency tree?" |

**When to use each:**

- **Multi-Version Dependencies (`multi-version-deps`)**: Use when a vulnerability is found in a specific library version and you need to identify all teams/applications that need to upgrade. Also useful for understanding library adoption patterns.

- **Multi-Version Sources (`multi-version-sources`)**: Use when analyzing a specific application to find diamond dependency problems that could cause runtime issues (e.g., NoSuchMethodError, ClassNotFoundException).

#### Multi-Version Dependencies Demo (Library Adoption)

The `acme_corp` graph includes multiple versions of common libraries used across different applications. This demonstrates the **Multi-Version Dependencies Report** - useful for understanding library adoption patterns and vulnerability remediation planning.

**Demo Libraries for `/reports/multi-version-deps`:**

| Library | Versions in Graph | Use Case |
|---------|------------------|----------|
| `jackson-databind` | 2.13.0, 2.14.0, 2.14.2, 2.15.2, 2.16.1 | Best demo - 5 different pinned versions |
| `slf4j-api` | 1.7.36, 2.0.9 | SLF4J 1.x vs 2.x compatibility |
| `guava` | 31.1-jre, 32.0.0-jre, 33.0.0-jre | Guava version evolution |

**Example Usage:**
```
/reports/multi-version-deps/jackson-databind?format=html
```

This shows which applications use which version of jackson-databind, helping identify:
- Which teams are on older (potentially vulnerable) versions
- Version fragmentation across the organization
- Migration progress tracking

#### Multi-Version Sources Demo (Diamond Dependencies)

The `acme_corp` graph includes diamond dependency scenarios where a library's transitive dependency tree contains multiple versions of the same package. This demonstrates the **Multi-Version Sources Report** - useful for identifying potential runtime issues (NoSuchMethodError, ClassNotFoundException).

**Demo Libraries for `/reports/multi-version-sources`:**

| Library Version | Query Parameters | Conflict On | Description |
|-----------------|------------------|-------------|-------------|
| `acme-kafka:2.0.0` | `project_name=acme-kafka&version_name=2.0.0` | `acme-events` | Best demo - serialization vs schema-registry pin different event versions |
| `acme-data-pipeline:2.0.0` | `project_name=acme-data-pipeline&version_name=2.0.0` | `acme-connection-pool` | Database vs cache libs pin different pool versions |
| `acme-web-common:2.0.0` | `project_name=acme-web-common&version_name=2.0.0` | `acme-logging` | Auth vs metrics pin different logging versions |

**Example Usage:**
```
/reports/multi-version-sources/acme-kafka/2.0.0?format=html
```

**Diamond Dependency Paths:**

1. **acme-kafka:2.0.0** (conflict on `acme-events`):
   - `acme-kafka -> acme-serialization 2.0.0 -> acme-events 1.1.0` (pinned for serialization stability)
   - `acme-kafka -> acme-schema-registry 2.0.0 -> acme-events 2.0.0` (uses latest for new schema features)

2. **acme-data-pipeline:2.0.0** (conflict on `acme-connection-pool`):
   - `acme-data-pipeline -> acme-db-common 2.1.0 -> acme-connection-pool 1.1.0` (pinned)
   - `acme-data-pipeline -> acme-cache 1.1.0 -> acme-connection-pool 2.0.0` (latest)

3. **acme-web-common:2.0.0** (conflict on `acme-logging`):
   - `acme-web-common -> acme-auth 3.0.0 -> acme-logging 2.0.0-SNAPSHOT` (latest)
   - `acme-web-common -> acme-metrics 1.1.0 -> acme-logging 1.2.0` (pinned)

#### Cyclic Dependencies Demo (Self-Referential Libraries)

The `acme_corp` graph includes self-referential libraries that create simple cycles. These are useful for demonstrating cycle detection and the **Self-Dependencies Report**.

**Self-Referential Libraries:**

| Library | Cycle | Description |
|---------|-------|-------------|
| `acme-plugin-loader:1.0.0` | Depends on itself | Plugin system that can load itself as a plugin |
| `acme-plugin-loader:1.1.0` | Depends on itself | Updated plugin loader with same self-reference |
| `acme-module-registry:1.0.0` | Depends on itself | Registry that references itself for nested modules |

**Demo Applications Using Cyclic Libraries:**

| Application:Version | Visualization Query | Cycles Included |
|---------------------|---------------------|-----------------|
| **`extensible-platform:1.0.0`** | `?project_name=extensible-platform&version_name=1.0.0` | Both (best demo) |
| `plugin-manager:1.0.0` | `?project_name=plugin-manager&version_name=1.0.0` | `acme-plugin-loader` |
| `module-loader:1.0.0` | `?project_name=module-loader&version_name=1.0.0` | `acme-module-registry` |

**Example Usage:**
```
# Visualize dependencies with spring layout (shows cycles in red)
/visualizations/dependencies?project_name=extensible-platform&version_name=1.0.0

# Report all self-referential dependencies in the graph
/reports/self-dependencies
```

**Best Demo: extensible-platform:1.0.0**

This application uses both cyclic libraries, making it ideal for demonstrating:
- Cycle detection in dependency graphs (cycles shown as red dashed edges)
- Force-directed (spring) layout that handles cyclic graphs
- Nodes involved in cycles have red borders

**Visualization Features:**
- Uses spring layout (forceAtlas2Based physics) for natural graph spreading
- Cycle edges are highlighted in red with dashed lines
- Nodes involved in cycles have thick red borders
- Interactive: pan, zoom, drag nodes, hover for details

## License

Open Source - MIT

## Contributing

Contact the Brett Crawley for contribution guidelines.
