# AGENTS.md - AI Agent Guidelines for Release Listener

This document provides guidance for AI agents working on this codebase.

## Project Overview

**Release Listener** is a Flask microservice that receives webhook events from
SonaType Lifecycle and processes release scans by ingesting dependency trees
into FalkorDB.

### Core Workflow

1. Receive webhook POST at `/webhook`
2. Validate it's a release scan
   (`applicationEvaluation.stage == "release"`)
3. Extract `application.id` and `application.publicId`
4. Use `CycloneDXHelper` and `SonaTypeClient` to fetch and ingest CycloneDX SBOM data
5. Optionally fetch and process VEX documents via `VexHelper` (best-effort, non-blocking)
6. Store dependency graph, vulnerabilities, and VEX statements in FalkorDB

## Project Structure

```text
sonatype-lifecycle-release-listener/
├── src/sonatype_lifecycle_release_listener/     # Main application code
│   ├── __init__.py
│   └── app.py               # Flask app with webhook handler
├── tests/
│   ├── conftest.py          # Pytest configuration
│   ├── test_app.py          # Test suite (22 tests)
│   └── resources/           # Test fixtures
│       ├── example-message.json      # Sample webhook payload
│       ├── acme_notification_service_sbom.json  # Sample SBOM for mocking
│       └── example_vex.json          # Sample VEX document for mocking
├── helm/sonatype-lifecycle-release-listener/   # Helm chart for Kubernetes
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/           # K8s manifests
├── Dockerfile               # Distroless multi-stage build
├── .dockerignore
├── gunicorn.conf.py         # Production server config
├── logging.conf             # Logging configuration
└── pyproject.toml           # uv dependencies
```

## Key Dependencies

| Dependency | Purpose |
| ------------ | --------- |
| `sbom-graph-model` | SonaType API and FalkorDB persistence |
| `flask` | Web framework for webhook handling |
| `gunicorn` | Production WSGI server |
| `falkordb` | Graph database client (used by sbom-graph-model) |

### sbom-graph-model Library

The `sbom-graph-model` library is a local dependency. Key classes:

- **`CycloneDXProcessor`**: Processes CycloneDX SBOM JSON and persists to FalkorDB
- **`VexProcessor`**: Parses OpenVEX documents and persists VEX statements
- **`Persistence`**: Handles FalkorDB operations
  - Connects via `FALKORDB_HOST`/`FALKORDB_PORT` (default port 6379)
  - Graph: `FALKORDB_GRAPH_NAME` (default `acme-corp`);
    optional `FALKORDB_PASSWORD` and `FALKORDB_CACERTS`

## Development Commands

```bash
# Install dependencies
uv sync

# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest -v

# Run tests with coverage
uv run pytest --cov=sonatype_lifecycle_release_listener --cov-report=term-missing

# Run development server
SONATYPE_USERNAME=user SONATYPE_PASSWORD=pass uv run python -m sonatype_lifecycle_release_listener.app

# Run production server
uv run gunicorn -c gunicorn.conf.py sonatype_lifecycle_release_listener.app:app

# Build Docker image
docker build -t sonatype-lifecycle-release-listener:latest .

# Run Docker container
docker run -p 8000:8000 \
  -e SONATYPE_USERNAME=user -e SONATYPE_PASSWORD=pass sonatype-lifecycle-release-listener:latest

# Helm install
helm install sonatype-lifecycle-release-listener ./helm/sonatype-lifecycle-release-listener \
  --set secrets.sonatypeUsername=user --set secrets.sonatypePassword=pass \
  --set falkordb.host=falkordb --set falkordb.graphName=acme-corp

# Add a new dependency
uv add <package-name>

# Add a dev dependency
uv add --group dev <package-name>

# Update dependencies
uv lock --upgrade
```

## Docker & Kubernetes Deployment

### Docker Image

The application uses a **distroless** base image
(`gcr.io/distroless/python3-debian12:nonroot`) for security:

- Multi-stage build: dependencies in builder stage, then copied to minimal
  runtime
- Runs as non-root user (UID 65532)
- No shell access - minimizes attack surface
- Uses gunicorn as the WSGI server

### Helm Chart

The Helm chart (`helm/sonatype-lifecycle-release-listener/`) provides:

- **Deployment** with security contexts, health probes, and resource limits
- **Service** (ClusterIP by default)
- **Secret** for SonaType credentials (or use `existingSecret`)
- **ConfigMap** for CA certificates
- **ServiceAccount** with minimal permissions
- **Ingress** (optional)
- **HorizontalPodAutoscaler** (optional)

Key Helm values (see `helm/sonatype-lifecycle-release-listener/values.yaml` for full list):

```yaml
sonatype:
  host: ""                  # Optional SonaType API base URL

secrets:
  sonatypeUsername: ""      # Or use existingSecret
  sonatypePassword: ""
  existingSecret: ""
  existingSecretUsernameKey: "sonatype-username"
  existingSecretPasswordKey: "sonatype-password"
  # Optional; FalkorDB password key in existing secret
  existingSecretFalkordbPasswordKey: ""

falkordb:
  host: "falkordb"
  port: 6379
  graphName: "acme-corp"
  # Optional; or use existingSecretFalkordbPasswordKey
  password: ""
  # Optional; defaults to config.caCertsPath when CA bundle mounted
  caCertsPath: ""

config:
  # Base64-encoded CA bundle (optional)
  caCerts: ""
  caCertsPath: /app/certs/ca_bundle.pem
```

## Testing Guidelines

### Test Structure

Tests are organized in `tests/test_app.py` with these test classes:

- `TestHealthEndpoint` - Health check endpoint tests
- `TestWebhookEndpoint` - Webhook validation and routing tests
- `TestProcessReleaseScan` - Unit tests for the processing function (SBOM + VEX)
- `TestIntegrationWithMockedSonatype` - End-to-end flow with mocked services
- `TestSonaTypeClient` - SonaType API client (CycloneDX and VEX endpoints)
- `TestVexHelper` - VEX document fetch and processing
- `TestCycloneDXHelper` - CycloneDX SBOM processing
- `TestFalkorDBIntegration` - Integration tests; FalkorDB at localhost:6379
- `TestEdgeCases` - Edge case and error handling tests

### Mocking Patterns

When mocking `CycloneDXHelper` or `VexHelper`:

```python
@patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
def test_example(self, mock_helper_class):
    mock_helper = MagicMock()
    mock_helper_class.return_value = mock_helper
    # ... test code
    mock_helper.process_cyclonedx_sbom.assert_called_once_with(
        app_id='expected_id',
        public_app_id='expected_public_id',
    )
```

For FalkorDB integration tests, mock `SonaTypeClient.get_cyclonedx_sbom`:

```python
@patch('sonatype_lifecycle_release_listener.app.SonaTypeClient.get_cyclonedx_sbom')
def test_integration(self, mock_get_sbom, example_cyclonedx):
    mock_get_sbom.return_value = example_cyclonedx
    # ... test code
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
| ---------- | ---------- | --------- | ------------- |
| `SONATYPE_USERNAME` | Yes | - | SonaType API username |
| `SONATYPE_PASSWORD` | Yes | - | SonaType API password |
| `SONATYPE_HOST` | No | (empty) | SonaType API base URL |
| `SONATYPE_CACERTS` | No | `certs/ca_bundle.pem` | CA certificates path |
| `FALKORDB_HOST` | No | (empty) | FalkorDB host |
| `FALKORDB_PORT` | No | `6379` | FalkorDB port |
| `FALKORDB_GRAPH_NAME` | No | `acme-corp` | FalkorDB graph name |
| `FALKORDB_PASSWORD` | No | (empty) | FalkorDB password (optional) |
| `FALKORDB_CACERTS` | No | `certs/ca_bundle.pem` | FalkorDB CA path |
| `INTERNAL_PREFIXES` | No | (empty) | Comma-separated `field:prefix` pairs for INTERNAL label (e.g., `"group:com.acme,name:acme-"`). Helm: `config.internalPrefixes` |
| `FLASK_DEBUG` | No | `false` | Enable debug mode |

### Logging

Logging is configured via `logging.conf`. The app falls back to basic
logging if the config file is not found (useful for testing).

## API Contracts

### POST /webhook

**Request:**

```json
{
    "applicationEvaluation": {
        "application": {
            "id": "sonatype-internal-id",
            "publicId": "human-readable-id"
        },
        "stage": "release"
    }
}
```

**Responses:**

- `200 OK` - `{"status": "processed"}` or
  `{"status": "ignored", "reason": "..."}`
- `400 Bad Request` - `{"error": "Invalid JSON payload"}` or
  `{"error": "Missing application id or publicId"}`
- `500 Internal Server Error` - `{"error": "...", "status": "error"}`

## Common Tasks

### Adding a New Endpoint

1. Add route in `src/sonatype_lifecycle_release_listener/app.py` inside `create_app()`
2. Add corresponding tests in `tests/test_app.py`
3. Update README.md API documentation

### Modifying Webhook Processing

The main processing logic is in `process_release_scan()`. This function:

1. Creates a `CycloneDXHelper` and processes the CycloneDX SBOM
2. Optionally creates a `VexHelper` and processes VEX data (best-effort)
3. Returns success/failure status (VEX failures do not block success)

### Running Security Scans

Before completing significant changes, run Snyk security scan:

```bash
# Via Snyk CLI or MCP tool
snyk code test /path/to/sonatype-lifecycle-release-listener
```

## Gotchas and Notes

1. **FalkorDB Connection**: Configured via `FALKORDB_HOST`, `FALKORDB_PORT`,
   `FALKORDB_GRAPH_NAME` (default `acme-corp`), and optionally
   `FALKORDB_PASSWORD` and `FALKORDB_CACERTS`

2. **MERGE Operations**: DB uses MERGE (idempotent); same data won't
   create duplicates

3. **Logging Config**: Tests may fail if `logging.conf` is missing. The app
   falls back to basic logging gracefully

4. **Stage Matching**: Stage comparison is case-insensitive
   (`"RELEASE"`, `"release"`, `"Release"` all match)

5. **Empty gitlab_url**: Per requirements, `process_cyclonedx_sbom()` is always
   called with `gitlab_project_url=""` (via CycloneDXProcessor)

6. **VEX best-effort**: VEX processing is non-blocking; webhook succeeds even if
   VEX fetch or processing fails

7. **Distroless Container**: The Docker image has no shell - cannot `exec` in.
   Use `kubectl logs` or a debug sidecar if needed

8. **Read-Only Filesystem**: Deployment mounts `/tmp` and `/app/data` as
   emptyDir; container root filesystem is read-only

9. **VEX API**: Sonatype IQ VEX endpoint is
   `vulnerabilities/vex/{app_id}/stages/{stage_id}`; returns 404 when no VEX
   data is available

10. **Helm Secrets**: Never commit credentials in `values.yaml`. Use `--set`,
   external secrets, or `existingSecret` reference
