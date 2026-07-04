# Release Listener

A Flask microservice that listens for SonaType webhook messages and processes
release scans by ingesting dependency trees into FalkorDB.

## Overview

This service listens for webhook events from SonaType Lifecycle. When it
receives a release scan event, it:

1. Extracts the application ID and public ID from the message
2. Uses the `sbom-graph-model` library to fetch the CycloneDX SBOM from SonaType
3. Ingests the dependency tree and vulnerabilities into FalkorDB
4. Optionally fetches and processes VEX (Vulnerability Exploitability eXchange)
   documents via `VexHelper` — best-effort, non-blocking; webhook succeeds even
   if VEX fetch or processing fails

## Prerequisites

- Python 3.14+
- uv for dependency management
- FalkorDB (host/port/graph name configurable via env or Helm)
- Access to SonaType Lifecycle API
- CA certificates for SonaType (and optionally FalkorDB) server verification

## Installation

```bash
# Install dependencies
uv sync

# For development/testing dependencies
uv sync --group dev
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `SONATYPE_USERNAME` | SonaType Lifecycle username | Required |
| `SONATYPE_PASSWORD` | SonaType Lifecycle password | Required |
| `SONATYPE_HOST` | SonaType API base URL (optional) | (empty) |
| `SONATYPE_CACERTS` | Path to CA certificates file | `certs/ca_bundle.pem` |
| `FALKORDB_HOST` | FalkorDB host | (empty) |
| `FALKORDB_PORT` | FalkorDB port | `6379` |
| `FALKORDB_GRAPH_NAME` | FalkorDB graph name | `acme-corp` |
| `FALKORDB_PASSWORD` | FalkorDB password (optional) | (empty) |
| `FALKORDB_CACERTS` | CA cert path for FalkorDB TLS | `certs/ca_bundle.pem` |
| `INTERNAL_PREFIXES` | Comma-separated `field:prefix` pairs for INTERNAL label assignment (e.g., `"group:com.acme,name:acme-"`) | (empty) |
| `FLASK_DEBUG` | Enable Flask debug mode | `false` |

## Running the Service

### Development

```bash
# Using Flask's development server
SONATYPE_USERNAME=your_user SONATYPE_PASSWORD=your_pass \
  uv run python -m sonatype_lifecycle_release_listener.app
```

### Production

```bash
# Using Gunicorn
SONATYPE_USERNAME=your_user SONATYPE_PASSWORD=your_pass \
  uv run gunicorn -c gunicorn.conf.py sonatype_lifecycle_release_listener.app:app
```

### Docker

The Docker **build context** must be the **`sonatype-lifecycle-release-listener/`**
directory. Dependencies are installed from PyPI via `uv pip` in the Dockerfile;
use `build-images.sh` from the monorepo root (it runs `docker build` inside that
subproject):

```bash
# From the repository root (sbom-graph/)
./build-images.sh sonatype-lifecycle-release-listener

# Or with a custom tag
./build-images.sh --rl-tag myrepo/sonatype-lifecycle-release-listener:v1

# Or directly with docker build (run from sonatype-lifecycle-release-listener/)
cd sonatype-lifecycle-release-listener
docker build -t sonatype-lifecycle-release-listener:latest -f Dockerfile \
  --build-arg "PYTHON_PACKAGE_VERSION=$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)" \
  .
```

The build script still builds the `sbom-graph-model` wheel when needed for
other targets; the release-listener image build does not copy that wheel into
the image.

```bash
# Run the container
docker run -p 8000:8000 \
  -e SONATYPE_USERNAME=your_user \
  -e SONATYPE_PASSWORD=your_pass \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_GRAPH_NAME=acme-corp \
  sonatype-lifecycle-release-listener:latest
```

### Kubernetes (Helm)

Deployment is via the monorepo **umbrella chart** at `helm/charts/sbom-graph` (the former
standalone `sonatype-lifecycle-release-listener/helm/` chart was removed). To deploy the listener
on its own — e.g. against an existing/external FalkorDB — disable the other components:

```bash
helm upgrade --install sbom-graph ../helm/charts/sbom-graph \
  --set releaseListener.enabled=true \
  --set sbomGraphApi.enabled=false \
  --set enrichment.enabled=false \
  --set falkordb.enabled=false \
  --set falkordb.connectHost=<external-falkordb-host> \
  --set falkordb.password=<external-falkordb-password>
```

Sonatype credentials and the webhook HMAC secret are configured under `releaseListener.*` — see
`helm/charts/sbom-graph/values.yaml` for the full, authoritative value schema.

#### INTERNAL_PREFIXES Configuration

Projects can be marked as INTERNAL based on configurable field prefixes. Set
`INTERNAL_PREFIXES` (env) or `config.internalPrefixes` (Helm) to a
comma-separated string of `field:prefix` pairs. Format: `"group:com.acme,name:acme-"`.
Supported fields: `group`, `name`, `purl`.

Example with Helm (umbrella chart uses `global.internalPrefixes`):
```bash
helm upgrade --install sbom-graph ../helm/charts/sbom-graph \
  --set global.internalPrefixes="group:com.acme, name:acme-" \
  ...
```

## API Endpoints

### Health Check

```http
GET /health
```

Returns `{"status": "healthy"}` with a 200 status code.

### Webhook

```http
POST /webhook
Content-Type: application/json
```

Accepts SonaType webhook payloads. Processes release scan events and ignores
other event types.

Example payload:

```json
{
    "timestamp": "2020-04-22T18:30:04.673+0000",
    "initiator": "admin",
    "id": "d5cc2e91d6454545841da5599d3c7156",
    "applicationEvaluation": {
        "application": {
            "id": "0f256982c80b4e13abef4917b93ac343",
            "publicId": "My-Application-ID",
            "name": "My-Application",
            "organizationId": "f25acda2a413ab2c62b44917b93ac232"
        },
        "policyEvaluationId": "d5cc2e91d6454545841da5599d3c7156",
        "stage": "release",
        "ownerId": "0f256982c80b4e13abef4917b93ac343",
        "evaluationDate": "2020-04-22T18:30:04.404+0000",
        "affectedComponentCount": 10,
        "criticalComponentCount": 2,
        "severeComponentCount": 5,
        "moderateComponentCount": 3,
        "outcome": "fail",
        "reportId": "36f37cf776dd408bacd063450ab04f71"
    }
}
```

Response codes:

- `200`: Message processed successfully or ignored (non-release stage)
- `400`: Invalid payload or missing required fields
- `500`: Processing error

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run with coverage report
uv run pytest --cov=sonatype_lifecycle_release_listener --cov-report=term-missing
```

**Note:** Integration tests require FalkorDB to be running at localhost:6379.

## Project Structure

```text
sonatype-lifecycle-release-listener/
├── src/
│   └── sonatype_lifecycle_release_listener/
│       ├── __init__.py
│       └── app.py           # Flask application
├── tests/
│   ├── conftest.py          # Pytest configuration
│   ├── test_app.py          # Test cases
│   └── resources/
│       ├── example-message.json      # Example webhook payload
│       └── example_cyclonedx.json    # Example SBOM for mocking
├── helm/
│   └── sonatype-lifecycle-release-listener/    # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── Dockerfile               # Distroless container build
├── .dockerignore
├── gunicorn.conf.py         # Gunicorn configuration
├── logging.conf             # Logging configuration
├── pyproject.toml           # uv configuration
├── AGENTS.md                # AI agent guidelines
└── README.md
```

## License

Open Source - MIT

## Contributing

Contact the Brett Crawley for contribution guidelines.
