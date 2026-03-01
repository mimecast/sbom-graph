# Release Listener

A Flask microservice that listens for SonaType webhook messages and processes
release scans by ingesting dependency trees into FalkorDB.

## Overview

This service listens for webhook events from SonaType Lifecycle. When it
receives a release scan event, it:

1. Extracts the application ID and public ID from the message
2. Uses the `data-ingestion` library to fetch the CycloneDX SBOM from SonaType
3. Ingests the dependency tree and vulnerabilities into FalkorDB

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
| `FLASK_DEBUG` | Enable Flask debug mode | `false` |

## Running the Service

### Development

```bash
# Using Flask's development server
SONATYPE_USERNAME=your_user SONATYPE_PASSWORD=your_pass \
  uv run python -m release_listener.app
```

### Production

```bash
# Using Gunicorn
SONATYPE_USERNAME=your_user SONATYPE_PASSWORD=your_pass \
  uv run gunicorn -c gunicorn.conf.py release_listener.app:app
```

### Docker

```bash
# Build the distroless container image
docker build -t release-listener:latest .

# Run the container
docker run -p 8000:8000 \
  -e SONATYPE_USERNAME=your_user \
  -e SONATYPE_PASSWORD=your_pass \
  -e FALKORDB_HOST=host.docker.internal \
  -e FALKORDB_GRAPH_NAME=acme-corp \
  release-listener:latest
```

### Kubernetes (Helm)

```bash
# Install the Helm chart
helm install release-listener ./helm/release-listener \
  --set secrets.sonatypeUsername=your_user \
  --set secrets.sonatypePassword=your_pass \
  --set sonatype.host=https://nexus.example.com \
  --set falkordb.host=falkordb-service \
  --set falkordb.graphName=acme-corp

# With FalkorDB password (from values or existing secret)
helm install release-listener ./helm/release-listener \
  --set secrets.sonatypeUsername=your_user \
  --set secrets.sonatypePassword=your_pass \
  --set falkordb.host=falkordb \
  --set falkordb.graphName=acme-corp \
  --set falkordb.password=secret

# Or using an existing secret
helm install release-listener ./helm/release-listener \
  --set secrets.existingSecret=my-secret \
  --set secrets.existingSecretFalkordbPasswordKey=falkordb-password \
  --set falkordb.host=falkordb-service

# Upgrade an existing release
helm upgrade release-listener ./helm/release-listener \
  --reuse-values

# Uninstall
helm uninstall release-listener
```

Key Helm values: `sonatype.host`, `falkordb.host`, `falkordb.port`,
`falkordb.graphName`, `falkordb.password`, `config.caCerts`, `config.caCertsPath`.
See `helm/release-listener/values.yaml`.

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
uv run pytest --cov=release_listener --cov-report=term-missing
```

**Note:** Integration tests require FalkorDB to be running at localhost:6379.

## Project Structure

```text
release-listener/
├── src/
│   └── release_listener/
│       ├── __init__.py
│       └── app.py           # Flask application
├── tests/
│   ├── conftest.py          # Pytest configuration
│   ├── test_app.py          # Test cases
│   └── resources/
│       ├── example-message.json      # Example webhook payload
│       └── example_cyclonedx.json    # Example SBOM for mocking
├── helm/
│   └── release-listener/    # Helm chart
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

Internal use only.
