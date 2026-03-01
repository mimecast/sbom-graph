# appsec-sbom-model

A Python library for parsing CycloneDX Software Bill of Materials (SBOM) files and persisting the extracted data into a [FalkorDB](https://www.falkordb.com/) graph database. Designed as a reusable component for both bulk importers and webhook-driven microservices that process SBOMs produced during release pipelines.

## Architecture

The library models software supply-chain data as a property graph with the following structure:

```
Project ──HAS_VERSION──▶ Version ──DEPENDENCY_VERSION──▶ Version
                             │
                             └──VERSION_DEFECT──▶ Defect
```

### Modules

| Module | Purpose |
|---|---|
| `appsec_sbom_model.model` | Data models — enums (`RiskStatus`, `DefectType`, `ProjectType`), node classes (`Project`, `Version`, `Defect`, `License`), and edge classes (`VersionDefect`, `DependencyVersion`, `HasVersion`). |
| `appsec_sbom_model.persistence` | FalkorDB persistence layer — parameterised Cypher queries for creating nodes, edges, indexes, and computing centrality scores. |
| `appsec_sbom_model.cyclonedx` | CycloneDX SBOM processor — parses CycloneDX JSON, extracts components, dependencies, and vulnerabilities, then persists them via the persistence layer. |

## Requirements

- Python >= 3.14
- A running [FalkorDB](https://www.falkordb.com/) instance accessible over TLS with authentication enabled

## Installation

The project uses [uv](https://docs.astral.sh/uv/) for dependency management and [Hatchling](https://hatch.pypa.io/) as the build backend.

```bash
# Clone the repository
git clone <repository-url>
cd appsec-sbom-model

# Install dependencies with uv
uv sync
```

To install the package into another project:

```bash
uv add appsec-sbom-model
```

## Usage

### Connecting to FalkorDB

All connections to FalkorDB **must** use TLS and authentication.

```python
from appsec_sbom_model import Persistence

persistence = Persistence(
    host="falkordb.example.com",
    port=6380,
    graph_name="appsec",
    password="your-password",
    ssl=True,
    ssl_ca_certs="/path/to/ca-cert.pem",
)

# Create indexes for query performance
persistence.create_indexes()
```

### Processing a CycloneDX SBOM

```python
import json
from appsec_sbom_model.cyclonedx import CycloneDXProcessor

processor = CycloneDXProcessor(persistence=persistence)

with open("sbom.cdx.json") as f:
    sbom_data = json.load(f)

projects, dependencies, defects = processor.process_cyclone_dx_json(
    app_id="lifecycle-hash",
    public_app_id="my-application",
    gitlab_project_url="https://gitlab.example.com/org/my-application",
    json_data=sbom_data,
)
```

### Working with models directly

```python
from appsec_sbom_model import Project, Version, Defect, RiskStatus, ProjectType

project = Project()
project.name = "my-service"
project.group = "com.example"
project.type = ProjectType.Application
project.purl = "pkg:maven/com.example/my-service@1.0.0"

version = Version()
version.version = "1.0.0"
version.project = project

persistence.create_project_version(version)
```

## Security Requirements

- **TLS only** — The persistence layer enforces TLS for all FalkorDB connections (`ssl=True` by default).
- **Authenticated access** — A password is required when constructing a `Persistence` instance.

## Development

### Running tests

```bash
uv run pytest
```

### Running tests with coverage

```bash
uv run pytest --cov=appsec_sbom_model --cov-report=html
```

### Project structure

```
appsec-sbom-model/
├── src/
│   └── appsec_sbom_model/
│       ├── __init__.py              # Public API exports
│       ├── model.py                 # Data models (nodes, edges, enums)
│       ├── persistence.py           # FalkorDB persistence layer
│       └── cyclonedx/
│           ├── __init__.py
│           └── processor.py         # CycloneDX SBOM parser
├── tests/
├── pyproject.toml                   # Project metadata and dependencies
├── Jenkinsfile                      # CI/CD pipeline
├── sonar-project.properties         # SonarQube configuration
└── README.md
```

## CI/CD

The project uses a Jenkins pipeline (`Jenkinsfile`) with the `mc-pipe` shared library. Builds run on `rocky` agents and support packaging via `pyproject.toml`.

## Public API

All public types are re-exported from the top-level package:

```python
from appsec_sbom_model import (
    # Enums
    RiskStatus,
    DefectType,
    ProjectType,
    # Node models
    Version,
    Project,
    Defect,
    License,
    # Edge models
    VersionDefect,
    DependencyVersion,
    HasVersion,
    # Persistence
    Persistence,
)
```

## Owner

**ENG - AppSec** — Application Security Engineering
