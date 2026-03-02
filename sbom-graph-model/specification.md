# Specification

The sbom_graph_model package should contain the following components that can be used by both a bulk importer as well as a microservice acting as a webhook for processing CycloneDX files being produced during release:

- sbom_graph_model/model.py - Data models: Project, Version, Defect, License, and edge classes
- sbom_graph_model/persistence.py - FalkorDB persistence layer (refactored)
- sbom_graph_model/cyclonedx/processor.py - CycloneDX SBOM parsing and persistence

The persistence module must be capable of handling connection to FalkorDB over TLS and must be Authenticated.
