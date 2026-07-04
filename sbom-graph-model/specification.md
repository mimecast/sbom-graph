# Specification

The sbom_graph_model package should contain the following components that can be used by both a bulk importer as well as a microservice acting as a webhook for processing CycloneDX files being produced during release:

- sbom_graph_model/model.py - Data models: Project, Version, Defect, License, and edge classes
- sbom_graph_model/persistence.py - FalkorDB persistence layer (refactored)
- sbom_graph_model/cyclonedx/processor.py - CycloneDX SBOM parsing and persistence

The persistence module must be capable of handling connection to FalkorDB over TLS and must be Authenticated.

## Node identity

A `Version` node's identity (the Cypher `MERGE` key in `create_project_version`) is:

- `name` (version string)
- `project_name`
- `project_group`
- `package_url` (purl) — **when present**

Including `package_url` means components that share the same
`name`/`project_name`/`project_group` but originate from different purls are
persisted as **distinct** nodes, preserving provenance. When `package_url` is
null or empty it is omitted from the identity, so the node falls back to the
`name`/`project_name`/`project_group` triplet bucket (the pre-purl behaviour).
The `scan_ids` back-fill matches on the same identity, including `package_url`
when present, so scan IDs attach to the correct node.

**Migration note:** this changes identity for *new* ingests only. Existing
nodes that were previously merged under the triplet identity are **not**
retroactively split — a re-ingest (or a one-off migration script) is required
to materialise the new identity. No automatic migration is performed.
