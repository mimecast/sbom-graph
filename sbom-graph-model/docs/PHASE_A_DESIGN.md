# Phase A Design: SBOMRecord + SourceRepository→TrustScore

## Summary

Three design variants for implementing SBOMRecord node, ProducedBySBOM edge, SBOM persistence methods, and SourceRepository→TrustScore link. All designs follow existing patterns in model.py and persistence.py.

---

## Design Alpha (Maintainability, Documentation, Clarity)

### SBOMRecord Node
- Plain class with `__init__` matching existing node patterns (Version, Defect, TrustScore).
- All attributes as `Optional[str]` except `record_id`, `format`, `ingested_at`, `source` (required).
- Comprehensive docstring with attribute descriptions and MERGE key.

### ProducedBySBOM Edge
- Edge class with `version` and `sbom_record` references, matching VersionSource/HasTrustScore pattern.

### Persistence Methods
- `create_sbom_record`: Use `_create_extended_query` for optional fields; MERGE on record_id with ON CREATE/ON MATCH.
- `link_version_to_sbom_record`: MATCH Version by package_url, MATCH SBOMRecord by record_id, MERGE edge.
- `link_version_to_sbom_record_by_name`: Two query variants (with/without project_group) like `link_version_to_source_by_name`.
- `get_sbom_inventory`: MATCH (s:SBOMRecord) OPTIONAL MATCH (v:Version)-[:PRODUCED_BY_SBOM]->(s) RETURN s props + count(v).
- `get_sbom_coverage`: Three sub-queries: total projects, projects with recent SBOMs, projects with stale SBOMs, projects with no SBOMs.

### Validation
- `record_id`: non-empty; `format`: allowlist {"cyclonedx", "spdx"}; `source`: allowlist {"webhook", "api_upload", "cli"}.
- `document_hash`: optional hex regex (64 chars) if provided.

---

## Design Beta (Performance, Cognitive Simplicity)

### SBOMRecord Node
- Same structure as Alpha; minimal indirection.

### Persistence Methods
- Single `get_sbom_coverage` query using aggregation where possible.
- `get_sbom_inventory`: Return list of dicts with `record_id`, `format`, `ingested_at`, `source`, `version_count`.

### Index
- `("SBOMRecord", "record_id")` — critical for lookup performance.

---

## Design Gamma (Security, Architectural Elegance)

### Input Validation
- `record_id`: UUID format validation (RFC 4122).
- `format`: allowlist only.
- `source`: allowlist only.
- `document_hash`: optional SHA-256 hex regex.
- All queries use parameterised params only.

### Defence in Depth
- No string concatenation in Cypher; all values from params.
- Early return on empty/invalid inputs.

---

## Aggregated Design (Orchestrator)

| Component | Decision |
|-----------|----------|
| SBOMRecord | Plain class, Alpha-style docstrings, Gamma validation |
| ProducedBySBOM | Edge class, minimal |
| create_sbom_record | MERGE on record_id, ON CREATE/ON MATCH for all fields |
| link_version_to_sbom_record | MATCH by purl + record_id, MERGE edge |
| link_version_to_sbom_record_by_name | Two query variants for project_group |
| get_sbom_inventory | OPTIONAL MATCH, return dicts with version_count |
| get_sbom_coverage | Define "recent" (e.g. 30 days) and "stale" (e.g. 90 days) via config |
| link_source_repo_to_trust_score | MATCH SourceRepository by url, TrustScore by purl, MERGE HAS_TRUST_SCORE |
| Index | ("SBOMRecord", "record_id") |

---

## Data Model

### SBOMRecord
```
record_id: str (MERGE key)
format: str ("cyclonedx" | "spdx")
tool_name: Optional[str]
tool_version: Optional[str]
serial_number: Optional[str]
ingested_at: str (ISO)
source: str ("webhook" | "api_upload" | "cli")
document_hash: Optional[str] (SHA-256 hex)
```

### ProducedBySBOM
```
version: Optional[Version]
sbom_record: Optional[SBOMRecord]
```

### Edge: Version -[:PRODUCED_BY_SBOM]-> SBOMRecord

### Edge: SourceRepository -[:HAS_TRUST_SCORE]-> TrustScore
