# Threat Model: Phase B — SBOM Provenance in Ingestion

## Summary

Phase B adds SBOM provenance tracking to ingestion: record_id, document_hash, tool
info stored in SBOMRecord nodes and linked via ProducedBySBOM edges. No
critical or high threats; existing mitigations (parameterised queries, JSON
Schema validation) apply.

---

## Assets and Trust Boundaries

| Asset | Description |
|-------|-------------|
| SBOMRecord nodes | Provenance metadata (record_id, format, document_hash, tool info) |
| Ingest payload | sbom, app_id, public_app_id, project_url |
| FalkorDB graph | Version→SBOMRecord links |

| Trust Boundary | Description |
|----------------|-------------|
| Client → API | POST /ingest/*; JWT required when AUTH_ENABLED |
| API → FalkorDB | Persistence layer |

---

## Threat Analysis (STRIPED)

| # | Threat | STRIDE | Asset | Risk | Mitigation |
|---|--------|--------|-------|------|------------|
| 1 | Cypher injection via app_id | S/T | FalkorDB | Low | Parameterised queries only |
| 2 | Malformed SBOM causing crash | D | API | Low | JSON Schema validation; try/except |
| 3 | document_hash spoofing | T | Integrity | Low | Optional; validated if provided |
| 4 | Exception details in response | I | Internal | Low | AGENTS.md: no exception leakage |
| 5 | Oversized payload DoS | D | API | Low | Request size limits; streaming parse |
| 6 | Dependency: sbom-graph-model | D | Library | Low | In-repo; same governance |

---

## Recommendations

1. Validate record_id as UUID; format/source against allowlists.
2. All Cypher uses $param placeholders.
3. Guard clauses for empty app_id, purl.

---

## Residual Risk

None. Design approved for implementation.
