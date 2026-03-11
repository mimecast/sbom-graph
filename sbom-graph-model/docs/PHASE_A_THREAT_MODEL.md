# Threat Model: Phase A — SBOMRecord + SourceRepository→TrustScore

## Summary

The design introduces SBOMRecord nodes and ProducedBySBOM edges for SBOM provenance tracking, plus SourceRepository→TrustScore links for repo-level scoring. No critical or high severity threats identified; mitigations are already present in the design (parameterised queries, input validation). Proceed to implementation.

---

## Assets and Trust Boundaries

| Asset | Description | Trust Boundary |
|------|-------------|----------------|
| SBOMRecord nodes | SBOM provenance metadata (record_id, format, source, document_hash) | FalkorDB (internal) |
| PRODUCED_BY_SBOM edges | Links Version→SBOMRecord | FalkorDB |
| HAS_TRUST_SCORE (SourceRepository→TrustScore) | Repo-level trust scoring | FalkorDB |
| Input parameters | record_id, purl, repo_url, etc. | API/CLI boundaries |

---

## Threat Analysis (STRIPED)

| # | Threat | STRIDE | Asset | Likelihood | Impact | Risk | Mitigation |
|---|--------|--------|-------|------------|--------|------|------------|
| 1 | Cypher injection via record_id | Spoofing/Tampering | FalkorDB | Low | High | Medium | **Mitigated**: Parameterised queries only; no string interpolation |
| 2 | Malformed input causing query failure | Denial of Service | FalkorDB | Low | Low | Low | **Mitigated**: Early return on empty inputs; validation |
| 3 | document_hash spoofing | Tampering | SBOM integrity | Low | Medium | Low | **Mitigated**: Optional field; validation if provided |
| 4 | Information disclosure via exception details | Information Disclosure | API | Low | Medium | Low | **Mitigated**: AGENTS.md rule 10; no exception details in responses |
| 5 | Repo URL injection | Spoofing | SourceRepository | Low | Medium | Low | **Mitigated**: Parameterised queries only |
| 6 | PII in SBOM metadata | Privacy | SBOMRecord | Low | Low | Low | **Mitigated**: No PII fields in spec; tool_name/tool_version are non-PII |

---

## Recommendations

1. **Input validation**: Validate `record_id` as UUID format; `format` and `source` against allowlists.
2. **Parameterised queries**: All queries use `$param` placeholders. **No exceptions**.
3. **Early returns**: Guard clauses for empty purl, record_id, repo_url.

---

## Residual Risk

None. All critical/high threats mitigated. Design approved for implementation.
