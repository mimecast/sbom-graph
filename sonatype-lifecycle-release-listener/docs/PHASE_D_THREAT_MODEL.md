# Threat Model: Phase D — VEX Support in Sonatype Webhook Listener

## Summary

Phase D adds VEX (Vulnerability Exploitability eXchange) document fetching and processing to the Sonatype webhook listener. The design reuses existing patterns (CycloneDXHelper, SonaTypeClient), adds a new `get_vex_document` API call, and introduces `VexHelper` to process OpenVEX documents via `VexProcessor`. VEX processing is best-effort and non-blocking; webhook success does not depend on VEX availability. The threat model identifies no critical or high risks; existing mitigations (input validation, no exception leakage, parameterised queries) apply.

## Assets and Trust Boundaries

| Asset | Description |
|-------|-------------|
| Sonatype API credentials | `SONATYPE_USERNAME`, `SONATYPE_PASSWORD` — used for VEX fetch |
| FalkorDB graph | VEX statements, links to Defect/Version nodes |
| Webhook payload | `app_id`, `public_id` — already validated |
| VEX JSON document | Fetched from Sonatype; parsed and persisted |

| Trust Boundary | Description |
|----------------|-------------|
| External → Listener | Webhook POST; HMAC verified |
| Listener → Sonatype IQ | Outbound HTTPS; credentials in env |
| Listener → FalkorDB | Outbound; persistence layer |

## Threat Analysis

| # | Threat | STRIDE | Asset | Likelihood | Impact | Risk | Mitigation |
|---|--------|--------|-------|------------|--------|------|------------|
| 1 | Malformed VEX from Sonatype causes crash | T | VEX doc | Low | Low | Low | `get_vex_document` returns None on 404/invalid; `VexHelper` catches exceptions; webhook succeeds |
| 2 | VEX doc injection (malicious JSON) | T | FalkorDB | Low | Medium | Low | `VexProcessor` validates structure; persistence uses parameterised Cypher |
| 3 | Credential exposure in logs | I | Credentials | Low | High | Low | No new credential logging; existing pattern |
| 4 | Exception details in HTTP response | I | Internal state | Low | Medium | Low | AGENTS.md: never include exception details in responses; VEX failures logged only |
| 5 | DoS via large VEX document | D | Listener | Low | Low | Low | Sonatype controls document size; no unbounded parsing |
| 6 | Path traversal in app_id | S/T | Sonatype API | Low | Low | Low | `app_id` validated by `_SONATYPE_ID_RE` before use |

## Third-Party Component Assessment

| Criterion | VexProcessor (sbom-graph-model) |
|-----------|---------------------------------|
| Already in use | Yes — existing model dependency |
| Input validation | Yes — `_validate_document` enforces structure |
| Parameterised queries | Yes — via Persistence layer |
| **Recommendation** | Use as-is |

## Recommendations

1. **Input validation**: Continue using `_SONATYPE_ID_RE` for `app_id`; `stage_id` is passed through `urlquote` to prevent injection.
2. **Fail-safe**: VEX processing must not block webhook success; wrap in try/except, log warning, continue.
3. **No exception leakage**: Per AGENTS.md, never return exception details to clients.
4. **Shared setup**: Extract common Persistence/SonaTypeClient init to avoid duplication and reduce cognitive load.

## Residual Risk

None. All identified threats are Low risk with existing or specified mitigations.
