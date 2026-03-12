# Threat Model: Phase F — CLI

## Summary

Phase F adds sbom-graph-cli: ingest, query, policy annotate, report export. CLI
calls sbom-graph-api via HTTP; no direct FalkorDB access. No critical or high
threats; token handling and input validation mitigate identified risks.

---

## Assets and Trust Boundaries

| Asset | Description |
|-------|-------------|
| API token | Bearer token for auth; env or config |
| SBOM files | Local path; CLI reads and POSTs |
| API responses | JSON; CLI parses for display/export |

| Trust Boundary | Description |
|----------------|-------------|
| User → CLI | Command-line args, env vars |
| CLI → API | HTTPS; auth header |

---

## Threat Analysis (STRIPED)

| # | Threat | STRIDE | Asset | Risk | Mitigation |
|---|--------|--------|-------|------|------------|
| 1 | Token in process list | I | Token | Low | Env var; avoid --token in history |
| 2 | Token in config file | I | Token | Low | File permissions; .gitignore |
| 3 | Path traversal in --sbom-file | T | Local FS | Low | Resolve path; validate exists |
| 4 | Malicious API response parsing | T | CLI | Low | Validate JSON; handle errors |
| 5 | Dependency: requests, click | D | Libs | Low | SCA; pinned versions |
| 6 | MITM on API connection | T | Network | Low | HTTPS only; verify certs |

---

## Recommendations

1. Prefer token from env (SBOM_GRAPH_TOKEN) over config file.
2. Validate file paths before read; fail on missing/invalid.
3. Use HTTPS; respect SSL verification (no --insecure).

---

## Residual Risk

None. Design approved for implementation.
