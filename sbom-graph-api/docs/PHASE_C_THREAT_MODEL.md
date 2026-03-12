# Threat Model: Phase C — New API Routes

## Summary

Phase C adds report and API routes: enrichment-coverage, license-dashboard,
trust-score-gaps, incident-response, source-impact, sbom-inventory, sbom-coverage,
/admin/policies, blast-radius, source-impact visualizations. No critical or high
threats; input validation and parameterised queries mitigate identified risks.

---

## Assets and Trust Boundaries

| Asset | Description |
|-------|-------------|
| Report endpoints | HTML/Excel/JSON output; path/query params |
| Admin policies | Policy CRUD; admin-only |
| FalkorDB | Read queries for reports |

| Trust Boundary | Description |
|----------------|-------------|
| User → API | GET/POST/DELETE; auth when enabled |
| Admin → /admin/policies | Admin role required |

---

## Threat Analysis (STRIPED)

| # | Threat | STRIDE | Asset | Risk | Mitigation |
|---|--------|--------|-------|------|------------|
| 1 | Path traversal in defect_id/purl | S/T | API | Low | validate_defect_id; validate_purl |
| 2 | IDOR: non-admin access to policies | E | Admin | Low | @admin_required decorator |
| 3 | Cypher injection via search params | T | FalkorDB | Low | Parameterised queries |
| 4 | Info disclosure via error messages | I | Internal | Low | AGENTS.md: no exception details |
| 5 | DoS via expensive graph queries | D | API | Low | limit, max_depth bounds |
| 6 | Dependency: openpyxl, pandas | D | Excel | Low | SCA; pinned versions |

---

## Recommendations

1. Validate all path and query params (defect_id, purl, limit, max_depth).
2. Enforce admin-only on POST/DELETE /admin/policies.
3. CSRF protection on policy admin forms.

---

## Residual Risk

None. Design approved for implementation.
