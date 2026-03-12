# Threat Model: Phase E — UI Features

## Summary

Phase E adds UI features: internal-only toggle, dynamic download links, frozen
table headers, interactive API docs, blast-radius and source-impact
visualizations. No critical or high threats; client-side and server-side
validation mitigate identified risks.

---

## Assets and Trust Boundaries

| Asset | Description |
|-------|-------------|
| HTML templates | Jinja2-rendered; user-controlled params |
| Download links | Excel/JSON URLs with query params |
| Visualization iframes | Embed blast-radius, source-impact graphs |

| Trust Boundary | Description |
|----------------|-------------|
| Browser → API | GET with format, internal_only, etc. |
| API → FalkorDB | Read-only for reports |

---

## Threat Analysis (STRIPED)

| # | Threat | STRIDE | Asset | Risk | Mitigation |
|---|--------|--------|-------|------|------------|
| 1 | XSS via project_name in table | I | HTML | Low | Jinja2 auto-escapes; no raw |
| 2 | Open redirect via download URL | S | Links | Low | url_for(); no user-supplied |
| 3 | Content-Disposition header injection | I | Excel | Low | sanitize_content_disposition |
| 4 | CSS dimension injection (height/width) | T | Viz | Low | validate_css_dimension allowlist |
| 5 | DoS via large table rendering | D | API | Low | limit param; pagination |
| 6 | Dependency: PyVis, NetworkX | D | Viz | Low | SCA; pinned versions |

---

## Recommendations

1. Never render raw user input in HTML; use Jinja2 escaping.
2. Validate format, layout, height, width against allowlists.
3. Ensure download URLs use url_for() or validated params.

---

## Residual Risk

None. Design approved for implementation.
