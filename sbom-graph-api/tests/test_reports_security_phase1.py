"""Phase 1 (TDD red) — security controls on the report/export surface.

Covers SRTM tests: TA-015 (rate limit → 429), TA-020 (export audit log),
TA-017 (internal_only consistency across paged fetch + count + stream),
TA-018 (no new data exposure vs the non-paged report).

Both fast-follows (rate limiting, audit logging) are IN SCOPE for Phase 1.
FAILS until the controls exist.
"""

from unittest.mock import MagicMock, patch

import pytest


def _paged_service(rows, total):
    svc = MagicMock()
    svc.get_all_projects.return_value = rows
    svc.count_all_projects.return_value = total
    svc.get_policy_annotations_for_purls.return_value = {}
    return svc


# --------------------------------------------------------------------------
# TA-015 — rate limiting on heavy endpoints
# --------------------------------------------------------------------------

class TestReportRateLimiting:
    def test_rapid_requests_eventually_throttled(self, client, monkeypatch):
        """TA-015: beyond the per-identity threshold, the endpoint returns 429."""
        from sbom_graph_api.routes.reports import _common
        # Contract: a configurable per-minute limit exists; force it low for the test.
        assert hasattr(_common, "REPORTS_RATE_LIMIT_PER_MINUTE"), \
            "Phase 1 must add a report rate-limit threshold"
        monkeypatch.setattr(_common, "REPORTS_RATE_LIMIT_PER_MINUTE", 3, raising=False)
        # reset any limiter state between runs if exposed
        if hasattr(_common, "_reset_rate_limiter"):
            _common._reset_rate_limiter()

        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = _paged_service([], 0)
            statuses = [client.get("/reports/projects?format=json&all=true").status_code
                        for _ in range(8)]
        assert 429 in statuses, f"expected a 429 after the threshold, got {statuses}"

    def test_stale_rate_entries_are_purged(self):
        """Memory-leak guard: the per-client rate-limit dict must not grow
        unboundedly — stale entries (older than the window) are evicted."""
        import time as _time

        from sbom_graph_api.routes.reports import _common
        _common._reset_rate_limiter()
        now = _time.monotonic()
        _common._rate_state["1.1.1.1"] = (5, now - _common._RATE_WINDOW_SECONDS - 10)
        _common._rate_state["2.2.2.2"] = (5, now)
        try:
            _common._cleanup_stale_rate_entries(now)
            assert "1.1.1.1" not in _common._rate_state  # stale → evicted
            assert "2.2.2.2" in _common._rate_state  # in-window → kept
        finally:
            _common._reset_rate_limiter()


# --------------------------------------------------------------------------
# TA-020 — export audit logging
# --------------------------------------------------------------------------

class TestExportAuditLog:
    def test_export_emits_access_record(self, client):
        """TA-020: a bulk export emits a structured access-log record."""
        from sbom_graph_api.routes.reports import _common
        assert hasattr(_common, "log_report_access"), \
            "Phase 1 must add a report access/audit logging hook"

        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g, \
                patch.object(_common, "log_report_access") as audit:
            g.return_value = _paged_service([], 0)
            resp = client.get("/reports/projects?format=json&all=true")

        assert resp.status_code in (200, 429)
        assert audit.called, "export must record an access-log entry"
        kwargs = audit.call_args.kwargs
        blob = {**kwargs, "_args": audit.call_args.args}
        flat = str(blob).lower()
        assert "json" in flat          # format recorded
        assert "projects" in flat      # endpoint/report recorded


# --------------------------------------------------------------------------
# TA-017 — internal_only consistency across page + count + stream
# --------------------------------------------------------------------------

class TestInternalOnlyConsistency:
    def test_internal_only_threaded_to_page_and_count(self, client):
        """TA-017/PRV-001: internal_only is passed to BOTH the paged fetch and the count."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = _paged_service(
                [{"project_name": "internal-lib", "version": "1.0.0", "package_url": None}], 1)
            resp = client.get("/reports/projects?internal_only=true")
        assert resp.status_code == 200

        # paged fetch received internal_only=True
        _, pk = g.return_value.get_all_projects.call_args
        assert pk.get("internal_only") is True or True in (g.return_value.get_all_projects.call_args[0] or [])
        # count received internal_only=True as well
        assert g.return_value.count_all_projects.called
        ca = g.return_value.count_all_projects.call_args
        assert (ca.kwargs.get("internal_only") is True) or (True in (ca.args or []))

    def test_internal_only_stream_passes_filter(self, client):
        """TA-017: the streamed JSON export path also fetches with internal_only=True."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = _paged_service([], 0)
            client.get("/reports/projects?format=json&all=true&internal_only=true")
        # every call to the paged getter must carry internal_only=True
        for c in g.return_value.get_all_projects.call_args_list:
            assert (c.kwargs.get("internal_only") is True) or (True in (c.args or []))


# --------------------------------------------------------------------------
# TA-018 — no new exposure vs the existing report
# --------------------------------------------------------------------------

class TestNoNewExposure:
    def test_json_export_columns_match_existing_fields(self, client):
        """TA-018: the paged JSON export exposes the same project fields as before
        (Phase 1 must not add columns — that is Phase 2)."""
        import json
        rows = [{"project_name": "p", "version": "1.0.0", "package_url": "pkg:pypi/p@1.0.0",
                 "spdx_id": "MIT", "risk_category": "low", "source_repo_url": None,
                 "direct_score": None, "effective_score": None, "confidence": None}]
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = _paged_service(rows, 1)
            resp = client.get("/reports/projects?format=json&all=true")
        if resp.status_code == 429:
            pytest.skip("rate limited in this run")
        doc = json.loads(b"".join(resp.response).decode() if resp.is_streamed else resp.data)
        data = doc.get("data", doc) if isinstance(doc, dict) else doc
        assert data and set(data[0].keys()) <= set(rows[0].keys()) | {"policy"}
