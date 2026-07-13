"""Phase 1 (TDD red) — pagination params, paged service methods, paging view.

Covers SRTM tests: TA-001, TA-002, TA-007, TA-008, TA-009, TA-010, TA-011,
TA-016, TA-017, TA-018, TA-019. These FAIL until the Phase 1 implementation exists
(new symbols: validate_page/validate_page_size, parse_pagination/PageRequest,
iterate_pages, count_all_projects/count_all_applications, offset-aware getters,
build_page_view/PageView). New symbols are imported inside each test so failures
are per-test and descriptive rather than a single collection error.
"""

from unittest.mock import MagicMock, patch

import pytest

from sbom_graph_api.config import FalkorDBConfig


@pytest.fixture
def fdb_config():
    return FalkorDBConfig(
        host="h", port=6379, password="p", graph_name="g",
        socket_timeout=30.0, socket_connect_timeout=10.0,
        internal_label="INTERNAL", ssl=False, ssl_ca_certs=None,
    )


@pytest.fixture
def service(fdb_config):
    from sbom_graph_api.services.falkordb_service import FalkorDBService
    return FalkorDBService(fdb_config)


# --------------------------------------------------------------------------
# Validation bounds — TA-009 (page_size), TA-010 (page/offset)
# --------------------------------------------------------------------------

class TestValidationBounds:
    @pytest.mark.parametrize(
        "raw,expected",
        [(None, 100), (50, 50), (1, 1), (1000, 1000), (1001, 100),
         (0, 100), (-1, 100), (99999999, 100), ("abc", 100)],
    )
    def test_validate_page_size_clamps(self, raw, expected):
        """TA-009: page_size ∈ [1,1000] default 100; invalid/oversized → default."""
        from sbom_graph_api.utils.validation import validate_page_size
        assert validate_page_size(raw) == expected

    def test_max_page_size_constant(self):
        """TA-009: MAX_PAGE_SIZE is 1000."""
        from sbom_graph_api.utils.validation import MAX_PAGE_SIZE
        assert MAX_PAGE_SIZE == 1000

    @pytest.mark.parametrize(
        "raw,expected",
        [(None, 1), (1, 1), (5, 5), (0, 1), (-3, 1), ("abc", 1)],
    )
    def test_validate_page_clamps(self, raw, expected):
        """TA-010: page ≥ 1, default 1; invalid → default."""
        from sbom_graph_api.utils.validation import validate_page
        assert validate_page(raw) == expected


# --------------------------------------------------------------------------
# parse_pagination / PageRequest — TA-001, TA-019
# --------------------------------------------------------------------------

class TestPageRequest:
    def test_offset_is_zero_based_from_page(self, app):
        """TA-001: offset = (page-1)*page_size."""
        from sbom_graph_api.routes.reports._common import parse_pagination
        with app.test_request_context("/x?page=3&page_size=100"):
            req = parse_pagination()
        assert req.page == 3
        assert req.page_size == 100
        assert req.offset == 200
        assert req.unlimited is False

    def test_all_flag_parsed(self, app):
        """TA-002: all=true sets unlimited."""
        from sbom_graph_api.routes.reports._common import parse_pagination
        with app.test_request_context("/x?all=true"):
            req = parse_pagination()
        assert req.unlimited is True

    def test_offset_capped_at_result_window(self, app):
        """TA-019: deep offset clamped to MAX_RESULT_WINDOW (no unbounded SKIP)."""
        from sbom_graph_api.routes.reports._common import MAX_RESULT_WINDOW, parse_pagination
        with app.test_request_context("/x?page=999999999&page_size=1000"):
            req = parse_pagination()
        assert req.offset <= MAX_RESULT_WINDOW


# --------------------------------------------------------------------------
# Generic page generator — TA-008 (no buffered path / constant memory)
# --------------------------------------------------------------------------

class TestIteratePages:
    def test_yields_pages_until_short_page(self):
        """TA-008: iterate_pages walks offsets and stops on a short final page."""
        from sbom_graph_api.services.falkordb_service import iterate_pages
        data = list(range(250))

        calls = []

        def fetch(offset, limit):
            calls.append((offset, limit))
            return data[offset:offset + limit]

        pages = list(iterate_pages(fetch, chunk=100))
        assert [len(p) for p in pages] == [100, 100, 50]
        assert calls == [(0, 100), (100, 100), (200, 100)]

    def test_never_requests_more_than_one_chunk(self):
        """TA-008: the fetcher is never asked for the whole dataset at once."""
        from sbom_graph_api.services.falkordb_service import iterate_pages

        def fetch(offset, limit):
            assert limit <= 1000, "chunk must stay bounded (no buffered path)"
            return list(range(offset, min(offset + limit, 5000)))[:limit] if offset < 5000 else []

        total = sum(len(p) for p in iterate_pages(fetch, chunk=1000))
        assert total == 5000

    def test_empty_first_page_terminates(self):
        from sbom_graph_api.services.falkordb_service import iterate_pages
        assert list(iterate_pages(lambda _offset, _limit: [], chunk=100)) == []


# --------------------------------------------------------------------------
# Paged service methods + counts — TA-011, TA-016, TA-017
# --------------------------------------------------------------------------

class TestPagedServiceMethods:
    def test_get_all_projects_accepts_offset_and_parameterises(self, service):
        """TA-011: SKIP/LIMIT use query params or a validated integer literal —
        never an interpolated user string."""
        import re
        with patch.object(service, "execute_query", return_value=[]) as ex:
            service.get_all_projects(limit=10, offset=20, internal_only=False)
        assert ex.called
        query, params = ex.call_args[0][0], (ex.call_args[0][1] if len(ex.call_args[0]) > 1 else {})
        # limit always parameterised (LIMIT $limit is the established pattern)
        assert params.get("limit") == 10
        # offset either parameterised ($offset) OR a validated integer literal (SKIP 20)
        assert params.get("offset") == 20 or re.search(r"SKIP\s+20\b", query)

    def test_get_all_applications_accepts_offset(self, service):
        """TA-011: applications getter is offset-aware too."""
        with patch.object(service, "execute_query", return_value=[]) as ex:
            service.get_all_applications(limit=5, offset=15, internal_only=False)
        assert ex.called

    def test_count_all_projects_returns_int(self, service):
        """TA-016: count_all_projects returns the total as an int."""
        with patch.object(service, "execute_query", return_value=[[42]]):
            assert service.count_all_projects(internal_only=False) == 42

    def test_count_uses_same_internal_label_as_page(self, service):
        """TA-017/PRV-001: the count query applies the SAME :INTERNAL filter as the page query."""
        captured = {}

        def spy(query, params=None):
            captured.setdefault("queries", []).append(query)
            return [[0]]

        with patch.object(service, "execute_query", side_effect=spy):
            service.count_all_projects(internal_only=True)
        assert any("INTERNAL" in q for q in captured["queries"]), \
            "count must include the INTERNAL label when internal_only=True"

    def test_internal_only_false_count_has_no_internal_label(self, service):
        captured = []
        with patch.object(service, "execute_query", side_effect=lambda q, p=None: captured.append(q) or [[0]]):
            service.count_all_projects(internal_only=False)
        assert not any(":INTERNAL" in q for q in captured)


# --------------------------------------------------------------------------
# HTML paging behaviour at the route — TA-001, TA-005, TA-007, TA-016, TA-018
# --------------------------------------------------------------------------

class TestProjectsPagingRoute:
    def _mock_service(self, rows, total):
        svc = MagicMock()
        svc.get_all_projects.return_value = rows
        svc.count_all_projects.return_value = total
        svc.get_policy_annotations_for_purls.return_value = {}
        return svc

    def test_html_requests_single_bounded_page(self, client):
        """TA-001/TA-008: HTML fetches ONE page (offset/limit), never the whole set."""
        from sbom_graph_api.utils.validation import MAX_PAGE_SIZE
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = self._mock_service(
                [{"project_name": "a", "version": "1", "package_url": None}], 500)
            resp = client.get("/reports/projects?page=2&page_size=100")
        assert resp.status_code == 200
        _, kwargs = g.return_value.get_all_projects.call_args
        limit = kwargs.get("limit", (g.return_value.get_all_projects.call_args[0] or [None])[0])
        assert limit is not None and limit <= MAX_PAGE_SIZE
        assert g.return_value.count_all_projects.called

    def test_html_renders_pagination_controls(self, client):
        """TA-005: page nav + 'Page X of Y (N total)' present."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = self._mock_service(
                [{"project_name": "a", "version": "1", "package_url": None}], 500)
            resp = client.get("/reports/projects?page=2&page_size=100")
        html = resp.data.decode()
        assert "Page 2 of 5" in html
        assert "500" in html  # total surfaced

    def test_oversized_page_size_does_not_blow_up(self, client):
        """TA-009 (route): page_size=99999999 → clamped, still 200, bounded fetch."""
        from sbom_graph_api.utils.validation import MAX_PAGE_SIZE
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = self._mock_service([], 0)
            resp = client.get("/reports/projects?page_size=99999999")
        assert resp.status_code == 200
        _, kwargs = g.return_value.get_all_projects.call_args
        limit = kwargs.get("limit", (g.return_value.get_all_projects.call_args[0] or [None])[0])
        assert limit <= MAX_PAGE_SIZE

    def test_legacy_limit_still_honoured(self, client):
        """TA-007: legacy ?limit=50 still bounds the page to ≤50 rows."""
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            g.return_value = self._mock_service([], 0)
            resp = client.get("/reports/projects?limit=50")
        assert resp.status_code == 200
        _, kwargs = g.return_value.get_all_projects.call_args
        limit = kwargs.get("limit", (g.return_value.get_all_projects.call_args[0] or [None])[0])
        assert limit == 50


# --------------------------------------------------------------------------
# Rolled-out list reports — snapshots & self-dependencies (follow-on)
# --------------------------------------------------------------------------

class TestRolledOutListReports:
    def _svc(self, rows, total):
        svc = MagicMock()
        svc.find_snapshot_dependencies.return_value = rows
        svc.count_snapshot_dependencies.return_value = total
        svc.find_self_dependencies.return_value = rows
        svc.count_self_dependencies.return_value = total
        return svc

    def test_snapshots_paged_and_counted(self, client):
        """Snapshots: HTML page is offset-aware and a count query backs the pager."""
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as g:
            g.return_value = self._svc(
                [{"application": "a", "app_version": "1", "dependency": "d",
                  "dep_version": "1-SNAPSHOT"}], 500)
            resp = client.get("/reports/snapshots?page=2&page_size=100&internal_only=true")
        assert resp.status_code == 200
        assert "Page 2 of 5" in resp.data.decode()
        _, kw = g.return_value.find_snapshot_dependencies.call_args
        assert kw.get("limit") == 100 and kw.get("offset") == 100
        assert kw.get("internal_only") is True
        assert g.return_value.count_snapshot_dependencies.called

    def test_snapshots_json_streamed(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as g:
            g.return_value = self._svc([], 0)
            resp = client.get("/reports/snapshots?format=json&all=true")
        assert resp.status_code == 200
        assert "application/json" in resp.content_type

    def test_self_dependencies_paged_and_counted(self, client):
        with patch("sbom_graph_api.routes.reports.dependencies.get_falkordb_service") as g:
            g.return_value = self._svc(
                [{"project_name": "p", "version": "1", "relationship_type": "DEPENDS_ON"}], 7)
            resp = client.get("/reports/self-dependencies?page=1&page_size=25")
        assert resp.status_code == 200
        _, kw = g.return_value.find_self_dependencies.call_args
        assert kw.get("limit") == 25 and kw.get("offset") == 0
        assert g.return_value.count_self_dependencies.called

    def test_source_repos_paged_and_counted(self, client):
        with patch("sbom_graph_api.routes.reports.inventory.get_falkordb_service") as g:
            svc = MagicMock()
            svc.get_all_source_repos.return_value = [
                {"url": "https://g/r", "vcs_type": "git", "namespace": "g",
                 "name": "r", "package_count": 3}]
            svc.count_source_repos.return_value = 300
            g.return_value = svc
            resp = client.get("/reports/source-repos?page=2&page_size=100&internal_only=true")
        assert resp.status_code == 200
        assert "Page 2 of 3" in resp.data.decode()
        _, kw = svc.get_all_source_repos.call_args
        assert kw.get("limit") == 100 and kw.get("offset") == 100
        assert kw.get("internal_only") is True
        assert svc.count_source_repos.called
