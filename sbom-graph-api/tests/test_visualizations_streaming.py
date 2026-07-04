"""Phase 1 (TDD red) — bounded + streamed visualizations (§1f).

Covers SRTM tests: TA-006 / TA-012 (graph node/edge cap + truncation notice +
streamed HTML). FAILS until build_bounded_network + MAX_GRAPH_NODES/EDGES land.
"""

from unittest.mock import MagicMock, patch

# --------------------------------------------------------------------------
# Unit: build_bounded_network — TA-012
# --------------------------------------------------------------------------

class TestBuildBoundedNetwork:
    def test_caps_nodes_and_reports_truncation(self):
        """TA-012: consuming more edges than the cap stops at the cap and flags truncation."""
        from sbom_graph_api.visualizations.bipartite import build_bounded_network

        # 5000 distinct dependant edges → far beyond the node cap.
        edges = (
            {"dependant_project": f"dep-{i}", "dependant_version": "1.0.0",
             "target_project": "lib-a", "target_version": "1.0.0"}
            for i in range(5000)
        )
        net, truncated, dropped = build_bounded_network(
            edges, max_nodes=2000, max_edges=5000,
        )
        assert truncated is True
        assert dropped > 0
        # node count must not exceed the cap (target nodes + bounded dependants)
        assert len(net.get_nodes()) <= 2000 + 50

    def test_no_truncation_under_cap(self):
        from sbom_graph_api.visualizations.bipartite import build_bounded_network
        edges = [
            {"dependant_project": "dep-1", "dependant_version": "1.0.0",
             "target_project": "lib-a", "target_version": "1.0.0"},
        ]
        net, truncated, dropped = build_bounded_network(
            iter(edges), max_nodes=2000, max_edges=5000)
        assert truncated is False
        assert dropped == 0

    def test_max_graph_constants_exist(self):
        from sbom_graph_api.visualizations import bipartite
        assert bipartite.MAX_GRAPH_NODES >= 1
        assert bipartite.MAX_GRAPH_EDGES >= 1


# --------------------------------------------------------------------------
# Route: truncation notice surfaced + response streamed — TA-006
# --------------------------------------------------------------------------

class TestBipartiteRouteBounded:
    def test_oversized_graph_shows_truncation_banner(self, client):
        """TA-006: a huge dependant set renders a visible truncation notice, not an OOM."""
        big = [
            {"dependant_project": f"dep-{i}", "dependant_version": "1.0.0",
             "target_project": "lib-a", "target_version": "1.0.0"}
            for i in range(5000)
        ]
        with patch("sbom_graph_api.routes.visualizations.get_falkordb_service") as g:
            svc = MagicMock()
            svc.get_all_versions_of_project.return_value = ["1.0.0"]
            svc.get_direct_dependants.return_value = big
            g.return_value = svc
            resp = client.get("/visualizations/bipartite/lib-a")

        assert resp.status_code == 200
        body = resp.data.decode().lower()
        assert "truncat" in body, "must surface a truncation notice when the cap is exceeded"


# --------------------------------------------------------------------------
# Unit: bound_nodes_edges + inject_truncation_banner — Module 1
# --------------------------------------------------------------------------

class TestBoundedNodeEdgeUtils:
    def test_bound_nodes_edges_caps_nodes(self):
        from sbom_graph_api.visualizations._bounded import bound_nodes_edges
        nodes = [{"id": f"n{i}"} for i in range(10)]
        edges = [{"source": "n0", "target": f"n{i}"} for i in range(1, 10)]
        bn, be, truncated, dropped = bound_nodes_edges(nodes, edges, 5, 100)
        assert len(bn) == 5
        assert truncated is True
        assert dropped > 0

    def test_bound_nodes_edges_retains_root(self):
        from sbom_graph_api.visualizations._bounded import bound_nodes_edges
        nodes = [{"id": f"n{i}"} for i in range(10)]
        edges = []
        bn, be, truncated, dropped = bound_nodes_edges(nodes, edges, 3, 100, root_id="n9")
        kept_ids = {n["id"] for n in bn}
        assert "n9" in kept_ids

    def test_bound_nodes_edges_caps_edges(self):
        from sbom_graph_api.visualizations._bounded import bound_nodes_edges
        nodes = [{"id": f"n{i}"} for i in range(5)]
        edges = [{"source": "n0", "target": f"n{i}"} for i in range(1, 5)]
        bn, be, truncated, dropped = bound_nodes_edges(nodes, edges, 100, 2)
        assert len(be) == 2
        assert truncated is True

    def test_inject_truncation_banner_in_body(self):
        from sbom_graph_api.visualizations._bounded import inject_truncation_banner
        html = "<html><body>content</body></html>"
        result = inject_truncation_banner(html, 100, 50)
        assert "truncat" in result.lower()
        assert "graph-truncation" in result

    def test_no_truncation_under_cap(self):
        from sbom_graph_api.visualizations._bounded import bound_nodes_edges
        nodes = [{"id": f"n{i}"} for i in range(3)]
        edges = [{"source": "n0", "target": "n1"}]
        bn, be, truncated, dropped = bound_nodes_edges(nodes, edges, 100, 100)
        assert truncated is False
        assert dropped == 0


# --------------------------------------------------------------------------
# Route: remaining viz builders streamed + truncation — Module 1
# --------------------------------------------------------------------------

class TestRemainingVizsStreamed:
    def test_dependants_graph_streams(self, client):
        svc = MagicMock()
        svc.find_version.return_value = {"properties": {}, "labels": []}
        svc.get_transitive_dependants.return_value = (
            [{"id": "a:1.0", "project_name": "a", "version": "1.0", "labels": [], "properties": {}}],
            [],
        )
        with patch("sbom_graph_api.visualizations.dependants_graph.get_falkordb_service", return_value=svc):
            resp = client.get("/visualizations/dependants/a/1.0")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type

    def test_dependants_graph_oversized_shows_banner(self, client):
        big_nodes = [
            {"id": f"n{i}:1.0", "project_name": f"n{i}", "version": "1.0", "labels": [], "properties": {}}
            for i in range(3000)
        ]
        svc = MagicMock()
        svc.find_version.return_value = {"properties": {}, "labels": []}
        svc.get_transitive_dependants.return_value = (big_nodes, [])
        with patch("sbom_graph_api.visualizations.dependants_graph.get_falkordb_service", return_value=svc):
            resp = client.get("/visualizations/dependants/a/1.0")
        assert resp.status_code == 200
        assert "truncat" in resp.data.decode().lower()

    def test_dependencies_graph_streams(self, client):
        svc = MagicMock()
        svc.find_version.return_value = {"properties": {}, "labels": []}
        svc.get_transitive_dependencies.return_value = (
            [{"id": "a:1.0", "project_name": "a", "version": "1.0", "labels": [], "properties": {}}],
            [],
        )
        # /visualizations/dependencies uses create_dependencies_multi_layout_visualization
        # which lives in multi_layout.py
        with patch("sbom_graph_api.visualizations.multi_layout.get_falkordb_service", return_value=svc):
            resp = client.get("/visualizations/dependencies/a/1.0")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type

    def test_kpartite_streams(self, client):
        svc = MagicMock()
        svc.find_version.return_value = {"properties": {}, "labels": []}
        svc.get_transitive_dependencies.return_value = (
            [{"id": "a:1.0", "project_name": "a", "version": "1.0", "labels": [], "properties": {}}],
            [],
        )
        svc.get_vulnerability_severities_for_versions.return_value = {}
        svc.get_license_risks_for_versions.return_value = {}
        svc.get_vex_statuses_for_versions.return_value = {}
        with patch("sbom_graph_api.visualizations.kpartite.get_falkordb_service", return_value=svc):
            resp = client.get("/visualizations/kpartite/a/1.0")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type


# --------------------------------------------------------------------------
# Unit: bound_nodes_edges + inject_truncation_banner — TA-012
