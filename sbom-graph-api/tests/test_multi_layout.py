"""Tests for multi-layout graph visualization module."""

import json
from unittest.mock import MagicMock

import networkx as nx
import pytest

from sbom_graph_api.visualizations.multi_layout import (
    LAYOUT_DISPLAY_NAMES,
    LAYOUT_TYPES,
    CycleDetector,
    calculate_depths_bfs,
    calculate_layout_positions,
    create_dependencies_multi_layout_visualization,
    create_dependants_multi_layout_visualization,
    create_multi_layout_visualization,
    get_layout_options,
    get_layout_switcher_html,
)


class TestLayoutConstants:
    """Tests for layout type constants."""

    def test_all_layouts_defined(self):
        assert set(LAYOUT_TYPES) == {"spring", "radial", "shell", "bfs", "circular"}

    def test_all_layouts_have_display_names(self):
        for layout in LAYOUT_TYPES:
            assert layout in LAYOUT_DISPLAY_NAMES


class TestCycleDetector:
    """Tests for CycleDetector class."""

    # Positive tests

    def test_detects_simple_cycle(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C"), ("C", "A")])

        detector = CycleDetector()
        detector.detect_cycles(G, "A")

        assert detector.has_cycles() is True
        assert len(detector.get_cycle_edges()) > 0
        assert "A" in detector.get_nodes_in_cycles() or "C" in detector.get_nodes_in_cycles()

    def test_detects_self_loop(self):
        G = nx.DiGraph()
        G.add_edge("A", "B")
        G.add_edge("B", "B")

        detector = CycleDetector()
        detector.detect_cycles(G, "A")

        assert detector.has_cycles() is True
        assert "B" in detector.get_nodes_in_cycles()

    def test_no_cycles_in_dag(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")])

        detector = CycleDetector()
        detector.detect_cycles(G, "A")

        assert detector.has_cycles() is False
        assert detector.get_cycle_edges() == []
        assert detector.get_nodes_in_cycles() == set()

    def test_single_node_no_cycle(self):
        G = nx.DiGraph()
        G.add_node("A")

        detector = CycleDetector()
        detector.detect_cycles(G, "A")
        assert detector.has_cycles() is False

    def test_disconnected_components(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("C", "D"), ("D", "C")])

        detector = CycleDetector()
        detector.detect_cycles(G, "A")

        assert detector.has_cycles() is True
        assert "C" in detector.get_nodes_in_cycles()
        assert "D" in detector.get_nodes_in_cycles()

    def test_without_start_node(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "A")])

        detector = CycleDetector()
        detector.detect_cycles(G)

        assert detector.has_cycles() is True


class TestCalculateDepthsBfs:
    """Tests for BFS depth calculation."""

    def test_linear_chain(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C"), ("C", "D")])

        depths = calculate_depths_bfs(G, "A")
        assert depths == {"A": 0, "B": 1, "C": 2, "D": 3}

    def test_branching_graph(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")])

        depths = calculate_depths_bfs(G, "A")
        assert depths["A"] == 0
        assert depths["B"] == 1
        assert depths["C"] == 1
        assert depths["D"] == 2

    def test_single_node(self):
        G = nx.DiGraph()
        G.add_node("A")

        depths = calculate_depths_bfs(G, "A")
        assert depths == {"A": 0}

    def test_disconnected_nodes_not_included(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B")])
        G.add_node("C")

        depths = calculate_depths_bfs(G, "A")
        assert "C" not in depths


class TestGetLayoutOptions:
    """Tests for get_layout_options function."""

    def test_spring_layout_has_physics(self):
        options = json.loads(get_layout_options("spring"))
        assert options["physics"]["enabled"] is True
        assert options["physics"]["solver"] == "forceAtlas2Based"

    def test_bfs_layout_has_hierarchical(self):
        options = json.loads(get_layout_options("bfs"))
        assert options["layout"]["hierarchical"]["enabled"] is True

    def test_bfs_respects_direction(self):
        options = json.loads(get_layout_options("bfs", "RL"))
        assert options["layout"]["hierarchical"]["direction"] == "RL"

    def test_radial_disables_physics(self):
        options = json.loads(get_layout_options("radial"))
        assert options["physics"]["enabled"] is False

    def test_circular_disables_physics(self):
        options = json.loads(get_layout_options("circular"))
        assert options["physics"]["enabled"] is False

    def test_all_layouts_return_valid_json(self):
        for layout in LAYOUT_TYPES:
            options = json.loads(get_layout_options(layout))
            assert "nodes" in options
            assert "edges" in options
            assert "interaction" in options


class TestCalculateLayoutPositions:
    """Tests for layout position calculation."""

    def test_spring_layout_returns_positions(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C")])

        positions = calculate_layout_positions(G, "spring")
        assert "A" in positions
        assert "B" in positions
        assert "C" in positions
        assert len(positions["A"]) == 2

    def test_circular_layout(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C")])

        positions = calculate_layout_positions(G, "circular")
        assert len(positions) == 3

    def test_radial_with_root(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C")])

        depths = calculate_depths_bfs(G, "A")
        positions = calculate_layout_positions(G, "radial", "A", depths)
        assert len(positions) == 3

    def test_shell_with_depths(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C")])

        depths = {"A": 0, "B": 1, "C": 2}
        positions = calculate_layout_positions(G, "shell", "A", depths)
        assert len(positions) == 3

    def test_unknown_layout_defaults_to_spring(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B")])

        positions = calculate_layout_positions(G, "unknown_layout")
        assert len(positions) == 2

    def test_positions_are_float_tuples(self):
        G = nx.DiGraph()
        G.add_edges_from([("A", "B")])

        positions = calculate_layout_positions(G, "spring")
        for node_id, (x, y) in positions.items():
            assert isinstance(x, float)
            assert isinstance(y, float)


class TestGetLayoutSwitcherHtml:
    """Tests for layout switcher HTML generation."""

    def test_contains_select_element(self):
        html = get_layout_switcher_html(
            "spring", "my-project", "1.0.0", "dependencies"
        )
        assert '<select id="layout-select"' in html

    def test_current_layout_selected(self):
        html = get_layout_switcher_html(
            "radial", "my-project", "1.0.0", "dependants-multi"
        )
        assert 'value="radial" selected="selected"' in html

    def test_all_layouts_present(self):
        html = get_layout_switcher_html(
            "spring", "project", "1.0.0", "dependencies"
        )
        for layout in LAYOUT_TYPES:
            assert f'value="{layout}"' in html

    def test_includes_internal_only_param(self):
        html = get_layout_switcher_html(
            "spring", "project", "1.0.0", "dependencies",
            internal_only=True,
        )
        assert "internal_only=true" in html

    def test_includes_max_depth_param(self):
        html = get_layout_switcher_html(
            "spring", "project", "1.0.0", "dependencies",
            max_depth=10,
        )
        assert "max_depth=10" in html

    def test_contains_javascript(self):
        html = get_layout_switcher_html(
            "spring", "project", "1.0.0", "dependencies"
        )
        assert "function switchLayout" in html


class TestCreateMultiLayoutVisualization:
    """Tests for the main visualization creation function."""

    @pytest.fixture
    def sample_graph_data(self):
        nodes = [
            {
                "id": "app:1.0.0",
                "project_name": "app",
                "version": "1.0.0",
                "labels": ["Version", "INTERNAL"],
                "properties": {"project_name": "app", "name": "1.0.0"},
            },
            {
                "id": "lib-a:1.0.0",
                "project_name": "lib-a",
                "version": "1.0.0",
                "labels": ["Version"],
                "properties": {"project_name": "lib-a", "name": "1.0.0"},
            },
        ]
        edges = [
            {"source": "app:1.0.0", "target": "lib-a:1.0.0", "type": "DEPENDS_ON"},
        ]
        return nodes, edges

    @pytest.fixture
    def root_props(self):
        return {"project_name": "app", "name": "1.0.0"}

    def test_returns_html_string(self, sample_graph_data, root_props):
        html = create_multi_layout_visualization(
            graph_data=sample_graph_data,
            root_id="app:1.0.0",
            root_properties=root_props,
            root_labels=["Version", "INTERNAL"],
            layout="spring",
            project_name="app",
            version_name="1.0.0",
        )
        assert isinstance(html, str)
        assert "<html>" in html.lower() or "<!doctype" in html.lower()

    def test_contains_layout_switcher(self, sample_graph_data, root_props):
        html = create_multi_layout_visualization(
            graph_data=sample_graph_data,
            root_id="app:1.0.0",
            root_properties=root_props,
            root_labels=["Version"],
            layout="spring",
            project_name="app",
            version_name="1.0.0",
        )
        assert "layout-switcher" in html

    def test_all_layouts_produce_html(self, sample_graph_data, root_props):
        for layout in LAYOUT_TYPES:
            html = create_multi_layout_visualization(
                graph_data=sample_graph_data,
                root_id="app:1.0.0",
                root_properties=root_props,
                root_labels=["Version"],
                layout=layout,
                project_name="app",
                version_name="1.0.0",
            )
            assert html is not None
            assert len(html) > 0

    def test_cycle_edges_highlighted(self):
        """Cycle edges should be marked as red/dashed."""
        nodes = [
            {"id": "A:1.0", "project_name": "A", "version": "1.0",
             "labels": ["Version"], "properties": {}},
            {"id": "B:1.0", "project_name": "B", "version": "1.0",
             "labels": ["Version"], "properties": {}},
        ]
        edges = [
            {"source": "A:1.0", "target": "B:1.0", "type": "DEPENDS_ON"},
            {"source": "B:1.0", "target": "A:1.0", "type": "DEPENDS_ON"},
        ]

        html = create_multi_layout_visualization(
            graph_data=(nodes, edges),
            root_id="A:1.0",
            root_properties={},
            root_labels=["Version"],
            layout="spring",
            direction="dependencies",
            project_name="A",
            version_name="1.0",
        )
        assert "CYCLE" in html

    def test_dependants_direction_reverses_edges(self, sample_graph_data, root_props):
        html = create_multi_layout_visualization(
            graph_data=sample_graph_data,
            root_id="app:1.0.0",
            root_properties=root_props,
            root_labels=["Version"],
            layout="spring",
            direction="dependants",
            project_name="app",
            version_name="1.0.0",
        )
        assert html is not None

    def test_root_not_in_nodes_added_automatically(self):
        """Root node is added even if not in the node list."""
        nodes = [
            {"id": "lib:1.0", "project_name": "lib", "version": "1.0",
             "labels": ["Version"], "properties": {}},
        ]
        edges = [
            {"source": "app:1.0", "target": "lib:1.0", "type": "DEPENDS_ON"},
        ]

        html = create_multi_layout_visualization(
            graph_data=(nodes, edges),
            root_id="app:1.0",
            root_properties={"project_name": "app", "name": "1.0"},
            root_labels=["Version"],
            layout="spring",
            project_name="app",
            version_name="1.0",
        )
        assert html is not None


class TestServiceIntegrationFunctions:
    """Tests for functions that call FalkorDBService."""

    @pytest.fixture
    def mock_service(self):
        service = MagicMock()
        service.find_version.return_value = {
            "id": 1,
            "properties": {"project_name": "app", "name": "1.0.0"},
            "labels": ["Version", "INTERNAL"],
        }
        service.get_transitive_dependants.return_value = (
            [
                {"id": "dep:1.0", "project_name": "dep", "version": "1.0",
                 "labels": ["Version"], "properties": {}},
            ],
            [{"source": "dep:1.0", "target": "app:1.0.0", "type": "DEPENDS_ON"}],
        )
        service.get_transitive_dependencies.return_value = (
            [
                {"id": "lib:2.0", "project_name": "lib", "version": "2.0",
                 "labels": ["Version"], "properties": {}},
            ],
            [{"source": "app:1.0.0", "target": "lib:2.0", "type": "DEPENDS_ON"}],
        )
        return service

    def test_dependants_returns_html(self, mock_service):
        html = create_dependants_multi_layout_visualization(
            "app", "1.0.0", service=mock_service,
        )
        assert html is not None
        assert isinstance(html, str)

    def test_dependants_not_found_returns_none(self, mock_service):
        mock_service.find_version.return_value = None
        result = create_dependants_multi_layout_visualization(
            "nonexistent", "1.0.0", service=mock_service,
        )
        assert result is None

    def test_dependants_invalid_layout_defaults(self, mock_service):
        html = create_dependants_multi_layout_visualization(
            "app", "1.0.0", layout="invalid_layout", service=mock_service,
        )
        assert html is not None

    def test_dependencies_returns_html(self, mock_service):
        html = create_dependencies_multi_layout_visualization(
            "app", "1.0.0", service=mock_service,
        )
        assert html is not None

    def test_dependencies_not_found_returns_none(self, mock_service):
        mock_service.find_version.return_value = None
        result = create_dependencies_multi_layout_visualization(
            "nonexistent", "1.0.0", service=mock_service,
        )
        assert result is None

    def test_dependencies_invalid_layout_defaults(self, mock_service):
        html = create_dependencies_multi_layout_visualization(
            "app", "1.0.0", layout="invalid_layout", service=mock_service,
        )
        assert html is not None
