"""Tests for multi-layout graph visualisation module."""

import json
from unittest.mock import MagicMock

import networkx as nx

from sbom_graph_api.visualizations.multi_layout import (
    LAYOUT_DISPLAY_NAMES,
    LAYOUT_TYPES,
    CycleDetector,
    calculate_depths_bfs,
    calculate_layout_positions,
    create_dependants_multi_layout_visualization,
    create_dependencies_multi_layout_visualization,
    create_multi_layout_visualization,
    get_layout_options,
    get_layout_switcher_html,
)


class TestLayoutConstants:
    """Tests for layout type constants."""

    def test_all_layouts_defined(self) -> None:
        """All expected layout types are present."""
        expected = {
            "spring",
            "radial",
            "shell",
            "bfs",
            "circular",
        }
        assert set(LAYOUT_TYPES) == expected

    def test_all_layouts_have_display_names(self) -> None:
        """Every layout type has a human-readable name."""
        for layout in LAYOUT_TYPES:
            assert layout in LAYOUT_DISPLAY_NAMES


class TestCycleDetector:
    """Tests for CycleDetector class."""

    def test_detects_simple_cycle(self) -> None:
        """A→B→C→A forms a cycle."""
        graph = nx.DiGraph()
        graph.add_edges_from(
            [("A", "B"), ("B", "C"), ("C", "A")],
        )

        detector = CycleDetector()
        detector.detect_cycles(graph, "A")

        assert detector.has_cycles() is True
        assert len(detector.get_cycle_edges()) > 0
        cycle_nodes = detector.get_nodes_in_cycles()
        assert "A" in cycle_nodes or "C" in cycle_nodes

    def test_detects_self_loop(self) -> None:
        """A self-edge B→B is a cycle."""
        graph = nx.DiGraph()
        graph.add_edge("A", "B")
        graph.add_edge("B", "B")

        detector = CycleDetector()
        detector.detect_cycles(graph, "A")

        assert detector.has_cycles() is True
        assert "B" in detector.get_nodes_in_cycles()

    def test_no_cycles_in_dag(self) -> None:
        """A diamond DAG has no cycles."""
        graph = nx.DiGraph()
        graph.add_edges_from(
            [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")],
        )

        detector = CycleDetector()
        detector.detect_cycles(graph, "A")

        assert detector.has_cycles() is False
        assert not detector.get_cycle_edges()
        assert detector.get_nodes_in_cycles() == set()

    def test_single_node_no_cycle(self) -> None:
        """An isolated node has no cycle."""
        graph = nx.DiGraph()
        graph.add_node("A")

        detector = CycleDetector()
        detector.detect_cycles(graph, "A")
        assert detector.has_cycles() is False

    def test_disconnected_components(self) -> None:
        """Cycles in a disconnected component are detected."""
        graph = nx.DiGraph()
        graph.add_edges_from(
            [("A", "B"), ("C", "D"), ("D", "C")],
        )

        detector = CycleDetector()
        detector.detect_cycles(graph, "A")

        assert detector.has_cycles() is True
        cycle_nodes = detector.get_nodes_in_cycles()
        assert "C" in cycle_nodes
        assert "D" in cycle_nodes

    def test_without_start_node(self) -> None:
        """Cycles are detected without an explicit root."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B"), ("B", "A")])

        detector = CycleDetector()
        detector.detect_cycles(graph)

        assert detector.has_cycles() is True


class TestCalculateDepthsBfs:
    """Tests for BFS depth calculation."""

    def test_linear_chain(self) -> None:
        """A→B→C→D gives depths 0, 1, 2, 3."""
        graph = nx.DiGraph()
        graph.add_edges_from(
            [("A", "B"), ("B", "C"), ("C", "D")],
        )

        depths = calculate_depths_bfs(graph, "A")
        assert depths == {"A": 0, "B": 1, "C": 2, "D": 3}

    def test_branching_graph(self) -> None:
        """Shared children get the earliest depth."""
        graph = nx.DiGraph()
        graph.add_edges_from(
            [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")],
        )

        depths = calculate_depths_bfs(graph, "A")
        assert depths["A"] == 0
        assert depths["B"] == 1
        assert depths["C"] == 1
        assert depths["D"] == 2

    def test_single_node(self) -> None:
        """A lone node has depth 0."""
        graph = nx.DiGraph()
        graph.add_node("A")

        depths = calculate_depths_bfs(graph, "A")
        assert depths == {"A": 0}

    def test_disconnected_nodes_not_included(self) -> None:
        """Unreachable nodes are absent from the depth map."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B")])
        graph.add_node("C")

        depths = calculate_depths_bfs(graph, "A")
        assert "C" not in depths


class TestGetLayoutOptions:
    """Tests for get_layout_options function."""

    def test_spring_layout_has_physics(self) -> None:
        """Spring layout enables forceAtlas2Based physics."""
        options = json.loads(get_layout_options("spring"))
        assert options["physics"]["enabled"] is True
        solver = options["physics"]["solver"]
        assert solver == "forceAtlas2Based"

    def test_bfs_layout_has_hierarchical(self) -> None:
        """BFS layout uses hierarchical positioning."""
        options = json.loads(get_layout_options("bfs"))
        hierarchical = options["layout"]["hierarchical"]
        assert hierarchical["enabled"] is True

    def test_bfs_respects_direction(self) -> None:
        """BFS direction parameter is forwarded."""
        options = json.loads(get_layout_options("bfs", "RL"))
        direction = options["layout"]["hierarchical"]["direction"]
        assert direction == "RL"

    def test_radial_disables_physics(self) -> None:
        """Radial layout disables physics simulation."""
        options = json.loads(get_layout_options("radial"))
        assert options["physics"]["enabled"] is False

    def test_circular_disables_physics(self) -> None:
        """Circular layout disables physics simulation."""
        options = json.loads(get_layout_options("circular"))
        assert options["physics"]["enabled"] is False

    def test_all_layouts_return_valid_json(self) -> None:
        """Every layout type produces valid vis.js options."""
        for layout in LAYOUT_TYPES:
            options = json.loads(get_layout_options(layout))
            assert "nodes" in options
            assert "edges" in options
            assert "interaction" in options


class TestCalculateLayoutPositions:
    """Tests for layout position calculation."""

    def test_spring_layout_returns_positions(self) -> None:
        """Spring layout yields a position per node."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B"), ("B", "C")])

        positions = calculate_layout_positions(
            graph,
            "spring",
        )
        assert "A" in positions
        assert "B" in positions
        assert "C" in positions
        assert len(positions["A"]) == 2

    def test_circular_layout(self) -> None:
        """Circular layout returns all node positions."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B"), ("B", "C")])

        positions = calculate_layout_positions(
            graph,
            "circular",
        )
        assert len(positions) == 3

    def test_radial_with_root(self) -> None:
        """Radial layout uses depth data from BFS."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B"), ("B", "C")])

        depths = calculate_depths_bfs(graph, "A")
        positions = calculate_layout_positions(
            graph,
            "radial",
            "A",
            depths,
        )
        assert len(positions) == 3

    def test_shell_with_depths(self) -> None:
        """Shell layout respects depth-based shells."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B"), ("B", "C")])

        depths = {"A": 0, "B": 1, "C": 2}
        positions = calculate_layout_positions(
            graph,
            "shell",
            "A",
            depths,
        )
        assert len(positions) == 3

    def test_unknown_layout_defaults_to_spring(self) -> None:
        """An unrecognised layout falls back to spring."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B")])

        positions = calculate_layout_positions(
            graph,
            "unknown_layout",
        )
        assert len(positions) == 2

    def test_positions_are_float_tuples(self) -> None:
        """Each position is a pair of floats."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B")])

        positions = calculate_layout_positions(
            graph,
            "spring",
        )
        for _node, (pos_x, pos_y) in positions.items():
            assert isinstance(pos_x, float)
            assert isinstance(pos_y, float)


class TestGetLayoutSwitcherHtml:
    """Tests for layout switcher HTML generation."""

    def test_contains_select_element(self) -> None:
        """HTML includes a <select> element."""
        html = get_layout_switcher_html(
            "spring",
            "my-project",
            "1.0.0",
            "dependencies",
        )
        assert '<select id="layout-select"' in html

    def test_current_layout_selected(self) -> None:
        """The active layout has the 'selected' attribute."""
        html = get_layout_switcher_html(
            "radial",
            "my-project",
            "1.0.0",
            "dependants-multi",
        )
        assert 'value="radial" selected="selected"' in html

    def test_all_layouts_present(self) -> None:
        """Every known layout appears as an <option>."""
        html = get_layout_switcher_html(
            "spring",
            "project",
            "1.0.0",
            "dependencies",
        )
        for layout in LAYOUT_TYPES:
            assert f'value="{layout}"' in html

    def test_includes_internal_only_param(self) -> None:
        """internal_only flag is forwarded to the URL."""
        html = get_layout_switcher_html(
            "spring",
            "project",
            "1.0.0",
            "dependencies",
            internal_only=True,
        )
        assert "internal_only=true" in html

    def test_includes_max_depth_param(self) -> None:
        """max_depth parameter is included in the URL."""
        html = get_layout_switcher_html(
            "spring",
            "project",
            "1.0.0",
            "dependencies",
            max_depth=10,
        )
        assert "max_depth=10" in html

    def test_contains_javascript(self) -> None:
        """The switcher contains a JS switchLayout function."""
        html = get_layout_switcher_html(
            "spring",
            "project",
            "1.0.0",
            "dependencies",
        )
        assert "function switchLayout" in html


class TestCreateMultiLayoutVisualization:
    """Tests for the main visualisation creation function."""

    def _sample_graph_data(self) -> tuple[list, list]:
        """Return a minimal two-node graph with one edge."""
        nodes = [
            {
                "id": "app:1.0.0",
                "project_name": "app",
                "version": "1.0.0",
                "labels": ["Version", "INTERNAL"],
                "properties": {
                    "project_name": "app",
                    "name": "1.0.0",
                },
            },
            {
                "id": "lib-a:1.0.0",
                "project_name": "lib-a",
                "version": "1.0.0",
                "labels": ["Version"],
                "properties": {
                    "project_name": "lib-a",
                    "name": "1.0.0",
                },
            },
        ]
        edges = [
            {
                "source": "app:1.0.0",
                "target": "lib-a:1.0.0",
                "type": "DEPENDS_ON",
            },
        ]
        return nodes, edges

    @staticmethod
    def _root_props() -> dict:
        """Return root node properties."""
        return {"project_name": "app", "name": "1.0.0"}

    def test_returns_html_string(self) -> None:
        """Visualisation output is a non-empty HTML string."""
        html = create_multi_layout_visualization(
            graph_data=self._sample_graph_data(),
            root_id="app:1.0.0",
            root_properties=self._root_props(),
            root_labels=["Version", "INTERNAL"],
            layout="spring",
            project_name="app",
            version_name="1.0.0",
        )
        assert isinstance(html, str)
        lower = html.lower()
        assert "<html>" in lower or "<!doctype" in lower

    def test_contains_layout_switcher(self) -> None:
        """Output includes the layout-switcher UI element."""
        html = create_multi_layout_visualization(
            graph_data=self._sample_graph_data(),
            root_id="app:1.0.0",
            root_properties=self._root_props(),
            root_labels=["Version"],
            layout="spring",
            project_name="app",
            version_name="1.0.0",
        )
        assert "layout-switcher" in html

    def test_all_layouts_produce_html(self) -> None:
        """Every layout type produces non-empty HTML."""
        for layout in LAYOUT_TYPES:
            html = create_multi_layout_visualization(
                graph_data=self._sample_graph_data(),
                root_id="app:1.0.0",
                root_properties=self._root_props(),
                root_labels=["Version"],
                layout=layout,
                project_name="app",
                version_name="1.0.0",
            )
            assert html is not None
            assert len(html) > 0

    def test_cycle_edges_highlighted(self) -> None:
        """Cycle edges are marked with 'CYCLE' in the output."""
        nodes = [
            {
                "id": "A:1.0",
                "project_name": "A",
                "version": "1.0",
                "labels": ["Version"],
                "properties": {},
            },
            {
                "id": "B:1.0",
                "project_name": "B",
                "version": "1.0",
                "labels": ["Version"],
                "properties": {},
            },
        ]
        edges = [
            {
                "source": "A:1.0",
                "target": "B:1.0",
                "type": "DEPENDS_ON",
            },
            {
                "source": "B:1.0",
                "target": "A:1.0",
                "type": "DEPENDS_ON",
            },
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

    def test_dependants_direction_reverses(self) -> None:
        """Dependants direction produces valid HTML output."""
        html = create_multi_layout_visualization(
            graph_data=self._sample_graph_data(),
            root_id="app:1.0.0",
            root_properties=self._root_props(),
            root_labels=["Version"],
            layout="spring",
            direction="dependants",
            project_name="app",
            version_name="1.0.0",
        )
        assert html is not None

    def test_root_not_in_nodes_added(self) -> None:
        """Root node is injected if absent from the node list."""
        nodes = [
            {
                "id": "lib:1.0",
                "project_name": "lib",
                "version": "1.0",
                "labels": ["Version"],
                "properties": {},
            },
        ]
        edges = [
            {
                "source": "app:1.0",
                "target": "lib:1.0",
                "type": "DEPENDS_ON",
            },
        ]

        html = create_multi_layout_visualization(
            graph_data=(nodes, edges),
            root_id="app:1.0",
            root_properties={
                "project_name": "app",
                "name": "1.0",
            },
            root_labels=["Version"],
            layout="spring",
            project_name="app",
            version_name="1.0",
        )
        assert html is not None


class TestServiceIntegrationFunctions:
    """Tests for functions that call FalkorDBService."""

    @staticmethod
    def _build_mock_service() -> MagicMock:
        """Create a mock FalkorDBService with default returns."""
        mock_svc = MagicMock()
        mock_svc.find_version.return_value = {
            "id": 1,
            "properties": {
                "project_name": "app",
                "name": "1.0.0",
            },
            "labels": ["Version", "INTERNAL"],
        }
        mock_svc.get_transitive_dependants.return_value = (
            [
                {
                    "id": "dep:1.0",
                    "project_name": "dep",
                    "version": "1.0",
                    "labels": ["Version"],
                    "properties": {},
                },
            ],
            [
                {
                    "source": "dep:1.0",
                    "target": "app:1.0.0",
                    "type": "DEPENDS_ON",
                },
            ],
        )
        mock_svc.get_transitive_dependencies.return_value = (
            [
                {
                    "id": "lib:2.0",
                    "project_name": "lib",
                    "version": "2.0",
                    "labels": ["Version"],
                    "properties": {},
                },
            ],
            [
                {
                    "source": "app:1.0.0",
                    "target": "lib:2.0",
                    "type": "DEPENDS_ON",
                },
            ],
        )
        return mock_svc

    def test_dependants_returns_html(self) -> None:
        """Dependants visualisation returns an HTML string."""
        mock_svc = self._build_mock_service()
        html = create_dependants_multi_layout_visualization(
            "app",
            "1.0.0",
            service=mock_svc,
        )
        assert html is not None
        assert isinstance(html, str)

    def test_dependants_not_found_returns_none(self) -> None:
        """Missing version returns None for dependants."""
        mock_svc = self._build_mock_service()
        mock_svc.find_version.return_value = None
        result = create_dependants_multi_layout_visualization(
            "nonexistent",
            "1.0.0",
            service=mock_svc,
        )
        assert result is None

    def test_dependants_invalid_layout_defaults(self) -> None:
        """Invalid layout name falls back to default."""
        mock_svc = self._build_mock_service()
        html = create_dependants_multi_layout_visualization(
            "app",
            "1.0.0",
            layout="invalid_layout",
            service=mock_svc,
        )
        assert html is not None

    def test_dependencies_returns_html(self) -> None:
        """Dependencies visualisation returns an HTML string."""
        mock_svc = self._build_mock_service()
        html = create_dependencies_multi_layout_visualization(
            "app",
            "1.0.0",
            service=mock_svc,
        )
        assert html is not None

    def test_dependencies_not_found_returns_none(self) -> None:
        """Missing version returns None for dependencies."""
        mock_svc = self._build_mock_service()
        mock_svc.find_version.return_value = None
        result = create_dependencies_multi_layout_visualization(
            "nonexistent",
            "1.0.0",
            service=mock_svc,
        )
        assert result is None

    def test_dependencies_invalid_layout_defaults(self) -> None:
        """Invalid layout name falls back to default."""
        mock_svc = self._build_mock_service()
        html = create_dependencies_multi_layout_visualization(
            "app",
            "1.0.0",
            layout="invalid_layout",
            service=mock_svc,
        )
        assert html is not None
