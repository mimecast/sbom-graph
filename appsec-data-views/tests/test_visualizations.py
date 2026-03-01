"""Tests for visualization modules."""

from unittest.mock import MagicMock

from appsec_data_views.visualizations.bipartite import create_bipartite_visualization
from appsec_data_views.visualizations.dependants_graph import (
    create_dependants_graph_visualization,
)
from appsec_data_views.visualizations.dependencies_graph import (
    DependencyVisitor,
    calculate_depths_with_cycles,
    create_dependencies_graph_visualization,
)
from appsec_data_views.visualizations.kpartite import (
    calculate_partitions_longest_path,
    create_kpartite_visualization,
    format_properties_for_tooltip,
    get_partition_color,
)


class TestPartitionColors:
    """Tests for get_partition_color function."""

    # Positive tests

    def test_partition_0_is_red(self):
        """Test partition 0 returns red color."""
        color = get_partition_color(0)
        assert color == "#e41a1c"

    def test_partition_1_is_blue(self):
        """Test partition 1 returns blue color."""
        color = get_partition_color(1)
        assert color == "#377eb8"

    def test_partition_within_range(self):
        """Test partitions within color range."""
        for i in range(9):
            color = get_partition_color(i)
            assert color.startswith("#")
            assert len(color) == 7

    # Negative tests

    def test_partition_beyond_range_uses_last_color(self):
        """Test partitions beyond range use last color."""
        color_8 = get_partition_color(8)
        color_100 = get_partition_color(100)
        assert color_100 == color_8  # Both should use the last color (gray)


class TestCalculatePartitionsLongestPath:
    """Tests for calculate_partitions_longest_path function."""

    # Positive tests

    def test_single_node(self):
        """Test partition calculation with single node."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_node("root")

        partitions = calculate_partitions_longest_path(G, "root")

        assert partitions == {"root": 0}

    def test_linear_graph(self):
        """Test partition calculation with linear graph."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "c"), ("c", "d")])

        partitions = calculate_partitions_longest_path(G, "a")

        assert partitions["a"] == 0
        assert partitions["b"] == 1
        assert partitions["c"] == 2
        assert partitions["d"] == 3

    def test_diamond_graph_uses_longest_path(self):
        """Test partition calculation uses longest path in diamond graph."""
        import networkx as nx

        # Diamond: a -> b -> d, a -> c -> d
        # But also: a -> c -> e -> d (longer path to d)
        G = nx.DiGraph()
        G.add_edges_from(
            [
                ("a", "b"),
                ("a", "c"),
                ("b", "d"),
                ("c", "e"),
                ("e", "d"),
            ]
        )

        partitions = calculate_partitions_longest_path(G, "a")

        assert partitions["a"] == 0
        assert partitions["d"] == 3  # Longest path: a -> c -> e -> d

    def test_branching_graph(self):
        """Test partition calculation with branching graph."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from(
            [
                ("root", "a"),
                ("root", "b"),
                ("a", "c"),
                ("b", "d"),
            ]
        )

        partitions = calculate_partitions_longest_path(G, "root")

        assert partitions["root"] == 0
        assert partitions["a"] == 1
        assert partitions["b"] == 1
        assert partitions["c"] == 2
        assert partitions["d"] == 2

    # Negative tests

    def test_disconnected_nodes_not_in_partitions(self):
        """Test disconnected nodes are not included in partitions."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b")])
        G.add_node("disconnected")

        partitions = calculate_partitions_longest_path(G, "a")

        assert "disconnected" not in partitions


class TestFormatPropertiesForTooltip:
    """Tests for format_properties_for_tooltip function."""

    # Positive tests

    def test_empty_properties(self):
        """Test formatting empty properties."""
        result = format_properties_for_tooltip({})
        assert result == ""

    def test_simple_properties(self):
        """Test formatting simple string properties."""
        props = {"name": "test", "version": "1.0.0"}
        result = format_properties_for_tooltip(props)

        assert "name: test" in result
        assert "version: 1.0.0" in result

    def test_list_properties(self):
        """Test formatting list properties."""
        props = {"tags": ["a", "b", "c"]}
        result = format_properties_for_tooltip(props)

        assert "tags: a, b, c" in result

    def test_dict_properties(self):
        """Test formatting dict properties."""
        props = {"config": {"key": "value"}}
        result = format_properties_for_tooltip(props)

        assert "config:" in result
        assert "key" in result

    def test_properties_are_sorted(self):
        """Test properties are sorted alphabetically."""
        props = {"zebra": "z", "alpha": "a", "beta": "b"}
        result = format_properties_for_tooltip(props)

        lines = result.split("\n")
        keys = [line.split(":")[0] for line in lines]
        assert keys == ["alpha", "beta", "zebra"]

    # Negative tests

    def test_none_properties(self):
        """Test formatting None properties."""
        result = format_properties_for_tooltip(None)
        assert result == ""


class TestCreateKpartiteVisualization:
    """Tests for create_kpartite_visualization function."""

    # Positive tests

    def test_returns_html_when_project_found(self):
        """Test returns HTML string when project exists."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "test", "name": "1.0.0"},
            "labels": ["Version"],
        }
        mock_service.get_transitive_dependencies.return_value = ([], [])

        result = create_kpartite_visualization(
            project_name="test",
            version_name="1.0.0",
            service=mock_service,
        )

        assert result is not None
        assert isinstance(result, str)
        assert "<html>" in result.lower() or "<!doctype" in result.lower()

    def test_passes_parameters_to_service(self):
        """Test passes max_depth and internal_only to service."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "test", "name": "1.0.0"},
            "labels": ["Version"],
        }
        mock_service.get_transitive_dependencies.return_value = ([], [])

        create_kpartite_visualization(
            project_name="test",
            version_name="1.0.0",
            max_depth=5,
            internal_only=True,
            service=mock_service,
        )

        mock_service.get_transitive_dependencies.assert_called_once_with("test", "1.0.0", 5, True)

    # Negative tests

    def test_returns_none_when_project_not_found(self):
        """Test returns None when project does not exist."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = None

        result = create_kpartite_visualization(
            project_name="nonexistent",
            version_name="0.0.0",
            service=mock_service,
        )

        assert result is None


class TestCreateBipartiteVisualization:
    """Tests for create_bipartite_visualization function."""

    # Positive tests

    def test_returns_html_when_project_found(self):
        """Test returns HTML string when project exists."""
        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
        mock_service.get_direct_dependants.return_value = [
            {
                "dependant_project": "dep-a",
                "dependant_version": "1.0.0",
                "target_project": "test",
                "target_version": "1.0.0",
            }
        ]

        result = create_bipartite_visualization(
            project_name="test",
            service=mock_service,
        )

        assert result is not None
        assert isinstance(result, str)

    def test_handles_project_with_no_dependants(self):
        """Test handles project with no dependants."""
        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
        mock_service.get_direct_dependants.return_value = []

        result = create_bipartite_visualization(
            project_name="isolated",
            service=mock_service,
        )

        assert result is not None

    # Negative tests

    def test_returns_none_when_no_versions_found(self):
        """Test returns None when project has no versions."""
        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = []

        result = create_bipartite_visualization(
            project_name="nonexistent",
            service=mock_service,
        )

        assert result is None


class TestCreateDependantsGraphVisualization:
    """Tests for create_dependants_graph_visualization function."""

    # Positive tests

    def test_returns_html_when_project_found(self):
        """Test returns HTML string when project exists."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "lib", "name": "1.0.0"},
            "labels": ["Version"],
        }
        mock_service.get_transitive_dependants.return_value = (
            [
                {
                    "id": "lib:1.0.0",
                    "project_name": "lib",
                    "version": "1.0.0",
                    "labels": [],
                    "properties": {},
                }
            ],
            [],
        )

        result = create_dependants_graph_visualization(
            project_name="lib",
            version_name="1.0.0",
            service=mock_service,
        )

        assert result is not None
        assert isinstance(result, str)

    def test_passes_max_depth_to_service(self):
        """Test passes max_depth parameter to service."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "lib", "name": "1.0.0"},
            "labels": ["Version"],
        }
        mock_service.get_transitive_dependants.return_value = ([], [])

        create_dependants_graph_visualization(
            project_name="lib",
            version_name="1.0.0",
            max_depth=10,
            service=mock_service,
        )

        mock_service.get_transitive_dependants.assert_called_once_with(
            "lib", "1.0.0", 10, False, skip_scan_filter=True
        )

    # Negative tests

    def test_returns_none_when_project_not_found(self):
        """Test returns None when project does not exist."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = None

        result = create_dependants_graph_visualization(
            project_name="nonexistent",
            version_name="0.0.0",
            service=mock_service,
        )

        assert result is None


class TestDependencyVisitor:
    """Tests for DependencyVisitor class."""

    # Positive tests

    def test_detects_self_loop(self):
        """Test visitor detects self-referential cycles."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edge("a", "a")  # Self-loop

        visitor = DependencyVisitor()
        visitor.traverse_all(G, start_node="a")

        assert visitor.has_cycles()
        assert ("a", "a") in visitor.get_cycle_edges()

    def test_detects_simple_cycle(self):
        """Test visitor detects simple two-node cycles."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "a")])

        visitor = DependencyVisitor()
        visitor.traverse_all(G, start_node="a")

        assert visitor.has_cycles()

    def test_detects_longer_cycle(self):
        """Test visitor detects longer cycles."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "c"), ("c", "a")])

        visitor = DependencyVisitor()
        visitor.traverse_all(G, start_node="a")

        assert visitor.has_cycles()

    def test_no_cycle_in_dag(self):
        """Test visitor correctly identifies DAGs without cycles."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")])

        visitor = DependencyVisitor()
        visitor.traverse_all(G, start_node="a")

        assert not visitor.has_cycles()

    def test_visits_all_nodes(self):
        """Test visitor visits all reachable nodes."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "c")])

        visited_nodes = []
        visitor = DependencyVisitor()
        visitor.traverse_all(G, start_node="a", on_visit=lambda n: visited_nodes.append(n))

        assert set(visited_nodes) == {"a", "b", "c"}

    # Negative tests

    def test_empty_graph(self):
        """Test visitor handles empty graph."""
        import networkx as nx

        G = nx.DiGraph()

        visitor = DependencyVisitor()
        visitor.traverse_all(G)

        assert not visitor.has_cycles()


class TestCalculateDepthsWithCycles:
    """Tests for calculate_depths_with_cycles function."""

    # Positive tests

    def test_simple_depths(self):
        """Test depth calculation for simple graph."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "c")])

        depths = calculate_depths_with_cycles(G, "a")

        assert depths["a"] == 0
        assert depths["b"] == 1
        assert depths["c"] == 2

    def test_handles_cycles(self):
        """Test depth calculation handles cycles without infinite loop."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "c"), ("c", "a")])

        depths = calculate_depths_with_cycles(G, "a")

        assert depths["a"] == 0
        assert depths["b"] == 1
        assert depths["c"] == 2

    def test_handles_self_loop(self):
        """Test depth calculation handles self-loops."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_edges_from([("a", "b"), ("b", "b")])  # Self-loop on b

        depths = calculate_depths_with_cycles(G, "a")

        assert depths["a"] == 0
        assert depths["b"] == 1


class TestCreateDependenciesGraphVisualization:
    """Tests for create_dependencies_graph_visualization function."""

    # Positive tests

    def test_returns_html_when_project_found(self):
        """Test returns HTML string when project exists."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "test", "name": "1.0.0"},
            "labels": ["Version"],
        }
        mock_service.get_transitive_dependencies.return_value = ([], [])

        result = create_dependencies_graph_visualization(
            project_name="test",
            version_name="1.0.0",
            service=mock_service,
        )

        assert result is not None
        assert isinstance(result, str)
        assert "<html>" in result.lower() or "<!doctype" in result.lower()

    def test_handles_cyclic_dependencies(self):
        """Test handles graphs with cyclic dependencies."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "app", "name": "1.0.0"},
            "labels": ["Version", "Application"],
        }
        # Create a graph with a cycle: app -> lib -> lib (self-loop)
        mock_service.get_transitive_dependencies.return_value = (
            [
                {
                    "id": "app:1.0.0",
                    "project_name": "app",
                    "version": "1.0.0",
                    "labels": ["Version", "Application"],
                    "properties": {},
                },
                {
                    "id": "lib:1.0.0",
                    "project_name": "lib",
                    "version": "1.0.0",
                    "labels": ["Version", "Library"],
                    "properties": {},
                },
            ],
            [
                {"source": "app:1.0.0", "target": "lib:1.0.0", "type": "DEPENDENCY_VERSION"},
                {"source": "lib:1.0.0", "target": "lib:1.0.0", "type": "DEPENDENCY_VERSION"},  # Self-loop
            ],
        )

        result = create_dependencies_graph_visualization(
            project_name="app",
            version_name="1.0.0",
            service=mock_service,
        )

        assert result is not None
        assert isinstance(result, str)

    def test_passes_parameters_to_service(self):
        """Test passes max_depth and internal_only to service."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = {
            "properties": {"project_name": "test", "name": "1.0.0"},
            "labels": ["Version"],
        }
        mock_service.get_transitive_dependencies.return_value = ([], [])

        create_dependencies_graph_visualization(
            project_name="test",
            version_name="1.0.0",
            max_depth=5,
            internal_only=True,
            service=mock_service,
        )

        mock_service.get_transitive_dependencies.assert_called_once_with(
            "test", "1.0.0", 5, True
        )

    # Negative tests

    def test_returns_none_when_project_not_found(self):
        """Test returns None when project does not exist."""
        mock_service = MagicMock()
        mock_service.find_version.return_value = None

        result = create_dependencies_graph_visualization(
            project_name="nonexistent",
            version_name="0.0.0",
            service=mock_service,
        )

        assert result is None
