"""Tests for FalkorDB service module."""

from unittest.mock import MagicMock, patch

import pytest

from sbom_graph_api.config import FalkorDBConfig
from sbom_graph_api.services.falkordb_service import (
    FalkorDBService,
    get_falkordb_service,
    reset_service,
)


class TestFalkorDBService:
    """Tests for FalkorDBService class."""

    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        return FalkorDBConfig(
            host="test-host",
            port=6379,
            password="test-pass",
            graph_name="test-graph",
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            internal_label="INTERNAL",
            ssl=False,
            ssl_ca_certs=None,
        )

    @pytest.fixture
    def service(self, config):
        """Create a service with test configuration."""
        return FalkorDBService(config)

    @pytest.fixture
    def mock_node(self):
        """Create a mock node."""
        node = MagicMock()
        node.id = 1
        node.labels = ["Version"]
        node.properties = {"project_name": "test", "name": "1.0.0"}
        return node

    # Positive tests

    def test_init_with_config(self, config):
        """Test service initialization with provided config."""
        service = FalkorDBService(config)
        assert service.config == config
        assert service._db is None

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_db_lazy_initialization(self, mock_falkordb_class, service):
        """Test that database connection is lazily initialized."""
        mock_db = MagicMock()
        mock_falkordb_class.return_value = mock_db

        # Access db property
        db = service.db

        assert db == mock_db
        mock_falkordb_class.assert_called_once_with(
            host="test-host",
            port=6379,
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            password="test-pass",
        )

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_db_without_password(self, mock_falkordb_class):
        """Test database connection without password."""
        config = FalkorDBConfig(
            host="test-host",
            port=6379,
            password=None,
            graph_name="test-graph",
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            internal_label="INTERNAL",
            ssl=False,
            ssl_ca_certs=None,
        )
        service = FalkorDBService(config)
        mock_db = MagicMock()
        mock_falkordb_class.return_value = mock_db

        _ = service.db

        mock_falkordb_class.assert_called_once_with(
            host="test-host",
            port=6379,
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
        )

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_graph_property(self, mock_falkordb_class, service):
        """Test graph property returns correct graph."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        graph = service.graph

        assert graph == mock_graph
        mock_db.select_graph.assert_called_once_with("test-graph")

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_execute_query(self, mock_falkordb_class, service):
        """Test execute_query with parameters."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [["row1"], ["row2"]]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.execute_query("MATCH (n) RETURN n", {"param": "value"})

        assert result == [["row1"], ["row2"]]
        mock_graph.ro_query.assert_called_once_with("MATCH (n) RETURN n", {"param": "value"})

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_execute_query_without_params(self, mock_falkordb_class, service):
        """Test execute_query without parameters."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = []
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.execute_query("RETURN 1")

        mock_graph.ro_query.assert_called_once_with("RETURN 1", {})
        assert result == []

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_find_version_found(self, mock_falkordb_class, service, mock_node):
        """Test find_version when version exists."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [[mock_node]]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.find_version("test", "1.0.0")

        assert result == {
            "properties": mock_node.properties,
            "labels": list(mock_node.labels),
        }

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_find_version_not_found(self, mock_falkordb_class, service):
        """Test find_version when version does not exist."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = []
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.find_version("nonexistent", "0.0.0")

        assert result is None

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_all_projects(self, mock_falkordb_class, service):
        """Test get_all_projects returns formatted data with licence info."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [
            [
                "project-a",
                "1.0.0",
                "pkg:maven/org/project-a@1.0.0",
                ["MIT"],
                ["permissive"],
                None,
                None,
                None,
                None,
            ],
            [
                "project-b",
                "2.0.0",
                "pkg:maven/org/project-b@2.0.0",
                [],
                [],
                None,
                None,
                None,
                None,
            ],
        ]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_all_projects(limit=100)

        assert len(result) == 2
        assert result[0] == {
            "project_name": "project-a",
            "version": "1.0.0",
            "package_url": "pkg:maven/org/project-a@1.0.0",
            "spdx_id": "MIT",
            "risk_category": "permissive",
            "source_repo_url": None,
            "direct_score": None,
            "effective_score": None,
            "confidence": None,
        }
        assert result[1] == {
            "project_name": "project-b",
            "version": "2.0.0",
            "package_url": "pkg:maven/org/project-b@2.0.0",
            "spdx_id": "",
            "risk_category": "",
            "source_repo_url": None,
            "direct_score": None,
            "effective_score": None,
            "confidence": None,
        }

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_all_projects_internal_only(self, mock_falkordb_class, service):
        """Test get_all_projects with internal_only filter."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [
            [
                "acme_corp-lib",
                "1.0.0",
                "pkg:maven/org/acme/lib@1.0.0",
                ["Apache-2.0"],
                ["permissive"],
                None,
                None,
                None,
                None,
            ],
        ]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_all_projects(limit=100, internal_only=True)

        assert len(result) == 1
        assert result[0]["project_name"] == "acme_corp-lib"
        assert result[0]["version"] == "1.0.0"
        # Verify the query uses the configured internal label
        call_args = mock_graph.ro_query.call_args
        query = call_args[0][0]
        # Default internal label is INTERNAL, but it's configurable
        assert f"Version:{service.internal_label}" in query

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_all_versions_of_project(self, mock_falkordb_class, service):
        """Test get_all_versions_of_project returns version list."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [["1.0.0"], ["2.0.0"], ["3.0.0"]]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_all_versions_of_project("my-project")

        assert result == ["1.0.0", "2.0.0", "3.0.0"]

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_direct_dependants_with_version(self, mock_falkordb_class, service):
        """Test get_direct_dependants with specific version."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [
            ["dependant-a", "1.0.0", "target", "1.0.0"],
        ]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_direct_dependants("target", "1.0.0")

        assert len(result) == 1
        assert result[0]["dependant_project"] == "dependant-a"
        assert result[0]["dependant_version"] == "1.0.0"
        assert result[0]["target_project"] == "target"
        assert result[0]["target_version"] == "1.0.0"

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_direct_dependants_without_version(self, mock_falkordb_class, service):
        """Test get_direct_dependants without specific version."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [
            ["dependant-a", "1.0.0", "target", "1.0.0"],
            ["dependant-b", "2.0.0", "target", "2.0.0"],
        ]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_direct_dependants("target")

        assert len(result) == 2

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_find_snapshot_dependencies(self, mock_falkordb_class, service):
        """Test find_snapshot_dependencies returns SNAPSHOT deps."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [
            ["app-a", "1.0.0", "lib-a", "1.0.0-SNAPSHOT"],
        ]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.find_snapshot_dependencies()

        assert len(result) == 1
        assert result[0]["application"] == "app-a"
        assert result[0]["dep_version"] == "1.0.0-SNAPSHOT"

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_find_self_dependencies(self, mock_falkordb_class, service):
        """Test find_self_dependencies returns self-referencing nodes."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = [
            ["self-ref", "1.0.0", "DEPENDS_ON"],
        ]
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.find_self_dependencies()

        assert len(result) == 1
        assert result[0]["project_name"] == "self-ref"
        assert result[0]["relationship_type"] == "DEPENDS_ON"

    # Negative tests

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_all_projects_empty(self, mock_falkordb_class, service):
        """Test get_all_projects with empty database."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = []
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_all_projects()

        assert result == []

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_find_snapshot_dependencies_none_found(self, mock_falkordb_class, service):
        """Test find_snapshot_dependencies when none exist."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = []
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.find_snapshot_dependencies()

        assert result == []

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_find_self_dependencies_none_found(self, mock_falkordb_class, service):
        """Test find_self_dependencies when none exist."""
        mock_db = MagicMock()
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.result_set = []
        mock_graph.ro_query.return_value = mock_result
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.find_self_dependencies()

        assert result == []

    @patch("sbom_graph_api.services.falkordb_service.FalkorDB")
    def test_get_source_repo_impact(self, mock_falkordb_class, service):
        """Test get_source_repo_impact returns packages, dependants, and graph."""
        mock_db = MagicMock()
        mock_graph = MagicMock()

        # packages, dependants, apps, edges
        packages_result = MagicMock()
        packages_result.result_set = [
            ["foo", "1.0.0", "pkg:maven/org/foo@1.0", 2, 3],
        ]
        dep_result = MagicMock()
        dep_result.result_set = [
            ["consumer", "1.0.0", "Version"],
        ]
        app_result = MagicMock()
        app_result.result_set = [
            ["myapp", "2.0.0"],
        ]
        edge_result = MagicMock()
        edge_result.result_set = [
            ["consumer", "1.0.0", "foo", "1.0.0"],
        ]

        mock_graph.ro_query.side_effect = [
            packages_result,
            dep_result,
            app_result,
            edge_result,
        ]
        mock_db.select_graph.return_value = mock_graph
        mock_falkordb_class.return_value = mock_db

        result = service.get_source_repo_impact(
            repo_url="https://github.com/org/repo",
            max_depth=10,
            internal_only=False,
        )

        assert "packages" in result
        assert len(result["packages"]) == 1
        assert result["packages"][0]["project_name"] == "foo"
        assert result["packages"][0]["direct_dependants"] == 2
        assert result["packages"][0]["transitive_dependants"] == 3
        assert "dependants" in result
        assert len(result["dependants"]) == 1
        assert result["affected_applications"] == [{"project_name": "myapp", "version": "2.0.0"}]
        assert result["stats"]["packages_from_repo"] == 1
        assert result["stats"]["total_downstream_consumers"] == 1
        assert result["stats"]["affected_applications"] == 1
        assert "graph_nodes" in result
        assert "graph_edges" in result


class TestServiceSingleton:
    """Tests for service singleton functions."""

    def setup_method(self):
        """Reset service before each test."""
        reset_service()

    def teardown_method(self):
        """Reset service after each test."""
        reset_service()

    def test_get_falkordb_service_returns_singleton(self):
        """Test that get_falkordb_service returns the same instance."""
        with patch("sbom_graph_api.services.falkordb_service.get_config") as mock_config:
            mock_config.return_value.falkordb = FalkorDBConfig(
                host="test",
                port=6379,
                password=None,
                graph_name="test",
                socket_timeout=30.0,
                socket_connect_timeout=10.0,
                internal_label="INTERNAL",
                ssl=False,
                ssl_ca_certs=None,
            )
            service1 = get_falkordb_service()
            service2 = get_falkordb_service()

        assert service1 is service2

    def test_reset_service_clears_singleton(self):
        """Test that reset_service clears the singleton."""
        with patch("sbom_graph_api.services.falkordb_service.get_config") as mock_config:
            mock_config.return_value.falkordb = FalkorDBConfig(
                host="test",
                port=6379,
                password=None,
                graph_name="test",
                socket_timeout=30.0,
                socket_connect_timeout=10.0,
                internal_label="INTERNAL",
                ssl=False,
                ssl_ca_certs=None,
            )
            service1 = get_falkordb_service()
            reset_service()
            service2 = get_falkordb_service()

        assert service1 is not service2
