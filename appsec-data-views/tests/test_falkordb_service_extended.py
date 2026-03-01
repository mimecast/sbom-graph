"""Extended tests for FalkorDB service - covering helper methods, semver, and categorization."""

from unittest.mock import MagicMock, patch

import pytest

from appsec_data_views.config import FalkorDBConfig
from appsec_data_views.services.falkordb_service import (
    SEMVER_PATTERN,
    FalkorDBService,
)


@pytest.fixture
def config():
    return FalkorDBConfig(
        host="test", port=6379, password="", graph_name="test",
        socket_timeout=30.0, socket_connect_timeout=10.0, internal_label="INTERNAL",
    )


@pytest.fixture
def service(config):
    return FalkorDBService(config=config)


def _mock_node(project_name, version, labels=None, properties=None):
    node = MagicMock()
    props = {"project_name": project_name, "name": version}
    if properties:
        props.update(properties)
    node.properties = props
    node.labels = labels or ["Version"]
    return node


class TestSemverPattern:
    """Tests for the SEMVER_PATTERN regex."""

    @pytest.mark.parametrize("version", [
        "1.0.0", "0.1.0", "10.20.30", "1.0", "v1.0.0", "V2.1.0",
        "1.0.0-alpha", "1.0.0-beta.1", "1.0.0+build.123",
        "1.0.0-alpha+build", "2.0.0-SNAPSHOT", "1.0.0.RELEASE",
        "1.0.0.Final", "1.0.0.GA", "1.0.0-rc.1",
    ])
    def test_valid_semver(self, version):
        assert SEMVER_PATTERN.match(version) is not None, f"{version} should be valid"

    @pytest.mark.parametrize("version", [
        "abc", "1", "latest", "20230101", "feature-branch-123",
        "abcdef1234567", "main-1234",
    ])
    def test_invalid_semver(self, version):
        assert SEMVER_PATTERN.match(version) is None, f"{version} should be invalid"


class TestHelperMethods:
    """Tests for FalkorDBService helper methods."""

    def test_get_node_label_default(self, service):
        assert service.get_node_label(False) == "Version"

    def test_get_node_label_internal(self, service):
        assert service.get_node_label(True) == "Version:INTERNAL"

    def test_internal_label_property(self, service):
        assert service.internal_label == "INTERNAL"

    def test_get_node_id(self, service):
        node = _mock_node("my-project", "1.0.0")
        assert service._get_node_id(node) == "my-project:1.0.0"

    def test_node_to_dict(self, service):
        node = _mock_node("proj", "2.0.0", ["Version", "INTERNAL"])
        result = service._node_to_dict(node)
        assert result["id"] == "proj:2.0.0"
        assert result["project_name"] == "proj"
        assert result["version"] == "2.0.0"
        assert result["labels"] == ["Version", "INTERNAL"]

    def test_parse_node_id_valid(self, service):
        assert service._parse_node_id("proj:1.0.0") == ("proj", "1.0.0")

    def test_parse_node_id_with_colon_in_name(self, service):
        assert service._parse_node_id("com.example:lib:1.0") == ("com.example:lib", "1.0")

    def test_parse_node_id_invalid(self, service):
        assert service._parse_node_id("no-colon") is None

    def test_add_edge_if_new(self, service):
        edges = []
        seen = set()
        result = service._add_edge_if_new("A", "B", "DEPENDS_ON", edges, seen)
        assert result is True
        assert len(edges) == 1
        assert edges[0] == {"source": "A", "target": "B", "type": "DEPENDS_ON"}

    def test_add_edge_duplicate_ignored(self, service):
        edges = []
        seen = set()
        service._add_edge_if_new("A", "B", "DEPENDS_ON", edges, seen)
        result = service._add_edge_if_new("A", "B", "DEPENDS_ON", edges, seen)
        assert result is False
        assert len(edges) == 1

    def test_build_node_conditions(self, service):
        params = {}
        conditions = service._build_node_conditions(
            ["proj:1.0", "lib:2.0"], params, "src", "s"
        )
        assert len(conditions) == 2
        assert params["s_proj_0"] == "proj"
        assert params["s_ver_0"] == "1.0"
        assert params["s_proj_1"] == "lib"
        assert params["s_ver_1"] == "2.0"

    def test_build_node_conditions_skips_invalid(self, service):
        params = {}
        conditions = service._build_node_conditions(
            ["valid:1.0", "nocolon"], params, "n", "p"
        )
        assert len(conditions) == 1

    def test_is_at_capacity(self, service):
        small = {f"n{i}": {} for i in range(10)}
        assert service._is_at_capacity(small) is False

    def test_get_remaining_capacity(self, service):
        nodes = {f"n{i}": {} for i in range(100)}
        remaining = service._get_remaining_capacity(nodes)
        assert remaining == 50000 - 100


class TestBuildDependantsQuery:
    """Tests for _build_dependants_query."""

    def test_single_filter_mode(self, service):
        query = service._build_dependants_query(["cond1"], "single", False)
        assert "$scan_id IN src.scan_ids" in query
        assert "Version" in query

    def test_any_filter_mode(self, service):
        query = service._build_dependants_query(["cond1"], "any", False)
        assert "ANY(sid IN $scan_ids WHERE sid IN src.scan_ids)" in query

    def test_none_filter_mode(self, service):
        query = service._build_dependants_query(["cond1"], "none", False)
        assert "scan_id" not in query.lower() or "$scan_id" not in query

    def test_internal_only_label(self, service):
        query = service._build_dependants_query(["cond1"], "none", True)
        assert "Version:INTERNAL" in query


class TestCategorizationAndSemver:
    """Tests for _categorize_non_semver_version and semver methods."""

    @pytest.mark.parametrize("version,expected", [
        ("1.0.0-rc1", "Release candidate"),
        ("2.0-beta", "Beta version"),
        ("3.0-alpha", "Alpha version"),
        ("dev-123", "Development version"),
        ("20230101", "Date-based version (YYYYMMDD)"),
        ("230101", "Date-based version (YYMMDD)"),
        ("abcdef1234567", "Git commit hash"),
        ("feature-branch-123", "Branch-based version"),
        ("12345", "Single number version"),
        ("latest", "No numeric component"),
        ("weird!version2", "Non-standard format"),
    ])
    def test_categorization(self, service, version, expected):
        assert service._categorize_non_semver_version(version) == expected

    def test_is_semver_compliant_all_valid(self, service):
        with patch.object(service, "get_all_versions_of_project", return_value=["1.0.0", "2.0.0"]):
            is_compliant, non_compliant = service.is_project_semver_compliant("proj")
            assert is_compliant is True
            assert non_compliant == []

    def test_is_semver_compliant_with_invalid(self, service):
        with patch.object(service, "get_all_versions_of_project", return_value=["1.0.0", "latest"]):
            is_compliant, non_compliant = service.is_project_semver_compliant("proj")
            assert is_compliant is False
            assert "latest" in non_compliant

    def test_get_latest_semver_version(self, service):
        with patch.object(service, "is_project_semver_compliant", return_value=(True, [])):
            with patch.object(service, "get_all_versions_of_project", return_value=["1.0.0", "2.0.0", "1.10.0"]):
                result = service.get_latest_semver_version("proj")
                assert result == "2.0.0"

    def test_get_latest_semver_not_compliant(self, service):
        with patch.object(service, "is_project_semver_compliant", return_value=(False, ["bad"])):
            assert service.get_latest_semver_version("proj") is None

    def test_get_latest_semver_no_versions(self, service):
        with patch.object(service, "is_project_semver_compliant", return_value=(True, [])):
            with patch.object(service, "get_all_versions_of_project", return_value=[]):
                assert service.get_latest_semver_version("proj") is None


class TestGetAllApplications:
    """Tests for get_all_applications method."""

    def test_returns_applications(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["app-a", "1.0.0", "scan-1", "app-1", "pub-1", "https://git.example.com", ["Application", "INTERNAL"]],
        ]):
            result = service.get_all_applications(limit=100)
            assert len(result) == 1
            assert result[0]["project_name"] == "app-a"
            assert result[0]["is_internal"] is True

    def test_latest_only_with_semver(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["app-a", "1.0.0", None, None, None, None, ["Application"]],
            ["app-a", "2.0.0", None, None, None, None, ["Application"]],
        ]):
            with patch.object(service, "get_latest_semver_version", return_value="2.0.0"):
                result = service.get_all_applications(latest_only=True)
                assert len(result) == 1
                assert result[0]["version"] == "2.0.0"

    def test_latest_only_no_semver_falls_back(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["app-b", "alpha", None, None, None, None, ["Application"]],
            ["app-b", "beta", None, None, None, None, ["Application"]],
        ]):
            with patch.object(service, "get_latest_semver_version", return_value=None):
                result = service.get_all_applications(latest_only=True)
                assert len(result) == 1
                assert result[0]["version"] == "beta"


class TestFindNonSemverVersions:
    """Tests for find_non_semver_versions."""

    def test_returns_non_semver(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["proj-a", "1.0.0", ["Version"]],
            ["proj-b", "latest", ["Version"]],
        ]):
            result = service.find_non_semver_versions()
            assert len(result) == 1
            assert result[0]["project_name"] == "proj-b"
            assert result[0]["reason"] == "No numeric component"


class TestFindCycles:
    """Tests for cycle finding methods."""

    def test_find_cycles_returns_list(self, service):
        with patch.object(service, "execute_query", return_value=[
            [[{"project_name": "a", "version": "1.0"}, {"project_name": "b", "version": "1.0"}]],
        ]):
            result = service.find_cycles(max_cycle_length=3)
            assert len(result) > 0

    def test_find_cycles_timeout_continues(self, service):
        with patch.object(service, "execute_query", side_effect=TimeoutError("timeout")):
            result = service.find_cycles(max_cycle_length=2)
            assert result == []

    def test_find_direct_cycles(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["proj-a", "1.0", "proj-b", "1.0", "DEPENDS_ON", "DEPENDS_ON"],
        ]):
            result = service.find_direct_cycles()
            assert len(result) == 1
            assert result[0]["project_a"] == "proj-a"


class TestGetApplicationsByScanIds:
    """Tests for get_applications_by_scan_ids."""

    def test_empty_scan_ids(self, service):
        assert service.get_applications_by_scan_ids([]) == []

    def test_returns_applications(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["app-a", "1.0.0", "scan-1"],
        ]):
            result = service.get_applications_by_scan_ids(["scan-1"])
            assert len(result) == 1
            assert result[0]["scan_id"] == "scan-1"


class TestGetAllVulnerabilities:
    """Tests for vulnerability methods."""

    def test_get_all_vulnerabilities(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["CVE-2024-001", "XSS Vuln", "desc", "HIGH", 7.5, "CWE-79", "2024-01-01",
             [{"project_name": "lib", "version": "1.0", "project_group": "com.example"}]],
        ]):
            result = service.get_all_vulnerabilities()
            assert len(result) == 1
            assert result[0]["defect_id"] == "CVE-2024-001"
            assert result[0]["severity"] == "HIGH"

    def test_get_vulnerability_by_id(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["CVE-2024-001", "title", "desc", "HIGH", 7.5, "CWE-79", "2024-01-01",
             [{"project_name": "lib", "version": "1.0", "project_group": "g"}]],
        ]):
            result = service.get_vulnerability_by_id("CVE-2024-001")
            assert result is not None
            assert result["defect_id"] == "CVE-2024-001"

    def test_get_vulnerability_by_id_not_found(self, service):
        with patch.object(service, "execute_query", return_value=[]):
            assert service.get_vulnerability_by_id("CVE-NOTEXIST") is None

    def test_get_vulnerability_by_id_filters_none_versions(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["CVE-1", "t", "d", "LOW", 2.0, None, None,
             [{"project_name": None, "version": None, "project_group": None},
              {"project_name": "lib", "version": "1.0", "project_group": "g"}]],
        ]):
            result = service.get_vulnerability_by_id("CVE-1")
            assert len(result["affected_versions"]) == 1


class TestGetInternalCentrality:
    """Tests for centrality report."""

    def test_returns_centrality_data(self, service):
        with patch.object(service, "execute_query", return_value=[
            ["com.example", "my-lib", "1.0.0", 10, 5],
        ]):
            result = service.get_internal_centrality()
            assert len(result) == 1
            assert result[0]["inDegree"] == 10
            assert result[0]["outDegree"] == 5

    def test_default_sort_by(self, service):
        with patch.object(service, "execute_query", return_value=[]):
            service.get_internal_centrality(sort_by="invalid_field")

    def test_handles_null_values(self, service):
        with patch.object(service, "execute_query", return_value=[
            [None, None, None, None, None],
        ]):
            result = service.get_internal_centrality()
            assert result[0]["project_group"] == ""
            assert result[0]["inDegree"] == 0


class TestTransitiveDependencies:
    """Tests for BFS traversal methods."""

    def test_get_transitive_dependencies_empty(self, service):
        with patch.object(service, "find_version", return_value=None):
            with patch.object(service, "execute_query", return_value=[]):
                nodes, edges = service.get_transitive_dependencies("proj", "1.0")
                assert nodes == []
                assert edges == []

    def test_get_transitive_dependencies_with_root(self, service):
        root_data = {"properties": {"project_name": "proj", "name": "1.0"}, "labels": ["Version"]}
        with patch.object(service, "find_version", return_value=root_data):
            with patch.object(service, "execute_query", return_value=[]):
                nodes, edges = service.get_transitive_dependencies("proj", "1.0")
                assert len(nodes) == 1
                assert nodes[0]["id"] == "proj:1.0"

    def test_get_transitive_dependants_empty(self, service):
        with patch.object(service, "find_version", return_value=None):
            with patch.object(service, "execute_query", return_value=[]):
                nodes, edges = service.get_transitive_dependants("proj", "1.0")
                assert nodes == []
                assert edges == []

    def test_get_transitive_dependencies_for_report_empty(self, service):
        with patch.object(service, "get_transitive_dependencies", return_value=([], [])):
            result = service.get_transitive_dependencies_for_report("proj", "1.0")
            assert result == []

    def test_get_transitive_dependencies_for_report_with_data(self, service):
        nodes = [
            {"id": "proj:1.0", "project_name": "proj", "version": "1.0",
             "labels": ["Version"], "properties": {}},
            {"id": "lib:2.0", "project_name": "lib", "version": "2.0",
             "labels": ["Version"], "properties": {}},
        ]
        edges = [{"source": "proj:1.0", "target": "lib:2.0", "type": "DEPENDS_ON"}]
        with patch.object(service, "get_transitive_dependencies", return_value=(nodes, edges)):
            result = service.get_transitive_dependencies_for_report("proj", "1.0")
            assert len(result) == 1
            assert result[0]["dependency_project"] == "lib"
            assert result[0]["depth"] == 1


class TestFindMultiVersionSources:
    """Tests for find_multi_version_dependency_sources."""

    def test_not_found_returns_empty(self, service):
        with patch.object(service, "find_version", return_value=None):
            result = service.find_multi_version_dependency_sources("p", "1.0")
            assert result["target"] is None
            assert result["multi_version_dependencies"] == []

    def test_no_multi_versions(self, service):
        root_data = {"properties": {"project_name": "p", "name": "1.0", "scan_ids": []}, "labels": ["Version"]}
        nodes = [
            {"id": "p:1.0", "project_name": "p", "version": "1.0", "labels": [], "properties": {}},
            {"id": "lib:1.0", "project_name": "lib", "version": "1.0", "labels": [], "properties": {}},
        ]
        with patch.object(service, "find_version", return_value=root_data):
            with patch.object(service, "get_transitive_dependencies", return_value=(nodes, [])):
                result = service.find_multi_version_dependency_sources("p", "1.0")
                assert result["multi_version_dependencies"] == []


class TestGetLibraryVersionUsage:
    """Tests for get_library_version_usage."""

    def test_returns_usage_data(self, service):
        mock_result = MagicMock()
        mock_result.result_set = [
            ["1.0.0", "com.example", ["Version", "INTERNAL"], 2,
             [{"project_name": "app-a", "version": "1.0", "project_group": "g", "labels": ["Version"]},
              {"project_name": "app-b", "version": "2.0", "project_group": "g", "labels": ["Version"]}]],
            ["2.0.0", "com.example", ["Version"], 0, []],
        ]
        mock_graph = MagicMock()
        mock_graph.query.return_value = mock_result
        mock_db = MagicMock()
        mock_db.select_graph.return_value = mock_graph
        service._db = mock_db

        result = service.get_library_version_usage("my-lib")
        assert result["library"]["project_name"] == "my-lib"
        assert result["library"]["total_versions"] == 2
        assert result["total_dependants"] == 2
        assert len(result["versions"]) == 2
        assert result["versions"][0]["dependant_count"] == 2

    def test_empty_result(self, service):
        mock_result = MagicMock()
        mock_result.result_set = []
        mock_graph = MagicMock()
        mock_graph.query.return_value = mock_result
        mock_db = MagicMock()
        mock_db.select_graph.return_value = mock_graph
        service._db = mock_db

        result = service.get_library_version_usage("nonexistent")
        assert result["library"]["total_versions"] == 0
        assert result["total_dependants"] == 0
