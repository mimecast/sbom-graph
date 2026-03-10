"""Extended tests for FalkorDB service.

Covers helper methods, semver pattern matching, version
categorisation, application listing, vulnerability queries,
centrality, transitive traversal, multi-version sources,
and library-version usage.

Several test classes exercise *internal* (underscore-prefixed)
methods of ``FalkorDBService``; the protected-access warnings
are suppressed with ``noqa: SLF001`` because these tests
explicitly verify implementation-level behaviour.
"""

from unittest.mock import MagicMock, patch
from typing import Any
import pytest

from sbom_graph_api.config import FalkorDBConfig
from sbom_graph_api.services.falkordb_service import (
    SEMVER_PATTERN,
    FalkorDBService,
)


@pytest.fixture
def falkordb_config() -> FalkorDBConfig:
    """Return a minimal FalkorDB configuration for testing."""
    return FalkorDBConfig(
        host="test",
        port=6379,
        password="",
        graph_name="test",
        socket_timeout=30.0,
        socket_connect_timeout=10.0,
        internal_label="INTERNAL",
        ssl=False,
        ssl_ca_certs=None,
    )


@pytest.fixture
def db_service(
    falkordb_config: FalkorDBConfig,
) -> FalkorDBService:
    """Return a ``FalkorDBService`` wired to test config."""
    return FalkorDBService(config=falkordb_config)


def _mock_node(
    project_name: str,
    version: str,
    labels: list[str] | None = None,
    properties: dict | None = None,
) -> MagicMock:
    """Build a mock graph node with the given attributes."""
    node = MagicMock()
    props: dict = {
        "project_name": project_name,
        "name": version,
    }
    if properties:
        props.update(properties)
    node.properties = props
    node.labels = labels or ["Version"]
    return node


class TestSemverPattern:
    """Tests for the SEMVER_PATTERN regex."""

    @pytest.mark.parametrize(
        "version",
        [
            "1.0.0",
            "0.1.0",
            "10.20.30",
            "1.0",
            "v1.0.0",
            "V2.1.0",
            "1.0.0-alpha",
            "1.0.0-beta.1",
            "1.0.0+build.123",
            "1.0.0-alpha+build",
            "2.0.0-SNAPSHOT",
            "1.0.0.RELEASE",
            "1.0.0.Final",
            "1.0.0.GA",
            "1.0.0-rc.1",
        ],
    )
    def test_valid_semver(self, version: str) -> None:
        """Verify that known-good semver strings match."""
        assert SEMVER_PATTERN.match(version) is not None

    @pytest.mark.parametrize(
        "version",
        [
            "abc",
            "1",
            "latest",
            "20230101",
            "feature-branch-123",
            "abcdef1234567",
            "main-1234",
        ],
    )
    def test_invalid_semver(self, version: str) -> None:
        """Verify that non-semver strings do not match."""
        assert SEMVER_PATTERN.match(version) is None


class TestHelperMethods:
    """Tests for FalkorDBService internal helper methods."""

    def test_get_node_label_default(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Default label should be 'Version'."""
        assert db_service.get_node_label(False) == "Version"

    def test_get_node_label_internal(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Internal label should be 'Version:INTERNAL'."""
        label = db_service.get_node_label(True)
        assert label == "Version:INTERNAL"

    def test_internal_label_property(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """The internal_label property returns 'INTERNAL'."""
        assert db_service.internal_label == "INTERNAL"

    def test_get_node_id(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Node ID is 'project_name:version'."""
        node = _mock_node("my-project", "1.0.0")
        node_id = db_service._get_node_id(node)  # noqa: SLF001
        assert node_id == "my-project:1.0.0"

    def test_node_to_dict(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Node dict contains id, project_name, version, labels."""
        node = _mock_node(
            "proj",
            "2.0.0",
            ["Version", "INTERNAL"],
        )
        result = db_service._node_to_dict(node)  # noqa: SLF001
        assert result["id"] == "proj:2.0.0"
        assert result["project_name"] == "proj"
        assert result["version"] == "2.0.0"
        assert result["labels"] == ["Version", "INTERNAL"]

    def test_parse_node_id_valid(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A 'proj:ver' string parses into a two-tuple."""
        parsed = db_service._parse_node_id(  # noqa: SLF001
            "proj:1.0.0",
        )
        assert parsed == ("proj", "1.0.0")

    def test_parse_node_id_with_colon_in_name(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Colons inside the project name are preserved."""
        parsed = db_service._parse_node_id(  # noqa: SLF001
            "com.example:lib:1.0",
        )
        assert parsed == ("com.example:lib", "1.0")

    def test_parse_node_id_invalid(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A string without a colon returns None."""
        parsed = db_service._parse_node_id(  # noqa: SLF001
            "no-colon",
        )
        assert parsed is None

    def test_add_edge_if_new(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A new edge is appended and returns True."""
        edges: list[dict] = []
        seen: set = set()
        added = db_service._add_edge_if_new(  # noqa: SLF001
            "A",
            "B",
            "DEPENDS_ON",
            edges,
            seen,
        )
        assert added is True
        assert len(edges) == 1
        assert edges[0] == {
            "source": "A",
            "target": "B",
            "type": "DEPENDS_ON",
        }

    def test_add_edge_duplicate_ignored(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Duplicate edges are silently ignored."""
        edges: list[dict] = []
        seen: set = set()
        db_service._add_edge_if_new(  # noqa: SLF001
            "A",
            "B",
            "DEPENDS_ON",
            edges,
            seen,
        )
        duplicate = db_service._add_edge_if_new(  # noqa: SLF001
            "A",
            "B",
            "DEPENDS_ON",
            edges,
            seen,
        )
        assert duplicate is False
        assert len(edges) == 1

    def test_build_node_conditions(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Conditions and params are built for each node ID."""
        params: dict = {}
        conditions = db_service._build_node_conditions(  # noqa: SLF001
            ["proj:1.0", "lib:2.0"],
            params,
            "src",
            "s",
        )
        assert len(conditions) == 2
        assert params["s_proj_0"] == "proj"
        assert params["s_ver_0"] == "1.0"
        assert params["s_proj_1"] == "lib"
        assert params["s_ver_1"] == "2.0"

    def test_build_node_conditions_skips_invalid(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """IDs without a colon are silently skipped."""
        params: dict = {}
        conditions = db_service._build_node_conditions(  # noqa: SLF001
            ["valid:1.0", "nocolon"],
            params,
            "n",
            "p",
        )
        assert len(conditions) == 1

    def test_is_at_capacity(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Small node sets are not at capacity."""
        small: dict[str, Any] = {f"n{i}": {} for i in range(10)}
        at_cap = db_service._is_at_capacity(small)  # noqa: SLF001
        assert at_cap is False

    def test_get_remaining_capacity(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Remaining capacity equals limit minus current count."""
        nodes: dict[str, Any] = {f"n{i}": {} for i in range(100)}
        remaining = db_service._get_remaining_capacity(  # noqa: SLF001
            nodes,
        )
        assert remaining == 50000 - 100


class TestBuildDependantsQuery:
    """Tests for _build_dependants_query."""

    def test_single_filter_mode(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Single-scan filter uses '$scan_id IN src.scan_ids'."""
        query = db_service._build_dependants_query(  # noqa: SLF001
            ["cond1"],
            "single",
            False,
        )
        assert "$scan_id IN src.scan_ids" in query
        assert "Version" in query

    def test_any_filter_mode(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Any-scan filter uses ANY() predicate."""
        query = db_service._build_dependants_query(  # noqa: SLF001
            ["cond1"],
            "any",
            False,
        )
        expected = "ANY(sid IN $scan_ids WHERE sid IN src.scan_ids)"
        assert expected in query

    def test_none_filter_mode(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """No-filter mode omits scan_id predicates."""
        query = db_service._build_dependants_query(  # noqa: SLF001
            ["cond1"],
            "none",
            False,
        )
        assert "$scan_id" not in query

    def test_internal_only_label(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Internal-only mode uses 'Version:INTERNAL' label."""
        query = db_service._build_dependants_query(  # noqa: SLF001
            ["cond1"],
            "none",
            True,
        )
        assert "Version:INTERNAL" in query


class TestCategorizationAndSemver:
    """Tests for non-semver categorisation and semver helpers."""

    @pytest.mark.parametrize(
        "version,expected",
        [
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
        ],
    )
    def test_categorization(
        self,
        db_service: FalkorDBService,
        version: str,
        expected: str,
    ) -> None:
        """Each version string maps to its expected category."""
        category = db_service._categorize_non_semver_version(  # noqa: SLF001
            version,
        )
        assert category == expected

    def test_is_semver_compliant_all_valid(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """All-valid versions yield compliant=True."""
        with patch.object(
            db_service,
            "get_all_versions_of_project",
            return_value=["1.0.0", "2.0.0"],
        ):
            is_compliant, non_compliant = db_service.is_project_semver_compliant("proj")
            assert is_compliant is True
            assert non_compliant == []

    def test_is_semver_compliant_with_invalid(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A non-semver version makes the project non-compliant."""
        with patch.object(
            db_service,
            "get_all_versions_of_project",
            return_value=["1.0.0", "latest"],
        ):
            is_compliant, non_compliant = db_service.is_project_semver_compliant("proj")
            assert is_compliant is False
            assert "latest" in non_compliant

    def test_get_latest_semver_version(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Latest semver version is the numerically highest."""
        with patch.object(
            db_service,
            "is_project_semver_compliant",
            return_value=(True, []),
        ):
            with patch.object(
                db_service,
                "get_all_versions_of_project",
                return_value=["1.0.0", "2.0.0", "1.10.0"],
            ):
                result = db_service.get_latest_semver_version(
                    "proj",
                )
                assert result == "2.0.0"

    def test_get_latest_semver_not_compliant(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Non-compliant project returns None for latest."""
        with patch.object(
            db_service,
            "is_project_semver_compliant",
            return_value=(False, ["bad"]),
        ):
            result = db_service.get_latest_semver_version(
                "proj",
            )
            assert result is None

    def test_get_latest_semver_no_versions(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """An empty version list returns None."""
        with patch.object(
            db_service,
            "is_project_semver_compliant",
            return_value=(True, []),
        ):
            with patch.object(
                db_service,
                "get_all_versions_of_project",
                return_value=[],
            ):
                result = db_service.get_latest_semver_version(
                    "proj",
                )
                assert result is None


class TestGetAllApplications:
    """Tests for get_all_applications method."""

    def test_returns_applications(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A single row yields one application dict."""
        row = [
            "app-a",
            "1.0.0",
            "scan-1",
            "app-1",
            "pub-1",
            "https://git.example.com",
            ["Application", "INTERNAL"],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[row],
        ):
            result = db_service.get_all_applications(limit=100)
            assert len(result) == 1
            assert result[0]["project_name"] == "app-a"
            assert result[0]["is_internal"] is True

    def test_latest_only_with_semver(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """latest_only keeps only the semver-latest version."""
        rows = [
            [
                "app-a",
                "1.0.0",
                None,
                None,
                None,
                None,
                ["Application"],
            ],
            [
                "app-a",
                "2.0.0",
                None,
                None,
                None,
                None,
                ["Application"],
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=rows,
        ):
            with patch.object(
                db_service,
                "get_latest_semver_version",
                return_value="2.0.0",
            ):
                result = db_service.get_all_applications(
                    latest_only=True,
                )
                assert len(result) == 1
                assert result[0]["version"] == "2.0.0"

    def test_latest_only_no_semver_falls_back(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """When semver is unavailable, last row wins."""
        rows = [
            [
                "app-b",
                "alpha",
                None,
                None,
                None,
                None,
                ["Application"],
            ],
            [
                "app-b",
                "beta",
                None,
                None,
                None,
                None,
                ["Application"],
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=rows,
        ):
            with patch.object(
                db_service,
                "get_latest_semver_version",
                return_value=None,
            ):
                result = db_service.get_all_applications(
                    latest_only=True,
                )
                assert len(result) == 1
                assert result[0]["version"] == "beta"


class TestFindNonSemverVersions:
    """Tests for find_non_semver_versions."""

    def test_returns_non_semver(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Only versions failing the semver regex are returned."""
        rows = [
            ["proj-a", "1.0.0", ["Version"]],
            ["proj-b", "latest", ["Version"]],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=rows,
        ):
            result = db_service.find_non_semver_versions()
            assert len(result) == 1
            assert result[0]["project_name"] == "proj-b"
            assert result[0]["reason"] == "No numeric component"


class TestFindCycles:
    """Tests for cycle-finding methods."""

    def test_find_cycles_returns_list(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Detected cycles produce a non-empty result."""
        cycle_row = [
            [
                {
                    "project_name": "a",
                    "version": "1.0",
                },
                {
                    "project_name": "b",
                    "version": "1.0",
                },
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[cycle_row],
        ):
            result = db_service.find_cycles(
                max_cycle_length=3,
            )
            assert len(result) > 0

    def test_find_cycles_timeout_continues(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A timeout yields an empty list, not an exception."""
        with patch.object(
            db_service,
            "execute_query",
            side_effect=TimeoutError("timeout"),
        ):
            result = db_service.find_cycles(
                max_cycle_length=2,
            )
            assert result == []

    def test_find_direct_cycles(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Direct (A↔B) cycles are detected correctly."""
        rows = [
            [
                "proj-a",
                "1.0",
                "proj-b",
                "1.0",
                "DEPENDS_ON",
                "DEPENDS_ON",
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=rows,
        ):
            result = db_service.find_direct_cycles()
            assert len(result) == 1
            assert result[0]["project_a"] == "proj-a"


class TestGetApplicationsByScanIds:
    """Tests for get_applications_by_scan_ids."""

    def test_empty_scan_ids(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """An empty scan-ID list returns an empty list."""
        assert db_service.get_applications_by_scan_ids([]) == []

    def test_returns_applications(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Matching scan IDs yield application records."""
        rows = [["app-a", "1.0.0", "scan-1"]]
        with patch.object(
            db_service,
            "execute_query",
            return_value=rows,
        ):
            result = db_service.get_applications_by_scan_ids(
                ["scan-1"],
            )
            assert len(result) == 1
            assert result[0]["scan_id"] == "scan-1"


class TestGetAllVulnerabilities:
    """Tests for vulnerability query methods."""

    def test_get_all_vulnerabilities(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A full vulnerability row is mapped correctly."""
        affected = [
            {
                "project_name": "lib",
                "version": "1.0",
                "project_group": "com.example",
            },
        ]
        row = [
            "CVE-2024-001",
            "XSS Vuln",
            "desc",
            "HIGH",
            7.5,
            "CWE-79",
            "2024-01-01",
            "2024-06-01T00:00:00Z",
            ["CVE-2024-001"],
            "osv",
            affected,
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[row],
        ):
            result = db_service.get_all_vulnerabilities()
            assert len(result) == 1
            assert result[0]["defect_id"] == "CVE-2024-001"
            assert result[0]["severity"] == "HIGH"
            enriched = result[0]["last_enriched_at"]
            assert enriched == "2024-06-01T00:00:00Z"
            assert result[0]["aliases"] == ["CVE-2024-001"]

    def test_get_vulnerability_by_id(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A single vulnerability is found by its ID."""
        affected = [
            {
                "project_name": "lib",
                "version": "1.0",
                "project_group": "g",
            },
        ]
        row = [
            "CVE-2024-001",
            "title",
            "desc",
            "HIGH",
            7.5,
            "CWE-79",
            "2024-01-01",
            affected,
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[row],
        ):
            result = db_service.get_vulnerability_by_id(
                "CVE-2024-001",
            )
            assert result is not None
            assert result["defect_id"] == "CVE-2024-001"

    def test_get_vulnerability_by_id_not_found(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A missing vulnerability returns None."""
        with patch.object(
            db_service,
            "execute_query",
            return_value=[],
        ):
            result = db_service.get_vulnerability_by_id(
                "CVE-NOTEXIST",
            )
            assert result is None

    def test_get_vulnerability_by_id_filters_none(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Affected versions with None fields are filtered out."""
        affected = [
            {
                "project_name": None,
                "version": None,
                "project_group": None,
            },
            {
                "project_name": "lib",
                "version": "1.0",
                "project_group": "g",
            },
        ]
        row = [
            "CVE-1",
            "t",
            "d",
            "LOW",
            2.0,
            None,
            None,
            affected,
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[row],
        ):
            result = db_service.get_vulnerability_by_id("CVE-1")
            assert result is not None and len(result["affected_versions"]) == 1


class TestGetInternalCentrality:
    """Tests for centrality report."""

    def test_returns_centrality_data(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A single centrality row maps to expected fields."""
        row = ["com.example", "my-lib", "1.0.0", 10, 5]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[row],
        ):
            result = db_service.get_internal_centrality()
            assert len(result) == 1
            assert result[0]["inDegree"] == 10
            assert result[0]["outDegree"] == 5

    def test_default_sort_by(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """An invalid sort_by falls back to the default."""
        with patch.object(
            db_service,
            "execute_query",
            return_value=[],
        ):
            db_service.get_internal_centrality(
                sort_by="invalid_field",
            )

    def test_handles_null_values(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Null database values are coerced to safe defaults."""
        row = [None, None, None, None, None]
        with patch.object(
            db_service,
            "execute_query",
            return_value=[row],
        ):
            result = db_service.get_internal_centrality()
            assert result[0]["project_group"] == ""
            assert result[0]["inDegree"] == 0


class TestTransitiveDependencies:
    """Tests for BFS traversal methods."""

    def test_get_transitive_deps_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """No root version yields empty lists."""
        with patch.object(
            db_service,
            "find_version",
            return_value=None,
        ):
            with patch.object(
                db_service,
                "execute_query",
                return_value=[],
            ):
                nodes, edges = db_service.get_transitive_dependencies(
                    "proj",
                    "1.0",
                )
                assert nodes == []
                assert edges == []

    def test_get_transitive_deps_with_root(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A found root version appears as the sole node."""
        root = {
            "properties": {
                "project_name": "proj",
                "name": "1.0",
            },
            "labels": ["Version"],
        }
        with patch.object(
            db_service,
            "find_version",
            return_value=root,
        ):
            with patch.object(
                db_service,
                "execute_query",
                return_value=[],
            ):
                nodes, _edges = db_service.get_transitive_dependencies(
                    "proj",
                    "1.0",
                )
                assert len(nodes) == 1
                assert nodes[0]["id"] == "proj:1.0"

    def test_get_transitive_dependants_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """No root version yields empty dependants."""
        with patch.object(
            db_service,
            "find_version",
            return_value=None,
        ):
            with patch.object(
                db_service,
                "execute_query",
                return_value=[],
            ):
                nodes, edges = db_service.get_transitive_dependants(
                    "proj",
                    "1.0",
                )
                assert nodes == []
                assert edges == []

    def test_report_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Empty graph data yields an empty report list."""
        with patch.object(
            db_service,
            "get_transitive_dependencies",
            return_value=([], []),
        ):
            result = db_service.get_transitive_dependencies_for_report(
                "proj",
                "1.0",
            )
            assert result == []

    def test_report_with_data(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A one-hop dependency appears at depth 1."""
        nodes = [
            {
                "id": "proj:1.0",
                "project_name": "proj",
                "version": "1.0",
                "labels": ["Version"],
                "properties": {},
            },
            {
                "id": "lib:2.0",
                "project_name": "lib",
                "version": "2.0",
                "labels": ["Version"],
                "properties": {},
            },
        ]
        edges = [
            {
                "source": "proj:1.0",
                "target": "lib:2.0",
                "type": "DEPENDS_ON",
            },
        ]
        with patch.object(
            db_service,
            "get_transitive_dependencies",
            return_value=(nodes, edges),
        ):
            result = db_service.get_transitive_dependencies_for_report(
                "proj",
                "1.0",
            )
            assert len(result) == 1
            assert result[0]["dependency_project"] == "lib"
            assert result[0]["depth"] == 1


class TestFindMultiVersionSources:
    """Tests for find_multi_version_dependency_sources."""

    def test_not_found_returns_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Unknown version yields a null target and empty list."""
        with patch.object(
            db_service,
            "find_version",
            return_value=None,
        ):
            result = db_service.find_multi_version_dependency_sources(
                "p",
                "1.0",
            )
            assert result["target"] is None
            assert result["multi_version_dependencies"] == []

    def test_no_multi_versions(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """All single-version deps produce an empty list."""
        root = {
            "properties": {
                "project_name": "p",
                "name": "1.0",
                "scan_ids": [],
            },
            "labels": ["Version"],
        }
        nodes = [
            {
                "id": "p:1.0",
                "project_name": "p",
                "version": "1.0",
                "labels": [],
                "properties": {},
            },
            {
                "id": "lib:1.0",
                "project_name": "lib",
                "version": "1.0",
                "labels": [],
                "properties": {},
            },
        ]
        with patch.object(
            db_service,
            "find_version",
            return_value=root,
        ):
            with patch.object(
                db_service,
                "get_transitive_dependencies",
                return_value=(nodes, []),
            ):
                result = db_service.find_multi_version_dependency_sources(
                    "p",
                    "1.0",
                )
                multi = result["multi_version_dependencies"]
                assert multi == []


class TestGetLibraryVersionUsage:
    """Tests for get_library_version_usage."""

    def _wire_mock_db(
        self,
        db_service: FalkorDBService,
        result_set: list,
    ) -> None:
        """Inject a mock database returning *result_set*."""
        mock_result = MagicMock()
        mock_result.result_set = result_set
        mock_graph = MagicMock()
        mock_graph.query.return_value = mock_result
        mock_db = MagicMock()
        mock_db.select_graph.return_value = mock_graph
        db_service._db = mock_db  # noqa: SLF001

    def test_returns_usage_data(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Two versions with dependants are reported."""
        dependants = [
            {
                "project_name": "app-a",
                "version": "1.0",
                "project_group": "g",
                "labels": ["Version"],
            },
            {
                "project_name": "app-b",
                "version": "2.0",
                "project_group": "g",
                "labels": ["Version"],
            },
        ]
        rows = [
            [
                "1.0.0",
                "com.example",
                ["Version", "INTERNAL"],
                2,
                dependants,
            ],
            [
                "2.0.0",
                "com.example",
                ["Version"],
                0,
                [],
            ],
        ]
        self._wire_mock_db(db_service, rows)

        result = db_service.get_library_version_usage("my-lib")
        lib = result["library"]
        assert lib["project_name"] == "my-lib"
        assert lib["total_versions"] == 2
        assert result["total_dependants"] == 2
        assert len(result["versions"]) == 2
        assert result["versions"][0]["dependant_count"] == 2

    def test_empty_result(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """A nonexistent library yields zero totals."""
        self._wire_mock_db(db_service, [])

        result = db_service.get_library_version_usage(
            "nonexistent",
        )
        assert result["library"]["total_versions"] == 0
        assert result["total_dependants"] == 0
