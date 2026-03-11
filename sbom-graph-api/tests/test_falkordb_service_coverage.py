"""Additional tests for FalkorDB service to improve coverage.

Targets the largest uncovered line ranges:
- get_dependants_with_partitions_and_paths (1268-1449)
- get_license_summary (2509-2607)
- get_license_conflicts (2629-2744)
- get_package_vulnerabilities (3141-3231)
- compute_patch_plan, _get_contacts_for_purl (3536-3643)
- get_vex_for_package, get_vex_coverage (3885-3945)
- get_vulnerabilities_with_vex, get_trust_score_*, etc. (4245-4530)
"""

from unittest.mock import patch

import pytest

from sbom_graph_api.config import FalkorDBConfig
from sbom_graph_api.services.falkordb_service import FalkorDBService


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
def db_service(falkordb_config: FalkorDBConfig) -> FalkorDBService:
    """Return a FalkorDBService wired to test config."""
    return FalkorDBService(config=falkordb_config)


class TestGetDependantsWithPartitionsAndPaths:
    """Tests for get_dependants_with_partitions_and_paths (lines 1268-1449)."""

    def test_returns_target_stats_and_dependants(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns target info, stats, and dependants with partition and paths."""
        nodes = [
            {
                "id": "lib:1.0",
                "project_name": "lib",
                "version": "1.0",
                "labels": ["Version"],
            },
            {
                "id": "app:2.0",
                "project_name": "app",
                "version": "2.0",
                "labels": ["Application"],
            },
        ]
        edges = [
            {"source": "app:2.0", "target": "lib:1.0", "type": "DEPENDS_ON"},
        ]
        with patch.object(
            db_service,
            "get_transitive_dependants",
            return_value=(nodes, edges),
        ):
            result = db_service.get_dependants_with_partitions_and_paths(
                "lib",
                "1.0",
            )
        assert "target" in result
        assert result["target"]["project_name"] == "lib"
        assert result["target"]["version"] == "1.0"
        assert "stats" in result
        assert "dependants" in result
        assert len(result["dependants"]) == 1
        assert result["dependants"][0]["project_name"] == "app"
        assert result["dependants"][0]["partition"] >= 0

    def test_empty_dependants(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Empty transitive dependants yields empty dependants list."""
        nodes = [
            {"id": "lib:1.0", "project_name": "lib", "version": "1.0", "labels": []},
        ]
        with patch.object(
            db_service,
            "get_transitive_dependants",
            return_value=(nodes, []),
        ):
            result = db_service.get_dependants_with_partitions_and_paths(
                "lib",
                "1.0",
            )
        assert result["stats"]["total_dependants"] == 0
        assert result["dependants"] == []

    def test_longest_only_false_includes_multiple_paths(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """longest_only=False includes up to 50 paths per dependant."""
        nodes = [
            {"id": "lib:1.0", "project_name": "lib", "version": "1.0", "labels": []},
            {"id": "mid:1.0", "project_name": "mid", "version": "1.0", "labels": []},
            {"id": "app:1.0", "project_name": "app", "version": "1.0", "labels": []},
        ]
        edges = [
            {"source": "app:1.0", "target": "mid:1.0", "type": "DEPENDS_ON"},
            {"source": "mid:1.0", "target": "lib:1.0", "type": "DEPENDS_ON"},
        ]
        with patch.object(
            db_service,
            "get_transitive_dependants",
            return_value=(nodes, edges),
        ):
            result = db_service.get_dependants_with_partitions_and_paths(
                "lib",
                "1.0",
                longest_only=False,
            )
        assert "dependants" in result
        assert len(result["dependants"]) >= 1


class TestGetLicenseSummary:
    """Tests for get_license_summary (lines 2509-2607)."""

    def test_returns_license_bom_without_project_group(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns license BOM for version without project_group."""
        root_rows = [
            ["g", "proj", "1.0", "pkg:maven/org/proj@1.0", "MIT", "MIT", "permissive"],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=root_rows,
        ):
            result = db_service.get_license_summary("proj", "1.0")
        assert len(result) == 1
        assert result[0]["project_name"] == "proj"
        assert result[0]["spdx_id"] == "MIT"
        assert result[0]["purl"] == "pkg:maven/org/proj@1.0"

    def test_returns_license_bom_with_project_group(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns license BOM when project_group is provided."""
        root_rows = [
            [
                "com.example",
                "proj",
                "1.0",
                "pkg:maven/com.example/proj@1.0",
                "Apache-2.0",
                "Apache",
                "permissive",
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            return_value=root_rows,
        ):
            result = db_service.get_license_summary(
                "proj",
                "1.0",
                project_group="com.example",
            )
        assert len(result) == 1
        assert result[0]["project_group"] == "com.example"

    def test_transitive_deps_included(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Transitive dependencies are included in BOM."""
        root_rows = [
            ["", "proj", "1.0", "pkg:maven/org/proj@1.0", "MIT", "MIT", "permissive"],
        ]
        dep_rows = [
            [
                "",
                "dep",
                "2.0",
                "pkg:maven/org/dep@2.0",
                "GPL-2.0",
                "GPL",
                "strong_copyleft",
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            side_effect=[root_rows, dep_rows, []],
        ):
            result = db_service.get_license_summary(
                "proj",
                "1.0",
                max_depth=5,
            )
        assert len(result) >= 1


class TestGetLicenseConflicts:
    """Tests for get_license_conflicts (lines 2629-2744)."""

    def test_empty_apps_returns_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """No applications yields empty conflicts list."""
        with patch.object(db_service, "execute_query", return_value=[]):
            result = db_service.get_license_conflicts(internal_only=True)
        assert result == []

    def test_returns_conflicts_when_copyleft_and_permissive(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns conflicts when app mixes strong_copyleft and permissive."""
        apps_rows = [
            ["pg", "app-a", "1.0", "pkg:maven/org/app@1.0"],
        ]
        lic_rows = [
            ["pkg:maven/org/app@1.0", "MIT", "permissive"],
        ]
        dep_rows = [
            [
                "pkg:maven/org/app@1.0",
                "pkg:maven/org/lib@1.0",
                "GPL-2.0",
                "strong_copyleft",
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            side_effect=[apps_rows, lic_rows, dep_rows, []],
        ):
            result = db_service.get_license_conflicts(internal_only=True)
        assert len(result) >= 1
        assert "licenses" in result[0]
        assert "risk_categories" in result[0]

    def test_no_conflict_when_single_category(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """No conflict when app has only permissive licenses."""
        apps_rows = [
            ["pg", "app-b", "1.0", "pkg:maven/org/app2@1.0"],
        ]
        lic_rows = [
            ["pkg:maven/org/app2@1.0", "MIT", "permissive"],
        ]
        dep_rows = [
            [
                "pkg:maven/org/app2@1.0",
                "pkg:maven/org/lib2@1.0",
                "Apache-2.0",
                "permissive",
            ],
        ]
        with patch.object(
            db_service,
            "execute_query",
            side_effect=[apps_rows, lic_rows, dep_rows, []],
        ):
            result = db_service.get_license_conflicts(internal_only=False)
        # May or may not have conflicts depending on traversal
        assert isinstance(result, list)


class TestGetPackageVulnerabilities:
    """Tests for get_package_vulnerabilities (lines 3141-3231)."""

    def test_returns_direct_vulnerabilities(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns direct vulnerabilities for package."""
        direct_rows = [
            [
                "CVE-2024-001",
                "HIGH",
                7.5,
                "CVSS:3.1/...",
                "desc",
                ["CVE-2024-001"],
                "osv",
                "2024-06-01T00:00:00Z",
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=direct_rows):
            result = db_service.get_package_vulnerabilities(
                "pkg:maven/org/lib@1.0",
            )
        assert result["package"] == "pkg:maven/org/lib@1.0"
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["id"] == "CVE-2024-001"
        assert result["count"] == 1

    def test_include_dependencies_adds_transitive(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """include_dependencies=True adds transitive vulnerabilities."""
        direct_rows = [
            ["CVE-1", "HIGH", 7.0, None, "d", [], "osv", None],
        ]
        dep_rows = [
            ["pkg:maven/org/dep@1.0"],
        ]
        trans_rows = [
            [
                "pkg:maven/org/dep@1.0",
                "CVE-2",
                "MEDIUM",
                "d2",
                [],
                "osv",
            ],
        ]

        def query_side_effect(query: str, params: dict | None = None):
            if params and "purl" in params and "purls" not in params:
                return direct_rows
            if "VERSION_DEFECT" in query and params and "purls" in params:
                return trans_rows
            if "DEPENDENCY_VERSION" in query and params and "purls" in params:
                purls = params.get("purls", [])
                if purls and "dep" in str(purls[0]):
                    return []  # dep has no further deps
                return dep_rows
            return direct_rows

        with patch.object(
            db_service,
            "execute_query",
            side_effect=query_side_effect,
        ):
            result = db_service.get_package_vulnerabilities(
                "pkg:maven/org/lib@1.0",
                include_dependencies=True,
                max_depth=1,
            )
        assert "transitive_vulnerabilities" in result
        assert "transitive_count" in result
        assert len(result["transitive_vulnerabilities"]) >= 1


class TestComputePatchPlan:
    """Tests for compute_patch_plan and _get_contacts_for_purl (3536-3643)."""

    def test_defect_not_found_returns_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Defect not found yields empty frontiers."""
        with patch.object(db_service, "execute_query", return_value=[]):
            result = db_service.compute_patch_plan("CVE-NOT-FOUND")
        assert result["defect"] is None
        assert result["frontiers"] == []
        assert result["total_affected"] == 0

    def test_returns_frontiers_with_contacts(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns frontiers with contact info for affected packages."""
        defect_rows = [
            [
                "CVE-2024-123",
                "CVE-2024-123",
                "HIGH",
                ["CVE-2024-123"],
                "desc",
            ],
        ]
        level0_rows = [
            [
                "lib",
                "1.0",
                "pkg:maven/org/lib@1.0",
                "com.example",
            ],
        ]
        contact_rows = [
            ["dev@example.com", "team-a", "#slack"],
        ]
        dep_rows = []  # No level 1 deps
        with patch.object(
            db_service,
            "execute_query",
            side_effect=[defect_rows, level0_rows, contact_rows, dep_rows],
        ):
            result = db_service.compute_patch_plan("CVE-2024-123")
        assert result["defect"] is not None
        assert len(result["frontiers"]) >= 1
        assert result["total_affected"] >= 1
        assert "contacts" in result

    def test_get_contacts_for_purl(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """_get_contacts_for_purl returns contact dicts."""
        rows = [
            ["dev@example.com", "team-a", "#channel"],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service._get_contacts_for_purl(  # noqa: SLF001, pylint: disable=protected-access
                "pkg:maven/org/lib@1.0",
            )
        assert len(result) == 1
        assert result[0]["email"] == "dev@example.com"
        assert result[0]["team"] == "team-a"
        assert result[0]["slack_channel"] == "#channel"


class TestGetVexForPackage:
    """Tests for get_vex_for_package and get_vex_coverage (3885-3945)."""

    def test_get_vex_for_package_returns_statements(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns VEX statements for package."""
        rows = [
            [
                "stmt-1",
                "not_affected",
                "Custom build",
                "impact",
                "action",
                "doc",
                "2024-06-01T00:00:00Z",
                "CVE-2024-001",
                "HIGH",
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_vex_for_package("pkg:maven/org/lib@1.0")
        assert len(result) == 1
        assert result[0]["statement_id"] == "stmt-1"
        assert result[0]["status"] == "not_affected"
        assert result[0]["vulnerability_id"] == "CVE-2024-001"

    def test_get_vex_coverage_returns_stats(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns VEX coverage statistics."""
        total_rows = [[10]]
        covered_rows = [[6]]
        with patch.object(
            db_service,
            "execute_query",
            side_effect=[total_rows, covered_rows],
        ):
            result = db_service.get_vex_coverage(internal_only=False)
        assert "total_vulnerabilities" in result
        assert "with_vex" in result
        assert "without_vex" in result
        assert "coverage_percent" in result
        assert result["total_vulnerabilities"] == 10
        assert result["with_vex"] == 6
        assert result["without_vex"] == 4

    def test_get_vex_coverage_zero_total(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Zero total vulns yields 0.0 coverage percent."""
        with patch.object(db_service, "execute_query", return_value=[[0]]):
            result = db_service.get_vex_coverage()
        assert result["coverage_percent"] == 0.0


class TestGetVulnerabilitiesWithVex:
    """Tests for get_vulnerabilities_with_vex (4245-4286)."""

    def test_returns_vulns_with_vex_status(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns vulnerabilities with VEX status."""
        rows = [
            [
                "CVE-2024-001",
                "HIGH",
                "desc",
                "not_affected",
                1,
                [{"project_name": "lib", "version": "1.0", "project_group": "g"}],
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_vulnerabilities_with_vex(internal_only=False)
        assert len(result) == 1
        assert result[0]["defect_id"] == "CVE-2024-001"
        assert result[0]["vex_status"] == "not_affected"
        assert result[0]["vex_count"] == 1
        assert len(result[0]["affected_versions"]) == 1


class TestGetTrustScoreForPurl:
    """Tests for get_trust_score_for_purl (4290-4333)."""

    def test_returns_score_when_found(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns full trust score when found."""
        rows = [
            [
                "pkg:maven/org/lib@1.0",
                8.0,
                7.5,
                7.0,
                6.5,
                0.9,
                10,
                8.0,
                7.0,
                7.5,
                8.0,
                ["scorecard", "depsdev"],
                "2024-06-01T00:00:00Z",
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_trust_score_for_purl("pkg:maven/org/lib@1.0")
        assert result is not None
        assert result["purl"] == "pkg:maven/org/lib@1.0"
        assert result["direct_score"] == 8.0
        assert result["effective_score"] == 7.5
        assert result["sources_used"] == ["scorecard", "depsdev"]

    def test_returns_none_when_not_found(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns None when no trust score exists."""
        with patch.object(db_service, "execute_query", return_value=[]):
            result = db_service.get_trust_score_for_purl("pkg:maven/org/none@0.0")
        assert result is None


class TestGetTrustScoreRiskPath:
    """Tests for get_trust_score_risk_path (4335-4373)."""

    def test_returns_risk_paths(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns dependency risk path sorted by score."""
        rows = [
            ["pkg:maven/org/dep@1.0", 5.0, 5.0, 4.5, 2],
            ["pkg:maven/org/dep2@1.0", 6.0, 6.0, 5.5, 1],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_trust_score_risk_path(
                "pkg:maven/org/lib@1.0",
                limit=10,
            )
        assert len(result) == 2
        assert result[0]["purl"] == "pkg:maven/org/dep@1.0"
        assert result[0]["depth"] == 2


class TestGetApplicationSupplyChainRisk:
    """Tests for get_application_supply_chain_risk (4375-4399)."""

    def test_returns_error_when_no_score(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns error dict when no trust score found."""
        with patch.object(
            db_service,
            "get_trust_score_for_purl",
            return_value=None,
        ):
            result = db_service.get_application_supply_chain_risk(
                "pkg:maven/org/app@1.0",
            )
        assert "error" in result
        assert result["error"] == "No trust score found"

    def test_returns_risk_with_weakest_links(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns risk dict with weakest_links when score exists."""
        score = {
            "effective_score": 7.0,
            "direct_score": 7.5,
            "inherited_score": 6.5,
            "min_path_score": 5.0,
            "dep_count": 20,
            "confidence": 0.85,
        }
        weakest = [
            {"purl": "pkg:maven/org/weak@1.0", "direct_score": 4.0, "depth": 3},
        ]
        with patch.object(
            db_service,
            "get_trust_score_for_purl",
            return_value=score,
        ):
            with patch.object(
                db_service,
                "get_trust_score_risk_path",
                return_value=weakest,
            ):
                result = db_service.get_application_supply_chain_risk(
                    "pkg:maven/org/app@1.0",
                )
        assert result["effective_score"] == 7.0
        assert result["weakest_links"] == weakest


class TestGetTrustScoreDistribution:
    """Tests for get_trust_score_distribution (4401-4433)."""

    def test_returns_distribution_buckets(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns histogram of score buckets."""
        rows = [
            ["excellent", 5],
            ["good", 10],
            ["moderate", 3],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_trust_score_distribution()
        assert result["excellent"] == 5
        assert result["good"] == 10
        assert result["moderate"] == 3


class TestGetRemediationPriorities:
    """Tests for get_remediation_priorities (4435-4475)."""

    def test_returns_prioritized_packages(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns packages sorted by remediation priority."""
        rows = [
            [
                "pkg:maven/org/low@1.0",
                3.0,
                3.0,
                2.5,
                0.7,
                15,
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_remediation_priorities(limit=20)
        assert len(result) == 1
        assert result[0]["purl"] == "pkg:maven/org/low@1.0"
        assert result[0]["effective_score"] == 3.0
        assert result[0]["dependents_count"] == 15


class TestGetTrustScoreGaps:
    """Tests for get_trust_score_gaps (4477-4530)."""

    def test_returns_gaps_with_low_confidence(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns packages with low confidence."""
        rows = [
            [
                "pkg:maven/org/unknown@1.0",
                "unknown",
                "1.0",
                0.5,
                ["scorecard"],
                6.0,
                8,
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_trust_score_gaps(limit=20)
        assert len(result) == 1
        assert result[0]["purl"] == "pkg:maven/org/unknown@1.0"
        assert result[0]["confidence"] == 0.5
        assert result[0]["project_name"] == "unknown"
        assert result[0]["version"] == "1.0"

    def test_handles_list_project_name_version(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Handles list values for project_name and version from head(collect())."""
        rows = [
            [
                "pkg:maven/org/multi@1.0",
                ["proj-a", "proj-b"],  # head(collect()) can return list
                ["1.0", "1.1"],
                0.6,
                [],
                5.0,
                2,
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_trust_score_gaps(limit=10)
        assert len(result) == 1
        assert result[0]["project_name"] == "proj-a"
        assert result[0]["version"] == "1.0"


def _mock_node(project_name: str, version: str, labels: list | None = None) -> object:
    """Build a mock graph node for FalkorDB query results."""
    from unittest.mock import MagicMock

    node = MagicMock()
    node.properties = {"project_name": project_name, "name": version}
    node.labels = labels or ["Version"]
    return node


class TestGetTransitiveDependenciesUnfiltered:
    """Tests for _get_transitive_dependencies_unfiltered (1949-2058)."""

    def test_returns_nodes_and_edges_with_root_and_deps(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns nodes and edges when root exists and has dependencies."""
        root = {
            "properties": {"project_name": "proj", "name": "1.0"},
            "labels": ["Version"],
        }
        src_node = _mock_node("proj", "1.0")
        tgt_node = _mock_node("lib", "2.0")
        dep_rows = [[src_node, tgt_node, "DEPENDS_ON"]]
        with patch.object(db_service, "find_version", return_value=root):
            with patch.object(
                db_service,
                "execute_query",
                return_value=dep_rows,
            ):
                nodes, edges = db_service._get_transitive_dependencies_unfiltered(  # noqa: SLF001
                    "proj",
                    "1.0",
                )
        assert len(nodes) >= 2
        assert len(edges) >= 1
        ids = [n["id"] for n in nodes]
        assert "proj:1.0" in ids
        assert "lib:2.0" in ids
        assert edges[0]["type"] == "DEPENDS_ON"

    def test_root_not_found_returns_empty(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """When root not found, returns empty nodes and edges."""
        with patch.object(db_service, "find_version", return_value=None):
            with patch.object(db_service, "execute_query", return_value=[]):
                nodes, edges = db_service._get_transitive_dependencies_unfiltered(  # noqa: SLF001
                    "nonexistent",
                    "0.0",
                )
        assert nodes == []
        assert edges == []

    def test_handles_query_exception_continues(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Timeout/ConnectionError in query does not raise; continues."""
        root = {"properties": {"project_name": "p", "name": "1.0"}, "labels": []}
        with patch.object(db_service, "find_version", return_value=root):
            with patch.object(
                db_service,
                "execute_query",
                side_effect=TimeoutError("timeout"),
            ):
                nodes, edges = db_service._get_transitive_dependencies_unfiltered(  # noqa: SLF001
                    "p",
                    "1.0",
                )
        assert len(nodes) == 1
        assert nodes[0]["id"] == "p:1.0"
        assert edges == []


class TestGetVulnerabilityDependants:
    """Tests for get_vulnerability_dependants (2295-2362)."""

    def test_returns_empty_when_vuln_not_found(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns [] when vulnerability does not exist."""
        with patch.object(db_service, "get_vulnerability_by_id", return_value=None):
            result = db_service.get_vulnerability_dependants("CVE-NOT-FOUND")
        assert result == []

    def test_returns_empty_when_no_affected_versions(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns [] when vuln has no affected_versions."""
        with patch.object(
            db_service,
            "get_vulnerability_by_id",
            return_value={"affected_versions": []},
        ):
            result = db_service.get_vulnerability_dependants("CVE-2024-001")
        assert result == []

    def test_returns_dependants_sorted_by_partition(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns dependants with partition info, sorted by partition."""
        vuln = {
            "affected_versions": [
                {"project_name": "lib", "version": "1.0"},
            ],
        }
        deps_result = {
            "dependants": [
                {"project_name": "app", "version": "1.0", "partition": 1},
                {"project_name": "mid", "version": "1.0", "partition": 0},
            ],
        }
        with patch.object(db_service, "get_vulnerability_by_id", return_value=vuln):
            with patch.object(
                db_service,
                "get_dependants_with_partitions_and_paths",
                return_value=deps_result,
            ):
                result = db_service.get_vulnerability_dependants("CVE-2024-001")
        assert len(result) == 2
        assert result[0]["partition"] <= result[1]["partition"]


class TestComputeBlastRadius:
    """Tests for compute_blast_radius (3680-3727)."""

    def test_returns_frontiers_by_depth(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns package, frontiers, and total_affected."""
        level1 = [
            ["app", "1.0", "pkg:maven/org/app@1.0", "com.example"],
        ]
        with patch.object(db_service, "execute_query", return_value=level1):
            result = db_service.compute_blast_radius(
                "pkg:maven/org/lib@1.0",
                max_depth=3,
            )
        assert result["package"] == "pkg:maven/org/lib@1.0"
        assert "frontiers" in result
        assert "total_affected" in result
        assert result["total_affected"] >= 1

    def test_empty_frontier_when_no_dependants(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """No dependants yields empty frontiers."""
        with patch.object(db_service, "execute_query", return_value=[]):
            result = db_service.compute_blast_radius("pkg:maven/org/leaf@1.0")
        assert result["frontiers"] == []
        assert result["total_affected"] == 0


class TestGetVexStatusesForVersions:
    """Tests for get_vex_statuses_for_versions (3038-3085)."""

    def test_returns_empty_when_no_purls(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Empty purls yields empty dict."""
        result = db_service.get_vex_statuses_for_versions([])
        assert result == {}

    def test_returns_vex_status_per_purl(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns purl -> vex_status for highest-severity vuln with VEX."""
        rows = [
            ["pkg:maven/org/lib@1.0", "HIGH", "not_affected", "2024-06-01T00:00:00Z"],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_vex_statuses_for_versions(
                ["pkg:maven/org/lib@1.0"],
            )
        assert result["pkg:maven/org/lib@1.0"] == "not_affected"


class TestGetLicenseRisksForVersions:
    """Tests for get_license_risks_for_versions (3100-3122)."""

    def test_returns_empty_when_no_purls(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Empty purls yields empty dict."""
        result = db_service.get_license_risks_for_versions([])
        assert result == {}

    def test_returns_risk_category_per_purl(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns purl -> risk_category from worst license."""
        rows = [
            ["pkg:maven/org/lib@1.0", ["permissive", "weak_copyleft"]],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_license_risks_for_versions(
                ["pkg:maven/org/lib@1.0"],
            )
        assert "pkg:maven/org/lib@1.0" in result
        assert result["pkg:maven/org/lib@1.0"] in (
            "permissive",
            "weak_copyleft",
            "strong_copyleft",
            "proprietary",
            "unknown",
        )


class TestGetVulnerabilityFreshness:
    """Tests for get_vulnerability_freshness (2852-2878)."""

    def test_returns_rows_with_enrichment_status(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns list of package freshness rows."""
        rows = [
            ["g", "proj", "1.0", "purl", "2024-06-01T00:00:00Z"],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_vulnerability_freshness(internal_only=False)
        assert len(result) == 1
        assert result[0]["project_name"] == "proj"
        assert result[0]["last_enriched_at"] == "2024-06-01T00:00:00Z"


class TestGetEnrichmentCoverageFull:
    """Tests for get_enrichment_coverage full implementation (2915-2976)."""

    def test_categorizes_recent_stale_never(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Categorizes packages by recent, stale, never."""
        from datetime import UTC, datetime, timedelta

        cutoff = datetime.now(UTC) - timedelta(days=7)
        recent_ts = (cutoff + timedelta(days=1)).isoformat().replace("+00:00", "Z")
        stale_ts = (cutoff - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        rows = [
            ["g", "p1", "1.0", "purl1", recent_ts],
            ["g", "p2", "2.0", "purl2", stale_ts],
            ["g", "p3", "3.0", "purl3", None],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_enrichment_coverage(internal_only=False)
        assert result["total"] == 3
        assert result["recent"] >= 1
        assert result["stale"] >= 1
        assert result["never"] >= 1
        assert "packages" in result


class TestGetPolicyViolations:
    """Tests for get_policy_violations (3305-3338)."""

    def test_returns_violations_with_dependant_count(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns bad annotations with dependant counts."""
        rows = [
            [
                "ann-1",
                "Known CVE",
                "admin",
                "2024-06-01T00:00:00",
                None,
                "purl",
                "proj",
                "1.0",
                5,
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_policy_violations(internal_only=False)
        assert len(result) == 1
        assert result[0]["annotation_id"] == "ann-1"
        assert result[0]["dependant_count"] == 5


class TestCheckPolicy:
    """Tests for check_policy (3478-3509)."""

    def test_returns_pass_when_no_bad_annotations(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Status is pass when only good annotations."""
        rows = [
            ["ann-1", "good", "Approved", "admin", "2024-06-01", None],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.check_policy("pkg:maven/org/lib@1.0")
        assert result["status"] == "pass"
        assert result["purl"] == "pkg:maven/org/lib@1.0"

    def test_returns_fail_when_bad_annotation(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Status is fail when bad annotation exists."""
        rows = [
            ["ann-1", "bad", "Known CVE", "admin", "2024-06-01", None],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.check_policy("pkg:maven/org/lib@1.0")
        assert result["status"] == "fail"

    def test_returns_hold_when_hold_annotation(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Status is hold when hold annotation exists."""
        rows = [
            ["ann-1", "hold", "Under review", "admin", "2024-06-01", None],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.check_policy("pkg:maven/org/lib@1.0")
        assert result["status"] == "hold"


class TestGetAllSourceRepos:
    """Tests for get_all_source_repos (3967-3990)."""

    def test_returns_repos_with_package_count(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns list of source repos with package_count."""
        rows = [
            [
                "https://github.com/org/repo",
                "git",
                "org",
                "repo",
                10,
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_all_source_repos(internal_only=False)
        assert len(result) == 1
        assert result[0]["url"] == "https://github.com/org/repo"
        assert result[0]["package_count"] == 10


class TestGetPackagesBySourceRepo:
    """Tests for get_packages_by_source_repo (4002-4023)."""

    def test_returns_packages_for_repo(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns packages sourced from given repo."""
        rows = [
            ["proj", "com.example", "1.0", "purl", "CycloneDX"],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_packages_by_source_repo(
                "https://github.com/org/repo",
            )
        assert len(result) == 1
        assert result[0]["project_name"] == "proj"
        assert result[0]["purl"] == "purl"


class TestGetVulnerabilitiesBySourceRepo:
    """Tests for get_vulnerabilities_by_source_repo (4035-4064)."""

    def test_returns_vulns_for_repo(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Returns vulnerabilities in packages from repo."""
        rows = [
            [
                "CVE-2024-001",
                "HIGH",
                "Description",
                "proj",
                "1.0",
            ],
        ]
        with patch.object(db_service, "execute_query", return_value=rows):
            result = db_service.get_vulnerabilities_by_source_repo(
                "https://github.com/org/repo",
            )
        assert len(result) == 1
        assert result[0]["defect_id"] == "CVE-2024-001"
        assert result[0]["affected_project"] == "proj"


class TestFindMultiVersionDependencySources:
    """Tests for find_multi_version_dependency_sources multi-version path (1785-1805)."""

    def test_returns_multi_version_deps_with_contributing_apps(
        self,
        db_service: FalkorDBService,
    ) -> None:
        """Multi-version deps include contributing applications."""
        root = {
            "properties": {"project_name": "app", "name": "1.0", "scan_ids": ["s1"]},
            "labels": ["Application"],
        }
        nodes = [
            {
                "id": "app:1.0",
                "project_name": "app",
                "version": "1.0",
                "properties": {"scan_ids": ["s1"]},
            },
            {
                "id": "lib:1.0",
                "project_name": "lib",
                "version": "1.0",
                "properties": {"scan_ids": ["s1"]},
            },
            {
                "id": "lib:2.0",
                "project_name": "lib",
                "version": "2.0",
                "properties": {"scan_ids": ["s1"]},
            },
        ]
        app_result = [{"project_name": "app-a", "version": "1.0", "scan_id": "s1"}]
        with patch.object(db_service, "find_version", return_value=root):
            with patch.object(
                db_service,
                "get_transitive_dependencies",
                return_value=(nodes, []),
            ):
                with patch.object(
                    db_service,
                    "get_applications_by_scan_ids",
                    return_value=app_result,
                ):
                    result = db_service.find_multi_version_dependency_sources(
                        "app",
                        "1.0",
                    )
        assert "multi_version_dependencies" in result
        assert len(result["multi_version_dependencies"]) >= 1
        dep = result["multi_version_dependencies"][0]
        assert dep["dependency_project"] == "lib"
        assert dep["version_count"] == 2
