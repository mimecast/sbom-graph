"""Tests for the persistence module.

Covers Persistence class methods including query building utilities,
node creation, edge creation, labeling, querying, centrality, and indexing.
All database calls are mocked via the mock_graph fixture.
"""

from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from appsec_sbom_model.model import (
    Defect,
    Project,
    RiskStatus,
    Version,
    VersionDefect,
)
from appsec_sbom_model.persistence import (
    ALLOWED_PROJECT_TYPES,
    Persistence,
    _SAFE_IDENTIFIER_RE,
)


# ---------------------------------------------------------------------------
# Static / utility helpers
# ---------------------------------------------------------------------------


class TestValidateLabel:
    """Tests for Persistence._validate_label."""

    def test_valid_label_application(self):
        result = Persistence._validate_label("Application", ALLOWED_PROJECT_TYPES)
        assert result == "Application"

    def test_valid_label_library(self):
        result = Persistence._validate_label("Library", ALLOWED_PROJECT_TYPES)
        assert result == "Library"

    @pytest.mark.parametrize("label", sorted(ALLOWED_PROJECT_TYPES))
    def test_all_allowed_types_accepted(self, label: str):
        assert Persistence._validate_label(label, ALLOWED_PROJECT_TYPES) == label

    def test_invalid_label_not_in_allowlist(self):
        with pytest.raises(ValueError, match="Invalid node label"):
            Persistence._validate_label("MaliciousLabel", ALLOWED_PROJECT_TYPES)

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="Invalid node label"):
            Persistence._validate_label("", ALLOWED_PROJECT_TYPES)

    def test_injection_attempt_rejected(self):
        with pytest.raises(ValueError, match="Invalid node label"):
            Persistence._validate_label(
                "Library}) RETURN n //", ALLOWED_PROJECT_TYPES
            )


class TestSafeIdentifierRegex:
    """Tests for the _SAFE_IDENTIFIER_RE pattern."""

    @pytest.mark.parametrize(
        "value",
        ["Application", "Library", "Machine-Learning-Model", "_private", "A123"],
    )
    def test_valid_identifiers(self, value: str):
        assert _SAFE_IDENTIFIER_RE.match(value) is not None

    @pytest.mark.parametrize(
        "value",
        ["123start", "-dash", "has space", "semi;colon", "quote'", ""],
    )
    def test_invalid_identifiers(self, value: str):
        assert _SAFE_IDENTIFIER_RE.match(value) is None


class TestGetPurlPrefix:
    """Tests for Persistence._get_purl_prefix."""

    def test_standard_purl(self):
        purl = "pkg:maven/com.example/test-lib@1.0.0"
        assert Persistence._get_purl_prefix(purl) == "pkg:maven/com.example/test-lib@"

    def test_purl_with_qualifiers(self):
        purl = "pkg:maven/com.example/test@2.0?type=jar"
        assert Persistence._get_purl_prefix(purl) == "pkg:maven/com.example/test@"

    def test_purl_no_version_marker(self):
        purl = "pkg:maven/com.example/no-version"
        assert Persistence._get_purl_prefix(purl) == "pkg:maven/com.example/no-version@"


class TestAppendToMainFields:
    """Tests for Persistence._append_to_main_fields."""

    def test_adds_field_when_value_present(self):
        main_fields, params = Persistence._append_to_main_fields(
            "name", "test", {}, ""
        )
        assert "name: $name" in main_fields
        assert params["name"] == "test"

    def test_skips_field_when_value_is_none(self):
        main_fields, params = Persistence._append_to_main_fields(
            "name", None, {}, ""
        )
        assert main_fields == ""
        assert "name" not in params

    def test_appends_comma_when_existing_fields(self):
        main_fields, params = Persistence._append_to_main_fields(
            "version", "1.0", {}, "name: $name"
        )
        assert main_fields.startswith("name: $name,")
        assert "version: $version" in main_fields

    def test_no_comma_for_first_field(self):
        main_fields, _ = Persistence._append_to_main_fields("x", "val", {}, "")
        assert not main_fields.startswith(",")


class TestAppendToAdditionalFields:
    """Tests for Persistence._append_to_additional_fields."""

    def test_adds_set_prefix_for_first_field(self):
        additional, params = Persistence._append_to_additional_fields(
            "severity", "high", {}, ""
        )
        assert additional.startswith("SET")
        assert "n.severity = $severity" in additional
        assert params["severity"] == "high"

    def test_appends_comma_for_subsequent_fields(self):
        existing = "SET\n\tn.severity = $severity"
        additional, params = Persistence._append_to_additional_fields(
            "cvss", 7.5, {"severity": "high"}, existing
        )
        assert "n.cvss = $cvss" in additional
        assert ",\n\t" in additional

    def test_skips_none_values(self):
        additional, params = Persistence._append_to_additional_fields(
            "missing", None, {}, ""
        )
        assert additional == ""
        assert "missing" not in params


class TestCreateExtendedQuery:
    """Tests for Persistence._create_extended_query."""

    def test_generates_on_match_on_create(self):
        pairs = [("severity", "high"), ("cvss", 7.5)]
        query, params = Persistence._create_extended_query(pairs, {})
        assert "ON MATCH" in query
        assert "ON CREATE" in query
        assert params["severity"] == "high"
        assert params["cvss"] == 7.5

    def test_empty_when_all_none_values(self):
        pairs = [("a", None), ("b", None)]
        query, params = Persistence._create_extended_query(pairs, {})
        assert query == ""

    def test_skips_none_values_in_mixed_list(self):
        pairs = [("keep", "yes"), ("drop", None), ("also_keep", 42)]
        query, params = Persistence._create_extended_query(pairs, {})
        assert "keep" in query
        assert "also_keep" in query
        assert "drop" not in params


# ---------------------------------------------------------------------------
# Persistence __init__
# ---------------------------------------------------------------------------


class TestPersistenceInit:
    """Tests for Persistence initialization."""

    def test_creates_connection(self, mock_persistence: Persistence):
        assert mock_persistence.graph is not None

    def test_connection_with_ssl(self, mock_graph: MagicMock):
        with patch("appsec_sbom_model.persistence.FalkorDB") as mock_fdb:
            mock_fdb_instance = MagicMock()
            mock_fdb_instance.select_graph.return_value = mock_graph
            mock_fdb.return_value = mock_fdb_instance

            p = Persistence(
                host="db.example.com",
                port=6380,
                graph_name="prod",
                password="secret",
                ssl=True,
                ssl_ca_certs="/path/to/ca.crt",
            )
            mock_fdb.assert_called_once_with(
                host="db.example.com",
                port=6380,
                password="secret",
                ssl=True,
                ssl_ca_certs="/path/to/ca.crt",
            )
            mock_fdb_instance.select_graph.assert_called_once_with("prod")


# ---------------------------------------------------------------------------
# run_query
# ---------------------------------------------------------------------------


class TestRunQuery:
    """Tests for Persistence.run_query."""

    def test_delegates_to_graph_query(self, mock_persistence, mock_graph):
        mock_persistence.run_query("MATCH (n) RETURN n")
        mock_graph.query.assert_called_once_with(
            q="MATCH (n) RETURN n", params=None, timeout=60000
        )

    def test_passes_params(self, mock_persistence, mock_graph):
        mock_persistence.run_query("MATCH (n {id: $id})", {"id": "123"})
        mock_graph.query.assert_called_once_with(
            q="MATCH (n {id: $id})", params={"id": "123"}, timeout=60000
        )


# ---------------------------------------------------------------------------
# create_project_version
# ---------------------------------------------------------------------------


class TestCreateProjectVersion:
    """Tests for Persistence.create_project_version."""

    def test_creates_application_version(
        self, mock_persistence, mock_graph, sample_version
    ):
        mock_persistence.create_project_version(sample_version)
        assert mock_graph.query.call_count >= 1

    def test_creates_library_version(
        self, mock_persistence, mock_graph, sample_library_version
    ):
        mock_persistence.create_project_version(sample_library_version)
        assert mock_graph.query.called

    def test_none_version_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_project_version(None)
        mock_graph.query.assert_not_called()

    def test_none_project_returns_early(self, mock_persistence, mock_graph):
        v = Version()
        v.version = "1.0"
        mock_persistence.create_project_version(v)
        mock_graph.query.assert_not_called()

    def test_empty_purl_logs_debug(
        self, mock_persistence, mock_graph, sample_version, caplog
    ):
        sample_version.project.purl = ""
        import logging

        with caplog.at_level(logging.DEBUG):
            mock_persistence.create_project_version(sample_version)
        assert mock_graph.query.called

    def test_none_purl_logs_debug(
        self, mock_persistence, mock_graph, sample_version, caplog
    ):
        sample_version.project.purl = None
        import logging

        with caplog.at_level(logging.DEBUG):
            mock_persistence.create_project_version(sample_version)
        assert mock_graph.query.called

    def test_application_type_adds_scan_id(
        self, mock_persistence, mock_graph, sample_version
    ):
        sample_version.project.type = "application"
        mock_persistence.create_project_version(sample_version)
        queries = [str(c) for c in mock_graph.query.call_args_list]
        assert any("scan_id" in q for q in queries)

    def test_default_type_is_library(self, mock_persistence, mock_graph):
        v = Version()
        v.version = "1.0"
        p = Project()
        p.name = "test"
        p.group = "com.test"
        p.type = None
        v.project = p
        mock_persistence.create_project_version(v)
        first_call_query = str(mock_graph.query.call_args_list[0])
        assert "Library" in first_call_query

    def test_scan_ids_appended(
        self, mock_persistence, mock_graph, sample_version
    ):
        mock_persistence.create_project_version(sample_version)
        assert mock_graph.query.call_count >= 2

    def test_no_scan_id_append_when_missing_name(
        self, mock_persistence, mock_graph
    ):
        v = Version()
        v.version = None
        p = Project()
        p.name = "test"
        p.group = "com.test"
        p.type = "library"
        v.project = p
        mock_persistence.create_project_version(v)
        assert mock_graph.query.call_count == 1

    def test_invalid_project_type_raises(self, mock_persistence):
        v = Version()
        v.version = "1.0"
        p = Project()
        p.name = "test"
        p.group = "com.test"
        p.type = "MaliciousType"
        v.project = p
        with pytest.raises(ValueError, match="Invalid node label"):
            mock_persistence.create_project_version(v)


# ---------------------------------------------------------------------------
# create_defect
# ---------------------------------------------------------------------------


class TestCreateDefect:
    """Tests for Persistence.create_defect."""

    def test_creates_defect_with_all_fields(
        self, mock_persistence, mock_graph, sample_defect
    ):
        mock_persistence.create_defect(sample_defect)
        mock_graph.query.assert_called_once()
        call_kwargs = mock_graph.query.call_args
        assert call_kwargs.kwargs["params"]["id"] == "CVE-2024-12345"

    def test_creates_defect_with_minimal_fields(self, mock_persistence, mock_graph):
        d = Defect()
        d.id = "CVE-2024-99999"
        mock_persistence.create_defect(d)
        mock_graph.query.assert_called_once()

    def test_none_defect_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_defect(None)
        mock_graph.query.assert_not_called()

    def test_none_defect_id_returns_early(self, mock_persistence, mock_graph):
        d = Defect()
        d.id = None
        mock_persistence.create_defect(d)
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# create_dependency
# ---------------------------------------------------------------------------


class TestCreateDependency:
    """Tests for Persistence.create_dependency."""

    def test_creates_dependency_with_groups(
        self, mock_persistence, mock_graph, sample_version, sample_library_version
    ):
        mock_persistence.create_dependency(
            parent=sample_version, child=sample_library_version
        )
        mock_graph.query.assert_called_once()
        call_kwargs = mock_graph.query.call_args
        assert "DEPENDENCY_VERSION" in call_kwargs.kwargs["q"]

    def test_none_parent_returns_early(
        self, mock_persistence, mock_graph, sample_library_version
    ):
        mock_persistence.create_dependency(parent=None, child=sample_library_version)
        mock_graph.query.assert_not_called()

    def test_none_child_returns_early(
        self, mock_persistence, mock_graph, sample_version
    ):
        mock_persistence.create_dependency(parent=sample_version, child=None)
        mock_graph.query.assert_not_called()

    def test_none_parent_project_returns_early(
        self, mock_persistence, mock_graph, sample_library_version
    ):
        parent = Version()
        parent.version = "1.0"
        parent.project = None
        mock_persistence.create_dependency(parent=parent, child=sample_library_version)
        mock_graph.query.assert_not_called()

    def test_none_child_project_returns_early(
        self, mock_persistence, mock_graph, sample_version
    ):
        child = Version()
        child.version = "1.0"
        child.project = None
        mock_persistence.create_dependency(parent=sample_version, child=child)
        mock_graph.query.assert_not_called()

    def test_parent_no_group_uses_purl_prefix(
        self, mock_persistence, mock_graph, sample_library_version
    ):
        parent = Version()
        parent.version = "1.0"
        p = Project()
        p.name = "no-group-lib"
        p.group = None
        p.purl = "pkg:npm/no-group-lib@1.0"
        parent.project = p

        mock_persistence.create_dependency(
            parent=parent, child=sample_library_version
        )
        mock_graph.query.assert_called_once()
        call_kwargs = mock_graph.query.call_args
        assert "parent_purl_prefix" in call_kwargs.kwargs["params"]

    def test_child_no_group_uses_purl_prefix(
        self, mock_persistence, mock_graph, sample_version
    ):
        child = Version()
        child.version = "2.0"
        p = Project()
        p.name = "child-lib"
        p.group = None
        p.purl = "pkg:npm/child-lib@2.0"
        child.project = p

        mock_persistence.create_dependency(parent=sample_version, child=child)
        mock_graph.query.assert_called_once()
        call_kwargs = mock_graph.query.call_args
        assert "child_purl_prefix" in call_kwargs.kwargs["params"]

    def test_parent_no_group_no_purl_returns_early(
        self, mock_persistence, mock_graph, sample_library_version
    ):
        parent = Version()
        parent.version = "1.0"
        p = Project()
        p.name = "no-group"
        p.group = None
        p.purl = None
        parent.project = p

        mock_persistence.create_dependency(
            parent=parent, child=sample_library_version
        )
        mock_graph.query.assert_not_called()

    def test_child_no_group_no_purl_returns_early(
        self, mock_persistence, mock_graph, sample_version
    ):
        child = Version()
        child.version = "1.0"
        p = Project()
        p.name = "no-group"
        p.group = None
        p.purl = None
        child.project = p

        mock_persistence.create_dependency(parent=sample_version, child=child)
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# create_version_defect
# ---------------------------------------------------------------------------


class TestCreateVersionDefect:
    """Tests for Persistence.create_version_defect."""

    def test_creates_edge_with_group(
        self, mock_persistence, mock_graph, sample_version_defect
    ):
        mock_persistence.create_version_defect(sample_version_defect)
        mock_graph.query.assert_called_once()
        call_kwargs = mock_graph.query.call_args
        assert "VERSION_DEFECT" in call_kwargs.kwargs["q"]

    def test_none_version_defect_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_version_defect(None)
        mock_graph.query.assert_not_called()

    def test_none_project_version_returns_early(self, mock_persistence, mock_graph):
        vd = VersionDefect()
        vd.project_version = None
        vd.defect = Defect()
        vd.defect.id = "CVE-1"
        mock_persistence.create_version_defect(vd)
        mock_graph.query.assert_not_called()

    def test_none_project_on_version_returns_early(self, mock_persistence, mock_graph):
        vd = VersionDefect()
        vd.project_version = Version()
        vd.project_version.project = None
        vd.defect = Defect()
        vd.defect.id = "CVE-1"
        mock_persistence.create_version_defect(vd)
        mock_graph.query.assert_not_called()

    def test_none_defect_returns_early(self, mock_persistence, mock_graph):
        vd = VersionDefect()
        vd.project_version = Version()
        vd.project_version.project = Project()
        vd.defect = None
        mock_persistence.create_version_defect(vd)
        mock_graph.query.assert_not_called()

    def test_no_group_uses_purl(self, mock_persistence, mock_graph):
        vd = VersionDefect()
        v = Version()
        v.version = "1.0"
        p = Project()
        p.name = "test"
        p.group = None
        p.purl = "pkg:npm/test@1.0"
        v.project = p
        vd.project_version = v
        d = Defect()
        d.id = "CVE-1"
        vd.defect = d

        mock_persistence.create_version_defect(vd)
        mock_graph.query.assert_called_once()
        call_kwargs = mock_graph.query.call_args
        assert "purl_prefix" in call_kwargs.kwargs["params"]

    def test_no_group_no_purl_returns_early(self, mock_persistence, mock_graph):
        vd = VersionDefect()
        v = Version()
        v.version = "1.0"
        p = Project()
        p.name = "test"
        p.group = None
        p.purl = None
        v.project = p
        vd.project_version = v
        d = Defect()
        d.id = "CVE-1"
        vd.defect = d

        mock_persistence.create_version_defect(vd)
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# Labeling methods
# ---------------------------------------------------------------------------


class TestLabelProjectsWithTypeInformation:
    """Tests for Persistence.label_projects_with_type_information."""

    def test_runs_two_labeling_queries(self, mock_persistence, mock_graph):
        mock_persistence.label_projects_with_type_information()
        assert mock_graph.query.call_count == 2
        queries = [c.kwargs["q"] for c in mock_graph.query.call_args_list]
        assert any("library" in q for q in queries)
        assert any("application" in q for q in queries)


class TestLabelProjectsWithRenovateUsage:
    """Tests for Persistence.label_projects_with_renovate_usage."""

    def test_labels_each_project(self, mock_persistence, mock_graph):
        projects = [
            {"project_name": "project-a", "name": "1.0.0"},
            {"project_name": "project-b", "name": "2.0.0"},
        ]
        mock_persistence.label_projects_with_renovate_usage(projects)
        assert mock_graph.query.call_count == 2

    def test_empty_project_list(self, mock_persistence, mock_graph):
        mock_persistence.label_projects_with_renovate_usage([])
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# Query methods
# ---------------------------------------------------------------------------


class TestRetrieveAllProjectNodesWithRepoUrl:
    """Tests for Persistence.retrieve_all_project_nodes_with_repo_url."""

    def test_returns_matching_nodes(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(
            result_set=[{"n": {"name": "proj-1"}}, {"n": {"name": "proj-2"}}]
        )
        result = mock_persistence.retrieve_all_project_nodes_with_repo_url(
            "https://gitlab.example.com/repo"
        )
        assert len(result) == 2
        assert result[0]["name"] == "proj-1"

    def test_returns_empty_for_no_matches(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[])
        result = mock_persistence.retrieve_all_project_nodes_with_repo_url("no-match")
        assert result == []


# ---------------------------------------------------------------------------
# Centrality methods
# ---------------------------------------------------------------------------


class TestCentralityScores:
    """Tests for centrality score methods."""

    def test_add_inward_centrality(self, mock_persistence, mock_graph):
        mock_persistence.add_inward_centrality_scores()
        mock_graph.query.assert_called_once()
        assert "inDegree" in mock_graph.query.call_args.kwargs["q"]

    def test_add_outward_centrality(self, mock_persistence, mock_graph):
        mock_persistence.add_outward_centrality_scores()
        mock_graph.query.assert_called_once()
        assert "outDegree" in mock_graph.query.call_args.kwargs["q"]


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------


class TestCreateIndexes:
    """Tests for Persistence.create_indexes."""

    def test_creates_four_indexes(self, mock_persistence, mock_graph):
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 4

    def test_handles_already_exists_gracefully(self, mock_persistence, mock_graph):
        mock_graph.query.side_effect = Exception("Index already exists")
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 4

    def test_handles_equivalent_index_gracefully(self, mock_persistence, mock_graph):
        mock_graph.query.side_effect = Exception("An equivalent index already exists")
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 4

    def test_logs_warning_on_unexpected_error(
        self, mock_persistence, mock_graph, caplog
    ):
        mock_graph.query.side_effect = Exception("Connection refused")
        import logging

        with caplog.at_level(logging.WARNING):
            mock_persistence.create_indexes()
        assert any("Failed to create index" in msg for msg in caplog.messages)

    def test_mixed_success_and_failure(self, mock_persistence, mock_graph):
        mock_graph.query.side_effect = [
            None,
            Exception("Index already exists"),
            None,
            Exception("Timeout"),
        ]
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 4
