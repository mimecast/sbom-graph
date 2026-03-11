"""Tests for the persistence module.

Covers Persistence class methods including query building utilities,
node creation, edge creation, labeling, querying, centrality, and indexing.
All database calls are mocked via the mock_graph fixture.
"""

from unittest.mock import MagicMock, patch

import pytest

from sbom_graph_model.model import (
    Defect,
    Project,
    Version,
    VersionDefect,
)
from sbom_graph_model.persistence import (
    ALLOWED_PROJECT_TYPES,
    INTERNAL_PREFIX_FIELDS,
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
        with patch("sbom_graph_model.persistence.FalkorDB") as mock_fdb:
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


class TestGetVersionsByPurl:
    """Tests for Persistence.get_versions_by_purl."""

    def test_returns_structured_rows(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(
            result_set=[
                {"name": "1.0.0", "project_name": "my-lib", "project_group": "com.example"},
                {"name": "2.0.0", "project_name": "my-lib", "project_group": "com.example"},
            ]
        )
        result = mock_persistence.get_versions_by_purl("pkg:maven/com.example/my-lib@1.0.0")
        assert len(result) == 2
        assert result[0] == {"name": "1.0.0", "project_name": "my-lib", "project_group": "com.example"}
        assert result[1] == {"name": "2.0.0", "project_name": "my-lib", "project_group": "com.example"}

        query_str = mock_graph.query.call_args.kwargs["q"]
        assert "package_url" in query_str
        assert mock_graph.query.call_args.kwargs["params"]["purl"] == "pkg:maven/com.example/my-lib@1.0.0"

    def test_returns_empty_for_no_matches(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[])
        result = mock_persistence.get_versions_by_purl("pkg:npm/-/nonexistent@0.0.0")
        assert result == []

    def test_handles_none_fields(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(
            result_set=[
                {"name": "1.0.0", "project_name": "my-lib", "project_group": None},
            ]
        )
        result = mock_persistence.get_versions_by_purl("pkg:npm/-/my-lib@1.0.0")
        assert result[0]["project_group"] is None


# ---------------------------------------------------------------------------
# update_defect_enrichment
# ---------------------------------------------------------------------------


class TestUpdateDefectEnrichment:
    """Tests for Persistence.update_defect_enrichment."""

    def test_updates_enrichment(self, mock_persistence, mock_graph):
        mock_persistence.update_defect_enrichment(
            defect_id="CVE-2024-1",
            source="osv",
            aliases=["GHSA-xxx"],
            timestamp="2024-06-01T00:00:00Z",
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["defect_id"] == "CVE-2024-1"
        assert params["enrichment_source"] == "osv"
        assert params["aliases"] == ["GHSA-xxx"]

    def test_empty_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.update_defect_enrichment(defect_id="", source="osv")
        mock_graph.query.assert_not_called()

    def test_without_aliases(self, mock_persistence, mock_graph):
        mock_persistence.update_defect_enrichment(
            defect_id="CVE-2024-1", source="osv"
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert "aliases" not in params


# ---------------------------------------------------------------------------
# get_packages_needing_enrichment
# ---------------------------------------------------------------------------


class TestGetPackagesNeedingEnrichment:
    """Tests for Persistence.get_packages_needing_enrichment."""

    def test_returns_purls(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(
            result_set=[
                {"purl": "pkg:maven/a/b@1.0"},
                {"purl": "pkg:npm/c/d@2.0"},
            ]
        )
        result = mock_persistence.get_packages_needing_enrichment()
        assert result == ["pkg:maven/a/b@1.0", "pkg:npm/c/d@2.0"]

    def test_empty_graph(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[])
        result = mock_persistence.get_packages_needing_enrichment()
        assert result == []


# ---------------------------------------------------------------------------
# create_policy_annotation
# ---------------------------------------------------------------------------


class TestCreatePolicyAnnotation:
    """Tests for Persistence.create_policy_annotation."""

    def test_creates_annotation(self, mock_persistence, mock_graph):
        mock_persistence.create_policy_annotation(
            annotation_id="uuid-1",
            policy_type="bad",
            justification="CVE",
            created_by="admin",
            created_at="2024-06-01",
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["annotation_id"] == "uuid-1"
        assert params["policy_type"] == "bad"

    def test_empty_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_policy_annotation(
            annotation_id="",
            policy_type="bad",
            justification="x",
            created_by="admin",
            created_at="2024-06-01",
        )
        mock_graph.query.assert_not_called()

    def test_invalid_type_raises(self, mock_persistence):
        with pytest.raises(ValueError):
            mock_persistence.create_policy_annotation(
                annotation_id="uuid-1",
                policy_type="invalid",
                justification="x",
                created_by="admin",
                created_at="2024-06-01",
            )

    def test_with_expires_at(self, mock_persistence, mock_graph):
        mock_persistence.create_policy_annotation(
            annotation_id="uuid-1",
            policy_type="hold",
            justification="Under review",
            created_by="admin",
            created_at="2024-06-01",
            expires_at="2025-01-01",
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["expires_at"] == "2025-01-01"


# ---------------------------------------------------------------------------
# link_policy_to_version
# ---------------------------------------------------------------------------


class TestLinkPolicyToVersion:
    """Tests for Persistence.link_policy_to_version."""

    def test_creates_edge(self, mock_persistence, mock_graph):
        mock_persistence.link_policy_to_version(
            purl="pkg:maven/a/b@1.0", annotation_id="uuid-1"
        )
        mock_graph.query.assert_called_once()
        q = mock_graph.query.call_args.kwargs["q"]
        assert "HAS_POLICY" in q

    def test_empty_purl_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_policy_to_version(purl="", annotation_id="uuid-1")
        mock_graph.query.assert_not_called()

    def test_empty_annotation_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_policy_to_version(purl="pkg:a/b@1", annotation_id="")
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# create_point_of_contact
# ---------------------------------------------------------------------------


class TestCreatePointOfContact:
    """Tests for Persistence.create_point_of_contact."""

    def test_creates_contact(self, mock_persistence, mock_graph):
        mock_persistence.create_point_of_contact(
            email="team@example.com",
            team="security",
            slack_channel="#patches",
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["email"] == "team@example.com"
        assert params["team"] == "security"
        assert params["slack_channel"] == "#patches"

    def test_empty_email_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_point_of_contact(email="")
        mock_graph.query.assert_not_called()

    def test_email_only(self, mock_persistence, mock_graph):
        mock_persistence.create_point_of_contact(email="owner@example.com")
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["email"] == "owner@example.com"


# ---------------------------------------------------------------------------
# link_contact_to_version
# ---------------------------------------------------------------------------


class TestLinkContactToVersion:
    """Tests for Persistence.link_contact_to_version."""

    def test_creates_edge(self, mock_persistence, mock_graph):
        mock_persistence.link_contact_to_version(
            email="team@example.com",
            purl="pkg:maven/com.example/lib@1.0",
        )
        mock_graph.query.assert_called_once()
        q = mock_graph.query.call_args.kwargs["q"]
        assert "CONTACT_FOR" in q
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["email"] == "team@example.com"
        assert params["purl"] == "pkg:maven/com.example/lib@1.0"

    def test_empty_email_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_contact_to_version(email="", purl="pkg:a@1")
        mock_graph.query.assert_not_called()

    def test_empty_purl_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_contact_to_version(email="a@b.com", purl="")
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# create_vex_statement
# ---------------------------------------------------------------------------


class TestCreateVexStatement:
    """Tests for Persistence.create_vex_statement."""

    def test_creates_statement(self, mock_persistence, mock_graph):
        mock_persistence.create_vex_statement(
            statement_id="vex-uuid-1",
            status="not_affected",
            justification="Component not in use",
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["statement_id"] == "vex-uuid-1"
        assert params["status"] == "not_affected"

    def test_empty_statement_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_vex_statement(
            statement_id="",
            status="not_affected",
        )
        mock_graph.query.assert_not_called()

    def test_invalid_status_raises(self, mock_persistence):
        with pytest.raises(ValueError, match="Invalid VEX status"):
            mock_persistence.create_vex_statement(
                statement_id="vex-1",
                status="invalid_status",
            )


# ---------------------------------------------------------------------------
# link_vex_to_version
# ---------------------------------------------------------------------------


class TestLinkVexToVersion:
    """Tests for Persistence.link_vex_to_version."""

    def test_creates_edge(self, mock_persistence, mock_graph):
        mock_persistence.link_vex_to_version(
            statement_id="vex-uuid-1",
            purl="pkg:maven/com.example/lib@1.0",
        )
        mock_graph.query.assert_called_once()
        q = mock_graph.query.call_args.kwargs["q"]
        assert "HAS_VEX" in q

    def test_empty_statement_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_vex_to_version(
            statement_id="",
            purl="pkg:a@1",
        )
        mock_graph.query.assert_not_called()

    def test_empty_purl_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_vex_to_version(
            statement_id="vex-1",
            purl="",
        )
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# link_vex_to_defect
# ---------------------------------------------------------------------------


class TestLinkVexToDefect:
    """Tests for Persistence.link_vex_to_defect."""

    def test_creates_edge(self, mock_persistence, mock_graph):
        mock_persistence.link_vex_to_defect(
            statement_id="vex-uuid-1",
            defect_id="CVE-2024-12345",
        )
        mock_graph.query.assert_called_once()
        q = mock_graph.query.call_args.kwargs["q"]
        assert "REFERS_TO" in q
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["statement_id"] == "vex-uuid-1"
        assert params["defect_id"] == "CVE-2024-12345"

    def test_empty_statement_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_vex_to_defect(
            statement_id="",
            defect_id="CVE-1",
        )
        mock_graph.query.assert_not_called()

    def test_empty_defect_id_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_vex_to_defect(
            statement_id="vex-1",
            defect_id="",
        )
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# delete_policy_annotation
# ---------------------------------------------------------------------------


class TestDeletePolicyAnnotation:
    """Tests for Persistence.delete_policy_annotation."""

    def test_deletes_existing(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[[1]])
        result = mock_persistence.delete_policy_annotation("uuid-1")
        assert result is True

    def test_not_found(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[])
        result = mock_persistence.delete_policy_annotation("nonexistent")
        assert result is False

    def test_empty_id(self, mock_persistence, mock_graph):
        result = mock_persistence.delete_policy_annotation("")
        assert result is False
        mock_graph.query.assert_not_called()


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

    def test_creates_thirteen_indexes(self, mock_persistence, mock_graph):
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 13

    def test_handles_already_exists_gracefully(self, mock_persistence, mock_graph):
        mock_graph.query.side_effect = Exception("Index already exists")
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 13

    def test_handles_equivalent_index_gracefully(self, mock_persistence, mock_graph):
        mock_graph.query.side_effect = Exception("An equivalent index already exists")
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 13

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
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]
        mock_persistence.create_indexes()
        assert mock_graph.query.call_count == 13


# ---------------------------------------------------------------------------
# Trust Score persistence
# ---------------------------------------------------------------------------


class TestCreateTrustScore:
    """Tests for Persistence.create_trust_score."""

    def test_creates_trust_score(self, mock_persistence, mock_graph):
        mock_persistence.create_trust_score(
            purl="pkg:maven/com.example/lib@1.0",
            direct_score=7.5,
            confidence=0.75,
            security_practices_score=8.0,
            vulnerability_profile_score=7.0,
            maintenance_health_score=6.5,
            supply_chain_hygiene_score=8.5,
            sources_used=["scorecard", "osv", "depsdev"],
            scored_at="2026-02-28T12:00:00Z",
        )
        mock_graph.query.assert_called_once()
        q = mock_graph.query.call_args.kwargs["q"]
        assert "MERGE" in q
        assert "TrustScore" in q
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["purl"] == "pkg:maven/com.example/lib@1.0"
        assert params["direct_score"] == 7.5
        assert params["confidence"] == 0.75

    def test_with_optional_raw_data(self, mock_persistence, mock_graph):
        mock_persistence.create_trust_score(
            purl="pkg:npm/foo@2.0",
            direct_score=6.0,
            confidence=1.0,
            security_practices_score=6.0,
            vulnerability_profile_score=6.0,
            maintenance_health_score=6.0,
            supply_chain_hygiene_score=6.0,
            sources_used=["scorecard", "osv", "ossindex", "depsdev"],
            scored_at="2026-02-28T12:00:00Z",
            scorecard_raw='{"score":6}',
            depsdev_raw='{"advisories":0}',
        )
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["scorecard_raw"] == '{"score":6}'
        assert params["depsdev_raw"] == '{"advisories":0}'

    def test_empty_purl_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.create_trust_score(
            purl="",
            direct_score=5.0,
            confidence=0.5,
            security_practices_score=5.0,
            vulnerability_profile_score=5.0,
            maintenance_health_score=5.0,
            supply_chain_hygiene_score=5.0,
            sources_used=[],
            scored_at="2026-02-28T12:00:00Z",
        )
        mock_graph.query.assert_not_called()


class TestLinkVersionToTrustScore:
    """Tests for Persistence.link_version_to_trust_score."""

    def test_creates_edge(self, mock_persistence, mock_graph):
        mock_persistence.link_version_to_trust_score("pkg:maven/a/b@1.0")
        mock_graph.query.assert_called_once()
        q = mock_graph.query.call_args.kwargs["q"]
        assert "HAS_TRUST_SCORE" in q
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["purl"] == "pkg:maven/a/b@1.0"

    def test_empty_purl_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.link_version_to_trust_score("")
        mock_graph.query.assert_not_called()


class TestUpdateTrustScorePropagation:
    """Tests for Persistence.update_trust_score_propagation."""

    def test_updates_fields(self, mock_persistence, mock_graph):
        mock_persistence.update_trust_score_propagation(
            purl="pkg:maven/a/b@1.0",
            effective_score=6.5,
            inherited_score=5.8,
            min_path_score=3.2,
            dep_count=42,
        )
        mock_graph.query.assert_called_once()
        params = mock_graph.query.call_args.kwargs["params"]
        assert params["effective_score"] == 6.5
        assert params["inherited_score"] == 5.8
        assert params["min_path_score"] == 3.2
        assert params["dep_count"] == 42

    def test_empty_purl_returns_early(self, mock_persistence, mock_graph):
        mock_persistence.update_trust_score_propagation(
            purl="",
            effective_score=0.0,
            inherited_score=0.0,
            min_path_score=0.0,
            dep_count=0,
        )
        mock_graph.query.assert_not_called()


class TestGetAllTrustScores:
    """Tests for Persistence.get_all_trust_scores."""

    def test_returns_rows(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(
            result_set=[
                {
                    "purl": "pkg:maven/a/b@1.0",
                    "direct_score": 7.5,
                    "effective_score": 6.5,
                    "inherited_score": 5.8,
                    "min_path_score": 3.2,
                    "confidence": 0.75,
                    "dep_count": 42,
                },
            ]
        )
        result = mock_persistence.get_all_trust_scores()
        assert len(result) == 1
        assert result[0]["purl"] == "pkg:maven/a/b@1.0"
        assert result[0]["direct_score"] == 7.5

    def test_empty_graph(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[])
        assert mock_persistence.get_all_trust_scores() == []


class TestGetDependencyGraphForPropagation:
    """Tests for Persistence.get_dependency_graph_for_propagation."""

    def test_returns_edges(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(
            result_set=[
                {"parent_purl": "pkg:maven/a/b@1.0", "child_purl": "pkg:maven/c/d@2.0"},
                {"parent_purl": "pkg:maven/a/b@1.0", "child_purl": "pkg:npm/e@3.0"},
            ]
        )
        result = mock_persistence.get_dependency_graph_for_propagation()
        assert len(result) == 2
        assert result[0]["parent_purl"] == "pkg:maven/a/b@1.0"
        assert result[1]["child_purl"] == "pkg:npm/e@3.0"

    def test_empty_graph(self, mock_persistence, mock_graph):
        mock_graph.query.return_value = MagicMock(result_set=[])
        assert mock_persistence.get_dependency_graph_for_propagation() == []


# ---------------------------------------------------------------------------
# Helper for tests needing custom internal_prefixes
# ---------------------------------------------------------------------------


def _make_persistence(
    mock_graph: MagicMock,
    internal_prefixes: list[tuple[str, str]] | None = None,
) -> Persistence:
    """Create a Persistence with mocked DB and optional internal_prefixes."""
    with patch("sbom_graph_model.persistence.FalkorDB") as mock_fdb:
        mock_fdb_instance = MagicMock()
        mock_fdb_instance.select_graph.return_value = mock_graph
        mock_fdb.return_value = mock_fdb_instance
        return Persistence(
            host="localhost",
            port=6379,
            graph_name="test_graph",
            password="test_password",
            ssl=False,
            internal_prefixes=internal_prefixes,
        )


# ---------------------------------------------------------------------------
# parse_internal_prefixes (static method)
# ---------------------------------------------------------------------------


class TestParseInternalPrefixes:
    """Tests for Persistence.parse_internal_prefixes."""

    def test_single_group_prefix(self):
        result = Persistence.parse_internal_prefixes("group:com.acme")
        assert result == [("group", "com.acme")]

    def test_single_name_prefix(self):
        result = Persistence.parse_internal_prefixes("name:acme-")
        assert result == [("name", "acme-")]

    def test_single_purl_prefix(self):
        result = Persistence.parse_internal_prefixes("purl:pkg:maven/com.acme/")
        assert result == [("purl", "pkg:maven/com.acme/")]

    def test_multiple_mixed_prefixes(self):
        result = Persistence.parse_internal_prefixes(
            "group:com.acme,name:acme-,purl:pkg:maven/com.acme/"
        )
        assert result == [
            ("group", "com.acme"),
            ("name", "acme-"),
            ("purl", "pkg:maven/com.acme/"),
        ]

    def test_empty_string_returns_empty(self):
        assert Persistence.parse_internal_prefixes("") == []

    def test_whitespace_only_returns_empty(self):
        assert Persistence.parse_internal_prefixes("   ") == []

    def test_invalid_field_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid internal prefix field"):
            Persistence.parse_internal_prefixes("invalid:something")

    def test_token_without_colon_raises_value_error(self):
        with pytest.raises(ValueError, match="Malformed INTERNAL_PREFIXES token"):
            Persistence.parse_internal_prefixes("badformat")

    def test_whitespace_around_tokens_trimmed(self):
        result = Persistence.parse_internal_prefixes(
            "  group:com.acme  ,  name:acme-  "
        )
        assert result == [("group", "com.acme"), ("name", "acme-")]

    def test_empty_tokens_from_trailing_comma_skipped(self):
        result = Persistence.parse_internal_prefixes("group:com.acme,")
        assert result == [("group", "com.acme")]

    def test_empty_tokens_from_double_comma_skipped(self):
        result = Persistence.parse_internal_prefixes("group:com.acme,,name:acme-")
        assert result == [("group", "com.acme"), ("name", "acme-")]

    @pytest.mark.parametrize("field", sorted(INTERNAL_PREFIX_FIELDS))
    def test_all_valid_fields_accepted(self, field: str):
        result = Persistence.parse_internal_prefixes(f"{field}:test-prefix")
        assert result == [(field, "test-prefix")]


# ---------------------------------------------------------------------------
# is_internal
# ---------------------------------------------------------------------------


class TestIsInternal:
    """Tests for Persistence.is_internal."""

    def test_matches_group_prefix(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("group", "com.example")])
        project = Project()
        project.group = "com.example.service"
        project.name = "my-service"
        assert p.is_internal(project) is True

    def test_exact_group_match(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("group", "com.example")])
        project = Project()
        project.group = "com.example"
        project.name = "my-service"
        assert p.is_internal(project) is True

    def test_matches_name_prefix(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("name", "acme-")])
        project = Project()
        project.name = "acme-service"
        project.group = "org.other"
        assert p.is_internal(project) is True

    def test_matches_purl_prefix(self, mock_graph):
        p = _make_persistence(
            mock_graph,
            internal_prefixes=[("purl", "pkg:maven/com.acme/")],
        )
        project = Project()
        project.purl = "pkg:maven/com.acme/core@1.0.0"
        project.name = "core"
        project.group = "com.acme"
        assert p.is_internal(project) is True

    def test_no_match_returns_false(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("group", "com.acme")])
        project = Project()
        project.group = "org.other"
        project.name = "other-lib"
        assert p.is_internal(project) is False

    def test_empty_prefixes_returns_false(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[])
        project = Project()
        project.group = "com.example"
        project.name = "any-project"
        assert p.is_internal(project) is False

    def test_none_group_handled_gracefully(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("group", "com.acme")])
        project = Project()
        project.group = None
        project.name = "test"
        assert p.is_internal(project) is False

    def test_none_name_handled_gracefully(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("name", "acme-")])
        project = Project()
        project.name = None
        project.group = "com.example"
        assert p.is_internal(project) is False

    def test_none_purl_handled_gracefully(self, mock_graph):
        p = _make_persistence(mock_graph, internal_prefixes=[("purl", "pkg:maven/")])
        project = Project()
        project.purl = None
        project.name = "test"
        project.group = "com.test"
        assert p.is_internal(project) is False

    def test_first_matching_prefix_wins(self, mock_graph):
        p = _make_persistence(
            mock_graph,
            internal_prefixes=[("group", "org.nomatch"), ("name", "acme-")],
        )
        project = Project()
        project.group = "com.other"
        project.name = "acme-lib"
        assert p.is_internal(project) is True


# ---------------------------------------------------------------------------
# Persistence __init__ with internal_prefixes
# ---------------------------------------------------------------------------


class TestPersistenceInitInternalPrefixes:
    """Tests for internal_prefixes in Persistence initialization."""

    def test_valid_prefixes_stored(self, mock_graph):
        prefixes = [("group", "com.acme"), ("name", "acme-")]
        p = _make_persistence(mock_graph, internal_prefixes=prefixes)
        assert p.internal_prefixes == prefixes

    def test_defaults_to_empty_list(self, mock_graph):
        p = _make_persistence(mock_graph)
        assert p.internal_prefixes == []

    def test_invalid_field_raises_value_error(self, mock_graph):
        with pytest.raises(ValueError, match="Invalid internal prefix field"):
            _make_persistence(
                mock_graph, internal_prefixes=[("invalid_field", "test")]
            )


# ---------------------------------------------------------------------------
# create_project_version with INTERNAL label
# ---------------------------------------------------------------------------


class TestCreateProjectVersionInternalLabel:
    """Tests for INTERNAL label in create_project_version."""

    def test_internal_label_when_prefixes_match(self, mock_graph, sample_version):
        p = _make_persistence(
            mock_graph,
            internal_prefixes=[("group", "com.example")],
        )
        p.create_project_version(sample_version)
        first_query = str(mock_graph.query.call_args_list[0])
        assert ":INTERNAL" in first_query

    def test_no_internal_label_when_prefixes_dont_match(
        self, mock_graph, sample_version
    ):
        p = _make_persistence(
            mock_graph,
            internal_prefixes=[("group", "org.nomatch")],
        )
        p.create_project_version(sample_version)
        first_query = str(mock_graph.query.call_args_list[0])
        assert ":INTERNAL" not in first_query

    def test_no_internal_label_when_no_prefixes(self, mock_graph, sample_version):
        p = _make_persistence(mock_graph, internal_prefixes=[])
        p.create_project_version(sample_version)
        first_query = str(mock_graph.query.call_args_list[0])
        assert ":INTERNAL" not in first_query

    def test_internal_label_via_name_prefix(self, mock_graph, sample_version):
        p = _make_persistence(
            mock_graph,
            internal_prefixes=[("name", "test-")],
        )
        p.create_project_version(sample_version)
        first_query = str(mock_graph.query.call_args_list[0])
        assert ":INTERNAL" in first_query

    def test_internal_label_via_purl_prefix(self, mock_graph, sample_version):
        p = _make_persistence(
            mock_graph,
            internal_prefixes=[("purl", "pkg:maven/com.example/")],
        )
        p.create_project_version(sample_version)
        first_query = str(mock_graph.query.call_args_list[0])
        assert ":INTERNAL" in first_query
