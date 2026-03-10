"""Tests for JSON schemas module."""

from sbom_graph_api.schemas import (
    APPLICATIONS_SCHEMA,
    CENTRALITY_SCHEMA,
    DEPENDANTS_SCHEMA,
    LICENSE_CONFLICTS_SCHEMA,
    LICENSE_SUMMARY_SCHEMA,
    LICENSES_SCHEMA,
    MULTI_VERSION_DEPS_SCHEMA,
    MULTI_VERSION_SOURCES_SCHEMA,
    NON_SEMVER_VERSIONS_SCHEMA,
    POLICY_VIOLATIONS_SCHEMA,
    PROJECTS_SCHEMA,
    SCHEMA_INDEX,
    SELF_DEPENDENCIES_SCHEMA,
    SNAPSHOTS_SCHEMA,
    SOURCE_REPOS_SCHEMA,
    VERSION_DEPENDENCIES_SCHEMA,
    VEX_COVERAGE_SCHEMA,
    VULNERABILITIES_SCHEMA,
    VULNERABILITY_DEPENDANTS_SCHEMA,
    VULNERABILITY_FRESHNESS_SCHEMA,
    get_schema,
    get_schema_list,
)
from sbom_graph_api.schemas.definitions import SCHEMA_VERSION

ALL_SCHEMAS = {
    "projects": PROJECTS_SCHEMA,
    "applications": APPLICATIONS_SCHEMA,
    "snapshots": SNAPSHOTS_SCHEMA,
    "self-dependencies": SELF_DEPENDENCIES_SCHEMA,
    "multi-version-deps": MULTI_VERSION_DEPS_SCHEMA,
    "multi-version-sources": MULTI_VERSION_SOURCES_SCHEMA,
    "non-semver-versions": NON_SEMVER_VERSIONS_SCHEMA,
    "version-dependencies": VERSION_DEPENDENCIES_SCHEMA,
    "dependants": DEPENDANTS_SCHEMA,
    "vulnerabilities": VULNERABILITIES_SCHEMA,
    "vulnerability-dependants": VULNERABILITY_DEPENDANTS_SCHEMA,
    "centrality": CENTRALITY_SCHEMA,
    "licenses": LICENSES_SCHEMA,
    "license-summary": LICENSE_SUMMARY_SCHEMA,
    "license-conflicts": LICENSE_CONFLICTS_SCHEMA,
    "vulnerability-freshness": VULNERABILITY_FRESHNESS_SCHEMA,
    "policy-violations": POLICY_VIOLATIONS_SCHEMA,
    "vex-coverage": VEX_COVERAGE_SCHEMA,
    "source-repos": SOURCE_REPOS_SCHEMA,
}


class TestSchemaDefinitions:
    """Tests for JSON schema definitions."""

    def test_all_schemas_have_required_meta_fields(self):
        """Every schema must have $schema, title, type, and properties."""
        for name, schema in ALL_SCHEMAS.items():
            assert "$schema" in schema, f"{name}: missing $schema"
            assert "title" in schema, f"{name}: missing title"
            assert "type" in schema, f"{name}: missing type"
            assert "properties" in schema, f"{name}: missing properties"

    def test_all_schemas_use_consistent_draft_version(self):
        """All schemas must reference the same JSON Schema draft."""
        for name, schema in ALL_SCHEMAS.items():
            assert schema["$schema"] == SCHEMA_VERSION, (
                f"{name}: uses {schema['$schema']}, expected {SCHEMA_VERSION}"
            )

    def test_all_schemas_are_object_type(self):
        """Top-level type must be 'object' for every schema."""
        for name, schema in ALL_SCHEMAS.items():
            assert schema["type"] == "object", f"{name}: type is {schema['type']}"

    def test_projects_schema_has_report_type(self):
        """Test projects schema defines report_type."""
        assert "report_type" in PROJECTS_SCHEMA["properties"]
        assert PROJECTS_SCHEMA["properties"]["report_type"]["const"] == "projects"

    def test_projects_schema_has_data_array(self):
        """Test projects schema defines data as array."""
        assert "data" in PROJECTS_SCHEMA["properties"]
        assert PROJECTS_SCHEMA["properties"]["data"]["type"] == "array"

    def test_snapshots_schema_has_required_fields(self):
        """Test snapshots schema has all required fields."""
        assert SNAPSHOTS_SCHEMA["properties"]["report_type"]["const"] == "snapshots"
        assert "data" in SNAPSHOTS_SCHEMA["properties"]

    def test_self_dependencies_schema_has_required_fields(self):
        """Test self-dependencies schema has all required fields."""
        assert SELF_DEPENDENCIES_SCHEMA["properties"]["report_type"]["const"] == "self-dependencies"

    def test_multi_version_sources_schema_has_required_fields(self):
        """Test multi-version-sources schema has all required fields."""
        assert (
            MULTI_VERSION_SOURCES_SCHEMA["properties"]["report_type"]["const"]
            == "multi-version-sources"
        )
        assert "multi_version_dependencies" in MULTI_VERSION_SOURCES_SCHEMA["properties"]

    def test_non_semver_versions_schema_has_required_fields(self):
        """Test non-semver-versions schema has all required fields."""
        assert (
            NON_SEMVER_VERSIONS_SCHEMA["properties"]["report_type"]["const"]
            == "non-semver-versions"
        )

    def test_version_dependencies_schema_has_required_fields(self):
        """Test version-dependencies report schema has all required fields."""
        assert (
            VERSION_DEPENDENCIES_SCHEMA["properties"]["report_type"]["const"]
            == "version-dependencies"
        )
        assert "summary" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "project_name" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "version" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "max_depth" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "semver_compliance" in VERSION_DEPENDENCIES_SCHEMA["properties"]

    def test_dependants_schema_has_required_fields(self):
        """Test dependants schema has all required fields."""
        assert DEPENDANTS_SCHEMA["properties"]["report_type"]["const"] == "dependants"
        assert "dependants" in DEPENDANTS_SCHEMA["properties"]

    def test_vulnerabilities_schema_has_required_fields(self):
        """Test vulnerabilities schema has all required fields."""
        assert VULNERABILITIES_SCHEMA["properties"]["report_type"]["const"] == "vulnerabilities"
        assert "data" in VULNERABILITIES_SCHEMA["properties"]

    def test_vulnerability_dependants_schema_has_required_fields(self):
        """Test vulnerability-dependants schema has all required fields."""
        assert (
            VULNERABILITY_DEPENDANTS_SCHEMA["properties"]["report_type"]["const"]
            == "vulnerability-dependants"
        )
        assert "dependants" in VULNERABILITY_DEPENDANTS_SCHEMA["properties"]

    def test_centrality_schema_has_required_fields(self):
        """Test centrality schema has all required fields."""
        assert CENTRALITY_SCHEMA["properties"]["report_type"]["const"] == "centrality"
        assert "data" in CENTRALITY_SCHEMA["properties"]

    def test_licenses_schema_has_required_fields(self):
        """Test licenses schema has all required fields."""
        assert LICENSES_SCHEMA["properties"]["report_type"]["const"] == "licenses"
        assert "licenses" in LICENSES_SCHEMA["properties"]
        assert "total" in LICENSES_SCHEMA["properties"]

    def test_license_summary_schema_has_required_fields(self):
        """Test license-summary schema has all required fields."""
        assert LICENSE_SUMMARY_SCHEMA["properties"]["report_type"]["const"] == "license-summary"
        assert "licenses" in LICENSE_SUMMARY_SCHEMA["properties"]
        assert "project_name" in LICENSE_SUMMARY_SCHEMA["properties"]
        assert "version_name" in LICENSE_SUMMARY_SCHEMA["properties"]

    def test_license_conflicts_schema_has_required_fields(self):
        """Test license-conflicts schema has all required fields."""
        assert LICENSE_CONFLICTS_SCHEMA["properties"]["report_type"]["const"] == "license-conflicts"
        assert "conflicts" in LICENSE_CONFLICTS_SCHEMA["properties"]
        assert "total" in LICENSE_CONFLICTS_SCHEMA["properties"]

    def test_vulnerability_freshness_schema_has_required_fields(self):
        """Test vulnerability-freshness schema has all required fields."""
        assert (
            VULNERABILITY_FRESHNESS_SCHEMA["properties"]["report_type"]["const"]
            == "vulnerability-freshness"
        )
        assert "stats" in VULNERABILITY_FRESHNESS_SCHEMA["properties"]
        assert "data" in VULNERABILITY_FRESHNESS_SCHEMA["properties"]

    def test_policy_violations_schema_has_required_fields(self):
        """Test policy-violations schema has all required fields."""
        assert POLICY_VIOLATIONS_SCHEMA["properties"]["report_type"]["const"] == "policy-violations"
        assert "stats" in POLICY_VIOLATIONS_SCHEMA["properties"]
        assert "data" in POLICY_VIOLATIONS_SCHEMA["properties"]

    def test_vex_coverage_schema_has_required_fields(self):
        """Test vex-coverage schema has all required fields."""
        assert VEX_COVERAGE_SCHEMA["properties"]["report_type"]["const"] == "vex-coverage"
        assert "stats" in VEX_COVERAGE_SCHEMA["properties"]
        assert "data" in VEX_COVERAGE_SCHEMA["properties"]

    def test_source_repos_schema_has_required_fields(self):
        """Test source-repos schema has all required fields."""
        assert SOURCE_REPOS_SCHEMA["properties"]["report_type"]["const"] == "source-repos"
        assert "data" in SOURCE_REPOS_SCHEMA["properties"]
        assert "total" in SOURCE_REPOS_SCHEMA["properties"]


class TestSchemaIndex:
    """Tests for schema index."""

    def test_schema_index_has_all_schemas(self):
        """Test schema index contains all expected schemas."""
        expected_schemas = list(ALL_SCHEMAS.keys())
        for schema_name in expected_schemas:
            assert schema_name in SCHEMA_INDEX, f"Missing from index: {schema_name}"

    def test_schema_index_count_matches_all_schemas(self):
        """SCHEMA_INDEX must contain all outbound schemas (and may include inbound)."""
        for name in ALL_SCHEMAS:
            assert name in SCHEMA_INDEX, f"Outbound schema {name} missing from SCHEMA_INDEX"
        assert len(SCHEMA_INDEX) >= len(ALL_SCHEMAS)

    def test_schema_index_entries_have_required_keys(self):
        """Test each schema index entry has required keys."""
        for name, entry in SCHEMA_INDEX.items():
            assert "schema" in entry, f"Schema {name} missing 'schema' key"
            assert "endpoint" in entry, f"Schema {name} missing 'endpoint' key"
            assert "description" in entry, f"Schema {name} missing 'description' key"


class TestGetSchema:
    """Tests for get_schema function."""

    def test_get_schema_returns_schema_for_valid_name(self):
        """Test get_schema returns schema for valid name."""
        schema = get_schema("projects")
        assert schema is not None
        assert schema == PROJECTS_SCHEMA

    def test_get_schema_returns_none_for_invalid_name(self):
        """Test get_schema returns None for invalid name."""
        schema = get_schema("nonexistent-schema")
        assert schema is None

    def test_get_schema_all_known_schemas(self):
        """Test get_schema works for all known schemas."""
        for schema_name in SCHEMA_INDEX:
            schema = get_schema(schema_name)
            assert schema is not None, f"get_schema returned None for: {schema_name}"


class TestGetSchemaList:
    """Tests for get_schema_list function."""

    def test_get_schema_list_returns_list(self):
        """Test get_schema_list returns a list."""
        result = get_schema_list()
        assert isinstance(result, list)

    def test_get_schema_list_has_expected_count(self):
        """Test get_schema_list returns correct count."""
        result = get_schema_list()
        assert len(result) == len(SCHEMA_INDEX)

    def test_get_schema_list_entries_have_required_keys(self):
        """Test get_schema_list entries have required keys."""
        result = get_schema_list()
        for entry in result:
            assert "name" in entry
            assert "schema_url" in entry
            assert "endpoint" in entry
            assert "description" in entry

    def test_get_schema_list_schema_urls_are_valid(self):
        """Test schema URLs follow expected pattern."""
        result = get_schema_list()
        for entry in result:
            assert entry["schema_url"].startswith("/schemas/")
