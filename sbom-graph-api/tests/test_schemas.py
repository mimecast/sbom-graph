"""Tests for JSON schemas module."""

from sbom_graph_api.schemas import (
    MULTI_VERSION_SOURCES_SCHEMA,
    NON_SEMVER_VERSIONS_SCHEMA,
    PROJECTS_SCHEMA,
    SCHEMA_INDEX,
    SELF_DEPENDENCIES_SCHEMA,
    SNAPSHOTS_SCHEMA,
    VERSION_DEPENDENCIES_SCHEMA,
    get_schema,
    get_schema_list,
)


class TestSchemaDefinitions:
    """Tests for JSON schema definitions."""

    def test_projects_schema_has_required_fields(self):
        """Test projects schema has all required fields."""
        assert "$schema" in PROJECTS_SCHEMA
        assert "title" in PROJECTS_SCHEMA
        assert "type" in PROJECTS_SCHEMA
        assert "required" in PROJECTS_SCHEMA
        assert "properties" in PROJECTS_SCHEMA

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
        assert "$schema" in SNAPSHOTS_SCHEMA
        assert SNAPSHOTS_SCHEMA["properties"]["report_type"]["const"] == "snapshots"
        assert "data" in SNAPSHOTS_SCHEMA["properties"]

    def test_self_dependencies_schema_has_required_fields(self):
        """Test self-dependencies schema has all required fields."""
        assert "$schema" in SELF_DEPENDENCIES_SCHEMA
        assert SELF_DEPENDENCIES_SCHEMA["properties"]["report_type"]["const"] == "self-dependencies"

    def test_multi_version_sources_schema_has_required_fields(self):
        """Test multi-version-sources schema has all required fields."""
        assert "$schema" in MULTI_VERSION_SOURCES_SCHEMA
        assert (
            MULTI_VERSION_SOURCES_SCHEMA["properties"]["report_type"]["const"]
            == "multi-version-sources"
        )
        assert "multi_version_dependencies" in MULTI_VERSION_SOURCES_SCHEMA["properties"]

    def test_non_semver_versions_schema_has_required_fields(self):
        """Test non-semver-versions schema has all required fields."""
        assert "$schema" in NON_SEMVER_VERSIONS_SCHEMA
        assert (
            NON_SEMVER_VERSIONS_SCHEMA["properties"]["report_type"]["const"]
            == "non-semver-versions"
        )

    def test_version_dependencies_schema_has_required_fields(self):
        """Test version-dependencies report schema has all required fields."""
        assert "$schema" in VERSION_DEPENDENCIES_SCHEMA
        assert (
            VERSION_DEPENDENCIES_SCHEMA["properties"]["report_type"]["const"]
            == "version-dependencies"
        )
        assert "summary" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "project_name" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "version" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "max_depth" in VERSION_DEPENDENCIES_SCHEMA["properties"]
        assert "semver_compliance" in VERSION_DEPENDENCIES_SCHEMA["properties"]


class TestSchemaIndex:
    """Tests for schema index."""

    def test_schema_index_has_all_schemas(self):
        """Test schema index contains all expected schemas."""
        expected_schemas = [
            "projects",
            "snapshots",
            "self-dependencies",
            "multi-version-sources",
            "non-semver-versions",
            "version-dependencies",
        ]
        for schema_name in expected_schemas:
            assert schema_name in SCHEMA_INDEX

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
            assert schema is not None


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
