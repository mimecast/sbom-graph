"""Tests for schema routes."""

import json


class TestListSchemasEndpoint:
    """Tests for GET /schemas/ endpoint."""

    def test_list_schemas_returns_json(self, client):
        """Test schemas list endpoint returns JSON."""
        response = client.get("/schemas/")

        assert response.status_code == 200
        assert response.content_type == "application/json"

    def test_list_schemas_has_schemas_key(self, client):
        """Test schemas list response has 'schemas' key."""
        response = client.get("/schemas/")
        data = json.loads(response.data)

        assert "schemas" in data
        assert isinstance(data["schemas"], list)

    def test_list_schemas_has_description(self, client):
        """Test schemas list response has description."""
        response = client.get("/schemas/")
        data = json.loads(response.data)

        assert "description" in data

    def test_list_schemas_includes_all_known_schemas(self, client):
        """Test schemas list includes all expected schemas."""
        response = client.get("/schemas/")
        data = json.loads(response.data)

        schema_names = [s["name"] for s in data["schemas"]]
        expected_schemas = [
            "projects",
            "snapshots",
            "self-dependencies",
            "multi-version-sources",
            "non-semver-versions",
            "version-dependencies",
        ]

        for expected in expected_schemas:
            assert expected in schema_names, f"Missing schema: {expected}"


class TestGetSchemaEndpoint:
    """Tests for GET /schemas/{schema_name} endpoint."""

    def test_get_schema_returns_json_schema(self, client):
        """Test get schema endpoint returns JSON schema."""
        response = client.get("/schemas/projects")

        assert response.status_code == 200
        assert "application/schema+json" in response.content_type

    def test_get_schema_has_schema_fields(self, client):
        """Test returned schema has expected JSON Schema fields."""
        response = client.get("/schemas/projects")
        data = json.loads(response.data)

        assert "$schema" in data
        assert "title" in data
        assert "type" in data
        assert "properties" in data

    def test_get_schema_has_content_disposition(self, client):
        """Test schema response has Content-Disposition header."""
        response = client.get("/schemas/projects")

        assert "Content-Disposition" in response.headers
        assert "projects.schema.json" in response.headers["Content-Disposition"]

    def test_get_schema_not_found_returns_404(self, client):
        """Test requesting non-existent schema returns 404."""
        response = client.get("/schemas/nonexistent")

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data
        assert "available_schemas" in data

    def test_get_schema_all_known_schemas(self, client):
        """Test all known schemas can be retrieved."""
        schemas = [
            "projects",
            "snapshots",
            "self-dependencies",
            "multi-version-sources",
            "non-semver-versions",
            "version-dependencies",
        ]

        for schema_name in schemas:
            response = client.get(f"/schemas/{schema_name}")
            assert response.status_code == 200, f"Failed to get schema: {schema_name}"


class TestSchemaValidation:
    """Tests that schemas are valid JSON Schema documents."""

    def test_projects_schema_is_valid(self, client):
        """Test projects schema is a valid JSON Schema document."""
        response = client.get("/schemas/projects")
        data = json.loads(response.data)

        # Check Draft-07 meta-schema reference
        assert data["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert data["type"] == "object"
        assert "report_type" in data["required"]

    def test_snapshots_schema_is_valid(self, client):
        """Test snapshots schema is a valid JSON Schema document."""
        response = client.get("/schemas/snapshots")
        data = json.loads(response.data)

        assert data["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert data["type"] == "object"

    def test_version_dependencies_schema_is_valid(self, client):
        """Test version-dependencies schema is a valid JSON Schema document."""
        response = client.get("/schemas/version-dependencies")
        data = json.loads(response.data)

        assert data["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert data["type"] == "object"
        assert "report_type" in data["required"]
        assert "version" in data["required"]
        assert "semver_compliance" in data["properties"]
        assert "max_depth" in data["properties"]
