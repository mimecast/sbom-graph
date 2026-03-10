"""Tests for schema routes."""

import json

from sbom_graph_api.schemas.definitions import SCHEMA_INDEX, SCHEMA_VERSION
from sbom_graph_api.schemas.inbound import INBOUND_SCHEMA_INDEX

ALL_SCHEMA_NAMES = list(SCHEMA_INDEX.keys())
OUTBOUND_SCHEMA_NAMES = [n for n in ALL_SCHEMA_NAMES if n not in INBOUND_SCHEMA_INDEX]


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
        """Test schemas list includes every schema in the index."""
        response = client.get("/schemas/")
        data = json.loads(response.data)

        schema_names = [s["name"] for s in data["schemas"]]
        for expected in ALL_SCHEMA_NAMES:
            assert expected in schema_names, f"Missing schema: {expected}"

    def test_list_schemas_count_matches_index(self, client):
        """Returned schema count must equal SCHEMA_INDEX size."""
        response = client.get("/schemas/")
        data = json.loads(response.data)

        assert len(data["schemas"]) == len(SCHEMA_INDEX)


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
        for schema_name in ALL_SCHEMA_NAMES:
            response = client.get(f"/schemas/{schema_name}")
            assert response.status_code == 200, f"Failed to get schema: {schema_name}"


class TestSchemaValidation:
    """Tests that schemas are valid JSON Schema documents."""

    def test_all_schemas_use_draft_07(self, client):
        """Every schema must reference the same JSON Schema draft."""
        for schema_name in ALL_SCHEMA_NAMES:
            response = client.get(f"/schemas/{schema_name}")
            data = json.loads(response.data)

            assert data["$schema"] == SCHEMA_VERSION, (
                f"{schema_name}: uses {data['$schema']}, expected {SCHEMA_VERSION}"
            )

    def test_all_schemas_are_object_type(self, client):
        """Top-level type must be 'object' for every schema."""
        for schema_name in ALL_SCHEMA_NAMES:
            response = client.get(f"/schemas/{schema_name}")
            data = json.loads(response.data)

            assert data["type"] == "object", f"{schema_name}: type is {data['type']}"

    def test_outbound_schemas_have_report_type_property(self, client):
        """Every outbound report schema should define a report_type property."""
        for schema_name in OUTBOUND_SCHEMA_NAMES:
            response = client.get(f"/schemas/{schema_name}")
            data = json.loads(response.data)

            assert "report_type" in data.get("properties", {}), (
                f"{schema_name}: missing report_type property"
            )

    def test_projects_schema_is_valid(self, client):
        """Test projects schema is a valid JSON Schema document."""
        response = client.get("/schemas/projects")
        data = json.loads(response.data)

        assert data["type"] == "object"
        assert "report_type" in data["required"]

    def test_snapshots_schema_is_valid(self, client):
        """Test snapshots schema is a valid JSON Schema document."""
        response = client.get("/schemas/snapshots")
        data = json.loads(response.data)

        assert data["type"] == "object"

    def test_version_dependencies_schema_is_valid(self, client):
        """Test version-dependencies schema is a valid JSON Schema document."""
        response = client.get("/schemas/version-dependencies")
        data = json.loads(response.data)

        assert data["type"] == "object"
        assert "report_type" in data["required"]
        assert "version" in data["required"]
        assert "semver_compliance" in data["properties"]
        assert "max_depth" in data["properties"]
