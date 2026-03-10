"""Tests for inbound JSON schemas and the validate_json_body utility."""

import pytest
from jsonschema import Draft7Validator

from sbom_graph_api.schemas.definitions import SCHEMA_INDEX, SCHEMA_VERSION
from sbom_graph_api.schemas.inbound import (
    CONTACT_CREATE_SCHEMA,
    ENRICHMENT_REQUEST_SCHEMA,
    INBOUND_SCHEMA_INDEX,
    POLICY_ANNOTATION_SCHEMA,
    SBOM_UPLOAD_SCHEMA,
    VEX_UPLOAD_SCHEMA,
)
from sbom_graph_api.utils.validation import validate_json_body

ALL_INBOUND_SCHEMAS = {
    "sbom-upload": SBOM_UPLOAD_SCHEMA,
    "vex-upload": VEX_UPLOAD_SCHEMA,
    "enrichment-request": ENRICHMENT_REQUEST_SCHEMA,
    "policy-annotation": POLICY_ANNOTATION_SCHEMA,
    "contact-create": CONTACT_CREATE_SCHEMA,
}


# =========================================================================
# Schema meta-property tests
# =========================================================================


class TestInboundSchemaMeta:
    """Verify that all inbound schemas have correct meta-properties."""

    @pytest.mark.parametrize("name,schema", ALL_INBOUND_SCHEMAS.items())
    def test_uses_draft_07(self, name: str, schema: dict) -> None:
        assert schema["$schema"] == SCHEMA_VERSION, f"{name} has wrong $schema"

    @pytest.mark.parametrize("name,schema", ALL_INBOUND_SCHEMAS.items())
    def test_is_valid_json_schema(self, name: str, schema: dict) -> None:
        Draft7Validator.check_schema(schema)

    @pytest.mark.parametrize("name,schema", ALL_INBOUND_SCHEMAS.items())
    def test_has_title(self, name: str, schema: dict) -> None:
        assert "title" in schema, f"{name} missing title"

    @pytest.mark.parametrize("name,schema", ALL_INBOUND_SCHEMAS.items())
    def test_has_description(self, name: str, schema: dict) -> None:
        assert "description" in schema, f"{name} missing description"

    @pytest.mark.parametrize("name,schema", ALL_INBOUND_SCHEMAS.items())
    def test_type_is_object(self, name: str, schema: dict) -> None:
        assert schema["type"] == "object", f"{name} type is not 'object'"


class TestInboundSchemaIndex:
    """Verify the INBOUND_SCHEMA_INDEX is consistent and registered."""

    def test_all_schemas_in_index(self) -> None:
        for name in ALL_INBOUND_SCHEMAS:
            assert name in INBOUND_SCHEMA_INDEX, f"{name} not in INBOUND_SCHEMA_INDEX"

    def test_index_entries_have_required_keys(self) -> None:
        for name, entry in INBOUND_SCHEMA_INDEX.items():
            assert "schema" in entry, f"{name} entry missing 'schema'"
            assert "endpoint" in entry, f"{name} entry missing 'endpoint'"
            assert "description" in entry, f"{name} entry missing 'description'"

    def test_inbound_schemas_registered_in_global_index(self) -> None:
        for name in INBOUND_SCHEMA_INDEX:
            assert name in SCHEMA_INDEX, f"Inbound schema '{name}' not found in global SCHEMA_INDEX"


# =========================================================================
# validate_json_body utility tests
# =========================================================================


class TestValidateJsonBody:
    """Test the validate_json_body() helper function."""

    def test_valid_body_returns_none(self) -> None:
        body = {"sbom": {"bomFormat": "CycloneDX"}}
        result = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert result is None

    def test_missing_required_field_returns_errors(self) -> None:
        body = {}
        result = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert result is not None
        assert any("sbom" in msg for msg in result)

    def test_wrong_type_returns_errors(self) -> None:
        body = {"sbom": "not-an-object"}
        result = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert result is not None
        assert any("sbom" in msg for msg in result)

    def test_additional_properties_rejected(self) -> None:
        body = {"sbom": {}, "unknown_field": "value"}
        result = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert result is not None
        assert any("unknown_field" in msg for msg in result)

    def test_multiple_errors_returned(self) -> None:
        body = {"purl": 123, "type": "invalid"}
        result = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert result is not None
        assert len(result) >= 2

    def test_empty_schema_accepts_any_object(self) -> None:
        body = {"anything": "goes", "nested": {"deep": True}}
        result = validate_json_body(body, VEX_UPLOAD_SCHEMA)
        assert result is None


# =========================================================================
# SBOM_UPLOAD_SCHEMA validation tests
# =========================================================================


class TestSbomUploadSchema:
    """Test SBOM_UPLOAD_SCHEMA accepts/rejects correct payloads."""

    def test_minimal_valid(self) -> None:
        body = {"sbom": {}}
        assert validate_json_body(body, SBOM_UPLOAD_SCHEMA) is None

    def test_full_valid(self) -> None:
        body = {
            "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5"},
            "app_id": "abc123",
            "public_app_id": "my-app",
            "project_url": "https://github.com/org/repo",
        }
        assert validate_json_body(body, SBOM_UPLOAD_SCHEMA) is None

    def test_missing_sbom(self) -> None:
        body = {"app_id": "abc"}
        errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert errors is not None
        assert any("sbom" in msg for msg in errors)

    def test_sbom_wrong_type(self) -> None:
        body = {"sbom": [1, 2, 3]}
        errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert errors is not None

    def test_app_id_too_long(self) -> None:
        body = {"sbom": {}, "app_id": "x" * 300}
        errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert errors is not None

    def test_rejects_additional_properties(self) -> None:
        body = {"sbom": {}, "extra": "field"}
        errors = validate_json_body(body, SBOM_UPLOAD_SCHEMA)
        assert errors is not None


# =========================================================================
# VEX_UPLOAD_SCHEMA validation tests
# =========================================================================


class TestVexUploadSchema:
    """Test VEX_UPLOAD_SCHEMA accepts/rejects correct payloads."""

    def test_valid_vex_object(self) -> None:
        body = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
        assert validate_json_body(body, VEX_UPLOAD_SCHEMA) is None

    def test_empty_object_valid(self) -> None:
        assert validate_json_body({}, VEX_UPLOAD_SCHEMA) is None


# =========================================================================
# ENRICHMENT_REQUEST_SCHEMA validation tests
# =========================================================================


class TestEnrichmentRequestSchema:
    """Test ENRICHMENT_REQUEST_SCHEMA accepts/rejects correct payloads."""

    def test_empty_body_valid(self) -> None:
        assert validate_json_body({}, ENRICHMENT_REQUEST_SCHEMA) is None

    def test_valid_purls(self) -> None:
        body = {"purls": ["pkg:maven/com.example/lib@1.0"]}
        assert validate_json_body(body, ENRICHMENT_REQUEST_SCHEMA) is None

    def test_purl_must_start_with_pkg(self) -> None:
        body = {"purls": ["not-a-purl"]}
        errors = validate_json_body(body, ENRICHMENT_REQUEST_SCHEMA)
        assert errors is not None

    def test_purls_not_array(self) -> None:
        body = {"purls": "pkg:maven/com.example/lib"}
        errors = validate_json_body(body, ENRICHMENT_REQUEST_SCHEMA)
        assert errors is not None

    def test_too_many_purls(self) -> None:
        body = {"purls": [f"pkg:maven/g/a@{i}" for i in range(1001)]}
        errors = validate_json_body(body, ENRICHMENT_REQUEST_SCHEMA)
        assert errors is not None

    def test_rejects_additional_properties(self) -> None:
        body = {"purls": [], "extra": True}
        errors = validate_json_body(body, ENRICHMENT_REQUEST_SCHEMA)
        assert errors is not None


# =========================================================================
# POLICY_ANNOTATION_SCHEMA validation tests
# =========================================================================


class TestPolicyAnnotationSchema:
    """Test POLICY_ANNOTATION_SCHEMA accepts/rejects correct payloads."""

    def test_minimal_valid(self) -> None:
        body = {
            "purl": "pkg:maven/com.example/lib@1.0",
            "type": "bad",
            "justification": "Known vulnerability",
        }
        assert validate_json_body(body, POLICY_ANNOTATION_SCHEMA) is None

    def test_with_expires_at(self) -> None:
        body = {
            "purl": "pkg:maven/com.example/lib@1.0",
            "type": "hold",
            "justification": "Under review",
            "expires_at": "2026-06-01T00:00:00Z",
        }
        assert validate_json_body(body, POLICY_ANNOTATION_SCHEMA) is None

    def test_missing_purl(self) -> None:
        body = {"type": "bad", "justification": "reason"}
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_missing_type(self) -> None:
        body = {"purl": "pkg:maven/g/a@1", "justification": "reason"}
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_missing_justification(self) -> None:
        body = {"purl": "pkg:maven/g/a@1", "type": "good"}
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_invalid_type_enum(self) -> None:
        body = {
            "purl": "pkg:maven/g/a@1",
            "type": "unknown",
            "justification": "reason",
        }
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_purl_wrong_prefix(self) -> None:
        body = {
            "purl": "http://example.com",
            "type": "bad",
            "justification": "reason",
        }
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_justification_too_long(self) -> None:
        body = {
            "purl": "pkg:maven/g/a@1",
            "type": "bad",
            "justification": "x" * 2001,
        }
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_empty_justification_rejected(self) -> None:
        body = {
            "purl": "pkg:maven/g/a@1",
            "type": "bad",
            "justification": "",
        }
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None

    def test_rejects_additional_properties(self) -> None:
        body = {
            "purl": "pkg:maven/g/a@1",
            "type": "good",
            "justification": "reason",
            "extra": "nope",
        }
        errors = validate_json_body(body, POLICY_ANNOTATION_SCHEMA)
        assert errors is not None


# =========================================================================
# CONTACT_CREATE_SCHEMA validation tests
# =========================================================================


class TestContactCreateSchema:
    """Test CONTACT_CREATE_SCHEMA accepts/rejects correct payloads."""

    def test_minimal_valid(self) -> None:
        body = {
            "email": "user@example.com",
            "purl": "pkg:maven/com.example/lib@1.0",
        }
        assert validate_json_body(body, CONTACT_CREATE_SCHEMA) is None

    def test_full_valid(self) -> None:
        body = {
            "email": "user@example.com",
            "purl": "pkg:maven/com.example/lib@1.0",
            "team": "Security",
            "slack_channel": "#alerts",
        }
        assert validate_json_body(body, CONTACT_CREATE_SCHEMA) is None

    def test_missing_email(self) -> None:
        body = {"purl": "pkg:maven/g/a@1"}
        errors = validate_json_body(body, CONTACT_CREATE_SCHEMA)
        assert errors is not None

    def test_missing_purl(self) -> None:
        body = {"email": "user@example.com"}
        errors = validate_json_body(body, CONTACT_CREATE_SCHEMA)
        assert errors is not None

    def test_purl_wrong_prefix(self) -> None:
        body = {"email": "user@example.com", "purl": "not-a-purl"}
        errors = validate_json_body(body, CONTACT_CREATE_SCHEMA)
        assert errors is not None

    def test_team_too_long(self) -> None:
        body = {
            "email": "user@example.com",
            "purl": "pkg:maven/g/a@1",
            "team": "x" * 201,
        }
        errors = validate_json_body(body, CONTACT_CREATE_SCHEMA)
        assert errors is not None

    def test_rejects_additional_properties(self) -> None:
        body = {
            "email": "user@example.com",
            "purl": "pkg:maven/g/a@1",
            "extra": "nope",
        }
        errors = validate_json_body(body, CONTACT_CREATE_SCHEMA)
        assert errors is not None
