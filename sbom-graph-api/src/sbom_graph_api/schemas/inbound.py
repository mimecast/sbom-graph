"""JSON schemas for validating inbound API request payloads.

These schemas validate the structure of POST request bodies at the API
boundary. For SBOM/VEX ingestion, only the envelope is validated here;
the inner document is validated downstream by the respective processors.
"""

from typing import Any

from sbom_graph_api.schemas.definitions import SCHEMA_VERSION

# Shared length constants (must match api_v1.py constraints)
_MAX_PURL_LENGTH = 512
_MAX_JUSTIFICATION_LENGTH = 2000
_MAX_EMAIL_LENGTH = 254
_MAX_TEAM_LENGTH = 200
_MAX_URL_LENGTH = 2048
_MAX_APP_ID_LENGTH = 256

# ============================================================================
# SBOM Upload Envelope Schema
# ============================================================================
SBOM_UPLOAD_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/inbound/sbom-upload",
    "title": "SBOM Upload Envelope",
    "description": (
        "Wrapper envelope for CycloneDX, SPDX, or auto-detected SBOM uploads. "
        "The inner 'sbom' object is validated by the respective processor."
    ),
    "type": "object",
    "required": ["sbom"],
    "properties": {
        "sbom": {
            "type": "object",
            "description": "The SBOM JSON document (CycloneDX or SPDX)",
        },
        "app_id": {
            "type": "string",
            "maxLength": _MAX_APP_ID_LENGTH,
            "description": "Custom application ID (defaults to SHA-1 of component name)",
        },
        "public_app_id": {
            "type": "string",
            "maxLength": _MAX_APP_ID_LENGTH,
            "description": "Public application identifier (defaults to component name)",
        },
        "project_url": {
            "type": "string",
            "maxLength": _MAX_URL_LENGTH,
            "description": "URL of the source repository",
        },
    },
    "additionalProperties": False,
}

# ============================================================================
# VEX Upload Schema
# ============================================================================
VEX_UPLOAD_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/inbound/vex-upload",
    "title": "VEX Upload",
    "description": (
        "OpenVEX document upload. Must be a JSON object; "
        "deeper validation is performed by the VexProcessor."
    ),
    "type": "object",
}

# ============================================================================
# Enrichment Request Schema
# ============================================================================
ENRICHMENT_REQUEST_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/inbound/enrichment-request",
    "title": "Enrichment Request",
    "description": "Trigger vulnerability enrichment for all or specific packages",
    "type": "object",
    "properties": {
        "purls": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": "^pkg:",
                "maxLength": _MAX_PURL_LENGTH,
            },
            "maxItems": 1000,
            "description": "Optional list of package URLs to enrich (omit to enrich all)",
        },
    },
    "additionalProperties": False,
}

# ============================================================================
# Policy Annotation Schema
# ============================================================================
POLICY_ANNOTATION_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/inbound/policy-annotation",
    "title": "Policy Annotation",
    "description": "Create a policy annotation (certifyBad/certifyGood/hold) on a package",
    "type": "object",
    "required": ["purl", "type", "justification"],
    "properties": {
        "purl": {
            "type": "string",
            "pattern": "^pkg:",
            "maxLength": _MAX_PURL_LENGTH,
            "description": "Package URL to annotate",
        },
        "type": {
            "type": "string",
            "enum": ["bad", "good", "hold"],
            "description": "Annotation type",
        },
        "justification": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_JUSTIFICATION_LENGTH,
            "description": "Reason for the annotation",
        },
        "expires_at": {
            "type": "string",
            "format": "date-time",
            "description": "Optional ISO 8601 expiration timestamp",
        },
    },
    "additionalProperties": False,
}

# ============================================================================
# Contact Create Schema
# ============================================================================
CONTACT_CREATE_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/inbound/contact-create",
    "title": "Contact Create",
    "description": "Create a point-of-contact linked to a package for incident response",
    "type": "object",
    "required": ["email", "purl"],
    "properties": {
        "email": {
            "type": "string",
            "format": "email",
            "maxLength": _MAX_EMAIL_LENGTH,
            "description": "Contact email address",
        },
        "purl": {
            "type": "string",
            "pattern": "^pkg:",
            "maxLength": _MAX_PURL_LENGTH,
            "description": "Package URL to link the contact to",
        },
        "team": {
            "type": "string",
            "maxLength": _MAX_TEAM_LENGTH,
            "description": "Team name",
        },
        "slack_channel": {
            "type": "string",
            "maxLength": _MAX_TEAM_LENGTH,
            "description": "Slack channel for notifications",
        },
    },
    "additionalProperties": False,
}

# ============================================================================
# Inbound Schema Index
# ============================================================================
INBOUND_SCHEMA_INDEX: dict[str, dict[str, Any]] = {
    "sbom-upload": {
        "schema": SBOM_UPLOAD_SCHEMA,
        "endpoint": "/ingest/cyclonedx, /ingest/spdx, /ingest/sbom",
        "description": "SBOM upload envelope (CycloneDX, SPDX, or auto-detect)",
    },
    "vex-upload": {
        "schema": VEX_UPLOAD_SCHEMA,
        "endpoint": "/ingest/vex",
        "description": "OpenVEX document upload",
    },
    "enrichment-request": {
        "schema": ENRICHMENT_REQUEST_SCHEMA,
        "endpoint": "/api/v1/enrich/vulnerabilities",
        "description": "Vulnerability enrichment trigger request",
    },
    "policy-annotation": {
        "schema": POLICY_ANNOTATION_SCHEMA,
        "endpoint": "/api/v1/policy/annotate",
        "description": "Policy annotation creation request",
    },
    "contact-create": {
        "schema": CONTACT_CREATE_SCHEMA,
        "endpoint": "/api/v1/contacts",
        "description": "Point-of-contact creation request",
    },
}
