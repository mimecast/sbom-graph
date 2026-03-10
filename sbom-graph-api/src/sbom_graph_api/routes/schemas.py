"""Flask routes for JSON schema endpoints."""

from flask import Blueprint, Response, jsonify

from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.schemas import get_schema, get_schema_list
from sbom_graph_api.utils.validation import (
    sanitize_content_disposition,
    validate_schema_name,
)

bp = Blueprint("schemas", __name__, url_prefix="/schemas")


@bp.route("/")
@auth_required
def list_schemas() -> Response:
    """List all available JSON schemas.

    Returns:
        JSON array of schema metadata
    """
    schemas = get_schema_list()
    return jsonify(
        {
            "schemas": schemas,
            "description": "JSON Schemas for AppSec Data Views API responses",
        }
    )


@bp.route("/<schema_name>")
@auth_required
def get_schema_endpoint(schema_name: str) -> Response | tuple[Response, int]:
    """Get a specific JSON schema by name.

    Args:
        schema_name: The schema identifier (e.g., 'projects', 'snapshots')

    Returns:
        JSON Schema document
    """
    if not validate_schema_name(schema_name):
        return jsonify({"error": "Invalid schema name"}), 400

    schema = get_schema(schema_name)
    if schema is None:
        return jsonify(
            {
                "error": "Schema not found",
                "available_schemas": [s["name"] for s in get_schema_list()],
            }
        ), 404

    return Response(
        response=jsonify(schema).get_data(),
        status=200,
        mimetype="application/schema+json",
        headers={
            "Content-Disposition": sanitize_content_disposition(f"{schema_name}.schema.json"),
        },
    )
