"""Flask routes for JSON schema endpoints."""

from flask import Blueprint, Response, jsonify

from appsec_data_views.routes.auth import auth_required
from appsec_data_views.schemas import get_schema, get_schema_list

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
    schema = get_schema(schema_name)
    if schema is None:
        return jsonify(
            {
                "error": "Schema not found",
                "available_schemas": [s["name"] for s in get_schema_list()],
            }
        ), 404

    # Return with proper JSON Schema content type
    return Response(
        response=jsonify(schema).get_data(),
        status=200,
        mimetype="application/schema+json",
        headers={
            "Content-Disposition": f'inline; filename="{schema_name}.schema.json"',
        },
    )
