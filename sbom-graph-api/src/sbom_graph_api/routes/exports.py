"""Flask routes for data exports (Excel downloads, JSON).

Note: The /exports/dependencies/{project_name} endpoints are deprecated.
Use /reports/version-dependencies/{project_name}/{version_name} instead,
which supports version filtering and 'latest' version resolution.
"""

from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, Response, abort, jsonify, redirect, request, url_for
from flask.typing import ResponseReturnValue

from sbom_graph_api.routes.auth import auth_required
from sbom_graph_api.utils.validation import (
    validate_boolean,
    validate_format,
    validate_project_name,
)

bp = Blueprint("exports", __name__, url_prefix="/exports")


def _get_current_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat()


def _build_json_response(data: dict[str, Any], filename: str) -> Response:
    """Build a JSON response with proper headers.

    Args:
        data: The data to serialize as JSON
        filename: Suggested filename for download

    Returns:
        Flask Response with JSON content
    """
    response = jsonify(data)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


# Template name for export landing page
EXPORT_TEMPLATE = "export.html"


@bp.route("/dependencies/<project_name>/excel")
@auth_required
def download_dependencies_excel(project_name: str) -> ResponseReturnValue:
    """Endpoint 3: Download Excel file with version dependencies.

    DEPRECATED: Use /reports/version-dependencies/{project_name}?format=excel instead.

    Returns an Excel spreadsheet with a table of version to dependant
    project versions.

    Args:
        project_name: The project name

    Returns:
        Redirect to new report endpoint
    """
    # Validate project name to prevent open redirect
    validated_name = validate_project_name(project_name)
    if not validated_name:
        abort(400, description="Invalid project name")

    internal_only = validate_boolean(request.args.get("internal_only"))
    # Use url_for for safe URL construction
    new_url = url_for(
        "reports.version_dependencies_report",
        project_name=validated_name,
        version_name="latest",
        format="excel",
        internal_only="true" if internal_only else None,
    )
    return redirect(new_url, code=301)


@bp.route("/dependencies/<project_name>/json")
@auth_required
def download_dependencies_json(project_name: str) -> ResponseReturnValue:
    """Download JSON file with version dependencies.

    DEPRECATED: Use /reports/version-dependencies/{project_name}?format=json instead.

    Returns a JSON document with version to dependant project versions.

    Args:
        project_name: The project name

    Returns:
        Redirect to new report endpoint
    """
    # Validate project name to prevent open redirect
    validated_name = validate_project_name(project_name)
    if not validated_name:
        abort(400, description="Invalid project name")

    internal_only = validate_boolean(request.args.get("internal_only"))
    # Use url_for for safe URL construction
    new_url = url_for(
        "reports.version_dependencies_report",
        project_name=validated_name,
        version_name="latest",
        format="json",
        internal_only="true" if internal_only else None,
    )
    return redirect(new_url, code=301)


@bp.route("/dependencies/<project_name>")
@auth_required
def dependencies_export(project_name: str) -> ResponseReturnValue:
    """Export version dependencies with format selection.

    DEPRECATED: Use /reports/version-dependencies/{project_name} instead,
    which supports version filtering and 'latest' version resolution.

    Args:
        project_name: The project name

    Query Parameters:
        format: 'excel' or 'json' to download (default: html landing page)
        internal_only: Set to 'true' for internal-labeled nodes only

    Returns:
        Redirect to new report endpoint
    """
    # Validate project name to prevent open redirect
    validated_name = validate_project_name(project_name)
    if not validated_name:
        abort(400, description="Invalid project name")

    # Validate and build query parameters safely
    output_format = validate_format(request.args.get("format"))
    internal_only = validate_boolean(request.args.get("internal_only"))

    # Use url_for for safe URL construction
    new_url = url_for(
        "reports.version_dependencies_report",
        project_name=validated_name,
        version_name="latest",
        format=output_format if output_format != "html" else None,
        internal_only="true" if internal_only else None,
    )
    return redirect(new_url, code=301)
