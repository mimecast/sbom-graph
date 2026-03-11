"""Shared helpers used across all report sub-modules."""

from datetime import UTC, datetime
from typing import Any

from flask import Response, jsonify

from sbom_graph_api.utils.validation import sanitize_content_disposition

TABLE_TEMPLATE = "table.html"


def get_internal_title(
    base_title: str,
    internal_only: bool,
) -> str:
    """Get the title with internal filter label based on config.

    Args:
        base_title: The base title (e.g., "Projects")
        internal_only: Whether internal-only filter is active

    Returns:
        Title string with or without internal label
    """
    if internal_only:
        return f"Internal {base_title}"
    return f"All {base_title}"


def build_json_response(
    data: dict[str, Any],
    filename: str,
) -> Response:
    """Build a JSON response with proper headers.

    Args:
        data: The data to serialize as JSON
        filename: Suggested filename for download

    Returns:
        Flask Response with JSON content
    """
    response = jsonify(data)
    safe_header = sanitize_content_disposition(filename).replace("inline", "attachment")
    response.headers["Content-Disposition"] = safe_header
    return response


def ts() -> str:
    """Return the current UTC time in ISO-8601 format."""
    return datetime.now(UTC).isoformat()
