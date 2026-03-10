"""Helpers for resolving Package URLs (purl) to project coordinates."""

from __future__ import annotations

from typing import Any

from markupsafe import escape

from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import validate_purl


def resolve_purl(raw_purl: str) -> dict[str, Any] | tuple[str, int]:
    """Resolve a versioned purl to project coordinates.

    Looks up a Version node whose ``package_url`` matches exactly.

    Args:
        raw_purl: The raw purl string from the path parameter.

    Returns:
        Dict with ``project_name``, ``version_name``, ``project_group``
        on success, or a ``(message, status_code)`` error tuple.
    """
    validated = validate_purl(raw_purl)
    if not validated:
        return "Invalid package URL format", 400

    service = get_falkordb_service()
    result = service.find_version_by_purl(validated)
    if not result:
        return f"No version found for purl: {escape(validated)}", 404

    return result


def resolve_purl_project(raw_purl: str) -> dict[str, Any] | tuple[str, int]:
    """Resolve a purl to just project-level coordinates.

    For routes that only need ``project_name`` (no specific version).
    Performs a prefix match so the purl does not need to include a version.

    Args:
        raw_purl: The raw purl string from the path parameter.

    Returns:
        Dict with ``project_name`` and ``project_group`` on success,
        or a ``(message, status_code)`` error tuple.
    """
    validated = validate_purl(raw_purl)
    if not validated:
        return "Invalid package URL format", 400

    service = get_falkordb_service()

    if "@" in validated:
        result = service.find_version_by_purl(validated)
    else:
        result = service.find_project_by_purl_prefix(validated)

    if not result:
        return f"No project found for purl: {escape(validated)}", 404

    return {
        "project_name": result["project_name"],
        "project_group": result.get("project_group"),
    }
