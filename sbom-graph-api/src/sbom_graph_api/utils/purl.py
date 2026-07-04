"""Helpers for resolving Package URLs (purl) to project coordinates."""

from __future__ import annotations

from typing import Any

from markupsafe import escape

from sbom_graph_api.services.falkordb_service import get_falkordb_service
from sbom_graph_api.utils.validation import validate_purl

# Map purl package types to a human-readable language/ecosystem label.
# purl types are lower-cased per the spec; unknown types fall back to the raw type.
_ECOSYSTEM_LABELS: dict[str, str] = {
    "maven": "Java",
    "gradle": "Java",
    "npm": "JavaScript",
    "pypi": "Python",
    "golang": "Go",
    "nuget": ".NET",
    "gem": "Ruby",
    "cargo": "Rust",
    "composer": "PHP",
    "cocoapods": "Swift/Objective-C",
    "swift": "Swift",
    "conan": "C/C++",
    "hex": "Elixir",
    "pub": "Dart",
    "cran": "R",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
    "docker": "Docker",
    "generic": "Generic",
}


def ecosystem_label(ptype: str | None) -> str:
    """Map a purl package type (e.g. ``maven``) to a language/ecosystem label.

    Unknown types fall back to the (lower-cased) type itself; an empty or
    ``None`` type returns ``""``.

    Args:
        ptype: A purl package type token (the ``<type>`` in ``pkg:<type>/…``).

    Returns:
        The ecosystem label, the lower-cased type when unmapped, or ``""``.
    """
    if not ptype:
        return ""
    normalized = ptype.strip().lower()
    if not normalized:
        return ""
    return _ECOSYSTEM_LABELS.get(normalized, normalized)


def purl_ecosystem(purl: str | None) -> str:
    """Derive a language/ecosystem label from a Package URL.

    Parses the ``pkg:<type>/…`` prefix and maps the package type to a
    language/ecosystem name (e.g. ``maven`` → ``Java``). Unknown types fall
    back to the raw type; a missing, empty, or non-purl string returns ``""``.

    Args:
        purl: A Package URL string (e.g. ``pkg:maven/com.example/foo@1.0.0``).

    Returns:
        The ecosystem label, the raw purl type when unmapped, or ``""``.
    """
    if not purl:
        return ""
    text = purl.strip()
    if not text.startswith("pkg:"):
        return ""
    # The type is the segment between ``pkg:`` and the first ``/``.
    ptype = text[len("pkg:") :].split("/", 1)[0]
    return ecosystem_label(ptype)


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
