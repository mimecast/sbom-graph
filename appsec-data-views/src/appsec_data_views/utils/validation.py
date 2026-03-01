"""Input validation and sanitization utilities.

This module provides functions for validating and sanitizing user input
to prevent security vulnerabilities like XSS and injection attacks.
"""

import re
from urllib.parse import urlencode

# Allowed CSS dimension patterns (e.g., "800px", "100%", "50em", "auto")
CSS_DIMENSION_PATTERN = re.compile(r"^(\d+)(px|%|em|rem|vh|vw|pt)?$|^auto$", re.IGNORECASE)

# Allowed output formats
ALLOWED_FORMATS = frozenset({"html", "excel", "json"})

# Allowed visualization layouts
ALLOWED_LAYOUTS = frozenset({"spring", "radial", "shell", "bfs", "circular"})

# Maximum reasonable values
MAX_DEPTH = 100
MAX_LIMIT = 100000
MAX_DIMENSION_VALUE = 10000

# Project name pattern - alphanumeric, hyphens, underscores, dots
# This prevents path traversal and injection attacks
PROJECT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")

# Version name pattern - alphanumeric, hyphens, underscores, dots, plus
# Examples: 1.0.0, 2.0.0-SNAPSHOT, v1, build-123, 1.0.0+build.1
VERSION_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+\-]*$")

# Defect/vulnerability ID pattern - same safe character class
# Examples: CVE-2021-44228, SNYK-JAVA-LOG4J-2314720
DEFECT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def validate_css_dimension(value: str, default: str = "800px") -> str:
    """Validate and sanitize a CSS dimension value.

    Args:
        value: The input dimension string (e.g., "800px", "100%")
        default: Default value if validation fails

    Returns:
        Validated dimension string or default
    """
    if not value:
        return default

    # Normalize input
    value = str(value).strip().lower()

    # Check pattern
    match = CSS_DIMENSION_PATTERN.match(value)
    if not match:
        return default

    # For numeric values, check reasonable bounds
    if match.group(1) and match.group(1) != "auto":
        try:
            num_value = int(match.group(1))
            if num_value > MAX_DIMENSION_VALUE or num_value < 0:
                return default
        except ValueError:
            return default

    return value


def validate_max_depth(value: int | None, default: int | None = None) -> int | None:
    """Validate max_depth parameter.

    Args:
        value: The input max_depth value
        default: Default value if validation fails

    Returns:
        Validated max_depth or default
    """
    if value is None:
        return default

    try:
        value = int(value)
        if value < 1 or value > MAX_DEPTH:
            return default
        return value
    except (ValueError, TypeError):
        return default


def validate_limit(value: int | None, default: int = 10000) -> int:
    """Validate limit parameter.

    Args:
        value: The input limit value
        default: Default value if validation fails

    Returns:
        Validated limit or default
    """
    if value is None:
        return default

    try:
        value = int(value)
        if value < 1 or value > MAX_LIMIT:
            return default
        return value
    except (ValueError, TypeError):
        return default


def validate_format(value: str | None, default: str = "html") -> str:
    """Validate output format parameter.

    Args:
        value: The input format value
        default: Default value if validation fails

    Returns:
        Validated format or default
    """
    if not value:
        return default

    value = str(value).strip().lower()
    if value in ALLOWED_FORMATS:
        return value
    return default


def validate_layout(value: str | None, default: str = "spring") -> str:
    """Validate visualization layout parameter.

    Args:
        value: The input layout value
        default: Default value if validation fails

    Returns:
        Validated layout or default
    """
    if not value:
        return default

    value = str(value).strip().lower()
    if value in ALLOWED_LAYOUTS:
        return value
    return default


def validate_boolean(value: str | None, default: bool = False) -> bool:
    """Validate boolean string parameter.

    Args:
        value: The input boolean string
        default: Default value if not explicitly true

    Returns:
        Boolean value
    """
    if not value:
        return default
    return str(value).strip().lower() == "true"


def validate_project_name(value: str) -> str | None:
    """Validate a project name for safe use in URLs.

    Prevents path traversal and injection attacks by ensuring the project name
    contains only safe characters (alphanumeric, hyphens, underscores, dots).

    Args:
        value: The project name to validate

    Returns:
        The validated project name, or None if invalid
    """
    if not value:
        return None

    value = str(value).strip()

    # Check for maximum length (reasonable limit)
    if len(value) > 256:
        return None

    # Validate pattern
    if not PROJECT_NAME_PATTERN.match(value):
        return None

    return value



def validate_version_name(value: str) -> str | None:
    """Validate a version name for safe use in URLs.

    Prevents path traversal and injection attacks by ensuring the version name
    contains only safe characters. Supports various version formats:
    - Semantic versions: 1.0.0, 2.1.0-SNAPSHOT
    - Prefix versions: v1, v2.1
    - Build versions: build-123, release-2024.01
    - Phase versions: alpha, beta, rc1, GA

    Args:
        value: The version name to validate

    Returns:
        The validated version name, or None if invalid
    """
    if not value:
        return None

    value = str(value).strip()

    # Check for maximum length (reasonable limit)
    if len(value) > 128:
        return None

    # Validate pattern
    if not VERSION_NAME_PATTERN.match(value):
        return None

    return value


def validate_defect_id(value: str) -> str | None:
    """Validate a defect/vulnerability ID for safe use in URLs.

    Args:
        value: The defect ID to validate (e.g., CVE-2021-44228)

    Returns:
        The validated defect ID, or None if invalid
    """
    if not value:
        return None

    value = str(value).strip()

    if len(value) > 128:
        return None

    if not DEFECT_ID_PATTERN.match(value):
        return None

    return value


def is_safe_redirect_url(url: str | None) -> bool:
    """Check if a redirect URL is safe (internal, relative path only).

    Args:
        url: The URL to validate

    Returns:
        True if the URL is safe for redirection, False otherwise
    """
    if not url:
        return False

    url = str(url).strip()

    # Must start with exactly one forward slash (relative path)
    if not url.startswith("/") or url.startswith("//") or url.startswith("/\\"):
        return False

    # Reject URLs with embedded credentials or unusual characters
    dangerous_patterns = [
        "@",  # Embedded credentials
        "\\",  # Backslash variations
        "\r",  # CRLF injection
        "\n",  # Newline injection
        "\t",  # Tab character
        "%00",  # Null byte
        "%0a",  # URL-encoded newline
        "%0d",  # URL-encoded carriage return
    ]
    url_lower = url.lower()
    for pattern in dangerous_patterns:
        if pattern in url_lower:
            return False

    return True


def get_safe_redirect_url(default_endpoint: str = "index") -> str:
    """Get a safe redirect URL from the request, falling back to default.

    This function checks the 'next' query parameter and returns it only
    if it passes security validation. Otherwise returns the default endpoint.

    Args:
        default_endpoint: Flask endpoint name to use as fallback

    Returns:
        Safe URL for redirection (always returns url_for result for safety)
    """
    from flask import request, url_for

    next_url = request.args.get("next", "")

    # Only use the provided URL if it passes validation
    if is_safe_redirect_url(next_url):
        # Return url_for with the path to ensure proper URL construction
        # We strip the leading slash to match against known routes
        return next_url

    return url_for(default_endpoint)


def build_url_params(
    format: str | None = None,
    limit: int | None = None,
    max_depth: int | None = None,
    internal_only: bool = False,
    longest_only: bool = True,
    latest_only: bool = False,
) -> str:
    """Build URL query parameters string, filtering out None/False values.

    Args:
        format: Output format (excel, json)
        limit: Limit parameter
        max_depth: Max depth parameter
        internal_only: Internal only filter
        longest_only: Show only longest paths (default True, only include param if False)
        latest_only: Show only latest version per application (default False)

    Returns:
        URL-encoded query string (without leading '?')
    """
    params = {}
    if format:
        params["format"] = format
    if limit is not None:
        params["limit"] = str(limit)
    if max_depth is not None:
        params["max_depth"] = str(max_depth)
    if internal_only:
        params["internal_only"] = "true"
    if not longest_only:
        params["longest_only"] = "false"
    if latest_only:
        params["latest_only"] = "true"

    return urlencode(params) if params else ""


def build_url_with_params(
    base_url: str,
    format: str | None = None,
    limit: int | None = None,
    max_depth: int | None = None,
    internal_only: bool = False,
    longest_only: bool = True,
    latest_only: bool = False,
) -> str:
    """Build a complete URL with query parameters.

    Args:
        base_url: The base URL path
        format: Output format (excel, json)
        limit: Limit parameter
        max_depth: Max depth parameter
        internal_only: Internal only filter
        longest_only: Show only longest paths (default True)
        latest_only: Show only latest version per application (default False)

    Returns:
        Complete URL with query string
    """
    query_string = build_url_params(
        format=format,
        limit=limit,
        max_depth=max_depth,
        internal_only=internal_only,
        longest_only=longest_only,
        latest_only=latest_only,
    )
    if query_string:
        return f"{base_url}?{query_string}"
    return base_url
