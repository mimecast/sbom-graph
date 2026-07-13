"""API response helpers for consistent JSON envelope formatting."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Response, jsonify

from sbom_graph_api.utils.validation import validate_int_param


def get_utc_timestamp() -> str:
    """Return the current UTC time in ISO-8601 format.

    Canonical timestamp helper for the whole codebase; all report/export
    ``generated_at``/``timestamp`` values route through here.
    """
    return datetime.now(UTC).isoformat()


def api_response(
    data: Any,
    *,
    pagination: dict[str, int] | None = None,
    meta: dict[str, Any] | None = None,
    status: int = 200,
) -> tuple[Response, int]:
    """Wrap API data in a consistent JSON envelope.

    Returns ``{data, pagination?, meta}`` structure.
    """
    envelope: dict[str, Any] = {"data": data}

    if pagination is not None:
        envelope["pagination"] = pagination

    if meta is None:
        meta = {}
    meta.setdefault("timestamp", get_utc_timestamp())
    envelope["meta"] = meta

    return jsonify(envelope), status


def paginate_params(
    offset_raw: str | None,
    limit_raw: str | None,
    *,
    default_limit: int = 100,
    max_limit: int = 1000,
) -> tuple[int, int]:
    """Parse and validate offset/limit pagination parameters.

    Returns (offset, limit) tuple with validated bounds.
    """
    offset = validate_int_param(
        offset_raw, default=0, min_val=0, max_val=1000000
    )
    limit = validate_int_param(
        limit_raw, default=default_limit, min_val=1, max_val=max_limit
    )
    return offset, limit


def make_pagination(offset: int, limit: int, total: int) -> dict[str, int]:
    """Build pagination metadata dict."""
    return {
        "offset": offset,
        "limit": limit,
        "total": total,
    }
