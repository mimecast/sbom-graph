"""Shared helpers used across all report sub-modules."""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from flask import Response, jsonify, render_template, request

from sbom_graph_api.exports.streaming import (
    SheetSpec,
    stream_json_response,
    stream_multi_sheet_workbook_response,
)
from sbom_graph_api.services.falkordb_service import iterate_pages
from sbom_graph_api.utils.api_helpers import get_utc_timestamp
from sbom_graph_api.utils.validation import (
    MAX_RESULT_WINDOW,
    sanitize_content_disposition,
    validate_boolean,
    validate_page,
    validate_page_size,
)

logger = logging.getLogger(__name__)

TABLE_TEMPLATE = "table.html"

# Total result-set size header for programmatic (API) consumers. Set uniformly
# on every paged report response so a script can learn the total without walking
# every page (reporting-gap #5).
TOTAL_COUNT_HEADER = "X-Total-Count"

# Characters Excel forbids in a worksheet title: \ / * ? : [ ]
_EXCEL_TITLE_INVALID = re.compile(r"[\\/*?:\[\]]")


def _excel_sheet_title(title: str) -> str:
    """Sanitise a report title into a valid Excel worksheet name.

    Excel rejects ``\\ / * ? : [ ]`` in sheet names and caps the length at 31
    characters. Report titles may contain those characters (e.g. a purl or a
    ``Foo / Bar`` label), so strip them here rather than at every call site.
    """
    cleaned = _EXCEL_TITLE_INVALID.sub(" ", title).strip()
    return cleaned[:31] or "Report"

PAGE_SIZE_OPTIONS = (25, 50, 100, 250, 1000)

# Per-identity rate limit on report/export/visualization endpoints (SEC-008).
# Monkeypatchable in tests; read as a module global at call time.
REPORTS_RATE_LIMIT_PER_MINUTE = 600
_RATE_WINDOW_SECONDS = 60
_RATE_CLEANUP_INTERVAL = 300  # purge stale per-client entries every 5 min
_rate_lock = threading.Lock()
_rate_state: dict[str, tuple[int, float]] = {}
_rate_cleanup = {"last_cleanup": time.monotonic()}


def _cleanup_stale_rate_entries(now: float) -> None:
    """Drop entries whose window has expired. Called under ``_rate_lock``.

    Without this the per-client dict would grow unbounded — one entry per
    distinct client address ever seen — over the process's lifetime.
    """
    stale = [
        client
        for client, (_, window_start) in _rate_state.items()
        if now - window_start > _RATE_WINDOW_SECONDS
    ]
    for client in stale:
        del _rate_state[client]


def _safe_int(value: Any, fallback: int) -> int:
    """Coerce a value to int, falling back when it isn't a real number
    (e.g. a test MagicMock or a missing count)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


# ---------------------------------------------------------------------------
# Pagination request + view
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PageRequest:
    """Validated pagination parameters for a report request."""

    page: int
    page_size: int
    unlimited: bool

    @property
    def offset(self) -> int:
        return min((self.page - 1) * self.page_size, MAX_RESULT_WINDOW)


def parse_pagination(args: Any = None) -> PageRequest:
    """Build a validated :class:`PageRequest` from request args.

    Legacy ``?limit`` maps to ``page_size`` when ``page_size`` is absent (FR-007).
    """
    args = args if args is not None else request.args
    raw_page_size = args.get("page_size", type=int)
    if raw_page_size is None and args.get("limit") is not None:
        raw_page_size = args.get("limit", type=int)
    return PageRequest(
        page=validate_page(args.get("page", type=int)),
        page_size=validate_page_size(raw_page_size),
        unlimited=validate_boolean(args.get("all")),
    )


@dataclass(frozen=True)
class PageView:
    """View-model for the HTML pagination controls."""

    page: int
    pages: int
    total: int
    page_size: int
    prev_url: str | None
    next_url: str | None
    size_urls: dict[int, str] = field(default_factory=dict)


def _clean_params(params: dict[str, Any]) -> dict[str, str]:
    """Drop empty/False params; render booleans as lowercase strings for URLs."""
    out: dict[str, str] = {}
    for key, value in params.items():
        if value is None or value is False:
            continue
        out[key] = "true" if value is True else str(value)
    return out


def build_page_view(
    req: PageRequest,
    total: Any,
    base_url: str,
    params: dict[str, Any],
) -> PageView:
    """Compute Prev/Next URLs, page count and the page-size selector links."""
    total_i = _safe_int(total, 0)
    pages = max(1, math.ceil(total_i / req.page_size)) if req.page_size else 1

    def _url(page: int, page_size: int | None = None) -> str:
        merged = dict(params)
        merged["page"] = page
        merged["page_size"] = page_size if page_size is not None else req.page_size
        return f"{base_url}?{urlencode(_clean_params(merged))}"

    return PageView(
        page=req.page,
        pages=pages,
        total=total_i,
        page_size=req.page_size,
        prev_url=_url(req.page - 1) if req.page > 1 else None,
        next_url=_url(req.page + 1) if req.page < pages else None,
        size_urls={size: _url(1, size) for size in PAGE_SIZE_OPTIONS},
    )


# ---------------------------------------------------------------------------
# Rate limiting (SEC-008) + audit logging (COMP-003)
# ---------------------------------------------------------------------------


def _reset_rate_limiter() -> None:
    """Clear rate-limit state (used between tests)."""
    with _rate_lock:
        _rate_state.clear()


def _check_report_rate_limit() -> tuple[Response, int] | None:
    """Return a 429 response when the caller exceeds the per-identity limit."""
    limit = REPORTS_RATE_LIMIT_PER_MINUTE
    client = request.remote_addr or "unknown"
    now = time.monotonic()
    with _rate_lock:
        # Periodic housekeeping to keep _rate_state bounded.
        if now - _rate_cleanup["last_cleanup"] > _RATE_CLEANUP_INTERVAL:
            _cleanup_stale_rate_entries(now)
            _rate_cleanup["last_cleanup"] = now
        count, window_start = _rate_state.get(client, (0, now))
        if now - window_start >= _RATE_WINDOW_SECONDS:
            count, window_start = 0, now
        count += 1
        _rate_state[client] = (count, window_start)
        if count > limit:
            retry_after = int(_RATE_WINDOW_SECONDS - (now - window_start)) + 1
            logger.warning("report rate limit exceeded for %s (%d/%ds)", client, count, _RATE_WINDOW_SECONDS)
            resp = jsonify({"error": "Too many report requests. Please retry later."})
            resp.headers["Retry-After"] = str(retry_after)
            return resp, 429
    return None


def log_report_access(**fields: Any) -> None:
    """Emit a structured access-log record for a report/export request (COMP-003)."""
    logger.info("report_access %s", fields)


# ---------------------------------------------------------------------------
# Central paged-report renderer (one choke point for all reports)
# ---------------------------------------------------------------------------


def render_paged_report(
    *,
    req: PageRequest,
    output_format: str,
    fetch_page: Callable[[int, int], list[dict[str, Any]]],
    count: Callable[[], Any],
    headers: list[str],
    to_cells: Callable[[dict[str, Any]], list[Any]],
    to_export_cells: Callable[[dict[str, Any]], list[Any]] | None = None,
    to_json_row: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    title: str,
    base_url: str,
    params: dict[str, Any],
    filename_stem: str,
    report_type: str,
    schema_url: str | None = None,
    stats_builder: Callable[[int], dict[str, Any]] | None = None,
    json_stats_builder: Callable[[int], dict[str, Any]] | None = None,
    json_meta: dict[str, Any] | None = None,
    template: str = TABLE_TEMPLATE,
    extra_toggles: list[dict[str, Any]] | None = None,
    internal_only: bool = False,
    extra_context: dict[str, Any] | None = None,
    page_context_fn: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
) -> Response | tuple[Response, int]:
    """Render a report as paged HTML, streamed Excel, or streamed JSON.

    HTML returns exactly one bounded page; Excel/JSON stream the FULL result set
    page-by-page so memory stays flat (no buffered path → ``all=true`` cannot OOM).
    """
    limited = _check_report_rate_limit()
    if limited is not None:
        return limited

    log_report_access(
        report_type=report_type,
        format=output_format,
        unlimited=req.unlimited,
        page=req.page,
        page_size=req.page_size,
    )

    export_cells = to_export_cells or to_cells
    json_row = to_json_row or (lambda row: row)

    if output_format == "excel":
        filename = f"{filename_stem}.xlsx"
        total_for_stats = _safe_int(count(), 0)
        stats_dict = stats_builder(total_for_stats) if stats_builder else {}
        rows = (export_cells(row) for page in iterate_pages(fetch_page) for row in page)
        main_sheet = SheetSpec(title=_excel_sheet_title(title), headers=headers, rows=rows)
        sheets: list[SheetSpec] = [main_sheet]
        if stats_dict:
            summary_rows = [[str(k), str(v)] for k, v in stats_dict.items()]
            sheets.append(SheetSpec(title="Summary", headers=["Metric", "Value"], rows=iter(summary_rows)))
        resp = stream_multi_sheet_workbook_response(sheets, filename)
        resp.headers[TOTAL_COUNT_HEADER] = str(total_for_stats)
        return resp

    if output_format == "json":
        filename = f"{filename_stem}.json"
        total = _safe_int(count(), 0)
        json_stats = json_stats_builder or stats_builder
        stats = json_stats(total) if json_stats else None
        meta = {"report_type": report_type, "generated_at": ts()}
        if json_meta:
            meta.update(json_meta)
        json_rows = (json_row(row) for page in iterate_pages(fetch_page) for row in page)
        # X-Total-Count only (not in the body): several report schemas set
        # additionalProperties:false at the top level, so the total is exposed
        # via the header rather than a new document field.
        resp = stream_json_response(meta, json_rows, filename, stats=stats)
        resp.headers[TOTAL_COUNT_HEADER] = str(total)
        return resp

    # HTML — exactly one bounded page + a count for the pager.
    page = fetch_page(req.offset, req.page_size)
    total = _safe_int(count(), len(page))
    page_view = build_page_view(req, total, base_url, params)
    url_params = _clean_params(params)
    ctx: dict[str, Any] = {
        "title": title,
        "internal_only": internal_only,
        "headers": headers,
        "data": [to_cells(row) for row in page],
        "stats": stats_builder(total) if stats_builder else None,
        "pagination": page_view,
        "excel_url": f"{base_url}?{urlencode({**url_params, 'format': 'excel'})}",
        "json_url": f"{base_url}?{urlencode({**url_params, 'format': 'json'})}",
        "schema_url": schema_url,
        "extra_toggles": extra_toggles,
    }
    if page_context_fn is not None:
        ctx.update(page_context_fn(page))
    if extra_context:
        ctx.update(extra_context)
    html = render_template(template, **ctx)
    resp = Response(html, mimetype="text/html")
    resp.headers[TOTAL_COUNT_HEADER] = str(total)
    return resp


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
    """Return the current UTC time in ISO-8601 format.

    Thin alias over the canonical :func:`get_utc_timestamp` so report code can
    keep importing the short ``ts`` name.
    """
    return get_utc_timestamp()
