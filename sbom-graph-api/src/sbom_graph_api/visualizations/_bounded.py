"""Shared bounding utilities for graph visualizations (Phase 1, Module 1)."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def inject_truncation_banner(html: str, max_nodes: int, dropped: int) -> str:
    """Insert a visible truncation notice at the top of the rendered page."""
    banner = (
        f'<div class="graph-truncation" style="background:#fff3cd;color:#664d03;'
        f'padding:8px 12px;font-family:sans-serif;border-bottom:1px solid #ffe69c;">'
        f"&#9888; Graph truncated at {max_nodes} nodes ({dropped} additional relationships "
        f"omitted). Narrow the query to see the full picture.</div>"
    )
    if "<body>" in html:
        return html.replace("<body>", "<body>" + banner, 1)
    return banner + html


def bound_nodes_edges(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    max_nodes: int,
    max_edges: int,
    root_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, int]:
    """Cap nodes and edges at the given limits, always retaining the root/seed node.

    Returns (bounded_nodes, bounded_edges, truncated, dropped).
    """
    truncated = False
    dropped = 0

    kept_ids: set[str] = set()
    kept_nodes: list[dict[str, Any]] = []

    if root_id is not None:
        for n in nodes:
            if n.get("id") == root_id:
                kept_ids.add(root_id)
                kept_nodes.append(n)
                break

    for n in nodes:
        if n.get("id") in kept_ids:
            continue
        if len(kept_ids) >= max_nodes:
            truncated = True
            dropped += 1
            continue
        kept_ids.add(n["id"])
        kept_nodes.append(n)

    kept_edges: list[dict[str, Any]] = []
    for e in edges:
        src = e.get("source", "")
        tgt = e.get("target", "")
        if src not in kept_ids or tgt not in kept_ids:
            truncated = True
            dropped += 1
            continue
        if len(kept_edges) >= max_edges:
            truncated = True
            dropped += 1
            continue
        kept_edges.append(e)

    return kept_nodes, kept_edges, truncated, dropped
