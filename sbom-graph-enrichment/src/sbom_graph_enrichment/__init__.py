"""Celery-based enrichment pipeline for sbom-graph.

Runs background certifiers (OSV, ClearlyDefined, etc.) to enrich
graph data with vulnerability, license, and scorecard information.
"""

from .celery_app import app as celery_app

__all__ = ["celery_app"]
