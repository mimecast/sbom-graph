"""WSGI entry point for gunicorn.

This module provides the WSGI application for production deployment
with gunicorn.

Usage:
    gunicorn sbom_graph_api.wsgi:app
"""

from sbom_graph_api.app import create_app

app = create_app()
