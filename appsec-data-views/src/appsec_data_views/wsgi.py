"""WSGI entry point for gunicorn.

This module provides the WSGI application for production deployment
with gunicorn.

Usage:
    gunicorn appsec_data_views.wsgi:app
"""

from appsec_data_views.app import create_app

app = create_app()
