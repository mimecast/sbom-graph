"""Gunicorn configuration file.

This module provides configuration for gunicorn that reads from environment
variables, including TLS settings.

Usage:
    gunicorn -c gunicorn.conf.py sbom_graph_api.wsgi:app
"""

import os

# Server socket
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8080")

# Worker processes
workers = int(os.environ.get("GUNICORN_WORKERS", "4"))
threads = int(os.environ.get("GUNICORN_THREADS", "2"))
worker_class = os.environ.get("GUNICORN_WORKER_CLASS", "gthread")

# Timeout settings
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "300"))
graceful_timeout = int(os.environ.get("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.environ.get("GUNICORN_KEEPALIVE", "5"))

# Worker lifecycle
max_requests = int(os.environ.get("GUNICORN_MAX_REQUESTS", "1000"))
max_requests_jitter = int(os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "50"))

# TLS Configuration
# Read from environment variables set for the application
tls_enabled = os.environ.get("TLS_ENABLED", "false").lower() == "true"
cert_file = os.environ.get("TLS_CERT_FILE", "")
key_file = os.environ.get("TLS_KEY_FILE", "")
ca_file = os.environ.get("TLS_CA_FILE", "")

if tls_enabled and cert_file and key_file:
    # Enable TLS
    certfile = cert_file
    keyfile = key_file

    # Update bind to TLS port if using default
    if bind == "0.0.0.0:8080":
        bind = "0.0.0.0:8443"

    # Optional: CA file for client certificate verification
    if ca_file:
        ca_certs = ca_file

# Logging
accesslog = os.environ.get("GUNICORN_ACCESS_LOG", "-")  # stdout
errorlog = os.environ.get("GUNICORN_ERROR_LOG", "-")  # stderr
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# Process naming
proc_name = "sbom-graph-api"

# Server mechanics
preload_app = False  # Don't preload to allow config changes per worker
