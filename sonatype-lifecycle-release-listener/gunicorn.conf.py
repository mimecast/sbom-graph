"""Gunicorn configuration file."""

import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 2

# Process naming
proc_name = "sonatype_lifecycle_release_listener"

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (configure these if needed)
# keyfile = None
# certfile = None
