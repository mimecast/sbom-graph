#!/bin/sh
# Startup wrapper: ensures at least one log line for debugging empty logs
echo "[sbom-graph-api] Starting..." >&2
exec /usr/local/bin/python3 -m gunicorn -c /app/gunicorn.conf.py sbom_graph_api.wsgi:app
