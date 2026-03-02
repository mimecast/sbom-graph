# Multi-stage Dockerfile for AppSec Data Views
# Builds a minimal distroless container for production deployment

# ============================================================================
# Stage 1: Builder - Install dependencies and build the application
# ============================================================================
FROM python:3.14-slim AS builder

# Install uv for dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Copy dependency files first for better layer caching
COPY ./sbom-graph-api/pyproject.toml ./sbom-graph-api/uv.lock ./sbom-graph-api/README.md ./

RUN uv pip install --target=/app/dependencies --no-cache --no-sources .

# Copy application source code
COPY ./sbom-graph-api/src/ ./src/


# Install the application itself
RUN uv venv /app/.venv
RUN uv pip install --target=/app/dependencies --no-cache ./

# ============================================================================
# Stage 2: Runtime - Distroless Python image
# ============================================================================
FROM gcr.io/distroless/python3-debian13:nonroot

# Set working directory
WORKDIR /app
# RUN mkdir -p /app/.venv
# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application source (needed for imports)
COPY --from=builder /app/src /app/src

# Copy gunicorn configuration file
COPY ./sbom-graph-api/gunicorn.conf.py /app/gunicorn.conf.py

# Set Python path to include the virtual environment
ENV PYTHONPATH="/app/.venv/lib/python3.12/site-packages:/app/src"
ENV PATH="/app/.venv/bin:$PATH"

# Environment variables with defaults (can be overridden)
# Flask configuration
ENV FLASK_HOST="0.0.0.0"
ENV FLASK_PORT="8080"
ENV FLASK_DEBUG="false"
ENV FLASK_SECRET_KEY=""

# FalkorDB configuration
ENV FALKORDB_HOST="localhost"
ENV FALKORDB_PORT="6379"
ENV FALKORDB_GRAPH_NAME="acme_corp"
ENV FALKORDB_SOCKET_TIMEOUT="30.0"
ENV FALKORDB_CONNECT_TIMEOUT="10.0"

# TLS configuration
ENV TLS_ENABLED="false"
ENV TLS_CERT_FILE=""
ENV TLS_KEY_FILE=""
ENV TLS_CA_FILE=""

# Authentication configuration
ENV AUTH_ENABLED="false"
ENV JWT_SECRET_KEY=""
ENV JWT_ACCESS_TOKEN_EXPIRES_HOURS="1"
ENV JWT_REFRESH_TOKEN_EXPIRES_DAYS="30"

# LDAP configuration
ENV LDAP_ENABLED="false"
ENV LDAP_SERVER=""
ENV LDAP_PORT="389"
ENV LDAP_USE_SSL="false"
ENV LDAP_BASE_DN=""
ENV LDAP_USER_DN_TEMPLATE=""
ENV LDAP_SEARCH_FILTER="(uid={username})"

# Token storage configuration
ENV TOKEN_DB_PATH="/data/tokens.db"
ENV TOKEN_DB_ENCRYPTION_KEY=""

# Volume for persistent token storage
VOLUME ["/data"]

# Volume for TLS certificates (optional)
VOLUME ["/certs"]

# Expose the application port
EXPOSE 8080
EXPOSE 8443

# Set non-root user explicitly (distroless:nonroot already defaults to 65532)
# This is explicit for security scanners and documentation
USER 65532

# Health check
# Note: Distroless doesn't have curl/wget, so we rely on Kubernetes probes
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Run with gunicorn
# Using the Python interpreter from distroless
#
# Memory considerations for graph visualizations with FalkorDB:
# - Each worker needs ~100MB base (Python + Flask)
# - Large visualization requests can use 100-200MB (up to 50K nodes)
# - With 4 workers: peak ~1.2GB, recommended container limit: 2Gi
# - Adjust --workers based on available memory: ~300MB per worker for heavy loads
#
# Worker calculation: (Available Memory - 200MB overhead) / 300MB per worker
# Example: 2GB container = (2048 - 200) / 300 ≈ 6 workers max, use 4 for safety
#
# TLS is automatically enabled when TLS_ENABLED=true and cert/key files are set
# The gunicorn_config.py reads environment variables for TLS configuration
ENTRYPOINT ["python", "-m", "gunicorn"]
# Use gthread worker for better handling of concurrent requests
# -c: Use the gunicorn config file for TLS and other settings from environment
# The config file handles TLS, worker settings, and timeouts from environment variables
CMD ["-c", "/app/gunicorn.conf.py", "sbom_graph_api.wsgi:app"]
