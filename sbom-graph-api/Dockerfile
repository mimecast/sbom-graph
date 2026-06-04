# Multi-stage Dockerfile for AppSec Data Views
# Builds a production container using python:3.14-slim (matches builder for C extension compatibility)

# ============================================================================
# Stage 1: Builder - Install dependencies and build the application
# ============================================================================
FROM python:3.14-slim AS builder

# Base image may default to non-root; builder must create paths and run uv as root.
USER root

# Set working directory
WORKDIR /app

RUN mkdir -p /app/dependencies

COPY ./dist/*.whl ./deps/
COPY ./scripts/ ./scripts/
COPY ./gunicorn.conf.py ./

ARG PYTHON_PACKAGE_VERSION
RUN test -n "${PYTHON_PACKAGE_VERSION}" \
  || (echo "PYTHON_PACKAGE_VERSION build-arg is required (e.g. from pyproject.toml)" >&2 && exit 1)

RUN export REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"

# RUN uv pip install --target=/app/dependencies --native-tls --no-cache --no-sources "sbom-graph-api==${PYTHON_PACKAGE_VERSION}"
RUN uv pip install --target=/app/dependencies --native-tls --no-cache --no-sources ./deps/*.whl "sbom-graph-api==${PYTHON_PACKAGE_VERSION}"

RUN mkdir -p /data /certs && chown -R nonroot:nonroot /app /data /certs


# Install build dependencies
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     gcc \
#     libffi-dev \
#     && rm -rf /var/lib/apt/lists/*

# Install uv for dependency management
# COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
# WORKDIR /app

# Copy dependency files first for better layer caching
# COPY ./sbom-graph-model/dist/*.whl ./deps/
# COPY ./sbom-graph-api/pyproject.toml ./sbom-graph-api/uv.lock ./sbom-graph-api/README.md ./
# Copy application source code
# COPY ./sbom-graph-api/src/ ./src/
# COPY ./sbom-graph-api/scripts/ ./scripts/
# COPY ./sbom-graph-api/gunicorn.conf.py ./
# COPY ./sbom-graph-api/entrypoint.sh ./
# RUN uv pip install --target=/app/dependencies --no-cache --no-sources ./deps/*.whl .


# ============================================================================
# Stage 2: Runtime - python:3.14-slim (matches builder for C extension ABI)
# ============================================================================
FROM gcr.io/distroless/python3-debian13:nonroot

COPY --from=builder /app/ /app/
COPY --from=builder /data/ /data/
COPY --from=builder /certs/ /certs/

# Set working directory
WORKDIR /app

# Set Python path to include our dependencies and source
ENV PYTHONPATH=/app/dependencies:scripts:.
ENV PYTHONUNBUFFERED=1

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
ENV AUTH_ENABLED="true"
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

# Run as nonroot (matches Kubernetes runAsUser: 65532)
USER daemon

# Health check
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Run with gunicorn
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
ENTRYPOINT ["python", "-m", "gunicorn", "-c", "/app/gunicorn.conf.py", "sbom_graph_api.wsgi:app"]

# FROM python:3.14-slim

# Create nonroot user (UID 65532 matches Kubernetes runAsUser)
# RUN groupadd --gid 65532 nonroot \
#     && useradd --uid 65532 --gid nonroot --shell /usr/sbin/nologin --no-create-home nonroot

# Set working directory
# WORKDIR /app

# Copy installed dependencies from builder
# COPY --from=builder /app/dependencies /app/dependencies

# Copy application source (needed for imports)
# COPY --from=builder /app/src /app/src

# Copy gunicorn configuration file
# COPY --from=builder /app/gunicorn.conf.py /app/gunicorn.conf.py

# Copy scripts (populate_acme_corp for init-data job)
# COPY --from=builder /app/scripts /app/scripts

# Copy and set up entrypoint (logs startup for debugging empty logs)
# COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh
# RUN chmod +x /app/entrypoint.sh

# Create volume directories and set ownership
# RUN mkdir -p /data /certs && chown -R nonroot:nonroot /app /data /certs

# Set Python path to include our dependencies and source
# ENV PYTHONPATH=/app/dependencies:/app/src