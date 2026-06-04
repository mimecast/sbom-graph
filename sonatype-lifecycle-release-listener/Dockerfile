# Multi-stage Dockerfile for Distroless sonatype-lifecycle-release-listener

# ============================================================================
# Stage 1: Builder - Install dependencies
# ============================================================================
FROM python:3.14-slim AS builder

# Base image may default to non-root; builder must create paths and run uv as root.
USER root

# Set working directory
WORKDIR /app

RUN mkdir -p /app/dependencies

COPY ./dist/*.whl ./deps/
# Wheel version must match published package (CI passes from pyproject [project].version).
ARG PYTHON_PACKAGE_VERSION
RUN test -n "${PYTHON_PACKAGE_VERSION}" \
  || (echo "PYTHON_PACKAGE_VERSION build-arg is required (e.g. from pyproject.toml)" >&2 && exit 1)

# Install wheel + project deps, skipping [tool.uv.sources] (path doesn't exist in container)
# RUN uv pip install --target=/app/dependencies --native-tls --no-cache --no-sources "sonatype-lifecycle-release-listener==${PYTHON_PACKAGE_VERSION}"
RUN uv pip install --target=/app/dependencies --native-tls --no-cache --no-sources ./deps/*.whl "sonatype-lifecycle-release-listener==${PYTHON_PACKAGE_VERSION}"

# Copy application source code
COPY ./logging.conf ./gunicorn.conf.py ./



# Install build dependencies
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     gcc \
#     libffi-dev \
#     && rm -rf /var/lib/apt/lists/*

# Set working directory
# WORKDIR /app

# Install uv
# COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy local wheel and project metadata
# COPY ./sbom-graph-model/dist/*.whl ./deps/
# COPY ./sonatype-lifecycle-release-listener/pyproject.toml ./sonatype-lifecycle-release-listener/uv.lock ./sonatype-lifecycle-release-listener/README.md ./

# Install wheel + project deps, skipping [tool.uv.sources] (path doesn't exist in container)
# RUN uv pip install --target=/app/dependencies --no-cache --no-sources ./deps/*.whl .

# Copy application source code
# COPY ./sonatype-lifecycle-release-listener/src/ ./src/
# COPY ./sonatype-lifecycle-release-listener/logging.conf ./sonatype-lifecycle-release-listener/gunicorn.conf.py ./


# ============================================================================
# Stage 2: Runtime - Distroless Python image
# ============================================================================
FROM gcr.io/distroless/python3-debian13:nonroot

# Set working directory
WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /app/dependencies /app/dependencies

# Copy application code
COPY --from=builder /app/logging.conf /app/logging.conf
COPY --from=builder /app/gunicorn.conf.py /app/gunicorn.conf.py

# Set Python path to include our dependencies and source
ENV PYTHONPATH=/app/dependencies:/app/src
ENV PYTHONUNBUFFERED=1

# Expose the port gunicorn listens on
EXPOSE 8000

USER daemon

# Run with gunicorn
# Note: distroless doesn't have shell, so we use the exec form
ENTRYPOINT ["/usr/bin/python3", "-m", "gunicorn", "-c", "/app/gunicorn.conf.py", "sonatype_lifecycle_release_listener.app:app"]





