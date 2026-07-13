# Multi-stage Dockerfile for sbom-graph-enrichment Celery worker
# Runs certifier tasks against OSV, ClearlyDefined, etc.

# ============================================================================
# Stage 1: Builder - Install dependencies
# ============================================================================
FROM python:3.14-slim AS builder

# Base image may default to non-root; builder must create paths and run uv as root.
USER root

WORKDIR /app

RUN mkdir -p /app/dependencies


COPY ./dist/*.whl ./deps/

ARG PYTHON_PACKAGE_VERSION
RUN test -n "${PYTHON_PACKAGE_VERSION}" \
  || (echo "PYTHON_PACKAGE_VERSION build-arg is required (e.g. from pyproject.toml)" >&2 && exit 1)

# RUN uv pip install --target=/app/dependencies --native-tls --no-cache --no-sources "sbom-graph-enrichment==${PYTHON_PACKAGE_VERSION}"
RUN uv pip install --target=/app/dependencies --native-tls --no-cache --no-sources ./deps/*.whl "sbom-graph-enrichment==${PYTHON_PACKAGE_VERSION}"

# ============================================================================
# Stage 2: Runtime - Distroless Python image
# ============================================================================
FROM gcr.io/distroless/python3-debian13:nonroot

WORKDIR /app

COPY --from=builder /app/dependencies /app/dependencies

ENV PYTHONPATH=/app/dependencies:.
ENV PYTHONUNBUFFERED=1

ENV FALKORDB_HOST="localhost"
ENV FALKORDB_PORT="6379"
ENV FALKORDB_GRAPH_NAME="acme-corp"
ENV FALKORDB_PASSWORD=""
ENV CELERY_BROKER_DB="1"
ENV CELERY_RESULT_DB="2"
ENV ENRICHMENT_INTERVAL="3600"
ENV INTERNAL_PREFIXES=""

USER daemon

ENTRYPOINT ["/usr/bin/python3", "-m", "celery"]
CMD ["-A", "sbom_graph_enrichment.celery_app", "worker", "--loglevel=info", "--concurrency=2", "-Q", "enrichment"]
# To run beat instead: override CMD with:
#   ["-A", "sbom_graph_enrichment.celery_app", "beat", "--loglevel=info"]
