# Multi-stage Dockerfile for sbom-graph-enrichment Celery worker
# Runs certifier tasks against OSV, ClearlyDefined, etc.

# ============================================================================
# Stage 1: Builder - Install dependencies
# ============================================================================
FROM python:3.14-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY ./sbom-graph-model/dist/*.whl ./deps/
COPY ./sbom-graph-enrichment/pyproject.toml ./sbom-graph-enrichment/README.md ./

RUN uv pip install --target=/app/dependencies --no-cache --no-sources ./deps/*.whl .

COPY ./sbom-graph-enrichment/src/ ./src/

# ============================================================================
# Stage 2: Runtime - Distroless Python image
# ============================================================================
FROM gcr.io/distroless/python3-debian13:nonroot

WORKDIR /app

COPY --from=builder /app/dependencies /app/dependencies
COPY --from=builder /app/src /app/src

ENV PYTHONPATH=/app/dependencies:/app/src
ENV PYTHONUNBUFFERED=1

ENV FALKORDB_HOST="localhost"
ENV FALKORDB_PORT="6379"
ENV FALKORDB_GRAPH_NAME="acme-corp"
ENV FALKORDB_PASSWORD=""
ENV CELERY_BROKER_DB="1"
ENV CELERY_RESULT_DB="2"
ENV ENRICHMENT_INTERVAL="3600"
ENV INTERNAL_PREFIXES=""

USER 65532

ENTRYPOINT ["/usr/bin/python3", "-m", "celery"]
CMD ["-A", "sbom_graph_enrichment.celery_app", "worker", "--loglevel=info", "--concurrency=2", "-Q", "enrichment"]
# To run beat instead: override CMD with:
#   ["-A", "sbom_graph_enrichment.celery_app", "beat", "--loglevel=info"]
