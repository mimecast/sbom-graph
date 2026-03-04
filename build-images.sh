#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ADV_TAG="${ADV_TAG:-sbom-graph-api:latest}"
RL_TAG="${RL_TAG:-sonatype-lifecycle-release-listener:latest}"
ENR_TAG="${ENR_TAG:-sbom-graph-enrichment:latest}"
NO_CACHE=""
TARGETS=()

usage() {
    cat <<'EOF'
Usage: build-images.sh [options] [targets...]

Build Docker images for the sbom-graph project. Must be run from the
repository root because Dockerfiles reference sibling project directories.

Targets:
  all                  Build everything (default)
  model                Build sbom-graph-model wheel only
  sbom-graph-api    Build sbom-graph-api Docker image
  sonatype-lifecycle-release-listener     Build sonatype-lifecycle-release-listener Docker image
  sbom-graph-enrichment                   Build sbom-graph-enrichment Docker image

Options:
  --adv-tag TAG    Tag for sbom-graph-api image (default: sbom-graph-api:latest)
  --rl-tag TAG     Tag for sonatype-lifecycle-release-listener image (default: sonatype-lifecycle-release-listener:latest)
  --enr-tag TAG    Tag for sbom-graph-enrichment image (default: sbom-graph-enrichment:latest)
  --no-cache       Disable Docker build cache
  -h, --help       Show this help

Examples:
  ./build-images.sh                          # Build everything
  ./build-images.sh sonatype-lifecycle-release-listener         # Build sonatype-lifecycle-release-listener only
  ./build-images.sh --adv-tag myrepo/adv:v2  # Custom image tag
  ./build-images.sh --no-cache all           # Full rebuild without cache

Environment variables:
  ADV_TAG    Override sbom-graph-api image tag
  RL_TAG     Override sonatype-lifecycle-release-listener image tag
  ENR_TAG    Override sbom-graph-enrichment image tag
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --adv-tag) ADV_TAG="$2"; shift 2 ;;
        --rl-tag)  RL_TAG="$2";  shift 2 ;;
        --enr-tag) ENR_TAG="$2"; shift 2 ;;
        --no-cache) NO_CACHE="--no-cache"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1"; usage; exit 1 ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(all)
fi

build_model() {
    echo "==> Building sbom-graph-model wheel..."
    (cd "$SCRIPT_DIR/sbom-graph-model" && uv build)
    echo "    Wheel built in sbom-graph-model/dist/"
}

build_sbom_graph_api() {
    echo "==> Building sbom-graph-api Docker image ($ADV_TAG)..."
    docker build \
        ${NO_CACHE:+"$NO_CACHE"} \
        -t "$ADV_TAG" \
        -f sbom-graph-api/Dockerfile \
        .
    echo "    Done: $ADV_TAG"
}

build_sonatype_lifecycle_release_listener() {
    if ! ls sbom-graph-model/dist/sbom_graph_model-*.whl >/dev/null 2>&1; then
        echo "    sbom-graph-model wheel not found, building it first..."
        build_model
    fi

    echo "==> Building sonatype-lifecycle-release-listener Docker image ($RL_TAG)..."
    docker build \
        ${NO_CACHE:+"$NO_CACHE"} \
        -t "$RL_TAG" \
        -f sonatype-lifecycle-release-listener/Dockerfile \
        .
    echo "    Done: $RL_TAG"
}

build_sbom_graph_enrichment() {
    if ! ls sbom-graph-model/dist/sbom_graph_model-*.whl >/dev/null 2>&1; then
        echo "    sbom-graph-model wheel not found, building it first..."
        build_model
    fi

    echo "==> Building sbom-graph-enrichment Docker image ($ENR_TAG)..."
    docker build \
        ${NO_CACHE:+"$NO_CACHE"} \
        -t "$ENR_TAG" \
        -f sbom-graph-enrichment/Dockerfile \
        .
    echo "    Done: $ENR_TAG"
}

for target in "${TARGETS[@]}"; do
    case "$target" in
        all)
            build_model
            build_sbom_graph_api
            build_sonatype_lifecycle_release_listener
            build_sbom_graph_enrichment
            ;;
        model)
            build_model
            ;;
        sbom-graph-api)
            build_sbom_graph_api
            ;;
        sonatype-lifecycle-release-listener)
            build_sonatype_lifecycle_release_listener
            ;;
        sbom-graph-enrichment)
            build_sbom_graph_enrichment
            ;;
        *)
            echo "Unknown target: $target"
            usage
            exit 1
            ;;
    esac
done

echo ""
echo "Build complete."
