#!/usr/bin/env bash
# release.sh — Build, tag, optionally push Docker images and update Helm values.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REGISTRY="${REGISTRY:-}"
PUSH=false
FORCE_BUILD=false
LOAD_MINIKUBE=false
DRY_RUN=false

usage() {
    cat <<'EOF'
Usage: release.sh [options]

Read sub-project versions from pyproject.toml files, build Docker images for
any that have changed, and update the Helm chart values.

Options:
  --registry REGISTRY   Docker registry prefix (e.g. ghcr.io/org).
                        Also accepted via REGISTRY env var.
  --push                Push built images to the remote registry.
  --force-build         Rebuild all images from scratch (--no-cache),
                        overwriting any existing local tags.
  --load-minikube       Load built images into minikube's container runtime.
                        Overwrites previously loaded images at the same tag.
  --dry-run             Print what would happen without executing.
  -h, --help            Show this help.

Examples:
  ./release.sh                                    # Build changed, local only
  ./release.sh --force-build                      # Full clean rebuild
  ./release.sh --registry ghcr.io/org --push      # Build & push to registry
  ./release.sh --force-build --load-minikube      # Rebuild all + load minikube
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)      REGISTRY="$2"; shift 2 ;;
        --push)          PUSH=true; shift ;;
        --force-build)   FORCE_BUILD=true; shift ;;
        --load-minikube) LOAD_MINIKUBE=true; shift ;;
        --dry-run)       DRY_RUN=true; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Read versions
# ---------------------------------------------------------------------------
read_version() {
    grep '^version' "$1" | sed 's/.*"\(.*\)"/\1/'
}

API_VER=$(read_version sbom-graph-api/pyproject.toml)
ENR_VER=$(read_version sbom-graph-enrichment/pyproject.toml)
LIS_VER=$(read_version sonatype-lifecycle-release-listener/pyproject.toml)

echo "==> Detected versions"
echo "    sbom-graph-api                          : $API_VER"
echo "    sbom-graph-enrichment                   : $ENR_VER"
echo "    sonatype-lifecycle-release-listener      : $LIS_VER"
echo ""

# ---------------------------------------------------------------------------
# Construct full image references
# ---------------------------------------------------------------------------
prefix=""
if [[ -n "$REGISTRY" ]]; then
    prefix="${REGISTRY%/}/"
fi

API_REF="${prefix}sbom-graph-api:${API_VER}"
ENR_REF="${prefix}sbom-graph-enrichment:${ENR_VER}"
LIS_REF="${prefix}sonatype-lifecycle-release-listener:${LIS_VER}"

# Track which images were actually built
declare -a BUILT_IMAGES=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
image_exists_locally() {
    docker image inspect "$1" >/dev/null 2>&1
}

run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight: minikube check
# ---------------------------------------------------------------------------
if $LOAD_MINIKUBE; then
    if ! command -v minikube >/dev/null 2>&1; then
        echo "ERROR: minikube is not installed." >&2
        exit 1
    fi
    if ! minikube status --format='{{.Host}}' 2>/dev/null | grep -q Running; then
        echo "ERROR: minikube is not running. Start it with 'minikube start'." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Build model wheel (all images depend on it)
# ---------------------------------------------------------------------------
needs_build=false
if $FORCE_BUILD; then
    needs_build=true
else
    for ref in "$API_REF" "$ENR_REF" "$LIS_REF"; do
        if ! image_exists_locally "$ref"; then
            needs_build=true
            break
        fi
    done
fi

if $needs_build; then
    echo "==> Building sbom-graph-model wheel..."
    run bash -c 'cd sbom-graph-model && uv build'
fi

# ---------------------------------------------------------------------------
# Determine build args
# ---------------------------------------------------------------------------
BUILD_EXTRA_ARGS=()
if $FORCE_BUILD; then
    BUILD_EXTRA_ARGS+=(--no-cache)
fi

# ---------------------------------------------------------------------------
# Build each image
# ---------------------------------------------------------------------------
build_if_needed() {
    local ref="$1"
    local target="$2"

    if $FORCE_BUILD; then
        echo "==> Force-building $ref ..."
        run ./build-images.sh "${BUILD_EXTRA_ARGS[@]}" --adv-tag "$API_REF" --rl-tag "$LIS_REF" --enr-tag "$ENR_REF" "$target"
        BUILT_IMAGES+=("$ref")
    elif image_exists_locally "$ref"; then
        echo "==> SKIP $ref (already exists locally)"
    else
        echo "==> Building $ref ..."
        run ./build-images.sh --adv-tag "$API_REF" --rl-tag "$LIS_REF" --enr-tag "$ENR_REF" "$target"
        BUILT_IMAGES+=("$ref")
    fi
}

build_if_needed "$API_REF" "sbom-graph-api"
build_if_needed "$LIS_REF" "sonatype-lifecycle-release-listener"
build_if_needed "$ENR_REF" "sbom-graph-enrichment"

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------
if $PUSH; then
    echo ""
    echo "==> Pushing images to registry..."
    for ref in "${BUILT_IMAGES[@]}"; do
        echo "    docker push $ref"
        run docker push "$ref"
    done
    if [[ ${#BUILT_IMAGES[@]} -eq 0 ]]; then
        echo "    Nothing to push (no images were built)."
    fi
fi

# ---------------------------------------------------------------------------
# Load into minikube
# ---------------------------------------------------------------------------
if $LOAD_MINIKUBE; then
    echo ""
    echo "==> Loading images into minikube..."
    for ref in "$API_REF" "$ENR_REF" "$LIS_REF"; do
        if image_exists_locally "$ref"; then
            echo "    minikube image load $ref --overwrite"
            run minikube image load "$ref" --overwrite
        else
            echo "    SKIP $ref (not present locally)"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Update Helm values.yaml
# ---------------------------------------------------------------------------
echo ""
echo "==> Updating helm/sbom-graph/values.yaml..."

VALUES="helm/sbom-graph/values.yaml"

update_helm_value() {
    local path="$1"
    local value="$2"
    if $DRY_RUN; then
        echo "[dry-run] yq -i '$path = \"$value\"' $VALUES"
    else
        yq -i "$path = \"$value\"" "$VALUES"
    fi
}

if [[ -n "$prefix" ]]; then
    update_helm_value '.sbomGraphApi.image.repository' "${prefix}sbom-graph-api"
    update_helm_value '.enrichment.image.repository'   "${prefix}sbom-graph-enrichment"
    update_helm_value '.releaseListener.image.repository' "${prefix}sonatype-lifecycle-release-listener"
fi

update_helm_value '.sbomGraphApi.image.tag'    "$API_VER"
update_helm_value '.enrichment.image.tag'      "$ENR_VER"
update_helm_value '.releaseListener.image.tag' "$LIS_VER"

if $LOAD_MINIKUBE; then
    update_helm_value '.sbomGraphApi.image.pullPolicy'    'Never'
    update_helm_value '.enrichment.image.pullPolicy'      'Never'
    update_helm_value '.releaseListener.image.pullPolicy'  'Never'
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Release Summary ==="
echo "  sbom-graph-api                       : $API_REF"
echo "  sbom-graph-enrichment                : $ENR_REF"
echo "  sonatype-lifecycle-release-listener   : $LIS_REF"
echo "  Images built : ${#BUILT_IMAGES[@]}"
echo "  Pushed       : $PUSH"
echo "  Minikube     : $LOAD_MINIKUBE"
echo "  Helm updated : $VALUES"
if $DRY_RUN; then
    echo "  ** DRY RUN — no changes were made **"
fi
echo ""
