#!/usr/bin/env bash
# release.sh — Build, tag, optionally push Docker images and update Helm values.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REGISTRY="${REGISTRY:-}"
PUSH=false
FORCE_BUILD=false
LOAD_MINIKUBE=false
# Replace an existing image in minikube when loading (minikube image load --overwrite).
MINIKUBE_IMAGE_OVERWRITE="${MINIKUBE_IMAGE_OVERWRITE:-1}"
# Empty = auto-select docker (prefer buildx) or podman — exported for build-images.sh.
DOCKER="${DOCKER:-}"
# Override single-arch platform for the LOCAL/minikube build (e.g. linux/arm64).
# Empty = build-images.sh default (linux/amd64). The registry/push build is always multi-arch.
LOCAL_PLATFORM="${LOCAL_PLATFORM:-}"
DRY_RUN=false

usage() {
    cat <<'EOF'
Usage: release.sh [options]

Read sub-project versions from pyproject.toml files, build container images for
any that have changed, and update the Helm chart values.

Uses Docker or Podman automatically (prefers docker when buildx works; otherwise
podman). Override by exporting DOCKER=podman or DOCKER=docker.

Options:
  --registry REGISTRY   Docker registry prefix (e.g. ghcr.io/org).
                        Also accepted via REGISTRY env var.
  --push                Push multi-arch images (linux/amd64 + linux/arm64) to the
                        registry during build (login first). With --minikube, runs a
                        second single-arch local build for loading into the cluster.
  --force-build         Rebuild all images from scratch (--no-cache).
  --load-minikube       Load images into minikube after building locally (single-arch).
                        Default: replace existing tags (--overwrite).
  --minikube            Same as --load-minikube (short).
  --overwrite-minikube  Replace images already in minikube (default).
  --no-overwrite-minikube
                        Load without --overwrite.
  --platform PLATFORM   Single-arch platform (e.g. linux/arm64, linux/amd64) for the LOCAL/minikube
                        build. Use this when your local container runtime (Podman/Docker on
                        Apple Silicon, minikube on a different arch, etc.) cannot load a
                        manifest list. The --push (multi-arch) build to the registry is unaffected.
  --dry-run             Print what would happen without executing.
  -h, --help            Show this help.

Examples:
  ./release.sh --registry ghcr.io/org --push
  ./release.sh --minikube
  ./release.sh --minikube --platform linux/arm64
  ./release.sh --registry ghcr.io/org --push --minikube --platform linux/arm64

Environment:
  MINIKUBE_IMAGE_OVERWRITE   1 (default) = minikube image load --overwrite
  LOCAL_PLATFORM             Same as --platform (single-arch for local/minikube build)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)      REGISTRY="$2"; shift 2 ;;
        --push)          PUSH=true; shift ;;
        --force-build)   FORCE_BUILD=true; shift ;;
        --load-minikube|--minikube) LOAD_MINIKUBE=true; shift ;;
        --overwrite-minikube)    MINIKUBE_IMAGE_OVERWRITE=1; shift ;;
        --no-overwrite-minikube) MINIKUBE_IMAGE_OVERWRITE=0; shift ;;
        --platform)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                echo "ERROR: --platform requires a value (e.g. linux/arm64)" >&2
                exit 1
            fi
            if [[ "$2" == *","* ]]; then
                echo "ERROR: --platform takes a single platform; multi-arch is implicit on --push." >&2
                exit 1
            fi
            LOCAL_PLATFORM="$2"
            shift 2
            ;;
        --dry-run)       DRY_RUN=true; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [[ -z "${DOCKER:-}" ]]; then
    if docker buildx version >/dev/null 2>&1; then
        DOCKER=docker
    elif podman buildx version >/dev/null 2>&1; then
        DOCKER=podman
    elif command -v docker >/dev/null 2>&1; then
        DOCKER=docker
    elif command -v podman >/dev/null 2>&1; then
        DOCKER=podman
    else
        echo "ERROR: install Docker or Podman." >&2
        exit 1
    fi
fi
export DOCKER
echo "==> Container CLI: ${DOCKER}"

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
    "${DOCKER}" image inspect "$1" >/dev/null 2>&1
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

# Normalise MINIKUBE_IMAGE_OVERWRITE (env may be set before invocation).
case "${MINIKUBE_IMAGE_OVERWRITE:-1}" in
    1|true|TRUE|yes|YES) MINIKUBE_IMAGE_OVERWRITE=1 ;;
    0|false|FALSE|no|NO) MINIKUBE_IMAGE_OVERWRITE=0 ;;
    *)
        echo "WARNING: invalid MINIKUBE_IMAGE_OVERWRITE=${MINIKUBE_IMAGE_OVERWRITE}; using 1 (overwrite)." >&2
        MINIKUBE_IMAGE_OVERWRITE=1
        ;;
esac

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
# Build args: registry pass (multi-arch push) vs local pass (single-arch, loadable)
# ---------------------------------------------------------------------------
REGISTRY_ARGS=( )
LOCAL_ARGS=( )
if $FORCE_BUILD; then
    REGISTRY_ARGS+=(--no-cache)
    LOCAL_ARGS+=(--no-cache)
fi

if [[ -n "${LOCAL_PLATFORM}" ]]; then
    LOCAL_ARGS+=(--platform "${LOCAL_PLATFORM}")
fi

IMAGES_PUSHED_WITH_BUILDX=false
if $PUSH; then
    REGISTRY_ARGS+=(--multi-arch --push)
    IMAGES_PUSHED_WITH_BUILDX=true
fi

# ---------------------------------------------------------------------------
# Build each image
# ---------------------------------------------------------------------------
_tag_flags=( --adv-tag "$API_REF" --rl-tag "$LIS_REF" --enr-tag "$ENR_REF" )

registry_build_if_needed() {
    local ref="$1"
    local target="$2"
    $PUSH || return 0

    if $FORCE_BUILD; then
        echo "==> [registry] Force-building $ref (multi-arch)..."
        run ./build-images.sh "${REGISTRY_ARGS[@]}" "${_tag_flags[@]}" "$target"
        BUILT_IMAGES+=("$ref")
    elif image_exists_locally "$ref"; then
        echo "==> [registry] SKIP $ref (already exists locally)"
    else
        echo "==> [registry] Building $ref (multi-arch push)..."
        run ./build-images.sh "${REGISTRY_ARGS[@]}" "${_tag_flags[@]}" "$target"
        BUILT_IMAGES+=("$ref")
    fi
}

local_build_if_needed() {
    local ref="$1"
    local target="$2"
    local force_local="${3:-false}"

    if $PUSH && ! $LOAD_MINIKUBE; then
        return 0
    fi

    if [[ "${force_local}" == "true" ]]; then
        echo "==> [local] Building $ref for minikube (single-arch)..."
        run ./build-images.sh "${LOCAL_ARGS[@]}" "${_tag_flags[@]}" "$target"
        return
    fi

    if $FORCE_BUILD; then
        echo "==> Force-building $ref ..."
        run ./build-images.sh "${LOCAL_ARGS[@]}" "${_tag_flags[@]}" "$target"
        BUILT_IMAGES+=("$ref")
    elif image_exists_locally "$ref"; then
        echo "==> SKIP $ref (already exists locally)"
    else
        echo "==> Building $ref ..."
        run ./build-images.sh "${LOCAL_ARGS[@]}" "${_tag_flags[@]}" "$target"
        BUILT_IMAGES+=("$ref")
    fi
}

registry_build_if_needed "$API_REF" "sbom-graph-api"
registry_build_if_needed "$LIS_REF" "sonatype-lifecycle-release-listener"
registry_build_if_needed "$ENR_REF" "sbom-graph-enrichment"

_fl="false"
if $PUSH && $LOAD_MINIKUBE; then
    _fl="true"
fi

local_build_if_needed "$API_REF" "sbom-graph-api" "$_fl"
local_build_if_needed "$LIS_REF" "sonatype-lifecycle-release-listener" "$_fl"
local_build_if_needed "$ENR_REF" "sbom-graph-enrichment" "$_fl"

# ---------------------------------------------------------------------------
# Push (only when images were not already pushed by buildx --push)
# ---------------------------------------------------------------------------
if $PUSH; then
    echo ""
    if $IMAGES_PUSHED_WITH_BUILDX; then
        echo "==> Registry push completed during multi-arch build (${DOCKER} buildx --push)."
        if [[ ${#BUILT_IMAGES[@]} -eq 0 ]]; then
            echo "    No builds ran (images skipped as already present locally)."
        fi
    else
        echo "==> Pushing images to registry..."
        for ref in "${BUILT_IMAGES[@]}"; do
            echo "    ${DOCKER} push $ref"
            run "${DOCKER}" push "$ref"
        done
        if [[ ${#BUILT_IMAGES[@]} -eq 0 ]]; then
            echo "    Nothing to push (no images were built)."
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Load into minikube
# ---------------------------------------------------------------------------
if $LOAD_MINIKUBE; then
    echo ""
    echo "==> Loading images into minikube..."
    if [[ "${MINIKUBE_IMAGE_OVERWRITE}" == "1" ]]; then
        echo "    (replacing existing tags: --overwrite)"
    else
        echo "    (not overwriting: omit --overwrite)"
    fi
    for ref in "$API_REF" "$ENR_REF" "$LIS_REF"; do
        if image_exists_locally "$ref"; then
            if [[ "${MINIKUBE_IMAGE_OVERWRITE}" == "1" ]]; then
                echo "    minikube image load $ref --overwrite"
                run minikube image load "$ref" --overwrite
            else
                echo "    minikube image load $ref"
                run minikube image load "$ref"
            fi
        else
            echo "    SKIP $ref (not present locally)"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Update Helm values.yaml
# ---------------------------------------------------------------------------
echo ""
echo "==> Updating helm/charts/sbom-graph/values.yaml..."

VALUES="helm/charts/sbom-graph/values.yaml"

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
echo "  CLI          : ${DOCKER}"
echo "  sbom-graph-api                       : $API_REF"
echo "  sbom-graph-enrichment                : $ENR_REF"
echo "  sonatype-lifecycle-release-listener   : $LIS_REF"
echo "  Images built : ${#BUILT_IMAGES[@]}"
if $PUSH && $IMAGES_PUSHED_WITH_BUILDX; then
    echo "  Pushed       : $PUSH (multi-arch during buildx)"
else
    echo "  Pushed       : $PUSH"
fi
if $LOAD_MINIKUBE; then
    echo "  Minikube     : $LOAD_MINIKUBE (overwrite=${MINIKUBE_IMAGE_OVERWRITE})"
else
    echo "  Minikube     : $LOAD_MINIKUBE"
fi
if [[ -n "${LOCAL_PLATFORM}" ]]; then
    echo "  Local arch   : ${LOCAL_PLATFORM} (override)"
else
    echo "  Local arch   : default (build-images.sh: linux/amd64)"
fi
echo "  Helm updated : $VALUES"
if $DRY_RUN; then
    echo "  ** DRY RUN — no changes were made **"
fi
echo ""
