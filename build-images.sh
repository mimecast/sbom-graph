#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Read [project].version from subproject/pyproject.toml (same literal as CI / pip).
read_python_package_version() {
    local pyproject="$1/pyproject.toml"
    if [[ ! -f "${pyproject}" ]]; then
        echo "error: missing ${pyproject}" >&2
        return 1
    fi
    python3 - "$pyproject" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
if not m:
    m = re.search(r"^version\s*=\s*'([^']+)'", text, re.MULTILINE)
if not m:
    sys.exit("Could not parse project.version from pyproject.toml")
print(m.group(1).strip())
PY
}

# OCI-safe image tag suffix (same as .github/workflows/build-subproject.yml: + -> -).
docker_safe_version() {
    local raw="$1"
    echo "${raw//+/-}"
}

# When unset, each build_* applies: <image>:<safe-pyproject-version> and :latest.
ADV_TAG="${ADV_TAG:-}"
RL_TAG="${RL_TAG:-}"
ENR_TAG="${ENR_TAG:-}"
NO_CACHE=""
# Comma-separated OCI platforms (default: single arch for local --load; use --multi-arch for amd64+arm64).
DOCKER_BUILD_PLATFORMS="${DOCKER_BUILD_PLATFORMS:-linux/amd64}"
# Optional dedicated builder for multi-arch (docker-container driver + QEMU).
DOCKER_BUILDX_BUILDER="${DOCKER_BUILDX_BUILDER:-sbom-graph-buildx}"
# Set to 1 or pass --push to push during buildx (required for multi-arch manifest lists).
DOCKER_BUILD_PUSH="${DOCKER_BUILD_PUSH:-}"
PUSH=""
# Container CLI: leave DOCKER unset for auto (prefer docker with buildx, else podman).
DOCKER="${DOCKER:-}"
# auto | 1 | 0 — use `docker buildx build`; auto enables buildx only if `${DOCKER} buildx version` works.
DOCKER_BUILD_USE_BUILDX="${DOCKER_BUILD_USE_BUILDX:-auto}"
# Plain docker/podman build: empty = auto (omit --platform when docker is a podman shim),
# 0 = always pass --platform, 1 = never pass --platform.
DOCKER_BUILD_SKIP_PLATFORM="${DOCKER_BUILD_SKIP_PLATFORM:-}"
TARGETS=()

usage() {
    cat <<'EOF'
Usage: build-images.sh [options] [targets...]

Build Docker images for the sbom-graph project. The script resolves paths from
its location; each image is built with that subproject directory as the Docker
context (same as CI: working-directory + Dockerfile in the subproject).

Targets:
  all                  Build everything (default)
  model                Build sbom-graph-model wheel only
  sbom-graph-api    Build sbom-graph-api Docker image
  sonatype-lifecycle-release-listener     Build sonatype-lifecycle-release-listener Docker image
  sbom-graph-enrichment                   Build sbom-graph-enrichment Docker image

Options:
  --adv-tag TAG    Full tag for sbom-graph-api (default: sbom-graph-api:<safe-version> and :latest)
  --rl-tag TAG     Full tag for release-listener (default: sonatype-lifecycle-release-listener:<safe-version> and :latest)
  --enr-tag TAG    Full tag for sbom-graph-enrichment (default: sbom-graph-enrichment:<safe-version> and :latest)
  --no-cache       Disable Docker build cache
  --platform PLAT  Single-arch target (e.g. linux/arm64, linux/amd64). Sets DOCKER_BUILD_PLATFORMS
                   for one platform. Use this to target a non-host arch when buildx --load is required
                   (local Docker/Podman cannot load multi-arch manifest lists).
  --multi-arch     Build linux/amd64 and linux/arm64 (manifest list; requires --push or DOCKER_BUILD_PUSH=1)
  --push           Push tags during docker buildx build (registry must allow push; docker login first)
  -h, --help       Show this help

  "Safe" version = pyproject [project].version with '+' replaced by '-' for OCI.
  PYTHON_PACKAGE_VERSION (--build-arg) always uses the raw pyproject version (PEP 440).

  Prefer Docker Buildx when available (${DOCKER} buildx build). If buildx is missing or
  DOCKER_BUILD_USE_BUILDX=0, falls back to ${DOCKER} build (Podman / docker compat).
  Plain builds never use --load (not supported); multi-arch still requires buildx + --push.

  Podman docker shim: auto-skips --platform on plain builds; override with
  DOCKER_BUILD_SKIP_PLATFORM=0. Force plain build: DOCKER_BUILD_USE_BUILDX=0

Examples:
  ./build-images.sh                          # Build everything (host arch / linux/amd64 default)
  ./build-images.sh sonatype-lifecycle-release-listener         # Build release-listener only
  ./build-images.sh --adv-tag myrepo/adv:v2  # Custom image tag (single -t)
  ./build-images.sh --no-cache all           # Full rebuild without cache
  ./build-images.sh --platform linux/arm64 sbom-graph-api       # Build single arch for arm64 (loadable)
  ./build-images.sh --multi-arch --push --adv-tag registry.example/sbom-graph-api:v1 sbom-graph-api

Environment variables:
  ADV_TAG    Override sbom-graph-api image tag (empty = auto from pyproject)
  RL_TAG     Override sonatype-lifecycle-release-listener image tag (empty = auto)
  ENR_TAG    Override sbom-graph-enrichment image tag (empty = auto)
  DOCKER_BUILD_PLATFORMS  Comma-separated platforms (default: linux/amd64). Example: linux/amd64,linux/arm64
  DOCKER_BUILD_PUSH       Set to 1 to push during build (same as --push)
  DOCKER_BUILDX_BUILDER   buildx builder name for multi-arch (default: sbom-graph-buildx)
  DOCKER                  Container CLI (unset = auto: docker with buildx, else podman)
  DOCKER_BUILD_USE_BUILDX auto (default), 1 = force buildx, 0 = plain docker/podman build
  DOCKER_BUILD_SKIP_PLATFORM  empty=auto, 0=always set --platform, 1=omit (plain builds only)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --adv-tag) ADV_TAG="$2"; shift 2 ;;
        --rl-tag)  RL_TAG="$2";  shift 2 ;;
        --enr-tag) ENR_TAG="$2"; shift 2 ;;
        --no-cache) NO_CACHE="--no-cache"; shift ;;
        --platform)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                echo "error: --platform requires a value (e.g. linux/arm64)" >&2
                exit 1
            fi
            if [[ "$2" == *","* ]]; then
                echo "error: --platform takes a single platform; use --multi-arch for amd64+arm64." >&2
                exit 1
            fi
            DOCKER_BUILD_PLATFORMS="$2"
            shift 2
            ;;
        --multi-arch) DOCKER_BUILD_PLATFORMS="linux/amd64,linux/arm64"; shift ;;
        --push) PUSH="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1"; usage; exit 1 ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(all)
fi

_pick_container_engine() {
    if [[ -n "${DOCKER:-}" ]]; then
        echo "${DOCKER}"
        return
    fi
    if docker buildx version >/dev/null 2>&1; then
        echo docker
        return
    fi
    if podman buildx version >/dev/null 2>&1; then
        echo podman
        return
    fi
    if command -v docker >/dev/null 2>&1; then
        echo docker
        return
    fi
    if command -v podman >/dev/null 2>&1; then
        echo podman
        return
    fi
    echo "error: install Docker or Podman (buildx recommended for multi-arch)." >&2
    exit 1
}

if [[ -z "${DOCKER:-}" ]]; then
    DOCKER="$(_pick_container_engine)"
    echo "==> Container CLI: ${DOCKER}" >&2
fi

_will_push() {
    [[ "${PUSH:-}" == "1" ]] || [[ "${DOCKER_BUILD_PUSH:-}" == "1" ]]
}

_count_platforms() {
    local IFS=','
    local -a _p
    read -ra _p <<< "${DOCKER_BUILD_PLATFORMS// /}"
    echo "${#_p[@]}"
}

_buildx_available() {
    "${DOCKER}" buildx version >/dev/null 2>&1
}

_use_buildx() {
    case "${DOCKER_BUILD_USE_BUILDX:-auto}" in
        1 | true | yes | YES)
            return 0
            ;;
        0 | false | no | NO)
            return 1
            ;;
        auto)
            if _buildx_available; then
                return 0
            fi
            return 1
            ;;
        *)
            echo "warning: invalid DOCKER_BUILD_USE_BUILDX=${DOCKER_BUILD_USE_BUILDX}; using auto" >&2
            if _buildx_available; then
                return 0
            fi
            return 1
            ;;
    esac
}

_docker_is_podman_compat() {
    local exe
    exe="$(command -v "${DOCKER}" 2>/dev/null)" || return 1
    case "$(basename "$exe")" in
        podman) return 0 ;;
    esac
    if [[ -L "$exe" ]]; then
        local t
        t="$(readlink "$exe")"
        case "$t" in
            *podman*) return 0 ;;
        esac
    fi
    return 1
}

# Returns 0 if plain build should include --platform.
_should_emit_platform_plain() {
    case "${DOCKER_BUILD_SKIP_PLATFORM}" in
        1 | true | yes | YES)
            return 1
            ;;
        0 | false | no | NO)
            return 0
            ;;
        "")
            if _docker_is_podman_compat; then
                return 1
            fi
            return 0
            ;;
        *)
            echo "warning: invalid DOCKER_BUILD_SKIP_PLATFORM=${DOCKER_BUILD_SKIP_PLATFORM}; emitting --platform" >&2
            return 0
            ;;
    esac
}

_ensure_buildx_builder() {
    local name="$1"
    if "${DOCKER}" buildx inspect "$name" >/dev/null 2>&1; then
        return 0
    fi
    echo "==> Creating buildx builder '${name}' (multi-arch)..."
    "${DOCKER}" buildx create --name "$name" --driver docker-container --bootstrap
}

# Run docker buildx build (or plain docker/podman build) for Python images.
docker_build_python_image() {
    local context_dir="$1"
    local dockerfile_name="$2"
    local pkg_version="$3"
    shift 3
    local -a tags=( "$@" )

    local nplat
    nplat="$(_count_platforms)"
    local multi=0
    [[ "$nplat" -gt 1 ]] && multi=1

    local use_buildx=0
    if _use_buildx; then
        use_buildx=1
    fi

    if [[ "$multi" -eq 1 ]] && [[ "$use_buildx" -eq 0 ]]; then
        echo "error: Multi-arch (${DOCKER_BUILD_PLATFORMS}) needs Docker Buildx." >&2
        echo "  Install/configure buildx, or use a single platform (DOCKER_BUILD_PLATFORMS=linux/amd64)." >&2
        exit 1
    fi

    if [[ "$multi" -eq 1 ]] && ! _will_push; then
        echo "error: Multi-arch build (${DOCKER_BUILD_PLATFORMS}) creates a manifest list and cannot be loaded into the local Docker daemon." >&2
        echo "  Pass --push (and log in to your registry), or set DOCKER_BUILD_PUSH=1." >&2
        echo "  For a single-arch local image: DOCKER_BUILD_PLATFORMS=linux/amd64 ./build-images.sh ..." >&2
        exit 1
    fi

    local -a cmd=()

    if [[ "$use_buildx" -eq 1 ]]; then
        cmd+=( "${DOCKER}" buildx build --platform "${DOCKER_BUILD_PLATFORMS}" )
        if [[ "$multi" -eq 1 ]]; then
            _ensure_buildx_builder "${DOCKER_BUILDX_BUILDER}"
            cmd+=( --builder "${DOCKER_BUILDX_BUILDER}" )
        fi
    else
        cmd+=( "${DOCKER}" build )
        # Plain docker/podman build: single-platform only; omit --platform for podman-docker shims unless forced.
        if [[ "$nplat" -eq 1 ]] && _should_emit_platform_plain; then
            cmd+=( --platform "${DOCKER_BUILD_PLATFORMS}" )
        fi
    fi

    if [[ -n "${NO_CACHE}" ]]; then
        cmd+=( --no-cache )
    fi
    cmd+=( --build-arg "PYTHON_PACKAGE_VERSION=${pkg_version}" )
    local t
    for t in "${tags[@]}"; do
        cmd+=( -t "$t" )
    done
    cmd+=( -f "${context_dir}/${dockerfile_name}" )

    if _will_push; then
        cmd+=( --push )
        if [[ "$use_buildx" -eq 0 ]]; then
            local bin
            bin="$(basename "$(command -v "${DOCKER}")")"
            if [[ "${bin}" != podman ]]; then
                export DOCKER_BUILDKIT=1
            fi
        fi
    elif [[ "$use_buildx" -eq 1 ]]; then
        cmd+=( --load )
    fi

    cmd+=( "${context_dir}" )
    "${cmd[@]}"
}

build_model() {
    echo "==> Building sbom-graph-model wheel..."
    (cd "$SCRIPT_DIR/sbom-graph-model" && uv build)
    echo "    Wheel built in sbom-graph-model/dist/"
}

build_sbom_graph_api() {
    _pkg_version="$(read_python_package_version "${SCRIPT_DIR}/sbom-graph-api")"
    _safe="$(docker_safe_version "${_pkg_version}")"
    if [[ -n "${ADV_TAG}" ]]; then
        echo "==> Building sbom-graph-api Docker image (${ADV_TAG})..."
        docker_build_python_image "${SCRIPT_DIR}/sbom-graph-api" "Dockerfile" "${_pkg_version}" "${ADV_TAG}"
    else
        echo "==> Building sbom-graph-api Docker image (sbom-graph-api:${_safe}, sbom-graph-api:latest)..."
        docker_build_python_image "${SCRIPT_DIR}/sbom-graph-api" "Dockerfile" "${_pkg_version}" \
            "sbom-graph-api:${_safe}" "sbom-graph-api:latest"
    fi
    echo "    Done."
}

build_sonatype_lifecycle_release_listener() {
    if ! ls sbom-graph-model/dist/sbom_graph_model-*.whl >/dev/null 2>&1; then
        echo "    sbom-graph-model wheel not found, building it first..."
        build_model
    fi

    _pkg_version="$(read_python_package_version "${SCRIPT_DIR}/sonatype-lifecycle-release-listener")"
    _safe="$(docker_safe_version "${_pkg_version}")"
    if [[ -n "${RL_TAG}" ]]; then
        echo "==> Building sonatype-lifecycle-release-listener Docker image (${RL_TAG})..."
        docker_build_python_image \
            "${SCRIPT_DIR}/sonatype-lifecycle-release-listener" \
            "Dockerfile" \
            "${_pkg_version}" \
            "${RL_TAG}"
    else
        echo "==> Building sonatype-lifecycle-release-listener Docker image (sonatype-lifecycle-release-listener:${_safe}, :latest)..."
        docker_build_python_image \
            "${SCRIPT_DIR}/sonatype-lifecycle-release-listener" \
            "Dockerfile" \
            "${_pkg_version}" \
            "sonatype-lifecycle-release-listener:${_safe}" \
            "sonatype-lifecycle-release-listener:latest"
    fi
    echo "    Done."
}

build_sbom_graph_enrichment() {
    if ! ls sbom-graph-model/dist/sbom_graph_model-*.whl >/dev/null 2>&1; then
        echo "    sbom-graph-model wheel not found, building it first..."
        build_model
    fi

    _pkg_version="$(read_python_package_version "${SCRIPT_DIR}/sbom-graph-enrichment")"
    _safe="$(docker_safe_version "${_pkg_version}")"
    if [[ -n "${ENR_TAG}" ]]; then
        echo "==> Building sbom-graph-enrichment Docker image (${ENR_TAG})..."
        docker_build_python_image \
            "${SCRIPT_DIR}/sbom-graph-enrichment" \
            "Dockerfile" \
            "${_pkg_version}" \
            "${ENR_TAG}"
    else
        echo "==> Building sbom-graph-enrichment Docker image (sbom-graph-enrichment:${_safe}, sbom-graph-enrichment:latest)..."
        docker_build_python_image \
            "${SCRIPT_DIR}/sbom-graph-enrichment" \
            "Dockerfile" \
            "${_pkg_version}" \
            "sbom-graph-enrichment:${_safe}" \
            "sbom-graph-enrichment:latest"
    fi
    echo "    Done."
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
