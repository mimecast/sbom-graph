#!/usr/bin/env bash
# bump-version.sh — Set every sub-project's version, the Helm chart's own
# version/appVersion, and the three component Docker image tags to a single,
# identical version string in one pass.
#
# This is the missing "write" step ahead of sync-helm-tags.sh / release.sh,
# which both only *read* versions from pyproject.toml files and propagate
# them outward -- neither one bumps the version itself.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat <<'EOF'
Usage: scripts/bump-version.sh <version> [--dry-run]

Sets ALL of the following to the given version string, atomically:
  - version = "..." in every sub-project's pyproject.toml:
      sbom-graph-model, sbom-graph-api, sbom-graph-enrichment,
      sbom-graph-cli, sonatype-lifecycle-release-listener
  - helm/charts/sbom-graph/Chart.yaml: both `version:` and `appVersion:`
  - helm/charts/sbom-graph/values.yaml image tags:
      sbomGraphApi.image.tag, enrichment.image.tag, releaseListener.image.tag

Does NOT touch inter-package dependency constraints (e.g. the
"sbom-graph-model>=0.2.0-beta.4,<2.0.0" range inside other packages'
`dependencies = [...]` lists) -- that's a compatibility range, not this
package's own release version, and bumping it automatically could silently
exclude older-but-compatible wheels.

<version> must be a valid SemVer 2 core version (X.Y.Z), optionally with a
-prerelease and/or +build suffix (e.g. 1.4.0, 1.4.0-rc.1, 2.0.0+build.5) --
Helm's Chart.yaml `version` field requires this shape, so every location is
held to the same rule for consistency. Note this is SemVer's dash-prerelease
form (1.2.0-a1), not PEP 440's compact form (1.2.0a1); pyproject.toml accepts
either as a bare string, but stick to one form across the repo.

Options:
  --dry-run   Print what would change without writing any files.
  -h, --help  Show this help.

Examples:
  scripts/bump-version.sh 1.2.0
  scripts/bump-version.sh 1.2.0-rc.1 --dry-run
EOF
}

DRY_RUN=false
VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage; exit 0 ;;
        -*)
            echo "ERROR: unknown option: $1" >&2
            usage
            exit 1
            ;;
        *)
            if [[ -n "$VERSION" ]]; then
                echo "ERROR: unexpected extra argument: $1" >&2
                usage
                exit 1
            fi
            VERSION="$1"
            shift
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "ERROR: version argument is required." >&2
    usage
    exit 1
fi

# SemVer 2 core + optional prerelease/build metadata (same shape Helm's
# Chart.yaml `version` field requires).
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
if [[ ! "$VERSION" =~ $SEMVER_RE ]]; then
    echo "ERROR: '$VERSION' is not a valid SemVer version (expected X.Y.Z[-prerelease][+build])." >&2
    exit 1
fi

if ! command -v yq >/dev/null 2>&1; then
    echo "ERROR: yq is required (https://github.com/mikefarah/yq)." >&2
    exit 1
fi

PYPROJECTS=(
    sbom-graph-model/pyproject.toml
    sbom-graph-api/pyproject.toml
    sbom-graph-enrichment/pyproject.toml
    sbom-graph-cli/pyproject.toml
    sonatype-lifecycle-release-listener/pyproject.toml
)
CHART="helm/charts/sbom-graph/Chart.yaml"
VALUES="helm/charts/sbom-graph/values.yaml"

for f in "${PYPROJECTS[@]}" "$CHART" "$VALUES"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: $f not found (run this script from the repo root, or check paths above)." >&2
        exit 1
    fi
done

echo "==> Bumping every version to: $VERSION"
$DRY_RUN && echo "    (dry run — no files will be modified)"
echo ""

set_pyproject_version() {
    local file="$1"
    # Only the line starting exactly with `version = "..."` -- in this repo
    # that's the single [project].version line; dependency constraints like
    # "sbom-graph-model>=..." live inside dependencies = [...] arrays and
    # never start a line with `version`, so this is unambiguous.
    if $DRY_RUN; then
        echo "[dry-run] $file: version = \"$VERSION\""
    else
        sed -i.bak -E "s/^version = \".*\"/version = \"$VERSION\"/" "$file"
        rm -f "${file}.bak"
    fi
}

echo "==> pyproject.toml files"
for f in "${PYPROJECTS[@]}"; do
    echo "    $f"
    set_pyproject_version "$f"
done

echo ""
echo "==> $CHART"
if $DRY_RUN; then
    echo "[dry-run] yq -i '.version = \"$VERSION\" | .appVersion = \"$VERSION\"' $CHART"
else
    yq -i ".version = \"$VERSION\" | .appVersion = \"$VERSION\"" "$CHART"
fi

echo ""
echo "==> $VALUES image tags"
for path in '.sbomGraphApi.image.tag' '.enrichment.image.tag' '.releaseListener.image.tag'; do
    if $DRY_RUN; then
        echo "[dry-run] yq -i '$path = \"$VERSION\"' $VALUES"
    else
        yq -i "$path = \"$VERSION\"" "$VALUES"
    fi
done

echo ""
echo "=== Summary ==="
echo "  Version set    : $VERSION"
echo "  pyproject.toml : ${#PYPROJECTS[@]} files"
echo "  Chart.yaml     : version + appVersion"
echo "  values.yaml    : sbomGraphApi/enrichment/releaseListener image tags"
if $DRY_RUN; then
    echo ""
    echo "  ** DRY RUN — no changes were made **"
else
    echo ""
    echo "Next: ./release.sh --push --registry <your-registry>   # build & push images at the new version"
fi
