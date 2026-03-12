#!/usr/bin/env bash
# sync-helm-tags.sh — Update Helm values.yaml with versions from pyproject.toml.
#
# When the REGISTRY environment variable is set (e.g. REGISTRY=ghcr.io/org),
# the image.repository values are also updated to include the registry prefix.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REGISTRY="${REGISTRY:-}"
VALUES="helm/sbom-graph/values.yaml"

API_VER=$(grep '^version' sbom-graph-api/pyproject.toml | sed 's/.*"\(.*\)"/\1/')
ENR_VER=$(grep '^version' sbom-graph-enrichment/pyproject.toml | sed 's/.*"\(.*\)"/\1/')
LIS_VER=$(grep '^version' sonatype-lifecycle-release-listener/pyproject.toml | sed 's/.*"\(.*\)"/\1/')

yq -i ".sbomGraphApi.image.tag = \"$API_VER\"" "$VALUES"
yq -i ".enrichment.image.tag = \"$ENR_VER\"" "$VALUES"
yq -i ".releaseListener.image.tag = \"$LIS_VER\"" "$VALUES"

if [[ -n "$REGISTRY" ]]; then
    prefix="${REGISTRY%/}/"
    yq -i ".sbomGraphApi.image.repository = \"${prefix}sbom-graph-api\"" "$VALUES"
    yq -i ".enrichment.image.repository = \"${prefix}sbom-graph-enrichment\"" "$VALUES"
    yq -i ".releaseListener.image.repository = \"${prefix}sonatype-lifecycle-release-listener\"" "$VALUES"
fi

echo "Synced Helm tags → API=$API_VER  ENR=$ENR_VER  LIS=$LIS_VER"
if [[ -n "$REGISTRY" ]]; then
    echo "Registry prefix  → $REGISTRY"
fi
