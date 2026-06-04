#!/usr/bin/env bash
# deploy.sh — Helm upgrade/install the sbom-graph umbrella chart, preserving volumes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NAMESPACE="${NAMESPACE:-sbom-graph}"
RELEASE="${RELEASE:-sbom-graph}"
VALUES_FILE=""
DRY_RUN=false
CHART_DIR="helm/charts/sbom-graph"

usage() {
    cat <<'EOF'
Usage: deploy.sh [options]

Upgrade (or install) the sbom-graph Helm release on the current Kubernetes
cluster, preserving all persistent volumes and auto-generated secrets.

Options:
  --namespace NS    Kubernetes namespace (default: sbom-graph).
                    Also accepted via NAMESPACE env var.
  --release NAME    Helm release name (default: sbom-graph).
                    Also accepted via RELEASE env var.
  --values FILE     Additional Helm values file (e.g. secrets override).
  --dry-run         Run helm upgrade --dry-run to preview changes.
  -h, --help        Show this help.

Examples:
  ./deploy.sh                                         # Default upgrade
  ./deploy.sh --namespace staging --values prod.yaml  # Staging with overrides
  ./deploy.sh --dry-run                               # Preview only
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --release)   RELEASE="$2";   shift 2 ;;
        --values)    VALUES_FILE="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
for cmd in helm kubectl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is not installed." >&2
        exit 1
    fi
done

if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to Kubernetes cluster. Check your kubeconfig." >&2
    exit 1
fi

if [[ ! -d "$CHART_DIR" ]]; then
    echo "ERROR: Helm chart directory not found at $CHART_DIR" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Create namespace if it doesn't exist
# ---------------------------------------------------------------------------
if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "==> Creating namespace '$NAMESPACE'..."
    kubectl create namespace "$NAMESPACE"
else
    echo "==> Namespace '$NAMESPACE' already exists."
fi

# ---------------------------------------------------------------------------
# Build helm upgrade command
# ---------------------------------------------------------------------------
HELM_ARGS=(
    upgrade --install "$RELEASE" "$CHART_DIR"
    --namespace "$NAMESPACE"
    --reuse-values
    --wait
    --timeout 5m
)

if [[ -n "$VALUES_FILE" ]]; then
    if [[ ! -f "$VALUES_FILE" ]]; then
        echo "ERROR: Values file not found: $VALUES_FILE" >&2
        exit 1
    fi
    HELM_ARGS+=(-f "$VALUES_FILE")
    echo ""
    echo "WARNING: Using --values file alongside --reuse-values."
    echo "         Keys present in '$VALUES_FILE' will override existing release values."
    echo "         Auto-generated secrets (FalkorDB password, Flask keys) are safe"
    echo "         unless explicitly overridden in the values file."
    echo ""
fi

if $DRY_RUN; then
    HELM_ARGS+=(--dry-run)
fi

# ---------------------------------------------------------------------------
# Run helm upgrade
# ---------------------------------------------------------------------------
echo "==> Running: helm ${HELM_ARGS[*]}"
echo ""
helm "${HELM_ARGS[@]}"

# ---------------------------------------------------------------------------
# Post-deploy status
# ---------------------------------------------------------------------------
if ! $DRY_RUN; then
    echo ""
    echo "==> Deployment status"
    echo ""

    echo "--- Helm release ---"
    helm status "$RELEASE" --namespace "$NAMESPACE" --show-desc 2>/dev/null || true
    echo ""

    echo "--- Rollout status ---"
    DEPLOYMENTS=$(kubectl get deployments -n "$NAMESPACE" -l "app.kubernetes.io/instance=$RELEASE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)

    if [[ -n "$DEPLOYMENTS" ]]; then
        for dep in $DEPLOYMENTS; do
            echo "  Checking $dep ..."
            kubectl rollout status deployment/"$dep" -n "$NAMESPACE" --timeout=120s 2>/dev/null || \
                echo "  WARNING: $dep rollout did not complete within timeout."
        done
    else
        echo "  No deployments found for release '$RELEASE' in namespace '$NAMESPACE'."
    fi

    echo ""
    echo "--- Persistent Volume Claims ---"
    kubectl get pvc -n "$NAMESPACE" -o wide 2>/dev/null || echo "  No PVCs found."
    echo ""
    echo "==> Deploy complete."
fi
