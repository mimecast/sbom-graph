#!/usr/bin/env bash
set -euo pipefail

# Generates a cryptographically random HMAC shared secret for webhook
# signature verification between SonaType and the sonatype-lifecycle-release-listener.
#
# Usage:
#   ./scripts/generate-webhook-secret.sh
#   ./scripts/generate-webhook-secret.sh --k8s-secret <namespace>
#
# The first form prints the secret to stdout.
# The second form creates (or updates) a Kubernetes Secret in the given
# namespace so it can be referenced by the Helm chart.

SECRET_LENGTH=64  # 64 hex chars = 256 bits of entropy
SECRET=$(openssl rand -hex "$((SECRET_LENGTH / 2))")

if [[ "${1:-}" == "--k8s-secret" ]]; then
    NAMESPACE="${2:?Usage: $0 --k8s-secret <namespace>}"
    SECRET_NAME="${3:-sbom-graph-webhook-secret}"

    kubectl create secret generic "$SECRET_NAME" \
        --namespace "$NAMESPACE" \
        --from-literal=webhook-secret="$SECRET" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "Kubernetes Secret '$SECRET_NAME' created/updated in namespace '$NAMESPACE'."
    echo ""
    echo "Reference it in your Helm values:"
    echo "  releaseListener:"
    echo "    webhookSecret:"
    echo "      existingSecret: $SECRET_NAME"
    echo ""
    echo "Configure the same secret in your SonaType webhook to sign payloads with:"
    echo "  Header:  X-Webhook-Signature: sha256=<HMAC-SHA256 hex digest>"
    echo "  Secret:  (stored in the Kubernetes Secret)"
else
    echo "$SECRET"
    echo "" >&2
    echo "Save this secret securely. Use it in both places:" >&2
    echo "  1. sonatype-lifecycle-release-listener:  WEBHOOK_SECRET env var (or Helm values)" >&2
    echo "  2. SonaType webhook:  Sign payloads with HMAC-SHA256 using this secret" >&2
    echo "     Header format:  X-Webhook-Signature: sha256=<hex_digest>" >&2
fi
