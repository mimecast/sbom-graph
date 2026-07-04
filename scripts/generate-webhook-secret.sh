#!/usr/bin/env bash
set -euo pipefail

# Generates a cryptographically random HMAC shared secret for webhook
# signature verification between Sonatype Lifecycle and the
# sonatype-lifecycle-release-listener.
#
# Usage:
#   ./scripts/generate-webhook-secret.sh
#   ./scripts/generate-webhook-secret.sh --k8s-secret <namespace> [secret-name]
#
# The first form prints the secret to stdout.
# The second form creates (or updates) a Kubernetes Secret in the given
# namespace. Default secret name is sbom-graph-webhook (matches a Helm release
# named "sbom-graph"); override with the optional third argument.

SECRET_LENGTH=64  # 64 hex chars = 256 bits of entropy
SECRET=$(openssl rand -hex "$((SECRET_LENGTH / 2))")

if [[ "${1:-}" == "--k8s-secret" ]]; then
    NAMESPACE="${2:?Usage: $0 --k8s-secret <namespace> [secret-name]}"
    SECRET_NAME="${3:-sbom-graph-webhook}"

    kubectl create secret generic "$SECRET_NAME" \
        --namespace "$NAMESPACE" \
        --from-literal=webhook-secret="$SECRET" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "Kubernetes Secret '$SECRET_NAME' created/updated in namespace '$NAMESPACE'."
    echo ""
    echo "Helm reuses an existing secret named '<release>-webhook' when"
    echo "releaseListener.webhookSecret is left empty. Either:"
    echo "  - pre-create the secret with the name Helm expects for your release, or"
    echo "  - pass the value at install time:"
    echo "      --set releaseListener.webhookSecret=\"<secret-value>\""
    echo ""
    echo "Configure the same secret as the Secret Key in your Sonatype Lifecycle"
    echo "webhook. Sonatype sends:"
    echo "  Header:  X-Nexus-Webhook-Signature: <HMAC-SHA1 hex digest of body>"
    echo "  Algorithm header:  X-Nexus-Webhook-Signature-Algorithm: HmacSHA1"
else
    echo "$SECRET"
    echo "" >&2
    echo "Save this secret securely. Use it in both places:" >&2
    echo "  1. sonatype-lifecycle-release-listener: WEBHOOK_SECRET env var (or Helm)" >&2
    echo "  2. Sonatype Lifecycle webhook: Secret Key field in webhook config" >&2
    echo "     Sonatype sends X-Nexus-Webhook-Signature (HMAC-SHA1 hex digest)" >&2
fi
