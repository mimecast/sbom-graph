# Getting Started -- Full Deployment Guide

This guide walks through deploying the entire **sbom-graph** stack from
source on a local Kubernetes cluster (macOS) or a remote Linux cluster.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Clone and Build](#clone-and-build)
3. [TLS Certificates](#tls-certificates)
4. [Helm Values Reference](#helm-values-reference)
5. [Deploy Locally (macOS)](#deploy-locally-macos)
6. [Deploy Remotely (Linux)](#deploy-remotely-linux)
7. [Verify the Deployment](#verify-the-deployment)
8. [Post-Install: Retrieve Auto-Generated Secrets](#post-install-retrieve-auto-generated-secrets)
9. [Configure Sonatype Lifecycle Webhook](#configure-sonatype-lifecycle-webhook)
10. [Upgrading](#upgrading)
11. [Uninstalling](#uninstalling)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Software Requirements

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| **Python** | 3.14+ | Building the model library and running tests |
| **uv** | 0.4+ | Python dependency management ([install](https://docs.astral.sh/uv/getting-started/installation/)) |
| **Docker** | 24+ | Building container images |
| **Helm** | 3.12+ | Deploying the Kubernetes chart |
| **kubectl** | 1.28+ | Interacting with the Kubernetes cluster |

### Local Kubernetes (macOS)

You need one of the following to run Kubernetes locally:

| Option | Notes |
|--------|-------|
| **Docker Desktop** | Enable Kubernetes in *Settings > Kubernetes*. Simplest option. |
| **OrbStack** | Lightweight Docker Desktop alternative with built-in K8s. |
| **Rancher Desktop** | Open-source alternative with containerd or dockerd backend. |
| **minikube** | `brew install minikube && minikube start` |
| **kind** (Kubernetes in Docker) | `brew install kind && kind create cluster` |

After setup, verify your cluster is running:

```bash
kubectl cluster-info
kubectl get nodes
```

### Remote Kubernetes (Linux)

Any Kubernetes 1.28+ cluster with:

- `kubectl` configured with a valid kubeconfig (`~/.kube/config`)
- Helm 3 installed on your workstation
- A container registry accessible from the cluster (to push images)
- A `StorageClass` that supports `ReadWriteOnce` PersistentVolumeClaims

Install Helm on Linux:

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Clone and Build

### 1. Clone the Repository

```bash
git clone https://github.com/<org>/sbom-graph.git
cd sbom-graph
```

### 2. Build Docker Images

All images must be built from the **repository root** because Dockerfiles
reference sibling project directories.

```bash
./build-images.sh
```

This builds three things in order:

1. The `sbom-graph-model` Python wheel
2. The `sbom-graph-api` Docker image (tagged `sbom-graph-api:latest`)
3. The `sonatype-lifecycle-release-listener` Docker image (tagged `sonatype-lifecycle-release-listener:latest`)

#### Custom Tags (for pushing to a registry)

```bash
./build-images.sh \
  --adv-tag registry.example.com/sbom-graph-api:v1.0.0 \
  --rl-tag registry.example.com/sonatype-lifecycle-release-listener:v1.0.0
```

#### Remote Clusters

If deploying to a remote cluster, push images to a registry the cluster
can pull from:

```bash
docker push registry.example.com/sbom-graph-api:v1.0.0
docker push registry.example.com/sonatype-lifecycle-release-listener:v1.0.0
```

#### Local Clusters

For **Docker Desktop** and **OrbStack**, locally built images are
available to Kubernetes automatically.

For **minikube**, load images into the minikube VM:

```bash
minikube image load sbom-graph-api:latest
minikube image load sonatype-lifecycle-release-listener:latest
```

For **kind**, load images into the kind cluster:

```bash
kind load docker-image sbom-graph-api:latest
kind load docker-image sonatype-lifecycle-release-listener:latest
```

---

## TLS Certificates

The Helm chart supports TLS encryption between all components and FalkorDB.
There are two modes: **self-signed** (default) and **user-provided**.

### Option A: Auto-Generated Self-Signed Certificates (Default)

When `falkordb.tls.enabled` is `true` (the default) and no certificates are
provided, Helm automatically generates a self-signed CA and server certificate.
These are persisted across `helm upgrade` operations.

No action is required -- just deploy.

### Option B: User-Provided Certificates

Generate a CA and server certificate for FalkorDB. The server certificate
must include the Kubernetes service DNS name as a SAN.

#### Generate with OpenSSL

```bash
# Create a directory for the certificates
mkdir -p certs && cd certs

# 1. Generate a CA key and certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout ca.key -out ca.crt \
  -days 365 \
  -subj "/CN=sbom-graph-ca"

# 2. Generate a server key
openssl genrsa -out tls.key 4096

# 3. Create a certificate signing request (CSR)
#    Replace <RELEASE_NAME> and <NAMESPACE> with your Helm release name and namespace.
#    The default release name is "sbom-graph" and namespace is "default".
cat > san.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = sbom-graph-falkordb

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = sbom-graph-falkordb
DNS.2 = sbom-graph-falkordb.default.svc
DNS.3 = sbom-graph-falkordb.default.svc.cluster.local
EOF

openssl req -new -key tls.key -out tls.csr -config san.cnf

# 4. Sign the server certificate with the CA
openssl x509 -req -in tls.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out tls.crt -days 365 \
  -extensions v3_req -extfile san.cnf

cd ..
```

> **Important:** If you use a custom release name or namespace, update the
> DNS names in `san.cnf` to match `<RELEASE_NAME>-falkordb.<NAMESPACE>.svc`.

Pass the certificates to Helm:

```bash
helm install sbom-graph ./helm/sbom-graph \
  --set-file falkordb.tls.key=certs/tls.key \
  --set-file falkordb.tls.cert=certs/tls.crt \
  --set-file falkordb.tls.caCert=certs/ca.crt
```

---

## Helm Values Reference

The umbrella chart is located at `helm/sbom-graph/`. Below are the key
configuration values and their defaults.

### Global Settings

| Value | Default | Description |
|-------|---------|-------------|
| `global.internalPrefixes` | `"group:com.acme,name:acme-"` | Comma-separated prefixes to identify internal dependencies |
| `graphName` | `"acme-corp"` | FalkorDB graph name |
| `initData.enabled` | `true` | Load demo data (acme-corp) on first install |

### FalkorDB

| Value | Default | Description |
|-------|---------|-------------|
| `falkordb.image.repository` | `falkordb/falkordb` | FalkorDB container image |
| `falkordb.image.tag` | `latest` | Image tag |
| `falkordb.password` | `""` (auto-generated) | FalkorDB password. Leave empty to auto-generate a 32-char random password |
| `falkordb.persistence.enabled` | `true` | Persist FalkorDB data to a PVC |
| `falkordb.persistence.size` | `5Gi` | PVC size |
| `falkordb.persistence.storageClass` | `""` (cluster default) | Storage class name |
| `falkordb.tls.enabled` | `true` | Enable TLS for FalkorDB connections |
| `falkordb.tls.key` | `""` | PEM-encoded TLS private key (auto-generates self-signed if empty) |
| `falkordb.tls.cert` | `""` | PEM-encoded TLS certificate |
| `falkordb.tls.caCert` | `""` | PEM-encoded CA certificate |

### SBOM Graph API

| Value | Default | Description |
|-------|---------|-------------|
| `sbomGraphApi.image.repository` | `sbom-graph-api` | Container image |
| `sbomGraphApi.image.tag` | `latest` | Image tag |
| `sbomGraphApi.replicas` | `1` | Number of replicas |
| `sbomGraphApi.service.port` | `80` | Kubernetes Service port |
| `sbomGraphApi.service.targetPort` | `8000` | Container port |
| `sbomGraphApi.secrets.flaskSecretKey` | `""` (auto-generated) | Flask session signing key |
| `sbomGraphApi.secrets.jwtSecretKey` | `""` (auto-generated) | JWT token signing key |
| `sbomGraphApi.secrets.tokenDbEncryptionKey` | `""` (auto-generated) | SQLite token database encryption key |
| `sbomGraphApi.tokenDb.persistence.enabled` | `true` | Persist the token database |
| `sbomGraphApi.tokenDb.persistence.size` | `1Gi` | PVC size for token database |

### Sonatype Lifecycle Release Listener

| Value | Default | Description |
|-------|---------|-------------|
| `releaseListener.image.repository` | `sonatype-lifecycle-release-listener` | Container image |
| `releaseListener.image.tag` | `latest` | Image tag |
| `releaseListener.replicas` | `1` | Number of replicas |
| `releaseListener.webhookSecret` | `""` (auto-generated) | HMAC shared secret for webhook signature verification |
| `releaseListener.service.port` | `80` | Kubernetes Service port |
| `releaseListener.service.targetPort` | `8000` | Container port |

### Enrichment & Trust Score

| Value | Default | Description |
|-------|---------|-------------|
| `enrichment.enabled` | `true` | Enable enrichment pipeline |
| `enrichment.trustScore.enabled` | `true` | Enable trust score computation |
| `enrichment.trustScore.interval` | `"7200"` | Trust score propagation interval (seconds) |
| `enrichment.trustScore.alpha` | `"0.4"` | Blend weight for own vs inherited score |
| `enrichment.trustScore.decay` | `"0.8"` | Depth attenuation factor for propagation |
| `enrichment.trustScore.maxDepth` | `"20"` | Maximum traversal depth for propagation |
| `enrichment.trustScore.weights.securityPractices` | `"0.3"` | Weight for Security Practices category |
| `enrichment.trustScore.weights.vulnerabilityProfile` | `"0.35"` | Weight for Vulnerability Profile category |
| `enrichment.trustScore.weights.maintenanceHealth` | `"0.2"` | Weight for Maintenance Health category |
| `enrichment.trustScore.weights.supplyChainHygiene` | `"0.15"` | Weight for Supply-Chain Hygiene category |
| `enrichment.trustScore.ossindex.user` | `""` | OSS Index API username (optional, for higher rate limits) |
| `enrichment.trustScore.ossindex.token` | `""` | OSS Index API token (optional) |

**OSS Index API key (optional):** For higher rate limits, create a [Sonatype OSS Index](https://ossindex.sonatype.org/) account and set `enrichment.trustScore.ossindex.user` and `enrichment.trustScore.ossindex.token` in your values or via `--set`. Without credentials, the enrichment pipeline uses anonymous access with stricter rate limits.

### Secrets Behaviour

All secrets (FalkorDB password, Flask/JWT/encryption keys, webhook secret) follow
the same pattern:

1. If an explicit value is provided in `values.yaml` or via `--set`, it is used.
2. On `helm upgrade`, existing Secret values are preserved via `lookup`.
3. On first `helm install` with no explicit value, a random value is generated.

This means you never need to set secrets manually unless you have specific
requirements (e.g., sharing the webhook secret with an external system).

---

## Deploy Locally (macOS)

### Quick Start (Minimal Configuration)

Build images and deploy with all defaults (self-signed TLS, auto-generated
secrets, demo data loaded):

```bash
# Build all images
./build-images.sh

# Deploy
helm install sbom-graph ./helm/sbom-graph

# Wait for pods to be ready
kubectl get pods -w
```

### Production-Like Local Deployment

Override values for a more production-like setup:

```bash
helm install sbom-graph ./helm/sbom-graph \
  --set falkordb.password="$(openssl rand -base64 24)" \
  --set sbomGraphApi.secrets.jwtSecretKey="$(openssl rand -base64 36)" \
  --set sbomGraphApi.secrets.flaskSecretKey="$(openssl rand -base64 36)" \
  --set sbomGraphApi.secrets.tokenDbEncryptionKey="$(openssl rand -base64 36)" \
  --set initData.enabled=false
```

### Access the UI

```bash
kubectl port-forward svc/sbom-graph-sbom-graph-api 8080:80
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

---

## Deploy Remotely (Linux)

### 1. Push Images to a Registry

```bash
REGISTRY="registry.example.com"

./build-images.sh \
  --adv-tag "$REGISTRY/sbom-graph-api:v1.0.0" \
  --rl-tag "$REGISTRY/sonatype-lifecycle-release-listener:v1.0.0"

docker push "$REGISTRY/sbom-graph-api:v1.0.0"
docker push "$REGISTRY/sonatype-lifecycle-release-listener:v1.0.0"
```

### 2. Create a Custom Values File

Create `my-values.yaml`:

```yaml
graphName: "my-org"

global:
  internalPrefixes: "group:com.myorg,name:myorg-"

falkordb:
  persistence:
    size: 20Gi
    storageClass: "gp3"  # AWS EBS example

sbomGraphApi:
  image:
    repository: registry.example.com/sbom-graph-api
    tag: v1.0.0
  replicas: 2
  resources:
    limits:
      cpu: "1"
      memory: 1Gi
    requests:
      cpu: 250m
      memory: 256Mi

releaseListener:
  image:
    repository: registry.example.com/sonatype-lifecycle-release-listener
    tag: v1.0.0

initData:
  enabled: false  # Disable demo data for production
```

### 3. Deploy

```bash
kubectl create namespace sbom-graph

helm install sbom-graph ./helm/sbom-graph \
  -n sbom-graph \
  -f my-values.yaml
```

### 4. Expose the Service

Use an Ingress, LoadBalancer, or `kubectl port-forward` depending on your
cluster setup:

```bash
# Port forward for quick access
kubectl port-forward -n sbom-graph svc/sbom-graph-sbom-graph-api 8080:80
```

---

## Verify the Deployment

### Check Pod Status

```bash
kubectl get pods
```

All pods should show `Running` with `1/1` ready containers:

```
NAME                                                           READY   STATUS
sbom-graph-falkordb-...                                        1/1     Running
sbom-graph-sbom-graph-api-...                                  1/1     Running
sbom-graph-sonatype-lifecycle-release-listener-...             1/1     Running
```

If `initData.enabled` is `true`, you will also see a completed Job:

```
sbom-graph-init-data-...                                       0/1     Completed
```

### Check Logs

```bash
# FalkorDB
kubectl logs -l app.kubernetes.io/component=falkordb

# SBOM Graph API
kubectl logs -l app.kubernetes.io/component=sbom-graph-api

# Release Listener
kubectl logs -l app.kubernetes.io/component=sonatype-lifecycle-release-listener
```

### Health Checks

```bash
# SBOM Graph API
kubectl port-forward svc/sbom-graph-sbom-graph-api 8080:80 &
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

---

## Post-Install: Retrieve Auto-Generated Secrets

If you did not set secrets explicitly, Helm generated them automatically.
Retrieve them with:

```bash
NAMESPACE="default"  # Change if you deployed to a different namespace

# FalkorDB password
kubectl get secret sbom-graph-falkordb \
  -n "$NAMESPACE" \
  -o jsonpath='{.data.password}' | base64 -d; echo

# Webhook HMAC secret (needed for Sonatype configuration)
kubectl get secret sbom-graph-webhook \
  -n "$NAMESPACE" \
  -o jsonpath='{.data.webhook-secret}' | base64 -d; echo

# Flask secret key
kubectl get secret sbom-graph-sbom-graph-api \
  -n "$NAMESPACE" \
  -o jsonpath='{.data.flask-secret-key}' | base64 -d; echo

# JWT secret key
kubectl get secret sbom-graph-sbom-graph-api \
  -n "$NAMESPACE" \
  -o jsonpath='{.data.jwt-secret-key}' | base64 -d; echo

# Token DB encryption key
kubectl get secret sbom-graph-sbom-graph-api \
  -n "$NAMESPACE" \
  -o jsonpath='{.data.token-db-encryption-key}' | base64 -d; echo
```

### Trust Score Verification

With the API port-forwarded (e.g. `kubectl port-forward svc/sbom-graph-sbom-graph-api 8080:80`), verify trust score endpoints. When `AUTH_ENABLED=true`, include `Authorization: Bearer <token>` in requests.

```bash
# Package trust score (replace PURL with a known package, e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1)
curl "http://localhost:8080/api/v1/package/pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1/trust-score"

# Trust score distribution histogram
curl "http://localhost:8080/api/v1/analysis/trust-score-distribution"

# CI/CD gate: check if package meets minimum score (min_score defaults to 5.0)
curl "http://localhost:8080/api/v1/package/pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1/trust-check?min_score=5.0"
```

---

## Configure Sonatype Lifecycle Webhook

The release listener receives webhook events from Sonatype Lifecycle when
SCA scans complete. To set this up:

1. **Retrieve the webhook secret** (see section above).

2. **In Sonatype Lifecycle**, configure a webhook pointing to:

   ```
   https://<your-release-listener-url>/webhook
   ```

3. **Set the signing secret** to the value retrieved in step 1.
   Sonatype must send the header:

   ```
   X-Webhook-Signature: sha256=<HMAC-SHA256 hex digest of request body>
   ```

4. **If using a pre-shared secret**, pass it at install time:

   ```bash
   helm install sbom-graph ./helm/sbom-graph \
     --set releaseListener.webhookSecret="your-pre-shared-secret"
   ```

---

## Upgrading

```bash
helm upgrade sbom-graph ./helm/sbom-graph
```

- Secrets are preserved automatically across upgrades (via `lookup`).
- Self-signed TLS certificates are reused, not regenerated.
- If you pass new `--set` values, they take precedence.

To upgrade images after a rebuild:

```bash
./build-images.sh
helm upgrade sbom-graph ./helm/sbom-graph \
  --set sbomGraphApi.image.tag=v1.1.0 \
  --set releaseListener.image.tag=v1.1.0
```

---

## Uninstalling

```bash
helm uninstall sbom-graph
```

PersistentVolumeClaims are **not** deleted by `helm uninstall`. To remove
all data:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=sbom-graph
```

---

## Troubleshooting

### Pod stuck in CrashLoopBackOff

Check logs for the failing container:

```bash
kubectl logs <pod-name> --previous
```

Common causes:
- FalkorDB not ready yet -- the SBOM Graph API and release listener wait for
  FalkorDB, but if the FalkorDB PVC takes too long to provision, pods may
  restart a few times before stabilising.
- Incorrect image tag or missing image -- ensure images are available in the
  cluster (see [Build](#2-build-docker-images) section).

### Init data job fails

```bash
kubectl logs job/sbom-graph-init-data
```

The job has a `backoffLimit: 3` and `activeDeadlineSeconds: 300`. If FalkorDB
is slow to start, the init container waits, but if it exceeds 5 minutes
the job fails. Delete and re-run:

```bash
kubectl delete job sbom-graph-init-data
helm upgrade sbom-graph ./helm/sbom-graph
```

### TLS connection errors

If you see `SSL: CERTIFICATE_VERIFY_FAILED` in logs:

- **Self-signed mode:** Ensure the CA certificate is being mounted correctly.
  Check `kubectl describe pod <api-pod>` and look for the `tls-ca` volume mount.
- **User-provided certs:** Verify the SAN names match the FalkorDB service DNS
  name (`<release>-falkordb.<namespace>.svc`).

### Cannot connect to FalkorDB from outside the cluster

FalkorDB is deployed as a `ClusterIP` service (not exposed externally) by
design. To connect from your workstation:

```bash
kubectl port-forward svc/sbom-graph-falkordb 6379:6379
```

Then connect using the `redis-cli` or FalkorDB client:

```bash
redis-cli -h 127.0.0.1 -p 6379 --tls --cacert certs/ca.crt -a "$(kubectl get secret sbom-graph-falkordb -o jsonpath='{.data.password}' | base64 -d)"
```

### PVC pending (no storage provisioner)

If PVCs stay in `Pending` state, your cluster may not have a default
`StorageClass`. Check:

```bash
kubectl get storageclass
```

If none is marked `(default)`, either set one:

```bash
kubectl patch storageclass <name> -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

Or specify the storage class in your values:

```bash
helm install sbom-graph ./helm/sbom-graph \
  --set falkordb.persistence.storageClass="standard" \
  --set sbomGraphApi.tokenDb.persistence.storageClass="standard"
```
