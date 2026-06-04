{{/*
Expand the name of the chart.
*/}}
{{- define "sbom-graph.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name, truncated to 63 characters (DNS label limit).
If the release name already contains the chart name, avoid duplication.
*/}}
{{- define "sbom-graph.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version for the chart label.
*/}}
{{- define "sbom-graph.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "sbom-graph.labels" -}}
helm.sh/chart: {{ include "sbom-graph.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/* ---- FalkorDB helpers ---- */}}

{{- define "sbom-graph.falkordb.fullname" -}}
{{- printf "%s-falkordb" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully-qualified in-cluster DNS name for the FalkorDB Service (avoids resolver/search
issues where the short service name fails inside init containers or some CNIs).
Must match a SAN on the generated TLS cert when using chart-managed certs.
*/}}
{{- define "sbom-graph.falkordb.clusterHostname" -}}
{{- printf "%s.%s.svc.cluster.local" (include "sbom-graph.falkordb.fullname" .) .Release.Namespace }}
{{- end }}

{{/*
Host used for FalkorDB TCP/TLS client connections (init wait, API, enrichment, etc.).
- Explicit .Values.falkordb.connectHost wins when non-empty.
- If preferClusterIP is true and connectHost is empty, uses kubectl lookup of the
  FalkorDB Service ClusterIP (falls back to clusterHostname if lookup is empty).
  Enables Minikube / clusters where pods cannot resolve *.svc.cluster.local.
  TLS still uses --sni clusterHostname in wait-for-falkordb.
*/}}
{{- define "sbom-graph.falkordb.connectHost" -}}
{{- $h := .Values.falkordb.connectHost | default "" | trim -}}
{{- if $h -}}
{{- $h -}}
{{- else if (.Values.falkordb.preferClusterIP | default false) -}}
{{- $svcName := include "sbom-graph.falkordb.fullname" . -}}
{{- $svc := lookup "v1" "Service" .Release.Namespace $svcName -}}
{{- if and $svc $svc.spec.clusterIP (ne $svc.spec.clusterIP "None") -}}
{{- $svc.spec.clusterIP -}}
{{- else -}}
{{- include "sbom-graph.falkordb.clusterHostname" . -}}
{{- end -}}
{{- else -}}
{{- include "sbom-graph.falkordb.clusterHostname" . -}}
{{- end -}}
{{- end }}

{{- define "sbom-graph.falkordb.labels" -}}
{{ include "sbom-graph.labels" . }}
app.kubernetes.io/component: falkordb
{{- end }}

{{- define "sbom-graph.falkordb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: falkordb
{{- end }}

{{/* ---- SBOM Graph API helpers ---- */}}

{{- define "sbom-graph.sbomGraphApi.fullname" -}}
{{- printf "%s-sbom-graph-api" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbom-graph.sbomGraphApi.labels" -}}
{{ include "sbom-graph.labels" . }}
app.kubernetes.io/component: sbom-graph-api
{{- end }}

{{- define "sbom-graph.sbomGraphApi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: sbom-graph-api
{{- end }}

{{/* ---- Release Listener helpers ---- */}}

{{- define "sbom-graph.releaseListener.fullname" -}}
{{- printf "%s-sonatype-lifecycle-release-listener" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbom-graph.releaseListener.labels" -}}
{{ include "sbom-graph.labels" . }}
app.kubernetes.io/component: sonatype-lifecycle-release-listener
{{- end }}

{{- define "sbom-graph.releaseListener.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: sonatype-lifecycle-release-listener
{{- end }}

{{/*
Comma-separated INTERNAL_PREFIXES (field:prefix,...) injected into sbom-graph-api,
sonatype-lifecycle-release-listener, and enrichment workloads. Configure once via
global.internalPrefixes only.
*/}}
{{- define "sbom-graph.internalPrefixesValue" -}}
{{- .Values.global.internalPrefixes | default "" | trim -}}
{{- end }}

{{/*
Name of the Secret holding the FalkorDB password.
*/}}
{{- define "sbom-graph.falkordb.secretName" -}}
{{- printf "%s-falkordb" (include "sbom-graph.fullname" .) }}
{{- end }}

{{/*
Name of the Secret holding the TLS key/cert pair.
*/}}
{{- define "sbom-graph.tls.secretName" -}}
{{- printf "%s-tls" (include "sbom-graph.fullname" .) }}
{{- end }}

{{/*
Name of the Secret holding SBOM Graph API application secrets
(FLASK_SECRET_KEY, JWT_SECRET_KEY, TOKEN_DB_ENCRYPTION_KEY).
*/}}
{{- define "sbom-graph.sbomGraphApi.secretName" -}}
{{- printf "%s-sbom-graph-api" (include "sbom-graph.fullname" .) }}
{{- end }}

{{- define "sbom-graph.sbomGraphApi.serviceAccountName" -}}
{{- if .Values.sbomGraphApi.serviceAccount.name }}
{{- .Values.sbomGraphApi.serviceAccount.name }}
{{- else }}
{{- printf "%s-sbom-graph-api" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "sbom-graph.sbomGraphApi.applicationSecretName" -}}
{{- if .Values.sbomGraphApi.secrets.kubernetesVolume.secretName }}
{{- .Values.sbomGraphApi.secrets.kubernetesVolume.secretName }}
{{- else }}
{{- include "sbom-graph.sbomGraphApi.secretName" . }}
{{- end }}
{{- end }}

{{- define "sbom-graph.sbomGraphApi.awsSecretProviderClassName" -}}
{{- default (printf "%s-sbom-graph-api-aws-secrets" (include "sbom-graph.fullname" .)) .Values.sbomGraphApi.secrets.awsSecretsManagerCsi.secretProviderClassName }}
{{- end }}

{{/*
Name of the Secret holding the webhook HMAC shared secret.
*/}}
{{- define "sbom-graph.webhookSecret.secretName" -}}
{{- printf "%s-webhook" (include "sbom-graph.fullname" .) }}
{{- end }}

{{/*
Determine whether TLS certificates are user-provided (not self-signed).
Returns "true" when both key and cert values are non-empty.
*/}}
{{- define "sbom-graph.tls.isProvided" -}}
{{- if and .Values.falkordb.tls.key .Values.falkordb.tls.cert }}true{{- end }}
{{- end }}

{{/*
Determine whether self-signed certs are being used.
Returns "true" when TLS is enabled but no key/cert values are provided.
*/}}
{{- define "sbom-graph.tls.selfSigned" -}}
{{- if and .Values.falkordb.tls.enabled (not (include "sbom-graph.tls.isProvided" .)) }}true{{- end }}
{{- end }}

{{/* ---- Enrichment Worker helpers ---- */}}

{{- define "sbom-graph.enrichment.fullname" -}}
{{- printf "%s-enrichment" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbom-graph.enrichment.labels" -}}
{{ include "sbom-graph.labels" . }}
app.kubernetes.io/component: enrichment
{{- end }}

{{- define "sbom-graph.enrichment.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: enrichment
{{- end }}

{{/*
Shared environment variables used by both the enrichment worker and beat
Deployments.  Include via: {{- include "sbom-graph.enrichment.env" . | nindent N }}
*/}}
{{- define "sbom-graph.enrichment.env" -}}
- name: FALKORDB_HOST
  value: {{ include "sbom-graph.falkordb.connectHost" . | quote }}
- name: FALKORDB_PORT
  value: "6379"
- name: FALKORDB_GRAPH_NAME
  value: {{ .Values.graphName | quote }}
- name: FALKORDB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "sbom-graph.falkordb.secretName" . }}
      key: password
{{- /*
Socket/connect timeouts mirror the API deployment so a wedged or restarting
FalkorDB cannot pin a Celery worker thread indefinitely on a half-open TLS
connection (observed during FalkorDB OOMKill / restart windows).
*/}}
- name: FALKORDB_SOCKET_TIMEOUT
  value: "60.0"
- name: FALKORDB_CONNECT_TIMEOUT
  value: "30.0"
- name: CELERY_BROKER_DB
  value: {{ .Values.enrichment.celeryBrokerDb | quote }}
- name: CELERY_RESULT_DB
  value: {{ .Values.enrichment.celeryResultDb | quote }}
- name: ENRICHMENT_INTERVAL
  value: {{ .Values.enrichment.interval | quote }}
- name: ENRICHMENT_SOURCES
  value: {{ .Values.enrichment.sources | quote }}
- name: FALKORDB_INTERNAL_LABEL
  value: {{ .Values.sbomGraphApi.falkordbInternalLabel | default "INTERNAL" | quote }}
- name: CENTRALITY_REFRESH_ENABLED
  value: {{ .Values.enrichment.centralityRefresh.enabled | quote }}
- name: CENTRALITY_REFRESH_INTERVAL
  value: {{ .Values.enrichment.centralityRefresh.interval | quote }}
{{- $internalPrefixes := include "sbom-graph.internalPrefixesValue" . | trim }}
{{- if ne $internalPrefixes "" }}
- name: INTERNAL_PREFIXES
  value: {{ $internalPrefixes | quote }}
{{- end }}
{{- if .Values.falkordb.tls.enabled }}
- name: FALKORDB_SSL
  value: "true"
- name: FALKORDB_CACERTS
  value: /tls/ca.crt
- name: FALKORDB_CLIENT_CERT
  value: /tls/client.crt
- name: FALKORDB_CLIENT_KEY
  value: /tls/client.key
- name: CELERY_REDIS_SSL
  value: "true"
{{- end }}
{{- if .Values.enrichment.trustScore }}
- name: TRUST_SCORE_ENABLED
  value: {{ .Values.enrichment.trustScore.enabled | quote }}
- name: TRUST_SCORE_INTERVAL
  value: {{ .Values.enrichment.trustScore.interval | quote }}
- name: TRUST_SCORE_ALPHA
  value: {{ .Values.enrichment.trustScore.alpha | quote }}
- name: TRUST_SCORE_DECAY
  value: {{ .Values.enrichment.trustScore.decay | quote }}
- name: TRUST_SCORE_MAX_DEPTH
  value: {{ .Values.enrichment.trustScore.maxDepth | quote }}
- name: TRUST_SCORE_ALERT_THRESHOLD
  value: {{ .Values.enrichment.trustScore.alertThreshold | default "4.0" | quote }}
- name: TRUST_SCORE_WEIGHT_SECURITY_PRACTICES
  value: {{ .Values.enrichment.trustScore.weights.securityPractices | quote }}
- name: TRUST_SCORE_WEIGHT_VULNERABILITY_PROFILE
  value: {{ .Values.enrichment.trustScore.weights.vulnerabilityProfile | quote }}
- name: TRUST_SCORE_WEIGHT_MAINTENANCE_HEALTH
  value: {{ .Values.enrichment.trustScore.weights.maintenanceHealth | quote }}
- name: TRUST_SCORE_WEIGHT_SUPPLY_CHAIN_HYGIENE
  value: {{ .Values.enrichment.trustScore.weights.supplyChainHygiene | quote }}
{{- if and .Values.enrichment.trustScore.enabled .Values.enrichment.trustScore.ossindex.user }}
- name: OSSINDEX_USER
  valueFrom:
    secretKeyRef:
      name: {{ include "sbom-graph.fullname" . }}-ossindex
      key: OSSINDEX_USER
- name: OSSINDEX_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "sbom-graph.fullname" . }}-ossindex
      key: OSSINDEX_TOKEN
{{- end }}
{{- end }}
{{- end }}

{{/*
Shared init container that waits until FalkorDB accepts TLS (and mTLS when enabled)
connections — same redis-cli pattern as falkordb-deployment probes.

Uses the FalkorDB **server** image so redis-cli matches the running Redis/FalkorDB
version and does not depend on the API image Python stack.

Parameters:
  ctx:       The Helm rendering context (.)
  tlsVolume: Name of the pod volume that contains TLS material (default: "tls-ca")

Guard with (.Values.falkordb.waitForReady | default true) at the Pod spec:
omit initContainers entirely when wait is disabled.
*/}}
{{- define "sbom-graph.falkordb.waitContainer" -}}
{{- $ctx := .ctx -}}
{{- $tlsVolume := .tlsVolume | default "tls-ca" -}}
{{- $fdbSvc := include "sbom-graph.falkordb.fullname" $ctx -}}
{{- $serviceLinkHostVar := printf "%s_SERVICE_HOST" (upper (replace "-" "_" $fdbSvc)) -}}
- name: wait-for-falkordb
  image: "{{ $ctx.Values.falkordb.image.repository }}:{{ $ctx.Values.falkordb.image.tag }}"
  imagePullPolicy: {{ $ctx.Values.falkordb.image.pullPolicy | default "IfNotPresent" }}
  command: ["/bin/sh", "-c"]
  args:
    - |
      set -eu
      if ! command -v redis-cli >/dev/null 2>&1; then
        echo "FATAL: redis-cli is missing from this container image."
        echo "wait-for-falkordb must use falkordb.image (see chart template sbom-graph.falkordb.waitContainer)."
        echo "Your API Deployment still points the init container at sbomGraphApi.image — run helm upgrade from this chart revision, then: kubectl rollout restart deployment -n {{ $ctx.Release.Namespace }} -l app.kubernetes.io/component=sbom-graph-api"
        exit 1
      fi
      TLS_NAME="{{ include "sbom-graph.falkordb.clusterHostname" $ctx }}"
      LINK_KEY='{{ $serviceLinkHostVar }}'
      LINK_IP=$(printenv "$LINK_KEY" || true)
      HELM_HOST="{{ include "sbom-graph.falkordb.connectHost" $ctx }}"
      if [ -n "${LINK_IP:-}" ]; then
        HOST="${LINK_IP}"
        echo "Using service-link ${LINK_KEY}=${HOST} for TCP (TLS SNI ${TLS_NAME})"
      else
        HOST="${HELM_HOST}"
      fi
      PORT="6379"
      echo "Waiting for FalkorDB (redis-cli) at ${HOST}:${PORT}..."
      sleep 3
{{- if $ctx.Values.falkordb.tls.enabled }}
      until redis-cli --tls --cacert /tls/ca.crt \
{{- if $ctx.Values.falkordb.tls.requireClientAuth }}
        --cert /tls/client.crt --key /tls/client.key \
{{- end }}
        --sni "${TLS_NAME}" \
        -h "${HOST}" -p "${PORT}" -a "${FALKORDB_PASSWORD}" ping | grep -q PONG
      do
        echo "  Not ready (last ping below), retrying in 2s..."
        redis-cli --tls --cacert /tls/ca.crt \
{{- if $ctx.Values.falkordb.tls.requireClientAuth }}
          --cert /tls/client.crt --key /tls/client.key \
{{- end }}
          --sni "${TLS_NAME}" \
          -h "${HOST}" -p "${PORT}" -a "${FALKORDB_PASSWORD}" ping || true
        sleep 2
      done
{{- else }}
      until redis-cli -h "${HOST}" -p "${PORT}" -a "${FALKORDB_PASSWORD}" ping | grep -q PONG
      do
        echo "  Not ready (last ping below), retrying in 2s..."
        redis-cli -h "${HOST}" -p "${PORT}" -a "${FALKORDB_PASSWORD}" ping || true
        sleep 2
      done
{{- end }}
      echo "FalkorDB ready."
  env:
    - name: FALKORDB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: {{ include "sbom-graph.falkordb.secretName" $ctx }}
          key: password
  resources:
    limits:
      cpu: 100m
      memory: 128Mi
    requests:
      cpu: 50m
      memory: 64Mi
  {{- /* FalkorDB image expects root/redis user; override pod runAsNonRoot for this init only */}}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: false
    runAsNonRoot: false
    runAsUser: 0
    capabilities:
      drop:
        - ALL
  volumeMounts:
  {{- if $ctx.Values.falkordb.tls.enabled }}
    - name: {{ $tlsVolume }}
      mountPath: /tls
      readOnly: true
  {{- end }}
{{- end }}

{{/* ---- Enrichment Beat helpers ---- */}}

{{- define "sbom-graph.enrichmentBeat.fullname" -}}
{{- printf "%s-enrichment-beat" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbom-graph.enrichmentBeat.labels" -}}
{{ include "sbom-graph.labels" . }}
app.kubernetes.io/component: enrichment-beat
{{- end }}

{{- define "sbom-graph.enrichmentBeat.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: enrichment-beat
{{- end }}

{{/* ---- Enrichment Ingest Worker helpers ---- */}}
{{/*
Dedicated worker pool that listens only on the ``ingest`` Celery queue.
Separating this from the main enrichment pool gives true priority to
SBOM upload jobs (see docs/sbom-graph-api-troubleshooting.md §10.6 and
docs/ingest-pipeline.md).
*/}}

{{- define "sbom-graph.enrichmentIngest.fullname" -}}
{{- printf "%s-enrichment-ingest" (include "sbom-graph.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbom-graph.enrichmentIngest.labels" -}}
{{ include "sbom-graph.labels" . }}
app.kubernetes.io/component: enrichment-ingest
{{- end }}

{{- define "sbom-graph.enrichmentIngest.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: enrichment-ingest
{{- end }}
