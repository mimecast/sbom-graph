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
  value: {{ include "sbom-graph.falkordb.fullname" . | quote }}
- name: FALKORDB_PORT
  value: "6379"
- name: FALKORDB_GRAPH_NAME
  value: {{ .Values.graphName | quote }}
- name: FALKORDB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "sbom-graph.falkordb.secretName" . }}
      key: password
- name: CELERY_BROKER_DB
  value: {{ .Values.enrichment.celeryBrokerDb | quote }}
- name: CELERY_RESULT_DB
  value: {{ .Values.enrichment.celeryResultDb | quote }}
- name: ENRICHMENT_INTERVAL
  value: {{ .Values.enrichment.interval | quote }}
{{- if .Values.global.internalPrefixes }}
- name: INTERNAL_PREFIXES
  value: {{ .Values.global.internalPrefixes | quote }}
{{- end }}
{{- if .Values.falkordb.tls.enabled }}
- name: FALKORDB_CACERTS
  value: /tls/ca.crt
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
