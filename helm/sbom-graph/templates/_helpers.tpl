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
