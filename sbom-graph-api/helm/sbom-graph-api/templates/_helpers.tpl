{{/*
Expand the name of the chart.
*/}}
{{- define "sbom-graph-api.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sbom-graph-api.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "sbom-graph-api.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sbom-graph-api.labels" -}}
helm.sh/chart: {{ include "sbom-graph-api.chart" . }}
{{ include "sbom-graph-api.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sbom-graph-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbom-graph-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sbom-graph-api.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sbom-graph-api.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Kubernetes Secret name holding Flask/JWT/token DB material when using chart-managed secret.
*/}}
{{- define "sbom-graph-api.chartApplicationSecretName" -}}
{{- printf "%s-secret" (include "sbom-graph-api.fullname" .) }}
{{- end }}

{{/*
Secret used for file-based delivery (single Secret or CSI volume with matching filenames).
*/}}
{{- define "sbom-graph-api.applicationSecretName" -}}
{{- if .Values.secrets.kubernetesVolume.secretName }}
{{- .Values.secrets.kubernetesVolume.secretName }}
{{- else }}
{{- include "sbom-graph-api.chartApplicationSecretName" . }}
{{- end }}
{{- end }}

{{- define "sbom-graph-api.awsSecretProviderClassName" -}}
{{- default (printf "%s-aws-secrets" (include "sbom-graph-api.fullname" .)) .Values.secrets.awsSecretsManagerCsi.secretProviderClassName }}
{{- end }}
