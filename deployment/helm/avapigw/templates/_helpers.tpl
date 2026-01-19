{{/*
Expand the name of the chart.
*/}}
{{- define "avapigw.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "avapigw.fullname" -}}
{{- if .Values.global.fullnameOverride }}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.global.nameOverride }}
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
{{- define "avapigw.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "avapigw.labels" -}}
helm.sh/chart: {{ include "avapigw.chart" . }}
{{ include "avapigw.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "avapigw.selectorLabels" -}}
app.kubernetes.io/name: {{ include "avapigw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Operator labels
*/}}
{{- define "avapigw.operator.labels" -}}
{{ include "avapigw.labels" . }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Operator selector labels
*/}}
{{- define "avapigw.operator.selectorLabels" -}}
{{ include "avapigw.selectorLabels" . }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Gateway labels
*/}}
{{- define "avapigw.gateway.labels" -}}
{{ include "avapigw.labels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Gateway selector labels
*/}}
{{- define "avapigw.gateway.selectorLabels" -}}
{{ include "avapigw.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "avapigw.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "avapigw.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the namespace name
*/}}
{{- define "avapigw.namespace" -}}
{{- if .Values.namespace.name }}
{{- .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Operator image
*/}}
{{- define "avapigw.operator.image" -}}
{{- $tag := default .Chart.AppVersion .Values.operator.image.tag }}
{{- printf "%s:%s" .Values.operator.image.repository $tag }}
{{- end }}

{{/*
Gateway image
*/}}
{{- define "avapigw.gateway.image" -}}
{{- $tag := default .Chart.AppVersion .Values.gateway.image.tag }}
{{- printf "%s:%s" .Values.gateway.image.repository $tag }}
{{- end }}

{{/*
Webhook service name
*/}}
{{- define "avapigw.webhook.serviceName" -}}
{{- printf "%s-webhook" (include "avapigw.fullname" .) }}
{{- end }}

{{/*
Webhook certificate secret name
*/}}
{{- define "avapigw.webhook.certSecretName" -}}
{{- printf "%s-webhook-certs" (include "avapigw.fullname" .) }}
{{- end }}

{{/*
Operator service name
*/}}
{{- define "avapigw.operator.serviceName" -}}
{{- printf "%s-operator" (include "avapigw.fullname" .) }}
{{- end }}

{{/*
Gateway service name
*/}}
{{- define "avapigw.gateway.serviceName" -}}
{{- printf "%s-gateway" (include "avapigw.fullname" .) }}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "avapigw.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}
