{{/*
Expand the name of the chart.
*/}}
{{- define "avapigw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "avapigw.fullname" -}}
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
Create the name of the configmap
*/}}
{{- define "avapigw.configMapName" -}}
{{- printf "%s-config" (include "avapigw.fullname" .) }}
{{- end }}

{{/*
Redis host
*/}}
{{- define "avapigw.redisHost" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" .Release.Name }}
{{- else }}
{{- .Values.redis.externalHost | default "" }}
{{- end }}
{{- end }}

{{/*
Redis port
*/}}
{{- define "avapigw.redisPort" -}}
{{- if .Values.redis.enabled }}
{{- 6379 }}
{{- else }}
{{- .Values.redis.externalPort | default 6379 }}
{{- end }}
{{- end }}

{{/*
Generate gateway configuration
*/}}
{{- define "avapigw.gatewayConfig" -}}
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: {{ include "avapigw.fullname" . }}
  labels:
    app: {{ include "avapigw.name" . }}
    environment: {{ .Values.gateway.environment | default "production" }}
spec:
  listeners:
    {{- if .Values.gateway.listeners.http.enabled }}
    - name: http
      port: {{ .Values.gateway.listeners.http.port | default 8080 }}
      {{- if and .Values.vault .Values.vault.enabled .Values.vault.pki .Values.vault.pki.enabled }}
      protocol: HTTPS
      tls:
        vault:
          enabled: true
          pkiMount: {{ .Values.vault.pki.pkiMount | default "pki" | quote }}
          role: {{ .Values.vault.pki.role | quote }}
          commonName: {{ .Values.vault.pki.commonName | quote }}
          {{- if .Values.vault.pki.altNames }}
          altNames:
            {{- toYaml .Values.vault.pki.altNames | nindent 12 }}
          {{- end }}
          {{- if .Values.vault.pki.ttl }}
          ttl: {{ .Values.vault.pki.ttl | quote }}
          {{- end }}
      {{- else }}
      protocol: HTTP
      {{- end }}
      hosts:
        {{- toYaml .Values.gateway.listeners.http.hosts | nindent 8 }}
      bind: {{ .Values.gateway.listeners.http.bind | default "0.0.0.0" }}
    {{- end }}
    {{- if .Values.gateway.listeners.grpc.enabled }}
    - name: grpc
      port: {{ .Values.gateway.listeners.grpc.port | default 9000 }}
      protocol: GRPC
      hosts:
        {{- toYaml .Values.gateway.listeners.grpc.hosts | nindent 8 }}
      bind: {{ .Values.gateway.listeners.grpc.bind | default "0.0.0.0" }}
      grpc:
        maxConcurrentStreams: {{ .Values.gateway.listeners.grpc.maxConcurrentStreams | default 100 }}
        maxRecvMsgSize: {{ .Values.gateway.listeners.grpc.maxRecvMsgSize | default 4194304 }}
        maxSendMsgSize: {{ .Values.gateway.listeners.grpc.maxSendMsgSize | default 4194304 }}
        reflection: {{ .Values.gateway.listeners.grpc.reflection | default true }}
        healthCheck: {{ .Values.gateway.listeners.grpc.healthCheck | default true }}
    {{- end }}

  {{- if .Values.gateway.routes }}
  routes:
    {{- toYaml .Values.gateway.routes | nindent 4 }}
  {{- else }}
  routes:
    - name: health-check
      match:
        - uri:
            exact: /health
          methods:
            - GET
      directResponse:
        status: 200
        body: '{"status":"healthy"}'
        headers:
          Content-Type: application/json
  {{- end }}

  {{- if .Values.gateway.backends }}
  backends:
    {{- toYaml .Values.gateway.backends | nindent 4 }}
  {{- end }}

  {{- if .Values.gateway.grpcRoutes }}
  grpcRoutes:
    {{- toYaml .Values.gateway.grpcRoutes | nindent 4 }}
  {{- end }}

  {{- if .Values.gateway.grpcBackends }}
  grpcBackends:
    {{- toYaml .Values.gateway.grpcBackends | nindent 4 }}
  {{- end }}

  rateLimit:
    enabled: {{ .Values.gateway.rateLimit.enabled | default true }}
    requestsPerSecond: {{ .Values.gateway.rateLimit.requestsPerSecond | default 100 }}
    burst: {{ .Values.gateway.rateLimit.burst | default 200 }}
    perClient: {{ .Values.gateway.rateLimit.perClient | default true }}

  circuitBreaker:
    enabled: {{ .Values.gateway.circuitBreaker.enabled | default true }}
    threshold: {{ .Values.gateway.circuitBreaker.threshold | default 5 }}
    timeout: {{ .Values.gateway.circuitBreaker.timeout | default "30s" }}
    halfOpenRequests: {{ .Values.gateway.circuitBreaker.halfOpenRequests | default 3 }}

  {{- if .Values.gateway.maxSessions }}
  maxSessions:
    enabled: {{ .Values.gateway.maxSessions.enabled | default false }}
    maxConcurrent: {{ .Values.gateway.maxSessions.maxConcurrent | default 10000 }}
    queueSize: {{ .Values.gateway.maxSessions.queueSize | default 1000 }}
    queueTimeout: {{ .Values.gateway.maxSessions.queueTimeout | default "30s" }}
  {{- end }}

  requestLimits:
    maxBodySize: {{ .Values.gateway.requestLimits.maxBodySize | default 10485760 | int }}
    maxHeaderSize: {{ .Values.gateway.requestLimits.maxHeaderSize | default 1048576 | int }}

  security:
    enabled: {{ .Values.gateway.security.enabled | default true }}
    headers:
      enabled: {{ .Values.gateway.security.headers.enabled | default true }}
      xFrameOptions: {{ .Values.gateway.security.headers.xFrameOptions | default "DENY" | quote }}
      xContentTypeOptions: {{ .Values.gateway.security.headers.xContentTypeOptions | default "nosniff" | quote }}
      xXSSProtection: {{ .Values.gateway.security.headers.xXSSProtection | default "1; mode=block" | quote }}
    hsts:
      enabled: {{ .Values.gateway.security.hsts.enabled | default false }}
      maxAge: {{ .Values.gateway.security.hsts.maxAge | default 31536000 | int }}
      includeSubDomains: {{ .Values.gateway.security.hsts.includeSubDomains | default true }}
      preload: {{ .Values.gateway.security.hsts.preload | default false }}

  cors:
    allowOrigins:
      {{- toYaml .Values.gateway.cors.allowOrigins | nindent 6 }}
    allowMethods:
      {{- toYaml .Values.gateway.cors.allowMethods | nindent 6 }}
    allowHeaders:
      {{- toYaml .Values.gateway.cors.allowHeaders | nindent 6 }}
    exposeHeaders:
      {{- toYaml .Values.gateway.cors.exposeHeaders | nindent 6 }}
    maxAge: {{ .Values.gateway.cors.maxAge | default 86400 }}
    allowCredentials: {{ .Values.gateway.cors.allowCredentials | default false }}

  {{- if .Values.gateway.audit }}
  audit:
    enabled: {{ .Values.gateway.audit.enabled | default true }}
    output: {{ .Values.gateway.audit.output | default "stdout" }}
    format: {{ .Values.gateway.audit.format | default "json" }}
    level: {{ .Values.gateway.audit.level | default "info" }}
    {{- if .Values.gateway.audit.events }}
    events:
      authentication: {{ .Values.gateway.audit.events.authentication | default true }}
      authorization: {{ .Values.gateway.audit.events.authorization | default true }}
      request: {{ .Values.gateway.audit.events.request | default false }}
      response: {{ .Values.gateway.audit.events.response | default false }}
      configuration: {{ .Values.gateway.audit.events.configuration | default true }}
      security: {{ .Values.gateway.audit.events.security | default true }}
    {{- end }}
    {{- if .Values.gateway.audit.skipPaths }}
    skipPaths:
      {{- toYaml .Values.gateway.audit.skipPaths | nindent 6 }}
    {{- end }}
    {{- if .Values.gateway.audit.redactFields }}
    redactFields:
      {{- toYaml .Values.gateway.audit.redactFields | nindent 6 }}
    {{- end }}
  {{- end }}

  observability:
    metrics:
      enabled: {{ .Values.gateway.observability.metrics.enabled | default true }}
      path: {{ .Values.gateway.observability.metrics.path | default "/metrics" }}
      port: {{ .Values.gateway.observability.metrics.port | default 9090 }}
    tracing:
      enabled: {{ .Values.gateway.observability.tracing.enabled | default false }}
      samplingRate: {{ .Values.gateway.observability.tracing.samplingRate | default 1.0 }}
      otlpEndpoint: {{ .Values.gateway.observability.tracing.otlpEndpoint | default "" | quote }}
      serviceName: {{ .Values.gateway.observability.tracing.serviceName | default "avapigw" }}
    logging:
      level: {{ .Values.gateway.observability.logging.level | default "info" }}
      format: {{ .Values.gateway.observability.logging.format | default "json" }}

  {{- if and .Values.vault .Values.vault.enabled }}
  vault:
    enabled: true
    address: {{ .Values.vault.address | quote }}
    authMethod: {{ .Values.vault.authMethod | default "kubernetes" }}
    {{- if eq (.Values.vault.authMethod | default "kubernetes") "token" }}
    token: ${VAULT_TOKEN}
    {{- end }}
    {{- if eq (.Values.vault.authMethod | default "kubernetes") "kubernetes" }}
    kubernetes:
      role: {{ .Values.vault.role | default "" | quote }}
    {{- end }}
  {{- end }}

  {{- if .Values.gateway.customConfig }}
  {{- toYaml .Values.gateway.customConfig | nindent 2 }}
  {{- end }}
{{- end }}
