# AVAPIGW Operator Configuration Guide

This guide covers all configuration options for the AVAPIGW Operator, including deployment configuration, runtime settings, and integration options.

## Table of Contents

- [Overview](#overview)
- [Deployment Configuration](#deployment-configuration)
- [Operator Configuration](#operator-configuration)
- [gRPC Server Configuration](#grpc-server-configuration)
- [Certificate Providers](#certificate-providers)
- [Webhook Configuration](#webhook-configuration)
- [Vault Integration](#vault-integration)
- [Monitoring Configuration](#monitoring-configuration)
- [Security Configuration](#security-configuration)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## Overview

The AVAPIGW Operator can be configured through multiple methods with enhanced boolean environment variable support:

1. **Helm Values** - Primary configuration method for deployment
2. **Environment Variables** - Runtime configuration and overrides with symmetric boolean handling
3. **Command Line Flags** - Direct operator configuration
4. **ConfigMaps** - External configuration files
5. **Secrets** - Sensitive configuration data

### Boolean Environment Variable Support

The operator now supports symmetric true/false/yes/no/1/0 handling for all boolean environment variables (case-insensitive):

**Supported Boolean Values:**
- **True values**: `true`, `yes`, `1`, `on`, `enable`, `enabled`
- **False values**: `false`, `no`, `0`, `off`, `disable`, `disabled`

## Deployment Configuration

### Helm Values Configuration

The primary way to configure the operator is through Helm values. Here's the complete configuration reference:

```yaml
# values.yaml

# Replica configuration
replicaCount: 1                    # Number of operator replicas

# Image configuration
image:
  repository: ghcr.io/vyrodovalexey/avapigw-operator
  tag: ""                          # Defaults to chart appVersion
  pullPolicy: IfNotPresent

imagePullSecrets: []               # Image pull secrets for private registries

# Service account configuration
serviceAccount:
  create: true                     # Create service account
  automount: true                  # Auto-mount service account token
  annotations: {}                  # Service account annotations
  name: ""                         # Service account name (auto-generated if empty)

# Pod configuration
podAnnotations: {}                 # Pod annotations
podLabels: {}                      # Pod labels

# Security contexts
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  capabilities:
    drop: ["ALL"]

# Resource configuration
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

# Health probes
livenessProbe:
  httpGet:
    path: /healthz
    port: health
  initialDelaySeconds: 15
  periodSeconds: 20
  timeoutSeconds: 5
  failureThreshold: 3
  successThreshold: 1

readinessProbe:
  httpGet:
    path: /readyz
    port: health
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
  successThreshold: 1

# Scheduling configuration
nodeSelector: {}
tolerations: []
affinity: {}
topologySpreadConstraints: []

# Additional volumes and mounts
volumes: []
volumeMounts: []

# Environment variables
extraEnv: []
extraEnvFrom: []
```

### High Availability Configuration

For production deployments, configure high availability:

```yaml
# High availability configuration
replicaCount: 3

# Leader election (required for HA)
leaderElection:
  enabled: true
  leaseDuration: 15s
  renewDeadline: 10s
  retryPeriod: 2s
  resourceName: some_id.avapigw.io

# Pod disruption budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2                  # Keep at least 2 replicas available

# Anti-affinity for pod distribution
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values: ["avapigw-operator"]
          topologyKey: kubernetes.io/hostname

# Resource limits for production
resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi
```

## Operator Configuration

### Leader Election

Configure leader election for high availability:

```yaml
leaderElection:
  enabled: true                    # Enable leader election
  leaseDuration: 15s               # Lease duration
  renewDeadline: 10s               # Renew deadline
  retryPeriod: 2s                  # Retry period
  resourceName: some_id.avapigw.io  # Lease resource name
```

### Reconciliation Settings

Configure reconciliation behavior:

```yaml
# Environment variables for reconciliation
extraEnv:
  - name: RECONCILE_TIMEOUT
    value: "10m"                   # Max reconciliation time
  - name: RECONCILE_WORKERS
    value: "5"                     # Number of worker goroutines
  - name: RECONCILE_RATE_LIMIT_QPS
    value: "20"                    # Rate limit QPS
  - name: RECONCILE_RATE_LIMIT_BURST
    value: "30"                    # Rate limit burst
```

### Logging Configuration

Configure structured logging:

```yaml
extraEnv:
  - name: LOG_LEVEL
    value: "info"                  # debug, info, warn, error
  - name: LOG_FORMAT
    value: "json"                  # json, console
  - name: LOG_DEVELOPMENT
    value: "false"                 # Enable development logging
  - name: LOG_STACKTRACE_LEVEL
    value: "error"                 # Stacktrace level
```

## gRPC Server Configuration

The operator runs a gRPC server for communication with gateway instances:

```yaml
grpc:
  port: 9444                       # gRPC server port
  
  # TLS configuration
  tls:
    mode: selfsigned               # selfsigned, vault
    
    # Self-signed certificate configuration
    selfsigned:
      validity: 8760h              # Certificate validity (1 year)
      keySize: 4096                # RSA key size
      organization: "AVAPIGW"      # Certificate organization
      country: "US"                # Certificate country
    
    # Vault PKI configuration
    vault:
      pkiMount: pki                # Vault PKI mount path
      role: operator-server        # Vault PKI role
      commonName: avapigw-operator.avapigw-system.svc
      altNames:                    # Subject alternative names
        - avapigw-operator.avapigw-system.svc.cluster.local
        - localhost
      ipSans:                      # IP SANs
        - 127.0.0.1
      ttl: 24h                     # Certificate TTL
      renewBefore: 1h              # Renew before expiry
```

### gRPC Server Advanced Configuration

The environment overrides the operator actually consumes for the gRPC
server are:

```yaml
extraEnv:
  - name: GRPC_PORT
    value: "9444"                  # gRPC server port
  - name: ENABLE_GRPC_SERVER
    value: "true"                  # Enable/disable the gRPC server
  - name: GRPC_REQUIRE_CLIENT_CERT
    value: "false"                 # Require client certificates (mTLS)
```

Message-size, keepalive, connection-age, and graceful-shutdown settings use
the server's built-in defaults (e.g. graceful shutdown timeout 30s) and are
not currently exposed as environment variables.

## Certificate Providers

One certificate manager (selected by the `--cert-provider` flag /
`CERT_PROVIDER` env) serves **both** the webhook server (called by the
Kubernetes API server) and the gRPC ConfigurationService (dialed by the
gateway), so the certificate's SAN list must cover both service names. The
Helm chart renders the provider from `operator.webhook.tls.mode` (when
webhooks are enabled) or `operator.grpc.tls.mode`, and supplies the
identity through `CERT_SERVICE_NAME`/`CERT_DNS_NAMES`/`CERT_NAMESPACE`.

| Provider | Source | Rotation |
|----------|--------|----------|
| `selfsigned` (default) | Operator-generated CA + serving certificate; CA and serving cert are **persisted to a Kubernetes Secret** and reused/adopted across restarts when `--cert-secret-name` is set | Internal rotation loop (`RotateBefore` 7 days before expiry) |
| `vault` | Vault PKI issuance (kubernetes auth) | Internal rotation loop (1 hour before expiry, matching the default 24h TTL) |
| `file` | Pre-provisioned PEM files (`--cert-file`/`--key-file`, optional `--ca-file`) — e.g. a mounted Secret | Reloaded from disk on change/approaching expiry (external rotation) |
| `cert-manager` | cert-manager-provisioned Secret mounted at the webhook cert dir | controller-runtime certwatcher (external rotation) |

### Self-Signed Provider with CA Persistence

Without persistence, the self-signed provider regenerates an in-memory CA on
every start, so clients can never pin a stable CA. With
`--cert-secret-name` (chart: rendered automatically as
`CERT_SECRET_NAME=<operator-fullname>-grpc-cert` for the selfsigned
provider) the provider:

1. **Loads** a previously persisted CA from the Secret (`ca.crt`/`ca.key`)
   and reuses it (`avapigw_operator_cert_ca_reuse_total`), also priming the
   persisted serving certificate when still valid;
2. **Adopts** a CA seeded by Helm (`templates/operator/grpc-cert-secret.yaml`
   generates the Secret with `genCA` on first install and reuses it via
   `lookup` on upgrades);
3. **Persists** a newly generated CA and each issued/rotated serving
   certificate back to the Secret
   (`avapigw_operator_cert_secret_sync_total{operation,result}`).

The gateway can then verify the operator connection against the stable
`ca.crt` in that Secret. RBAC for the Secret writes comes from the chart's
namespaced `operator/cert-secret-role.yaml` (rendered only for the
selfsigned provider). `--cert-secret-namespace` defaults to `POD_NAMESPACE`,
then the cert namespace.

### File Provider

```bash
avapigw-operator \
  --cert-provider=file \
  --cert-file=/etc/operator/certs/tls.crt \
  --key-file=/etc/operator/certs/tls.key \
  --ca-file=/etc/operator/certs/ca.crt        # optional
```

- `certFile`/`keyFile` are required; `caFile` is optional (when empty, the
  CA bundle is derived from extra certificate blocks in `certFile`, if any).
- The initial load is eager, so misconfiguration fails fast at startup.
- Files are re-read when they change on disk or approach expiry, matching
  controller-runtime's certwatcher behavior — rotation is owned by whoever
  provisions the files (cert-manager, Vault agent, Helm).
- For webhooks, the certificate directory is derived from the cert/key
  paths (they must share a directory) unless `--webhook-cert-dir` is set
  explicitly.

### cert-manager Provider

`--cert-provider=cert-manager` treats the webhook certificates as externally
provisioned: the operator serves whatever cert-manager mounts into the
webhook cert dir (`--webhook-cert-dir`, defaulting to the conventional
`/tmp/k8s-webhook-server/serving-certs` with `tls.crt`/`tls.key`), and
controller-runtime watches the files for rotation. Internal provisioning
never overrides an explicitly configured `WebhookCertDir`.

### Serving-Certificate Rotation Loop

For the internally provisioned providers (`selfsigned`, `vault`) the
operator runs a rotation loop that checks the serving certificate every
minute (with up to 20% jitter to desynchronize HA replicas) and re-issues it
inside the rotate-before window (7 days for selfsigned, 1 hour for vault).
The rotated certificate is hot-swapped into the gRPC server (via the
`tls.Config.GetCertificate` pattern) and rewritten into the webhook cert
directory (controller-runtime's certwatcher reloads the files natively) — no
restart required. Rotation failures are logged and retried on the next tick.
External providers (`file`, `cert-manager`) rotate on disk and skip the loop.

### Certificate Metrics

```prometheus
avapigw_operator_cert_issued_total{provider}            # Certificates issued
avapigw_operator_cert_rotations_total{provider}         # Rotations performed
avapigw_operator_cert_errors_total{provider,operation}  # issue/rotate/renew/load errors
avapigw_operator_cert_expiry_seconds{common_name}       # Time until expiry
avapigw_operator_cert_ca_reuse_total{provider}          # Persisted CA reused
avapigw_operator_cert_secret_sync_total{operation,result} # Secret persistence ops
```

## Webhook Configuration

Configure admission webhooks for CRD validation:

```yaml
webhook:
  enabled: true                    # Enable admission webhooks
  port: 9443                       # Webhook server port
  
  # TLS configuration
  tls:
    mode: selfsigned               # selfsigned, vault, cert-manager
    
    # Self-signed configuration
    selfsigned:
      validity: 8760h              # Certificate validity
    
    # Vault PKI configuration
    vault:
      pkiMount: pki
      role: webhook
      commonName: avapigw-operator-webhook.avapigw-system.svc
      altNames:
        - avapigw-operator-webhook.avapigw-system.svc.cluster.local
      ttl: 24h
    
    # cert-manager configuration
    certManager:
      issuerRef:
        name: ca-issuer            # Issuer name
        kind: ClusterIssuer        # Issuer kind (Issuer or ClusterIssuer)
        group: cert-manager.io     # Issuer group
```

### Webhook Advanced Configuration

```yaml
extraEnv:
  # Webhook settings
  - name: WEBHOOK_TIMEOUT
    value: "10s"                   # Webhook timeout
  - name: WEBHOOK_FAILURE_POLICY
    value: "Fail"                  # Fail or Ignore
  - name: WEBHOOK_ADMISSION_REVIEW_VERSIONS
    value: "v1,v1beta1"            # Supported admission review versions
  - name: WEBHOOK_SIDE_EFFECTS
    value: "None"                  # Webhook side effects
```

## Ingress Controller Configuration

Configure the ingress controller for standard Kubernetes Ingress support:

```yaml
ingressController:
  enabled: false                   # Enable ingress controller
  className: avapigw              # IngressClass name
  isDefaultClass: false           # Set as default IngressClass
  lbAddress: ""                   # LoadBalancer address for status updates
  
  # Ingress controller behavior
  watchNamespaces: []             # Namespaces to watch (empty = all)
  resyncPeriod: 30s               # Resync period for Ingress resources
  
  # Status update configuration
  statusUpdate:
    enabled: true                 # Enable status updates
    loadBalancer:
      ip: ""                      # Static LoadBalancer IP
      hostname: ""                # Static LoadBalancer hostname
```

### Ingress Controller Advanced Configuration

```yaml
extraEnv:
  # Ingress controller settings
  - name: ENABLE_INGRESS_CONTROLLER
    value: "true"                 # Enable ingress controller
  - name: INGRESS_CLASS_NAME
    value: "avapigw"              # IngressClass name
  - name: INGRESS_DEFAULT_CLASS
    value: "false"                # Set as default IngressClass
  - name: INGRESS_LB_ADDRESS
    value: "192.168.1.100"        # LoadBalancer address
  - name: INGRESS_WATCH_NAMESPACES
    value: "default,production"   # Comma-separated namespaces
  - name: INGRESS_RESYNC_PERIOD
    value: "30s"                  # Resync period
```

### Ingress Controller Examples

#### Basic Ingress Controller Setup

```yaml
# Enable ingress controller with default settings
ingressController:
  enabled: true
  className: avapigw
```

#### Production Ingress Controller Setup

```yaml
# Production setup with LoadBalancer and specific namespaces
ingressController:
  enabled: true
  className: avapigw
  isDefaultClass: false
  lbAddress: "192.168.1.100"
  watchNamespaces:
    - production
    - staging
  statusUpdate:
    enabled: true
    loadBalancer:
      ip: "192.168.1.100"
```

#### Multi-tenant Ingress Controller

```yaml
# Multi-tenant setup with hostname-based LoadBalancer
ingressController:
  enabled: true
  className: avapigw-tenant1
  statusUpdate:
    enabled: true
    loadBalancer:
      hostname: "gateway.tenant1.example.com"
```

## Vault Integration

Configure HashiCorp Vault integration for certificate management:

```yaml
vault:
  enabled: true                    # Enable Vault integration
  address: "https://vault.example.com:8200"  # Vault server address
  
  # Authentication method
  authMethod: kubernetes           # kubernetes, token, approle, aws, gcp
  
  # Kubernetes authentication
  role: avapigw-operator          # Kubernetes auth role
  kubernetesMountPath: kubernetes  # Kubernetes auth mount path
  
  # Token authentication (development only)
  token: ""                        # Vault token
  
  # AppRole authentication
  roleId: ""                       # AppRole role ID
  secretId: ""                     # AppRole secret ID
  approleMountPath: approle        # AppRole mount path
  
  # AWS authentication
  awsRole: ""                      # AWS auth role
  awsMountPath: aws                # AWS auth mount path
  
  # GCP authentication
  gcpRole: ""                      # GCP auth role
  gcpMountPath: gcp                # GCP auth mount path
```

### Vault Configuration Examples

#### Kubernetes Authentication

```yaml
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: avapigw-operator
  kubernetesMountPath: kubernetes

# Service account token will be used automatically
```

#### Token Authentication (Development)

```yaml
vault:
  enabled: true
  address: "http://vault.local:8200"
  authMethod: token
  token: "hvs.CAESIJ..."           # Vault token

# Or use secret reference
extraEnvFrom:
  - secretRef:
      name: vault-token-secret
```

#### AppRole Authentication

```yaml
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: approle
  roleId: "12345678-1234-1234-1234-123456789012"

# Secret ID from secret
extraEnvFrom:
  - secretRef:
      name: vault-approle-secret   # Contains VAULT_SECRET_ID
```

## Monitoring Configuration

Configure Prometheus metrics and monitoring:

```yaml
# Metrics configuration
metrics:
  enabled: true                    # Enable metrics
  port: 8080                       # Metrics port

# Health probes configuration
health:
  port: 8081                       # Health probe port

# ServiceMonitor for Prometheus Operator
serviceMonitor:
  enabled: true                    # Enable ServiceMonitor
  namespace: ""                    # ServiceMonitor namespace (defaults to release namespace)
  labels: {}                       # Additional labels
  interval: 30s                    # Scrape interval
  scrapeTimeout: 10s               # Scrape timeout
  metricRelabelings: []            # Metric relabeling configs
  relabelings: []                  # Relabeling configs
```

### Advanced Monitoring Configuration

```yaml
extraEnv:
  # Metrics settings
  - name: METRICS_BIND_ADDRESS
    value: ":8080"                 # Metrics bind address
  - name: HEALTH_PROBE_BIND_ADDRESS
    value: ":8081"                 # Health probe bind address
  - name: ENABLE_PPROF
    value: "false"                 # Enable pprof endpoints
  - name: PPROF_BIND_ADDRESS
    value: ":6060"                 # pprof bind address
```

## Security Configuration

### RBAC Configuration

The operator requires specific RBAC permissions:

```yaml
# Automatically configured by Helm chart
rbac:
  create: true                     # Create RBAC resources

# Custom RBAC rules (if needed)
extraRbacRules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

### Network Policies

Configure network policies for security:

```yaml
networkPolicy:
  enabled: true                    # Enable network policies
  
  # Ingress rules
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: avapigw-gateways
      ports:
        - protocol: TCP
          port: 9444               # gRPC port
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 8080               # Metrics port
  
  # Egress rules
  egress:
    - to: []                       # Allow all egress (customize as needed)
      ports:
        - protocol: TCP
          port: 443                # HTTPS (Vault, etc.)
        - protocol: TCP
          port: 53                 # DNS
        - protocol: UDP
          port: 53                 # DNS
```

### Pod Security Standards

Configure Pod Security Standards compliance:

```yaml
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  capabilities:
    drop: ["ALL"]

# Pod Security Policy (if using PSP)
podSecurityPolicy:
  enabled: false                   # Enable PSP
  annotations: {}
```

## Environment Variables

### Core Environment Variables

| Variable | Description | Default | Boolean Support |
|----------|-------------|---------|----------------|
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` | N/A |
| `LOG_FORMAT` | Log format (json, console) | `json` | N/A |
| `METRICS_BIND_ADDRESS` | Metrics server bind address | `:8080` | N/A |
| `HEALTH_PROBE_BIND_ADDRESS` | Health probe bind address | `:8081` | N/A |
| `LEADER_ELECT` | Enable leader election | `true` | ✅ |
| `LEADER_ELECT_RESOURCE_NAME` | Leader election resource name | `some_id.avapigw.io` | N/A |

**Boolean Environment Variable Examples:**
```bash
# All equivalent ways to enable leader election
export LEADER_ELECT=true
export LEADER_ELECT=yes
export LEADER_ELECT=1
export LEADER_ELECT=on

# All equivalent ways to disable leader election
export LEADER_ELECT=false
export LEADER_ELECT=no
export LEADER_ELECT=0
export LEADER_ELECT=off
```

### gRPC and Webhook Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GRPC_PORT` | gRPC server port | `9444` |
| `ENABLE_GRPC_SERVER` | Enable the gRPC configuration server (boolean) | `true` |
| `GRPC_REQUIRE_CLIENT_CERT` | Require client certificates (mTLS, boolean) | `false` |
| `WEBHOOK_PORT` | Webhook server port | `9443` |
| `ENABLE_WEBHOOKS` | Enable admission webhooks (boolean) | `true` |
| `WEBHOOK_CERT_DIR` | Directory with webhook TLS certificates (external providers) | `""` |
| `WEBHOOK_CONFIG_NAME` | ValidatingWebhookConfiguration name | `avapigw-operator-validating-webhook-configuration` |
| `ENABLE_CLUSTER_WIDE_DUPLICATE_CHECK` | Cluster-wide duplicate detection (boolean) | `false` |
| `DUPLICATE_CACHE_ENABLED` | Cache duplicate-detection lookups (boolean) | `true` |
| `DUPLICATE_CACHE_TTL` | Duplicate-detection cache TTL | `30s` |

> The gRPC/webhook **TLS provider** is not a dedicated env variable — it is
> the shared `CERT_PROVIDER` (see below), rendered by the Helm chart from
> `operator.webhook.tls.mode` / `operator.grpc.tls.mode` as the
> `--cert-provider` flag.

### Certificate Provider Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERT_PROVIDER` | Certificate provider (`selfsigned`, `vault`, `file`, `cert-manager`) | `selfsigned` |
| `CERT_FILE` | PEM serving certificate path (file provider) | `""` |
| `KEY_FILE` | PEM private key path (file provider) | `""` |
| `CA_FILE` | PEM CA bundle path (file provider, optional) | `""` |
| `CERT_SECRET_NAME` | Secret persisting the selfsigned CA + serving cert (empty disables persistence) | `""` |
| `CERT_SECRET_NAMESPACE` | Namespace of the persistence Secret | `POD_NAMESPACE`, then cert namespace |
| `CERT_SERVICE_NAME` | Service name / certificate CN | `avapigw-operator` |
| `CERT_DNS_NAMES` | Comma-separated SAN override (must cover webhook AND gRPC services) | derived from service name |
| `CERT_NAMESPACE` | Namespace for default certificate DNS names | `avapigw-system` |

### Vault Configuration Variables

The operator's Vault certificate provider authenticates with **Kubernetes
auth only** (ServiceAccount JWT):

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server address | `""` |
| `VAULT_PKI_MOUNT` | Vault PKI mount path | `pki` |
| `VAULT_PKI_ROLE` | Vault PKI role name | `operator` |
| `VAULT_K8S_ROLE` | Vault role for Kubernetes authentication | `""` |
| `VAULT_K8S_MOUNT_PATH` | Kubernetes auth mount path | `kubernetes` |
| `VAULT_INIT_TIMEOUT` | Vault certificate manager init timeout | `30s` |

### Observability Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_TRACING` | Enable OpenTelemetry tracing (boolean) | `false` |
| `OTLP_ENDPOINT` | OTLP exporter endpoint | `""` |
| `TRACING_SAMPLING_RATE` | Trace sampling rate (0.0–1.0) | `1.0` |

### Invalid Values Warn Instead of Being Silently Ignored

Non-string environment overrides (int/float/duration/boolean) that fail to
parse are **logged as warnings** after logger setup (variable name, invalid
value, and the retained fallback) and the flag/default value stays in
effect — parity with the gateway's env handling. Example:
`GRPC_PORT=not-a-number` keeps `9444` and logs
`WARNING: ignoring invalid environment variable value; keeping current setting`.

## Configuration Examples

### Development Configuration

```yaml
# values-dev.yaml
replicaCount: 1

image:
  tag: "latest"
  pullPolicy: Always

resources:
  limits:
    cpu: 200m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

vault:
  enabled: false

grpc:
  tls:
    mode: selfsigned

webhook:
  tls:
    mode: selfsigned

extraEnv:
  - name: LOG_LEVEL
    value: "debug"
  - name: LOG_FORMAT
    value: "console"
```

### Production Configuration

```yaml
# values-prod.yaml
replicaCount: 3

image:
  repository: ghcr.io/vyrodovalexey/avapigw-operator
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi

leaderElection:
  enabled: true

podDisruptionBudget:
  enabled: true
  minAvailable: 2

vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: avapigw-operator

grpc:
  tls:
    mode: vault
    vault:
      pkiMount: pki
      role: operator-server
      commonName: avapigw-operator.avapigw-system.svc
      ttl: 24h

webhook:
  tls:
    mode: vault
    vault:
      pkiMount: pki
      role: webhook
      commonName: avapigw-operator-webhook.avapigw-system.svc
      ttl: 24h

serviceMonitor:
  enabled: true
  interval: 30s

networkPolicy:
  enabled: true

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values: ["avapigw-operator"]
          topologyKey: kubernetes.io/hostname

extraEnv:
  - name: LOG_LEVEL
    value: "info"
  - name: LOG_FORMAT
    value: "json"
```

### Multi-Environment Configuration

```yaml
# values-staging.yaml
replicaCount: 2

vault:
  enabled: true
  address: "https://vault-staging.example.com:8200"
  authMethod: kubernetes
  role: avapigw-operator-staging

grpc:
  tls:
    mode: vault
    vault:
      pkiMount: pki-staging
      role: operator-server-staging

webhook:
  tls:
    mode: vault
    vault:
      pkiMount: pki-staging
      role: webhook-staging

extraEnv:
  - name: ENVIRONMENT
    value: "staging"
  - name: LOG_LEVEL
    value: "debug"
```

### Custom Certificate Configuration

```yaml
# values-custom-certs.yaml
webhook:
  tls:
    mode: cert-manager
    certManager:
      issuerRef:
        name: ca-issuer
        kind: ClusterIssuer

grpc:
  tls:
    mode: vault
    vault:
      pkiMount: custom-pki
      role: custom-operator-role
      commonName: operator.custom.domain
      altNames:
        - operator.custom.domain
        - operator-internal.custom.domain

# Mount custom CA certificates
volumes:
  - name: custom-ca
    configMap:
      name: custom-ca-certs

volumeMounts:
  - name: custom-ca
    mountPath: /etc/ssl/certs/custom
    readOnly: true

extraEnv:
  - name: SSL_CERT_DIR
    value: "/etc/ssl/certs:/etc/ssl/certs/custom"
```

For more configuration examples and advanced setups, see the operator-mode
values overlays shipped with the Helm chart
([`helm/avapigw/values-local.yaml`](../../helm/avapigw/values-local.yaml),
[`helm/avapigw/values-vault-file.yaml`](../../helm/avapigw/values-vault-file.yaml))
and the CRD samples in [`test/crd-samples/`](../../test/crd-samples/).