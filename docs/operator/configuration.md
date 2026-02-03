# AVAPIGW Operator Configuration Guide

This guide covers all configuration options for the AVAPIGW Operator, including deployment configuration, runtime settings, and integration options.

## Table of Contents

- [Overview](#overview)
- [Deployment Configuration](#deployment-configuration)
- [Operator Configuration](#operator-configuration)
- [gRPC Server Configuration](#grpc-server-configuration)
- [Webhook Configuration](#webhook-configuration)
- [Vault Integration](#vault-integration)
- [Monitoring Configuration](#monitoring-configuration)
- [Security Configuration](#security-configuration)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## Overview

The AVAPIGW Operator can be configured through multiple methods:

1. **Helm Values** - Primary configuration method for deployment
2. **Environment Variables** - Runtime configuration and overrides
3. **Command Line Flags** - Direct operator configuration
4. **ConfigMaps** - External configuration files
5. **Secrets** - Sensitive configuration data

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

```yaml
extraEnv:
  # gRPC server settings
  - name: GRPC_MAX_RECV_MSG_SIZE
    value: "4194304"               # 4MB max receive message size
  - name: GRPC_MAX_SEND_MSG_SIZE
    value: "4194304"               # 4MB max send message size
  - name: GRPC_MAX_CONCURRENT_STREAMS
    value: "100"                   # Max concurrent streams
  - name: GRPC_KEEPALIVE_TIME
    value: "30s"                   # Keepalive time
  - name: GRPC_KEEPALIVE_TIMEOUT
    value: "10s"                   # Keepalive timeout
  - name: GRPC_MAX_CONNECTION_IDLE
    value: "5m"                    # Max connection idle time
  - name: GRPC_MAX_CONNECTION_AGE
    value: "30m"                   # Max connection age
  - name: GRPC_MAX_CONNECTION_AGE_GRACE
    value: "5s"                    # Max connection age grace
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

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |
| `LOG_FORMAT` | Log format (json, console) | `json` |
| `METRICS_BIND_ADDRESS` | Metrics server bind address | `:8080` |
| `HEALTH_PROBE_BIND_ADDRESS` | Health probe bind address | `:8081` |
| `LEADER_ELECT` | Enable leader election | `true` |
| `LEADER_ELECT_RESOURCE_NAME` | Leader election resource name | `some_id.avapigw.io` |

### gRPC Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GRPC_PORT` | gRPC server port | `9444` |
| `GRPC_TLS_MODE` | TLS mode (selfsigned, vault) | `selfsigned` |
| `GRPC_MAX_RECV_MSG_SIZE` | Max receive message size | `4194304` |
| `GRPC_MAX_SEND_MSG_SIZE` | Max send message size | `4194304` |
| `GRPC_MAX_CONCURRENT_STREAMS` | Max concurrent streams | `100` |

### Webhook Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WEBHOOK_PORT` | Webhook server port | `9443` |
| `WEBHOOK_TLS_MODE` | TLS mode (selfsigned, vault, cert-manager) | `selfsigned` |
| `WEBHOOK_TIMEOUT` | Webhook timeout | `10s` |
| `WEBHOOK_FAILURE_POLICY` | Failure policy (Fail, Ignore) | `Fail` |

### Vault Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server address | `""` |
| `VAULT_AUTH_METHOD` | Authentication method | `kubernetes` |
| `VAULT_ROLE` | Vault role | `""` |
| `VAULT_TOKEN` | Vault token (dev only) | `""` |
| `VAULT_KUBERNETES_MOUNT_PATH` | Kubernetes auth mount path | `kubernetes` |
| `VAULT_APPROLE_MOUNT_PATH` | AppRole auth mount path | `approle` |
| `VAULT_ROLE_ID` | AppRole role ID | `""` |
| `VAULT_SECRET_ID` | AppRole secret ID | `""` |

### Reconciliation Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RECONCILE_TIMEOUT` | Max reconciliation time | `10m` |
| `RECONCILE_WORKERS` | Number of worker goroutines | `5` |
| `RECONCILE_RATE_LIMIT_QPS` | Rate limit QPS | `20` |
| `RECONCILE_RATE_LIMIT_BURST` | Rate limit burst | `30` |

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

For more configuration examples and advanced setups, see the [examples/operator/](../../examples/operator/) directory.