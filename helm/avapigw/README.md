# Ava API Gateway Helm Chart

High-performance API Gateway built with Go and gin-gonic, with optional Kubernetes operator for CRD-based configuration management.

## Features

- **Gateway**: High-performance HTTP/gRPC API Gateway
- **Operator** (optional): Kubernetes operator for managing gateway configuration through CRDs
- **Ingress Controller** (optional): Standard Kubernetes Ingress support with rich annotations
- **CRDs**: APIRoute, GRPCRoute, Backend, GRPCBackend custom resources

## Deployment Modes

This chart supports three deployment modes:

1. **Gateway-only** (default) - Just the API Gateway without operator
2. **With-operator** - Gateway + Operator for CRD-based configuration management
3. **With-ingress** - Gateway + Operator + Ingress Controller for standard Kubernetes Ingress support

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+

## Installation

### Add the Helm repository (if published)

```bash
helm repo add avapigw https://vyrodovalexey.github.io/avapigw
helm repo update
```

### Install the chart

```bash
# Gateway-only mode (default)
helm install my-gateway avapigw/avapigw

# With operator enabled
helm install my-gateway avapigw/avapigw --set operator.enabled=true

# With ingress controller enabled
helm install my-gateway avapigw/avapigw \
  --set operator.enabled=true \
  --set operator.ingressController.enabled=true
```

### Install from local directory

```bash
# Gateway-only mode
helm install my-gateway ./helm/avapigw

# With operator enabled
helm install my-gateway ./helm/avapigw --set operator.enabled=true

# With ingress controller enabled
helm install my-gateway ./helm/avapigw \
  --set operator.enabled=true \
  --set operator.ingressController.enabled=true
```

### Install with custom values

```bash
helm install my-gateway ./helm/avapigw -f my-values.yaml
```

## Uninstallation

```bash
helm uninstall my-gateway
```

## Configuration

The following table lists the configurable parameters of the avapigw chart and their default values.

### General

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/vyrodovalexey/avapigw` |
| `image.tag` | Image tag | `""` (uses appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |

### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.automount` | Automount API credentials | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |

### Security Context

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsNonRoot` | Run as non-root | `true` |
| `podSecurityContext.runAsUser` | Run as user ID | `1000` |
| `podSecurityContext.runAsGroup` | Run as group ID | `1000` |
| `podSecurityContext.fsGroup` | Filesystem group ID | `1000` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| `securityContext.capabilities.drop` | Drop capabilities | `["ALL"]` |

### Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.httpPort` | HTTP port | `8080` |
| `service.httpsPort` | HTTPS port | `8443` |
| `service.grpcPort` | gRPC port | `9000` |
| `service.grpcTlsPort` | gRPC TLS port | `9443` |
| `service.metricsPort` | Metrics port | `9090` |
| `service.annotations` | Service annotations | `{}` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | `[]` |

### Resources

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

### Probes

| Parameter | Description | Default |
|-----------|-------------|---------|
| `livenessProbe.httpGet.path` | Liveness probe path | `/health` |
| `livenessProbe.httpGet.port` | Liveness probe port | `metrics` |
| `livenessProbe.initialDelaySeconds` | Initial delay | `10` |
| `livenessProbe.periodSeconds` | Period | `15` |
| `readinessProbe.httpGet.path` | Readiness probe path | `/ready` |
| `readinessProbe.httpGet.port` | Readiness probe port | `metrics` |
| `readinessProbe.initialDelaySeconds` | Initial delay | `5` |
| `readinessProbe.periodSeconds` | Period | `10` |

### Autoscaling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `1` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target memory utilization | `80` |

### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PDB | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

### Gateway Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `gateway.logLevel` | Log level | `info` |
| `gateway.logFormat` | Log format | `json` |
| `gateway.environment` | Environment name | `production` |
| `gateway.listeners.http.enabled` | Enable HTTP listener | `true` |
| `gateway.listeners.http.port` | HTTP listener port | `8080` |
| `gateway.listeners.grpc.enabled` | Enable gRPC listener | `false` |
| `gateway.listeners.grpc.port` | gRPC listener port | `9000` |
| `gateway.listeners.grpc.tls.enabled` | Enable TLS for gRPC listener | `false` |
| `gateway.listeners.grpc.tls.port` | gRPC TLS listener port | `9443` |
| `gateway.listeners.grpc.tls.mode` | gRPC TLS mode (SIMPLE, MUTUAL, OPTIONAL_MUTUAL, INSECURE) | `SIMPLE` |
| `gateway.rateLimit.enabled` | Enable rate limiting | `true` |
| `gateway.rateLimit.requestsPerSecond` | Requests per second | `100` |
| `gateway.rateLimit.burst` | Burst size | `200` |
| `gateway.circuitBreaker.enabled` | Enable circuit breaker | `true` |
| `gateway.circuitBreaker.threshold` | Failure threshold | `5` |
| `gateway.maxSessions.enabled` | Enable max sessions limiting | `false` |
| `gateway.maxSessions.maxConcurrent` | Maximum concurrent sessions | `10000` |
| `gateway.maxSessions.queueSize` | Queue size for pending requests | `1000` |
| `gateway.maxSessions.queueTimeout` | Timeout for queued requests | `30s` |
| `gateway.observability.metrics.enabled` | Enable metrics | `true` |
| `gateway.observability.tracing.enabled` | Enable tracing | `false` |

### Audit Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `gateway.audit.enabled` | Enable audit logging | `true` |
| `gateway.audit.output` | Audit output destination (stdout, stderr, file path) | `stdout` |
| `gateway.audit.format` | Audit log format (json, text) | `json` |
| `gateway.audit.level` | Minimum audit level (debug, info, warn, error) | `info` |
| `gateway.audit.events.authentication` | Audit authentication events | `true` |
| `gateway.audit.events.authorization` | Audit authorization events | `true` |
| `gateway.audit.events.request` | Audit request events | `false` |
| `gateway.audit.events.response` | Audit response events | `false` |
| `gateway.audit.events.configuration` | Audit configuration changes | `true` |
| `gateway.audit.events.security` | Audit security events | `true` |
| `gateway.audit.skipPaths` | Paths to skip from auditing | `["/health", "/metrics", "/ready", "/live"]` |
| `gateway.audit.redactFields` | Fields to redact from audit logs | `["password", "secret", "token", "authorization", "cookie"]` |

### Redis (Bitnami Subchart)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redis.enabled` | Enable Redis | `false` |
| `redis.architecture` | Redis architecture | `standalone` |
| `redis.auth.enabled` | Enable Redis auth | `true` |
| `redis.auth.password` | Redis password | `""` |
| `redis.master.persistence.enabled` | Enable persistence | `false` |

### Vault Integration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vault.enabled` | Enable Vault | `false` |
| `vault.address` | Vault address | `""` |
| `vault.authMethod` | Auth method | `kubernetes` |
| `vault.role` | Vault role | `""` |
| `vault.pki.enabled` | Enable Vault PKI for listener TLS | `false` |
| `vault.pki.pkiMount` | Vault PKI mount path | `pki` |
| `vault.pki.role` | Vault PKI role name | `gateway-server` |
| `vault.pki.commonName` | Certificate common name | `gateway.example.com` |
| `vault.pki.altNames` | Certificate alternative names | `[]` |
| `vault.pki.ttl` | Certificate TTL | `24h` |
| `vault.pki.renewBefore` | Renew before expiry | `1h` |
| `vault.pki.grpc.enabled` | Enable Vault PKI for gRPC listener TLS | `false` |
| `vault.pki.grpc.pkiMount` | gRPC-specific PKI mount path | `""` (uses main pkiMount) |
| `vault.pki.grpc.role` | gRPC-specific PKI role | `""` (uses main role) |
| `vault.pki.grpc.commonName` | gRPC certificate common name | `""` (uses main commonName) |
| `vault.pki.grpc.ttl` | gRPC certificate TTL | `""` (uses main ttl) |

### Keycloak Integration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keycloak.enabled` | Enable Keycloak | `false` |
| `keycloak.url` | Keycloak URL | `""` |
| `keycloak.realm` | Keycloak realm | `""` |
| `keycloak.clientId` | Client ID | `""` |

### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |

### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Enable NetworkPolicy | `false` |
| `networkPolicy.ingress` | Ingress rules | `[]` |
| `networkPolicy.egress` | Egress rules | `[]` |

### Operator Configuration

The operator enables Kubernetes-native configuration management through CRDs with comprehensive RBAC permissions, automated certificate management, and enhanced webhook validation. When enabled, you can manage routes and backends using APIRoute, GRPCRoute, Backend, and GRPCBackend custom resources.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.enabled` | Enable the avapigw operator | `false` |
| `operator.replicaCount` | Number of operator replicas | `1` |
| `operator.image.repository` | Operator image repository | `ghcr.io/vyrodovalexey/avapigw-operator` |
| `operator.image.tag` | Operator image tag | `""` (uses appVersion) |
| `operator.image.pullPolicy` | Operator image pull policy | `IfNotPresent` |
| `operator.leaderElection.enabled` | Enable leader election | `true` |
| `operator.leaderElection.resourceName` | Leader election resource name | `avapigw-operator-leader` |
| `operator.grpc.port` | gRPC ConfigurationService server port | `9444` |
| `operator.grpc.tls.mode` | gRPC TLS mode (selfsigned, vault, cert-manager) | `selfsigned` |
| `operator.grpc.gracefulShutdownTimeout` | gRPC server graceful shutdown timeout | `30s` |
| `operator.grpc.keepalive.time` | gRPC keepalive time | `30s` |
| `operator.grpc.keepalive.timeout` | gRPC keepalive timeout | `10s` |
| `operator.webhook.enabled` | Enable admission webhooks | `true` |
| `operator.webhook.port` | Webhook server port | `9443` |
| `operator.webhook.tls.mode` | Webhook TLS mode (selfsigned, vault, cert-manager) | `selfsigned` |
| `operator.webhook.failurePolicy` | Webhook failure policy (Fail, Ignore) | `Fail` |
| `operator.webhook.caInjection.enabled` | Enable automatic CA injection | `true` |
| `operator.webhook.caInjection.refreshInterval` | CA injection refresh interval | `1h` |
| `operator.metrics.enabled` | Enable Prometheus metrics | `true` |
| `operator.metrics.port` | Metrics server port | `8080` |
| `operator.health.port` | Health probe port | `8081` |
| `operator.resources.limits.cpu` | CPU limit | `500m` |
| `operator.resources.limits.memory` | Memory limit | `256Mi` |
| `operator.resources.requests.cpu` | CPU request | `100m` |
| `operator.resources.requests.memory` | Memory request | `128Mi` |
| `operator.serviceAccount.create` | Create operator service account | `true` |
| `operator.serviceAccount.name` | Operator service account name | `""` (auto-generated) |
| `operator.rbac.create` | Create RBAC resources | `true` |
| `operator.rbac.clusterRole` | Create ClusterRole for operator | `true` |
| `operator.podDisruptionBudget.enabled` | Enable operator PDB | `false` |
| `operator.serviceMonitor.enabled` | Enable operator ServiceMonitor | `false` |

### Certificate Management Configuration

The operator supports three certificate management modes for webhook validation and gRPC communication.

#### Self-Signed Mode (Default)
| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.webhook.tls.mode` | Certificate mode | `selfsigned` |
| `operator.webhook.tls.validity` | Certificate validity period | `8760h` |
| `operator.webhook.tls.keySize` | Private key size | `2048` |
| `operator.webhook.tls.organization` | Certificate organization | `AVAPIGW` |
| `operator.webhook.tls.country` | Certificate country | `US` |

#### Vault PKI Mode
| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.webhook.tls.mode` | Certificate mode | `vault` |
| `vault.enabled` | Enable Vault integration | `false` |
| `vault.address` | Vault server address | `""` |
| `vault.authMethod` | Vault auth method | `kubernetes` |
| `vault.role` | Vault role for operator | `""` |
| `vault.pki.enabled` | Enable Vault PKI for operator certs | `false` |
| `vault.pki.pkiMount` | Vault PKI mount path | `pki` |
| `vault.pki.role` | Vault PKI role name | `operator-certs` |
| `vault.pki.commonName` | Certificate common name | `avapigw-operator-webhook.avapigw-system.svc` |
| `vault.pki.altNames` | Certificate alternative names | `[]` |
| `vault.pki.ttl` | Certificate TTL | `24h` |
| `vault.pki.renewBefore` | Renew before expiry | `1h` |

#### Cert-Manager Mode
| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.webhook.tls.mode` | Certificate mode | `cert-manager` |
| `operator.webhook.tls.certificateName` | Certificate resource name | `""` (auto-detected) |
| `operator.webhook.tls.secretName` | Secret name for certificates | `avapigw-operator-webhook-certs` |

### Ingress Controller Configuration

The ingress controller enables the operator to watch standard Kubernetes Ingress resources and translate them into APIRoute/Backend configuration.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.ingressController.enabled` | Enable ingress controller mode | `false` |
| `operator.ingressController.className` | IngressClass name | `avapigw` |
| `operator.ingressController.isDefaultClass` | Set as default IngressClass | `false` |
| `operator.ingressController.lbAddress` | LoadBalancer address for Ingress status updates | `""` |

## Examples

### Enable gRPC with TLS

```yaml
gateway:
  listeners:
    grpc:
      enabled: true
      port: 9000
      tls:
        enabled: true
        port: 9443
        mode: SIMPLE
        # Use static certificates
        certFile: /app/certs/grpc/tls.crt
        keyFile: /app/certs/grpc/tls.key
        minVersion: "1.2"

# Or use Vault PKI for gRPC TLS
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: gateway-role
  pki:
    enabled: true
    pkiMount: pki
    role: gateway-server
    commonName: gateway.example.com
    altNames:
      - grpc.example.com
      - "*.grpc.example.com"
    ttl: 24h
    renewBefore: 1h
    grpc:
      enabled: true
      pkiMount: pki-grpc
      role: grpc-server
      commonName: grpc.example.com
      ttl: 12h
```

### Enable Redis

```yaml
redis:
  enabled: true
  auth:
    enabled: true
    password: "my-redis-password"
  master:
    persistence:
      enabled: true
      size: 1Gi
```

### Enable Autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### Enable Ingress with TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
          port: http
  tls:
    - secretName: api-tls
      hosts:
        - api.example.com
```

### Enable Max Sessions (Global)

```yaml
gateway:
  maxSessions:
    enabled: true
    maxConcurrent: 10000
    queueSize: 1000
    queueTimeout: 30s
```

### Enable Audit Logging

```yaml
gateway:
  audit:
    enabled: true
    output: stdout
    format: json
    level: info
    events:
      authentication: true
      authorization: true
      request: true
      response: false
      configuration: true
      security: true
    skipPaths:
      - /health
      - /metrics
    redactFields:
      - password
      - secret
      - token
```

### Backend with Rate Limiting and Max Sessions

```yaml
gateway:
  backends:
    - name: api-backend
      hosts:
        - address: backend.example.com
          port: 8080
      maxSessions:
        enabled: true
        maxConcurrent: 500
        queueSize: 50
        queueTimeout: 10s
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
      circuitBreaker:
        enabled: true
        threshold: 5
        timeout: 30s
```

### Route with Max Sessions

```yaml
gateway:
  routes:
    - name: api-route
      match:
        - uri:
            prefix: /api/v1
          methods:
            - GET
            - POST
      route:
        - destination:
            host: backend-service
            port: 8080
      timeout: 30s
      maxSessions:
        enabled: true
        maxConcurrent: 500
        queueSize: 50
        queueTimeout: 10s
```

### Local Kubernetes Deployment

Deploy to local Kubernetes (Docker Desktop) with TLS and performance testing support:

```yaml
# values-local.yaml
namespace: avapigw-test

replicaCount: 1

image:
  repository: avapigw
  pullPolicy: Never
  tag: "test"

service:
  type: NodePort
  httpPort: 8080
  httpsPort: 8443
  grpcPort: 9000
  grpcTlsPort: 9443
  metricsPort: 9090

gateway:
  logLevel: info
  environment: local-k8s
  
  listeners:
    http:
      enabled: true
      port: 8080
    grpc:
      enabled: true
      port: 9000
      tls:
        enabled: true
        port: 9443

  routes:
    - name: items-api
      match:
        - uri:
            prefix: /api/v1/items
      route:
        - destination:
            host: host.docker.internal
            port: 8801
          weight: 50
        - destination:
            host: host.docker.internal
            port: 8802
          weight: 50

  grpcRoutes:
    - name: test-service-route
      match:
        - service:
            exact: api.v1.TestService
      route:
        - destination:
            host: host.docker.internal
            port: 8803

vault:
  enabled: true
  address: "http://host.docker.internal:8200"
  authMethod: kubernetes
  role: avapigw
  pki:
    enabled: true
    pkiMount: "pki"
    role: "test-role"
    commonName: "avapigw.local"
    altNames:
      - "localhost"
      - "*.avapigw.local"
    ttl: "24h"
    grpc:
      enabled: true
```

Deploy with:
```bash
# Build local image
make docker-build

# Setup Vault for K8s
./test/performance/scripts/setup-vault-k8s.sh --namespace=avapigw-test

# Deploy to K8s
helm upgrade --install avapigw helm/avapigw/ \
  -f helm/avapigw/values-local.yaml \
  -n avapigw-test --create-namespace

# Run performance tests
make perf-test-k8s
```

### Enable Operator with CRD-based Configuration

```yaml
# Enable the operator for CRD-based configuration management
operator:
  enabled: true
  replicaCount: 1
  
  # Webhook validation (optional)
  webhook:
    enabled: true
    tls:
      mode: selfsigned
  
  # Leader election for HA
  leaderElection:
    enabled: true
    resourceName: some_id.avapigw.io
  
  # Resources
  resources:
    limits:
      cpu: 500m
      memory: 256Mi
    requests:
      cpu: 100m
      memory: 128Mi
```

### Enable Ingress Controller

```yaml
# Enable ingress controller for standard Kubernetes Ingress support
operator:
  enabled: true
  ingressController:
    enabled: true
    className: "avapigw"
    isDefaultClass: false
    lbAddress: "192.168.1.100"  # Optional LoadBalancer IP for status updates
```

After deploying with operator enabled, you can create CRDs:

```yaml
# Example APIRoute CRD
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: example-route
spec:
  match:
    - uri:
        prefix: /api/v1
      methods:
        - GET
        - POST
  route:
    - destination:
        host: backend-service
        port: 8080
  timeout: 30s
```

```yaml
# Example Backend CRD
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: example-backend
spec:
  hosts:
    - address: backend-service.default.svc.cluster.local
      port: 8080
      weight: 1
  healthCheck:
    path: /health
    interval: 10s
    timeout: 5s
  loadBalancer:
    algorithm: roundRobin
```

After deploying with ingress controller enabled, you can also use standard Kubernetes Ingress resources:

```yaml
# Example Ingress resource
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    avapigw.io/timeout: "30s"
    avapigw.io/retries: "3"
    avapigw.io/rate-limit-rps: "100"
    avapigw.io/cors-allow-origins: "https://example.com"
spec:
  ingressClassName: avapigw
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls
```

### Production Configuration

```yaml
replicaCount: 3

resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2

gateway:
  logLevel: info
  environment: production
  rateLimit:
    enabled: true
    requestsPerSecond: 1000
    burst: 2000
  circuitBreaker:
    enabled: true
    threshold: 10
    timeout: 60s

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: avapigw
          topologyKey: kubernetes.io/hostname
```

## Upgrading

### To 0.4.0

Added new features and improvements:
- **HTTP Flusher support** - All response writer wrappers now implement http.Flusher for streaming/SSE/WebSocket support
- **Config reload race fix** - Gateway config now uses atomic.Pointer for lock-free concurrent access
- **Hot-reload completion** - Rate limiter, max sessions, router, and backends now properly reload on config change
- **Circuit breaker limitation** - Circuit breaker does NOT support runtime reconfiguration (documented limitation)
- **gRPC hot-reload limitation** - gRPC routes do NOT support hot-reload in file-based mode (only in operator mode), but gRPC backends ARE hot-reloaded in both modes
- **TLS deprecation warnings** - ValidateConfigWithWarnings() API now warns about TLS 1.0/1.1 usage
- **gRPC plaintext warning** - Gateway logs warning when gRPC listener runs without TLS
- **WebSocket proxy fixes** - Fixed hop-by-hop header handling for WebSocket connections
- **gRPC PKI default change** - gRPC PKI enabled default changed to false for security
- **Vault TLS improvements** - Enhanced TLS manager fallback error handling
- **Helm deployment fixes** - Fixed port exposure for TLS, gRPC PKI ternary logic, service port mismatch
- **Audit trace context** - Audit events now include TraceID and SpanID when tracing is enabled
- **Metrics cardinality fix** - Prometheus metrics now use "route" label instead of "path" to prevent cardinality explosion
- **Retry deduplication** - internal/retry package is now the single source of truth for exponential backoff
- **X-Forwarded-For security** - New TrustedProxies configuration option with secure defaults
- **Gateway sentinel errors** - ErrGatewayNotStopped, ErrGatewayNotRunning, ErrNilConfig, ErrInvalidConfig
- **Complete documentation** - All 33 internal packages now have doc.go files
- **Helm chart fixes** - Fixed .helmignore excluding test hooks, fixed wget in test-connection.yaml for read-only filesystem

### To 0.3.0

**Major Changes:**
- **Operator Consolidation**: The `avapigw-operator` chart has been merged into the main `avapigw` chart
- Operator is now an optional feature controlled by `operator.enabled` (default: `false`)
- CRDs are included in the chart and installed when operator is enabled
- All operator templates are now in `templates/operator/` directory

**Migration from separate operator chart:**
1. Uninstall the old operator chart: `helm uninstall avapigw-operator -n <namespace>`
2. Update to the new unified chart with `operator.enabled: true`
3. CRDs will be automatically installed

Added improvements:
- Enhanced timer leak prevention in configuration watcher
- Shared error types for consistent circuit breaker behavior
- Improved Docker image security and optimization
- Enhanced CI health checks and reliability

### To 0.2.0

Added new features:
- Global max sessions configuration (`gateway.maxSessions`)
- Route-level max sessions configuration
- Backend-level max sessions configuration
- Backend-level rate limiting configuration

### To 0.1.0

Initial release.

## License

MIT License - see [LICENSE](https://github.com/vyrodovalexey/avapigw/blob/main/LICENSE) for details.
