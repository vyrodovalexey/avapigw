# Ava API Gateway Helm Chart

High-performance API Gateway built with Go and gin-gonic.

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
helm install my-gateway avapigw/avapigw
```

### Install from local directory

```bash
helm install my-gateway ./helm/avapigw
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
| `service.grpcPort` | gRPC port | `9000` |
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

## Examples

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

### To 0.3.0

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
