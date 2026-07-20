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

> **Values schema:** the chart ships a regenerated `values.schema.json`
> covering every values key (gateway `operatorMode`/`observability`/`cors`/
> `security`/`requestLimits`/`customConfig`/gRPC/GraphQL blocks, `tls`,
> `redisEnv`, and all operator-side keys) with top-level
> `additionalProperties: false` — misspelled keys are rejected at
> `helm install`/`upgrade`/`lint` time instead of being silently ignored.
> The gateway's own config-file schema lives at
> `pkg/schema/gateway.schema.json` (full `spec` coverage, listener protocols
> `HTTP`/`HTTPS`/`HTTP2`/`GRPC`/`GRAPHQL`).

### General

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/vyrodovalexey/avapigw` |
| `image.tag` | Image tag | `""` (uses appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets (merged and de-duplicated with `operator.imagePullSecrets` into a single `imagePullSecrets` key on the operator pod) | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |

> **Distroless runtime images:** both the gateway and operator images are
> built on `gcr.io/distroless/static-debian12:nonroot` and run as the
> distroless `nonroot` user (UID/GID 65532). There is **no shell** in the
> containers — use `kubectl debug` with an ephemeral container instead of
> `kubectl exec`. Health is covered by the chart's HTTP probes (the
> container-level Docker `HEALTHCHECK` was removed); the chart's helm test
> probes from a separate busybox pod.

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
| `gateway.operatorMode.enabled` | Connect to the operator's gRPC ConfigurationService for CRD-based configuration | `false` |
| `gateway.operatorMode.tls` | Use TLS for the operator connection | `true` |
| `gateway.operatorMode.tlsInsecure` | Skip TLS certificate verification (dev/test only) | `false` |
| `gateway.operatorMode.caSecret` | Secret with the operator CA (`ca.crt`). Empty mounts the chart-managed `<operator-fullname>-grpc-cert` Secret (see [Operator gRPC TLS](#operator-grpc-tls-and-ca-management)) | `""` |
| `gateway.listeners.http.enabled` | Enable HTTP listener | `true` |
| `gateway.listeners.http.port` | HTTP listener port | `8080` |
| `gateway.listeners.http.plainAlongsideTls` | Render an ADDITIONAL plain HTTP listener (`http-plain`, same port) alongside the TLS HTTP listener when TLS is active — local/perf convenience; ignored when the HTTP listener is already plaintext | `false` |
| `gateway.listeners.grpc.enabled` | Enable gRPC listener | `false` |
| `gateway.listeners.grpc.port` | gRPC listener port | `9000` |
| `gateway.listeners.grpc.tls.enabled` | Enable TLS for gRPC listener | `false` |
| `gateway.listeners.grpc.tls.port` | gRPC TLS listener port | `9443` |
| `gateway.listeners.grpc.tls.mode` | gRPC TLS mode (SIMPLE, MUTUAL, OPTIONAL_MUTUAL, INSECURE) | `SIMPLE` |
| `gateway.rateLimit.enabled` | Enable rate limiting | `true` |
| `gateway.rateLimit.requestsPerSecond` | Requests per second | `100` |
| `gateway.rateLimit.burst` | Burst size (must be >= 1) | `200` |
| `gateway.rateLimit.perClient` | Per-client (IP) rate limiting | `true` |
| `gateway.circuitBreaker.enabled` | Enable circuit breaker | `true` |
| `gateway.circuitBreaker.threshold` | Failure threshold | `5` |
| `gateway.maxSessions.enabled` | Enable max sessions limiting | `false` |
| `gateway.maxSessions.maxConcurrent` | Maximum concurrent sessions | `10000` |
| `gateway.maxSessions.queueSize` | Queue size for pending requests | `1000` |
| `gateway.maxSessions.queueTimeout` | Timeout for queued requests | `30s` |
| `gateway.observability.metrics.enabled` | Enable metrics | `true` |
| `gateway.observability.tracing.enabled` | Enable tracing | `false` |
| `gateway.observability.tracing.otlpEndpoint` | OTLP gRPC endpoint for trace export | `""` |
| `gateway.observability.tracing.otlpInsecure` | OTLP transport (tri-state): `null` (unset) derives the transport — TLS material forces TLS, plaintext only for unset/loopback endpoints, remote endpoints default to TLS with system roots; `true` forces plaintext; `false` forces TLS. The key is rendered into the config only when explicitly set | `null` |
| `gateway.observability.tracing.otlpTLS.certFile` | Client certificate (PEM) for mTLS to the collector (requires `keyFile`; paths must be mounted) | `""` |
| `gateway.observability.tracing.otlpTLS.keyFile` | Client private key (PEM) for mTLS (requires `certFile`) | `""` |
| `gateway.observability.tracing.otlpTLS.caFile` | PEM CA bundle verifying the collector certificate (empty = system trust store) | `""` |
| `gateway.vault` | Gateway-wide Vault client connection rendered verbatim as `spec.vault` in the generated config (see [Vault Integration](#vault-integration)) | `{}` |

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
| `vault.injectEnv` | Inject `VAULT_*` environment variables into the gateway deployment. Set `false` to source the Vault client connection solely from `gateway.vault` (`spec.vault`); PKI issuance (`vault.pki`) is unaffected | `true` |
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

#### File-based Vault client configuration (`gateway.vault`)

The gateway config file supports a `spec.vault` section for the gateway-wide
Vault client connection. Set `gateway.vault` to render it verbatim into the
generated ConfigMap:

```yaml
gateway:
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: kubernetes
    kubernetes:
      role: avapigw
    cache:
      enabled: true
      ttl: 5m
```

Semantics:

- **Precedence**: deployment-injected `VAULT_*` environment variables (driven
  by the top-level `vault.*` values) override `spec.vault` fields per-field
  (ENV > config file > defaults), so existing env-driven deployments are
  unaffected.
- When `gateway.vault` is set, it **replaces** the legacy `spec.vault` block
  derived from the top-level `vault.*` values in the rendered ConfigMap.
- `gateway.vault` does **not** by itself change `VAULT_*` env injection or Vault
  PKI listener TLS; those remain driven by the top-level `vault.*` values.
- Do not add a `vault` key under `gateway.customConfig` — it would produce a
  duplicate YAML mapping key, which the gateway rejects at startup.

##### File-only Vault client (`vault.injectEnv: false`)

By default the deployment injects `VAULT_*` environment variables (gated on
`vault.enabled` and `vault.injectEnv`), and those override `spec.vault` fields
per-field. To source the Vault client connection **purely from the file
section**, set `vault.injectEnv: false` so no `VAULT_*` env is injected, and
express the whole client in `gateway.vault`:

```yaml
vault:
  enabled: true
  injectEnv: false          # suppress VAULT_* env injection

gateway:
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: kubernetes
    kubernetes:
      role: avapigw
```

With no `VAULT_*` env present, the environment overlay is a no-op, so the
effective Vault configuration is exactly what `gateway.vault` renders. The
chart ships `values-vault-file.yaml` as a complete example of this pattern.
`vault.injectEnv: false` suppresses only the `VAULT_*` env; Vault PKI listener
TLS (`vault.pki`) is unaffected.

##### Legacy `spec.vault` block and tokens

When `gateway.vault` is **not** set and the top-level `vault.*` values are
enabled, the chart renders a legacy `spec.vault` block derived from those
values. The gateway merges this file config with the injected `VAULT_*`
environment variables **per-field** (ENV > config file > defaults), so with
`vault.injectEnv: true` (default) the injected env stays authoritative.

With `vault.authMethod: token`, the token is **no longer rendered into the
ConfigMap** (older chart versions emitted a literal `token: ${VAULT_TOKEN}`
line, which triggered inline-token warnings at boot): the token reaches the
gateway solely as the `VAULT_TOKEN` env variable from the
`<fullname>-vault` Secret. To source a token from the filesystem instead,
use `gateway.vault` with `tokenFile`.

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
| `operator.grpc.requireClientCert` | Require client certificates for gRPC connections (mTLS) | `false` |
| `operator.grpc.tls.mode` | gRPC TLS mode (selfsigned, vault) | `selfsigned` |
| `operator.grpc.tls.caBundle` | PEM CA bundle verifying the operator's gRPC serving certificate; stored as `ca.crt` in the `<operator-fullname>-grpc-cert` Secret. Required for a verified chain with `mode=vault` (set to the Vault PKI CA); `mode=selfsigned` needs no caBundle (see [Operator gRPC TLS](#operator-grpc-tls-and-ca-management)) | `""` |
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

The operator supports multiple certificate management modes for webhook
validation and gRPC communication. One certificate manager serves **both**
servers: the chart renders the operator's `--cert-provider` flag from
`operator.webhook.tls.mode` (when webhooks are enabled) or
`operator.grpc.tls.mode`, and passes the certificate identity
(`CERT_SERVICE_NAME`/`CERT_DNS_NAMES`) with SANs covering **both** the
webhook and operator gRPC services (FQDN forms in vault mode, so PKI roles
restricted to `svc` domains work).

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

In vault mode the operator authenticates with Kubernetes auth, issues its
serving certificate from the PKI mount, rotates it in place before expiry,
and injects the **PKI CA PEM** into the ValidatingWebhookConfiguration (no
probe-certificate issuance, so restrictive PKI roles work). The webhook
certificate volume is an `emptyDir` in vault mode (like selfsigned) — the
operator writes its own certificates.

#### Cert-Manager Mode
| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.webhook.tls.mode` | Certificate mode | `cert-manager` |
| `operator.webhook.tls.certificateName` | Certificate resource name | `""` (auto-detected) |
| `operator.webhook.tls.secretName` | Secret name for certificates | `avapigw-operator-webhook-certs` |

With `cert-manager` (and the operator's `file` cert provider), certificates
are provisioned externally: the operator serves whatever is mounted at the
webhook cert dir and controller-runtime watches the files for rotation.

### Operator gRPC TLS and CA Management

With `operator.enabled` + `gateway.operatorMode.enabled`, the gateway
verifies the operator's gRPC serving certificate against a CA Secret — and
the chart now guarantees that Secret exists, so the **secure default
(`tls: true`, `tlsInsecure: false`) works out of the box**:

1. **CA Secret provisioning** (`templates/operator/grpc-cert-secret.yaml`,
   rendered when TLS is on, not insecure, and no
   `gateway.operatorMode.caSecret` override):
   - `operator.grpc.tls.caBundle` set → stored verbatim as `ca.crt`
     (e.g. the Vault PKI CA);
   - otherwise an **existing** `<operator-fullname>-grpc-cert` Secret is
     reused via `lookup` — **upgrades do not rotate the CA**;
   - otherwise Helm generates a CA + signed serving cert (`genCA`/
     `genSignedCert`; `ca.crt`/`ca.key`/`tls.crt`/`tls.key`, SANs covering
     the operator and webhook services).
2. **Operator-side persistence/adoption** (selfsigned provider): the chart
   sets `CERT_SECRET_NAME=<operator-fullname>-grpc-cert` so the operator
   **adopts** the Helm-seeded CA (or its own previously persisted one) and
   persists rotated serving certificates back to the Secret. The CA is
   therefore **stable across operator restarts** and the gateway keeps
   verifying successfully. RBAC for the Secret writes comes from the
   namespaced `templates/operator/cert-secret-role.yaml` (rendered only for
   the selfsigned provider).
3. **Gateway mount**: the gateway deployment mounts `ca.crt` from
   `gateway.operatorMode.caSecret`, defaulting to the chart-managed
   `<operator-fullname>-grpc-cert` Secret.

For `operator.grpc.tls.mode=vault`, set `operator.grpc.tls.caBundle` to the
Vault PKI CA PEM (or point `gateway.operatorMode.caSecret` at a Secret
containing it — `values-local.yaml` uses the `avapigw-vault-pki-ca` Secret
created by `test/performance/scripts/setup-vault-k8s.sh --setup-pki`). The
PKI CA is stable across operator restarts by construction.

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
# Build BOTH local images matching values-local.yaml
# (avapigw:test + avapigw-operator:latest)
make docker-build-local

# Load the images into the cluster's container runtime. Detects
# kind / minikube / classic docker-desktop / containerd-backed nodes
# (kind-based Docker Desktop clusters do NOT share the docker daemon's
# image store — this target streams `docker save` into the node's
# containerd via a helper pod).
make k8s-load-images

# Setup Vault for K8s (kubernetes auth roles avapigw/avapigw-operator,
# PKI test-role incl. the `svc` domain, and the avapigw-vault-pki-ca Secret)
./test/performance/scripts/setup-vault-k8s.sh --namespace=avapigw-test --setup-pki

# Deploy to K8s (operator + gateway in operator mode)
make helm-install-with-operator
# equivalent to:
# helm upgrade --install avapigw helm/avapigw/ \
#   -f helm/avapigw/values-local.yaml \
#   -n avapigw-test --create-namespace

# Run performance tests
make perf-test-k8s
```

Notes on `values-local.yaml`:

- The **operator and its validating webhook are enabled by default**
  (`operator.webhook.enabled: true`), matching the production posture — CR
  creates/updates are validated locally exactly as they would be in
  production. Since the admission-lifecycle fix, the webhook never blocks
  finalizer removal, so it is safe to keep enabled during local CR churn.
- The **operator connection uses verified TLS** (no `tlsInsecure`):
  `operator.grpc.tls.mode: vault` + `operator.webhook.tls.mode: vault`
  issue the operator's serving certificate from Vault PKI (kubernetes
  auth), and the gateway verifies against the `avapigw-vault-pki-ca` Secret
  (`gateway.operatorMode.caSecret`) created by
  `setup-vault-k8s.sh --setup-pki`. The chart **default**
  (`mode: selfsigned`, no `caSecret`) also yields verified TLS without
  Vault thanks to the CA Secret persistence described in
  [Operator gRPC TLS](#operator-grpc-tls-and-ca-management).
- The Vault client uses **Kubernetes auth** (gateway ServiceAccount
  `avapigw` → role `avapigw`, operator ServiceAccount `avapigw-operator` →
  role `avapigw-operator`) — no static `vault-token` Secret.
- A **plain HTTP listener is rendered alongside the HTTPS one**
  (`gateway.listeners.http.plainAlongsideTls: true`) so local/perf runs can
  exercise plaintext 8080 without dropping the TLS listeners.
- The **global rate limit is perf-friendly** (`requestsPerSecond: 5000`,
  `burst: 10000`): the previous 100 rps default capped every PT suite run at
  ~97% 429 through a single port-forward client; route-level limits still
  apply where configured.
- `gateway.observability.tracing` points at the in-cluster collector
  (`otel-collector.avapigw-test.svc:4317`) with an explicit
  `otlpInsecure: true` — the test collector is plaintext and remote OTLP
  endpoints now default to TLS.
- There is intentionally **no `gateway.cache` block**: `gateway.cache` is
  not rendered by the chart templates (dead value; the schema marks it
  deprecated). Route-level caching — including Redis Sentinel — is
  configured through APIRoute/GRPCRoute CRDs in operator mode.
- The Vault PKI listener certificates request a `host.docker.internal`
  altName. The PKI `test-role` created by
  `test/performance/scripts/setup-vault-k8s.sh --setup-pki` (and kept in sync
  by `test/docker-compose/scripts/setup-vault.sh`) must therefore keep
  `docker.internal` (and `svc`) in its allowed domains — see the
  sync-contract comments in both scripts.

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

The CRDs shipped with the chart (`helm/avapigw/crds/`) also support
distributed rate limiting (`spec.rateLimit.store: redis` with a
`spec.rateLimit.redis` connection block — standalone URL or Redis Sentinel,
`failOpen` policy, Vault password paths) and redis-backed route caching
(`spec.cache.type: redis` with `spec.cache.redis`). Distributed rate limiting
is enforced for APIRoutes and GraphQLRoutes (gRPC routes keep the in-memory
limiter); redis route caching is wired for the HTTP APIRoute data path. The
admission webhook emits a conservative forward-compatibility warning for
these redis options on kinds other than APIRoute.

Recent CRD additions round-tripped to the gateway config: advanced
request/response transforms (`staticHeaders`, `dynamicHeaders`,
`injectFields`, `removeFields`, `defaultValues`, `validateBeforeTransform`;
response `groupFields`/`flattenFields`/`arrayOperations`/`template`/
`mergeStrategy`), cache tuning (`maxEntries`, `keyConfig`,
`honorCacheControl`, `negativeCacheTTL` — `keyComponents` is deprecated),
Redis TLS (`cache.redis.tls`, `rateLimit.redis.tls`,
`authorization.cache.redis.tls`), a Redis-backed authorization decision
cache (`authorization.cache.redis`, replacing the deprecated top-level
`sentinel` shape), structured security headers (`security.hsts`,
`security.csp`, `referrerPolicy`), and gRPC backend health checks
(`healthCheck.useGRPC`/`grpcService`/`port`). Fields the gateway does not
consume yet are admitted with "accepted but not applied" warnings. See the
[CRD reference](../../docs/crd-reference.md) for the full schema.

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
- **gRPC hot-reload capabilities** - gRPC backends support hot-reload in both file-based and operator modes; gRPC routes support hot-reload in operator mode only
- **Audit logger hot-reload** - AtomicAuditLogger enables lock-free audit configuration updates in both modes
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
