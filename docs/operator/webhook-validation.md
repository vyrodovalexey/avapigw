# Webhook Validation

The AVAPIGW Operator includes comprehensive admission webhooks that validate Custom Resource Definitions (CRDs) before they are applied to the cluster. This prevents invalid configurations and ensures consistency across the gateway infrastructure.

## Table of Contents

- [Overview](#overview)
- [Admission Lifecycle](#admission-lifecycle)
- [Validation Rules](#validation-rules)
- [Cross-CRD Duplicate Detection](#cross-crd-duplicate-detection)
- [Cross-Reference Validation](#cross-reference-validation)
- [Error Messages](#error-messages)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Overview

The admission webhooks provide five main types of validation with enhanced validation constants and improved thread safety:

1. **Schema Validation** - Ensures all required fields are present and have valid values using named constants for port ranges and weights
2. **Cross-Route Intersection Prevention** - Prevents path conflicts between APIRoute and GraphQLRoute CRDs
3. **Cross-CRD Duplicate Detection** - Prevents conflicting route configurations across Backend vs GRPCBackend with context-based cleanup lifecycle
4. **Ingress Webhook Validation** - Validates Ingress resources when ingress controller is enabled
5. **Cross-Reference Validation** - Ensures referenced resources exist with enhanced validation rules

### Webhook Types

- **ValidatingAdmissionWebhook** - Validates CRD specifications before creation/update
- **MutatingAdmissionWebhook** - Sets default values and normalizes configurations
- **Ingress ValidatingAdmissionWebhook** - Validates standard Kubernetes Ingress resources

## Admission Lifecycle

The update webhooks apply three lifecycle rules (uniformly across APIRoute,
Backend, GRPCRoute, GRPCBackend, GraphQLRoute, and GraphQLBackend) that
guarantee deletion and metadata housekeeping can never be blocked by
validation:

1. **Deleting objects are always admitted.** An UPDATE on an object whose
   `metadata.deletionTimestamp` is set is admitted unconditionally, so
   finalizer removal always proceeds and a resource can never wedge in
   `Terminating` because of webhook validation (this previously caused a
   webhook/finalizer deadlock).
2. **Metadata-only updates skip conflict checks.** When the spec is
   semantically unchanged (only labels, annotations, finalizers, or other
   metadata changed), the webhook still runs **local spec validation** but
   skips duplicate and cross-kind conflict checks — the update cannot
   introduce a new conflict, so finalizer or label changes on overlapping
   legacy objects are never rejected.
3. **Terminating candidates are excluded from conflict evaluation.** Both
   same-kind duplicate checks and cross-kind conflict checks skip existing
   resources that have a `deletionTimestamp`: a resource on its way out never
   blocks admission of a surviving or replacement resource.

## Validation Rules

### APIRoute Validation

#### Required Fields
- `metadata.name` - Must be a valid Kubernetes resource name
- `metadata.namespace` - Must be a valid namespace
- `spec.match` - At least one match condition is required
- `spec.route` - At least one route destination is required

#### Match Validation
```yaml
# Valid match configurations
match:
  - uri:
      exact: "/api/v1/users"     # Valid: exact path
  - uri:
      prefix: "/api/"            # Valid: prefix path
  - uri:
      regex: "^/api/v[0-9]+/"    # Valid: regex pattern
  - methods: ["GET", "POST"]     # Valid: HTTP methods
    headers:
      - name: "Authorization"
        present: true            # Valid: header presence check
```

#### Route Validation
```yaml
# Valid route configurations
route:
  - destination:
      host: "backend-service"    # Required: backend host
      port: 8080                 # Required: backend port
    weight: 50                   # Optional: traffic weight (1-100)
  - destination:
      host: "backup-service"
      port: 8080
    weight: 50
```

#### Timeout Validation
- Must be a valid duration string (e.g., "30s", "5m", "1h")
- Minimum value: 1s
- Maximum value: 24h

#### Retry Validation
```yaml
retries:
  attempts: 3                    # Range: 1-10
  perTryTimeout: "10s"          # Must be less than route timeout
  retryOn: "5xx,reset"          # Valid retry conditions
```

### GRPCRoute Validation

#### Service and Method Matching
```yaml
# Valid gRPC match configurations
match:
  - service:
      exact: "api.v1.UserService"     # Valid: exact service name
  - service:
      prefix: "api.v1."              # Valid: service prefix
  - method:
      exact: "GetUser"               # Valid: exact method name
  - metadata:
      - name: "authorization"
        present: true                # Valid: metadata presence
```

#### Authority Validation
- Must be a valid hostname or IP address
- Supports wildcard patterns (e.g., "*.example.com")

### Backend Validation

#### Host Configuration
```yaml
hosts:
  - address: "backend.example.com"   # Valid: hostname
    port: 8080                       # Range: 1-65535 (validated using named constants)
    weight: 1                        # Range: 1-100 (validated using named constants)
  - address: "192.168.1.100"         # Valid: IP address
    port: 8080
    weight: 2
```

**Validation Constants:**
- Port range: 1-65535 (using `MinPort` and `MaxPort` constants)
- Weight range: 1-100 (using `MinWeight` and `MaxWeight` constants)
- Timeout ranges: Validated using predefined minimum and maximum values

#### Health Check Validation
```yaml
healthCheck:
  path: "/health"                    # Must start with "/"
  interval: "10s"                    # Minimum: 1s
  timeout: "5s"                      # Must be less than interval
  healthyThreshold: 2                # Range: 1-10
  unhealthyThreshold: 3              # Range: 1-10
```

#### Load Balancer Validation
- `algorithm` must be one of: `roundRobin`, `weighted`, `leastConn`, `random`

#### Circuit Breaker Validation
```yaml
circuitBreaker:
  enabled: true
  threshold: 5                       # Range: 1-100
  timeout: "30s"                     # Minimum: 1s
  halfOpenRequests: 3                # Range: 1-10
```

### GRPCBackend Validation

Similar to Backend validation with additional gRPC-specific rules:

#### gRPC Health Check
```yaml
healthCheck:
  enabled: true
  service: "api.v1.UserService"      # Optional: specific service to check
  interval: "10s"
  timeout: "5s"
```

#### HTTP-Mode Health Check Fields (`useHTTP`)

The health check can switch from gRPC protocol to HTTP GET via `useHTTP`:

```yaml
healthCheck:
  enabled: true
  useHTTP: true
  httpPath: "/monitoring/health"     # Must start with "/"
  httpPort: 8080                     # Range: 1-65535; defaults to the backend port
```

Validation of `httpPath`/`httpPort` against the `useHTTP` toggle:

- **`useHTTP: true`** — `httpPath` must start with `/`; `httpPort` (when set)
  must be in range 1-65535
- **`useHTTP: false`** — an explicit `httpPath` other than the CRD schema
  default `/healthz` is rejected, and `httpPort` must not be set
- **Schema default tolerated** — the CRD schema defaults `httpPath` to
  `/healthz` (`+kubebuilder:default`), and the API server applies structural
  defaulting **before** the validating webhook runs. Every GRPCBackend with a
  `healthCheck` block therefore reaches the webhook with `httpPath: /healthz`
  populated even when the user never set it, and the webhook tolerates this
  inert default when `useHTTP` is false. (Before this fix, the webhook
  rejected the defaulted value, making every GRPCBackend with a `healthCheck`
  block unadmittable — an admission deadlock.)

## Cross-CRD Duplicate Detection

The webhook prevents duplicate route configurations that could cause conflicts across different CRD types:

### Cross-Route Intersection Prevention

The webhook prevents path intersections between APIRoute and GraphQLRoute CRDs to avoid routing conflicts, rejecting only **true duplicates** the data plane cannot order deterministically.

#### Overlap Detection Logic

Routes are rejected only when they are **true duplicates** — the same match
type with the same path (identical specificity) and overlapping methods.
Combinations of different specificity are resolved deterministically by the
router (exact = 1000 > prefix = 500 + prefix length > regex = 100; an empty
match acts as a priority-0 catch-all) and are therefore allowed:

- **Exact path vs Exact path**: Conflict only if paths are identical
- **Prefix match vs Prefix match**: Conflict only if prefixes are identical — nested prefixes (e.g. `/` and `/api`) resolve by longest-prefix specificity
- **Exact path vs Prefix match**: Never a conflict — the router resolves exact-first
- **Nil/empty match (catch-all)**: Coexists with any route that has match conditions; only two match-less catch-alls conflict with each other
- **Self-updates**: Updating a resource never conflicts with its own previous version

The same semantics apply across kinds sharing the HTTP data path
(APIRoute ↔ GraphQLRoute): only identical exact paths or identical prefixes
are cross-kind conflicts, because the APIRoute would be silently shadowed by
the GraphQL pipeline on exactly the path space it claims.

#### Examples of Conflicting Routes

```yaml
# CONFLICT: identical exact path across kinds
# APIRoute
apiVersion: avapigw.io/v1
kind: APIRoute
metadata:
  name: api-route
spec:
  match:
    - uri:
        exact: "/graphql"   # Conflicts with GraphQLRoute below

---
# GraphQLRoute  
apiVersion: avapigw.io/v1
kind: GraphQLRoute
metadata:
  name: graphql-route
spec:
  match:
    - path:
        exact: "/graphql"   # CONFLICT: identical exact path (same specificity)
```

```yaml
# CONFLICT: identical prefix across kinds
# APIRoute
apiVersion: avapigw.io/v1
kind: APIRoute
metadata:
  name: api-route
spec:
  match:
    - uri:
        prefix: "/api"      # Conflicts with GraphQLRoute below

---
# GraphQLRoute
apiVersion: avapigw.io/v1
kind: GraphQLRoute
metadata:
  name: graphql-route
spec:
  match:
    - path:
        prefix: "/api"      # CONFLICT: identical prefix (same specificity)
```

#### Examples of Non-Conflicting Routes

```yaml
# NO CONFLICT: exact vs prefix resolves exact-first
# APIRoute
apiVersion: avapigw.io/v1
kind: APIRoute
metadata:
  name: api-route
spec:
  match:
    - uri:
        prefix: "/api"      # Coexists: prefix has lower specificity

---
# GraphQLRoute
apiVersion: avapigw.io/v1
kind: GraphQLRoute
metadata:
  name: graphql-route
spec:
  match:
    - path:
        exact: "/api/graphql"  # Coexists: exact match wins on this path
```

```yaml
# NO CONFLICT: nested prefixes resolve by longest-prefix specificity
# APIRoute 1 (catch-all style prefix)
match:
  - uri:
      prefix: "/"

# APIRoute 2 (more specific prefix)
match:
  - uri:
      prefix: "/api"
```

#### Validation Modes

Cross-route intersection prevention works in two modes:

1. **Operator Mode (Webhooks)**: When using CRDs, the validating webhook checks for conflicts during CREATE and UPDATE operations
2. **Config Mode (Validator)**: When using YAML configuration files, the config validator checks for conflicts during configuration loading

Both modes use the same overlap detection logic to ensure consistent behavior across deployment scenarios.

### HTTP Route Conflicts

Routes are considered duplicates if they have:
- Same URI match type with the same path (identical specificity)
- Overlapping HTTP methods (an empty method list matches all methods)

```yaml
# This would be rejected as a duplicate:
# APIRoute 1
match:
  - uri:
      prefix: "/api/v1"
    methods: ["GET", "POST"]

# APIRoute 2 (DUPLICATE - identical prefix and overlapping methods)
match:
  - uri:
      prefix: "/api/v1"
    methods: ["GET", "PUT"]
```

Routes with the same path but **disjoint** methods (for example `GET` vs
`POST` on the same prefix) are not duplicates.

### Cross-CRD Backend Conflicts

The webhook detects conflicts between Backend and GRPCBackend resources using improved duplicate detection with context-based lifecycle management:

```yaml
# Backend CRD
apiVersion: avapigw.io/v1alpha1
kind: Backend
metadata:
  name: api-backend
spec:
  hosts:
    - address: api.example.com
      port: 8080

---
# This would be rejected as a duplicate:
apiVersion: avapigw.io/v1alpha1
kind: GRPCBackend
metadata:
  name: api-grpc-backend
spec:
  hosts:
    - address: api.example.com  # CONFLICT - same address as Backend
      port: 8080                # CONFLICT - same port as Backend
```

### gRPC Route Conflicts

gRPC routes are rejected only when two match blocks have **identical
specificity** AND **overlapping match values** in every dimension (some
request could satisfy both blocks) — mirroring the GraphQL checker. The
specificity formula is shared with the data-plane router
(`internal/grpc/router.Specificity`):

| Condition | Weight |
|-----------|--------|
| `service.exact` | 1000 |
| `service.prefix` | 500 + prefix length |
| `service.regex` | 100 |
| `method.exact` | 500 |
| `method.prefix` | 250 + prefix length |
| `method.regex` | 50 |
| `authority` set | +100 |
| Each `metadata` condition | +10 |
| Each `withoutHeaders` entry | +5 |
| No match block (catch-all) | 0 |

Consequences:

- **Different specificity → admitted.** A match-less catch-all coexists with
  any service-specific route (it conflicts only with **another catch-all**);
  a nil-method route coexists with a method-specific route on the same
  service; **metadata-discriminated routes** (e.g. header-differentiated
  variants of the same service/method) coexist with each other and with a
  generic route — the metadata/authority/withoutHeaders weights
  differentiate them, and the router orders all of them deterministically
  (higher specificity wins, route-name tie-break)
- **Identical specificity, disjoint values → admitted.** For example disjoint
  exact methods (`Get` vs `Create`) on the same service, or different exact
  services
- **Identical specificity, overlapping values → rejected.** For example two
  routes with the same `service.exact`/`method.exact` pair and no other
  distinguishing conditions, identical prefixes, or two match-less
  catch-alls (rejection message:
  `identical-specificity overlapping service/method match`)
- **Nested prefixes → admitted** (e.g. `com.example` and
  `com.example.user`); the longer prefix wins for requests matching both
- **Regex pairs → admitted** (intersection statically undecidable); the
  name tie-break keeps ordering stable

```yaml
# This would be rejected as a duplicate:
# Route 1
match:
  - service:
      exact: "api.v1.UserService"
    method:
      exact: "GetUser"

# Route 2 (DUPLICATE - same service and method, identical specificity)
match:
  - service:
      exact: "api.v1.UserService"
    method:
      exact: "GetUser"
```

```yaml
# NO CONFLICT: nested service prefixes resolve by longest-prefix priority
# Route 1
match:
  - service:
      prefix: "com.example"

# Route 2 (admitted - more specific prefix wins for its subtree)
match:
  - service:
      prefix: "com.example.user"
```

### GraphQL Route Conflicts

GraphQL routes are rejected only when two match blocks have **identical
specificity** AND **overlapping match values** in every dimension (some
request could satisfy both blocks). Everything else is admitted and ordered
deterministically by the GraphQL router, which sorts routes by descending
specificity with a route-name tie-break.

The specificity of a route is the sum over its match blocks of
(authoritative formula, shared with the data-plane router —
`internal/graphql/router.Specificity`):

| Condition | Weight |
|-----------|--------|
| `path.exact` | 1000 |
| `path.prefix` | 500 + prefix length |
| `path.regex` | 100 |
| `operationName.exact` | 500 |
| `operationName.prefix` | 250 + prefix length |
| `operationName.regex` | 50 |
| `operationType` set | +200 |
| Each header condition | +10 |
| No match block (catch-all) | 0 |

Consequences:

- **Different specificity → admitted.** A catch-all coexists with any
  path-specific route; nested path prefixes coexist; an
  `operationType`-specific route coexists with a generic route on the same
  path (the +200 operationType weight differentiates them)
- **Identical specificity, disjoint values → admitted.** For example two
  routes with `operationType: query` vs `operationType: mutation` on the same
  exact path, or exact paths `/graphql` vs `/api/graphql`
- **Identical specificity, overlapping values → rejected.** For example two
  match-less catch-alls, or two routes with the same exact path and no other
  distinguishing conditions
- **Regex pairs → admitted.** Regex intersection is statically undecidable,
  so equal-specificity regex routes are admitted; the router still orders
  them deterministically via the name tie-break

### Priority-Based Resolution

When routes have overlapping patterns of different specificity, the webhook
allows them and the gateway router orders them deterministically:

1. **Exact matches** — priority 1000 (highest)
2. **Prefix matches** — priority 500 + prefix length (longer prefixes win)
3. **Regex matches** — priority 100
4. **Empty match** — priority 0 (catch-all)

The same scheme applies to gRPC routes (service weights as above; method
weights halved: exact 500, prefix 250 + length, regex 50; plus authority
+100, +10 per metadata condition, +5 per `withoutHeaders` entry — see
[gRPC Route Conflicts](#grpc-route-conflicts)) and to GraphQL routes (see
[GraphQL Route Conflicts](#graphql-route-conflicts) for the full formula).

Routes with **equal priority** are ordered by route name (ascending), so
first-match-wins is a stable total order independent of load order. Only
patterns with **identical specificity and overlapping match values** are
ambiguous from the user's perspective and rejected at admission time.

### Admission Warnings

Some configurations are admitted with a **warning** instead of a rejection:

- `authentication.mtls` enabled without `caFile` — valid when the client CA
  is provided elsewhere (for example a Vault-managed CA); the warning flags
  that client certificate validation relies on an externally provided CA
- `rateLimit.store: redis` on every kind except APIRoute — GRPCRoute keeps
  the in-memory limiter and backend-level rate limits accept the field for
  forward compatibility. GraphQL routes enforce the redis limiter through
  the shared per-route middleware chain, but the conservative warning is
  still emitted on GraphQLRoute
- `cache.type: redis` on GRPCRoute/GraphQLRoute — redis route caching is
  wired for the HTTP APIRoute data path; GraphQL routes attach the shared
  cache middleware but only GET requests are cached
- Backend `spec.cache` — RESERVED; accepted but not applied by the gateway
- `cache.keyComponents` — deprecated, **not applied** (no gateway
  counterpart); use `cache.keyConfig` instead
- `authorization.cache.sentinel` (legacy top-level block) — deprecated in
  favor of `authorization.cache.redis.sentinel`; the operator converts it so
  it still takes effect
- `authorization.cache.type: redis` without a `redis`/`sentinel` connection
  — not applied; the gateway falls back to the in-memory decision cache
- Inline plaintext `password`/`sentinelPassword` in any Redis Sentinel block
  (including the authorization cache) — prefer the `*VaultPath` references
- "Accepted but not applied" fields with no gateway counterpart:
  `spec.rateLimit` on GRPCBackend/GraphQLBackend; `spec.maxSessions` and
  `spec.requestLimits` on GRPCRoute/GraphQLRoute; `spec.requestLimits`,
  `spec.transform`, `spec.encoding` on Backend/GRPCBackend;
  `spec.maxSessions`/`spec.encoding` on GraphQLBackend. The contract is
  **no silent drops** — every unconsumed field is converted or warned about

### ABAC CEL Validation

ABAC CEL expressions are compiled at admission time against the same
environment the gateway evaluates at runtime:

- **Variables**: `subject`, `request`, `resource` (string), `action`,
  `environment` (maps), and `now` (timestamp)
- **Functions**: `ip_in_range(string, string) bool`, `has_role(string) bool`

Expressions referencing undeclared variables (for example `identity.*`) are
rejected at admission time instead of failing at evaluation time.

## Ingress Webhook Validation

When the ingress controller is enabled, the webhook also validates standard Kubernetes Ingress resources:

### Ingress Validation Rules

- **IngressClass Validation** - Ensures the IngressClass exists and is managed by avapigw
- **Path Validation** - Validates path patterns and path types
- **Service Validation** - Ensures referenced services exist
- **Annotation Validation** - Validates avapigw-specific annotations
- **TLS Validation** - Validates TLS configuration and secret references

### Example Ingress Validation

```yaml
# This Ingress would be validated:
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    avapigw.io/timeout: "30s"        # Validated format
    avapigw.io/retries: "3"          # Validated range
    avapigw.io/rate-limit-rps: "100" # Validated positive number
spec:
  ingressClassName: avapigw           # Validated IngressClass exists
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix             # Validated path type
        backend:
          service:
            name: api-service        # Validated service exists
            port:
              number: 8080           # Validated port range
```

### Ingress Annotation Validation

The webhook validates all avapigw-specific annotations:

| Annotation | Validation Rule | Example |
|------------|----------------|---------|
| `avapigw.io/timeout` | Valid duration format | `30s`, `5m`, `1h` |
| `avapigw.io/retries` | Integer 1-10 | `3` |
| `avapigw.io/rate-limit-rps` | Positive integer | `100` |
| `avapigw.io/cors-allow-origins` | Valid origin format | `https://example.com` |
| `avapigw.io/circuit-breaker-threshold` | Integer 1-100 | `5` |
| `avapigw.io/load-balancer` | Valid algorithm | `round-robin`, `least-conn` |

## Cross-Reference Validation

The webhook validates that referenced resources exist:

### Backend References

```yaml
# APIRoute referencing a backend
route:
  - destination:
      host: "user-backend"           # Must exist as a Backend CRD
      port: 8080
```

The webhook checks:
- Backend CRD with name "user-backend" exists in the same namespace
- Backend has a host configured on the specified port

### Service References

```yaml
# Backend referencing a Kubernetes service
hosts:
  - address: "user-service.default.svc.cluster.local"
    port: 8080
```

The webhook validates:
- Service name follows Kubernetes DNS conventions
- Port is within valid range

## Error Messages

The webhook provides detailed error messages for validation failures:

### Schema Validation Errors

```json
{
  "message": "admission webhook denied the request",
  "details": {
    "name": "my-route",
    "kind": "APIRoute",
    "causes": [
      {
        "reason": "FieldValueInvalid",
        "message": "spec.timeout: invalid duration format '30seconds', expected format like '30s'",
        "field": "spec.timeout"
      }
    ]
  }
}
```

### Duplicate Detection Errors

```json
{
  "message": "admission webhook denied the request",
  "details": {
    "name": "duplicate-route",
    "kind": "APIRoute",
    "causes": [
      {
        "reason": "Duplicate",
        "message": "route match conflicts with existing route 'existing-route' in namespace 'default'",
        "field": "spec.match[0]"
      }
    ]
  }
}
```

### Cross-Reference Errors

```json
{
  "message": "admission webhook denied the request",
  "details": {
    "name": "invalid-route",
    "kind": "APIRoute",
    "causes": [
      {
        "reason": "NotFound",
        "message": "referenced backend 'missing-backend' not found in namespace 'default'",
        "field": "spec.route[0].destination.host"
      }
    ]
  }
}
```

### Cross-Route Intersection Errors

```json
{
  "message": "admission webhook denied the request",
  "details": {
    "name": "conflicting-route",
    "kind": "APIRoute",
    "causes": [
      {
        "reason": "PathConflict",
        "message": "route path '/graphql' conflicts with existing GraphQLRoute 'graphql-api' in namespace 'default': prefix '/graphql' overlaps with exact path '/graphql'",
        "field": "spec.match[0].uri.prefix"
      }
    ]
  }
}
```

## Configuration

### Webhook Configuration

The webhook is configured through the Helm chart:

```yaml
# values.yaml
operator:
  enabled: true
  webhook:
    enabled: true                    # Enable admission webhooks
    port: 9443                       # Webhook server port
    tls:
      mode: selfsigned              # TLS mode (selfsigned, vault, cert-manager)
    failurePolicy: Fail             # Fail or Ignore on webhook errors
    admissionReviewVersions:         # Supported admission review versions
      - v1
      - v1beta1
```

### TLS Configuration

The webhook requires TLS certificates for secure communication:

#### Self-Signed Certificates (Default)
```yaml
webhook:
  tls:
    mode: selfsigned
    # Certificates are automatically generated
```

#### Vault PKI Certificates
```yaml
webhook:
  tls:
    mode: vault
    vault:
      pkiMount: pki
      role: webhook
      commonName: avapigw-operator-webhook.avapigw-system.svc
      ttl: 24h
```

#### cert-manager Certificates
```yaml
webhook:
  tls:
    mode: cert-manager
    certManager:
      issuerRef:
        name: ca-issuer
        kind: ClusterIssuer
```

### Validation Rules Configuration

Customize validation behavior:

```yaml
operator:
  webhook:
    validation:
      strictMode: true               # Enable strict validation
      allowDuplicates: false         # Prevent duplicate routes
      crossReferenceCheck: true     # Validate resource references
      timeouts:
        min: "1s"                    # Minimum timeout value
        max: "24h"                   # Maximum timeout value
      retries:
        maxAttempts: 10              # Maximum retry attempts
```

## Troubleshooting

### Webhook Not Responding

```bash
# Check webhook pod status
kubectl get pods -n avapigw-system -l app.kubernetes.io/name=avapigw-operator

# Check webhook service
kubectl get svc -n avapigw-system avapigw-operator-webhook

# Check webhook configuration
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator
```

### Certificate Issues

```bash
# Check webhook TLS certificate
kubectl get secret -n avapigw-system webhook-certs -o yaml

# Test webhook connectivity
kubectl port-forward -n avapigw-system svc/avapigw-operator-webhook 9443:9443
curl -k https://localhost:9443/validate-apiroute
```

### Validation Failures

```bash
# Check operator logs for validation details
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator -f

# Test CRD validation manually
kubectl apply --dry-run=server -f your-route.yaml
```

### Common Issues

#### 1. Webhook Timeout
```bash
# Increase webhook timeout
kubectl patch validatingwebhookconfigurations avapigw-operator-webhook \
  --type='json' -p='[{"op": "replace", "path": "/webhooks/0/timeoutSeconds", "value": 30}]'
```

#### 2. Certificate Expiry
```bash
# Check certificate expiry
kubectl get secret -n avapigw-system webhook-certs -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -dates

# Force certificate renewal (Vault PKI)
kubectl delete secret -n avapigw-system webhook-certs
kubectl rollout restart deployment -n avapigw-system avapigw-operator
```

#### 3. Validation Rule Conflicts
```bash
# List all routes to check for conflicts
kubectl get apiroutes --all-namespaces -o wide

# Check specific route for conflicts
kubectl describe apiroute my-route
```

### Debug Mode

Enable debug logging for detailed validation information:

```bash
# Update operator deployment with debug logging
kubectl patch deployment -n avapigw-system avapigw-operator \
  --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--log-level=debug"}]'

# Watch debug logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator -f | grep webhook
```

## Best Practices

### 1. Route Design
- Use specific match patterns to avoid conflicts
- Prefer exact matches over regex when possible
- Group related routes in the same namespace

### 2. Validation Testing
- Use `kubectl apply --dry-run=server` to test configurations
- Validate configurations in development before production
- Use descriptive names for easier troubleshooting

### 3. Error Handling
- Monitor webhook metrics for validation failures
- Set up alerts for webhook downtime
- Have fallback procedures for webhook failures

### 4. Security
- Use Vault PKI or cert-manager for production certificates
- Regularly rotate webhook certificates
- Monitor webhook access logs

## Metrics and Monitoring

The webhook exposes Prometheus metrics for monitoring:

```bash
# Webhook validation metrics
webhook_admission_requests_total{result="allowed"}
webhook_admission_requests_total{result="denied"}
webhook_admission_duration_seconds

# Check webhook metrics
kubectl port-forward -n avapigw-system svc/avapigw-operator-metrics 8080:8080
curl http://localhost:8080/metrics | grep webhook
```

## References

- [Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [ValidatingAdmissionWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook)
- [CRD Reference](crd-reference.md)
- [Operator Configuration](configuration.md)