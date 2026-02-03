# Webhook Validation

The AVAPIGW Operator includes comprehensive admission webhooks that validate Custom Resource Definitions (CRDs) before they are applied to the cluster. This prevents invalid configurations and ensures consistency across the gateway infrastructure.

## Table of Contents

- [Overview](#overview)
- [Validation Rules](#validation-rules)
- [Duplicate Detection](#duplicate-detection)
- [Cross-Reference Validation](#cross-reference-validation)
- [Error Messages](#error-messages)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Overview

The admission webhooks provide three main types of validation:

1. **Schema Validation** - Ensures all required fields are present and have valid values
2. **Duplicate Detection** - Prevents conflicting route configurations
3. **Cross-Reference Validation** - Ensures referenced resources exist

### Webhook Types

- **ValidatingAdmissionWebhook** - Validates CRD specifications before creation/update
- **MutatingAdmissionWebhook** - Sets default values and normalizes configurations

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
    port: 8080                       # Range: 1-65535
    weight: 1                        # Range: 1-100
  - address: "192.168.1.100"         # Valid: IP address
    port: 8080
    weight: 2
```

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

## Duplicate Detection

The webhook prevents duplicate route configurations that could cause conflicts:

### HTTP Route Conflicts

Routes are considered duplicates if they have:
- Same URI match pattern
- Overlapping HTTP methods
- Same header constraints

```yaml
# This would be rejected as a duplicate:
# Route 1
match:
  - uri:
      prefix: "/api/v1"
    methods: ["GET", "POST"]

# Route 2 (DUPLICATE - same prefix and overlapping methods)
match:
  - uri:
      prefix: "/api/v1"
    methods: ["GET", "PUT"]
```

### gRPC Route Conflicts

gRPC routes are considered duplicates if they have:
- Same service match pattern
- Same method match pattern
- Same metadata constraints

```yaml
# This would be rejected as a duplicate:
# Route 1
match:
  - service:
      exact: "api.v1.UserService"
    method:
      exact: "GetUser"

# Route 2 (DUPLICATE - same service and method)
match:
  - service:
      exact: "api.v1.UserService"
    method:
      exact: "GetUser"
```

### Priority-Based Resolution

When routes have overlapping patterns, the webhook uses priority rules:

1. **Exact matches** have higher priority than prefix or regex
2. **More specific patterns** have higher priority
3. **Routes with more constraints** (headers, methods) have higher priority

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