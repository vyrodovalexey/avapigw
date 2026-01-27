# Vault PKI Integration Guide

## Overview

The AV API Gateway provides comprehensive integration with HashiCorp Vault's PKI (Public Key Infrastructure) secrets engine for dynamic certificate management. This integration enables automatic certificate issuance, renewal, and rotation without manual intervention, supporting three key use cases:

1. **Listener-level TLS** - Gateway's own TLS certificates with automatic renewal
2. **Route-level TLS** - Per-route certificates for SNI-based selection with automatic renewal  
3. **Backend mTLS** - Client certificates for mutual TLS authentication to backends with automatic renewal

All certificate operations include **Prometheus metrics** for expiry monitoring and support **hot-reload** without gateway restart.

## Architecture

### VaultProviderFactory Pattern

Due to circular import constraints between the `vault` and `tls` packages, the gateway uses a factory function pattern:

```go
type VaultProviderFactory func(config *VaultTLSConfig, logger observability.Logger) (CertificateProvider, error)
```

This pattern allows the `tls` package to remain independent while enabling Vault certificate providers to be injected at runtime.

### Certificate Lifecycle

1. **Issue** - Request certificate from Vault PKI with specified parameters
2. **Cache** - Store certificate in memory with expiry tracking
3. **Monitor** - Track certificate expiry via Prometheus metrics
4. **Renew** - Automatically renew before expiration (default: 1 hour before)
5. **Replace** - Hot-swap certificates without service interruption

## Vault PKI Setup

### 1. Enable PKI Secrets Engine

```bash
# Enable PKI secrets engine
vault secrets enable pki

# Configure max lease TTL
vault secrets tune -max-lease-ttl=8760h pki

# Generate root CA
vault write pki/root/generate/internal \
    common_name="My Root CA" \
    ttl=8760h

# Configure CA and CRL URLs
vault write pki/config/urls \
    issuing_certificates="http://vault.example.com:8200/v1/pki/ca" \
    crl_distribution_points="http://vault.example.com:8200/v1/pki/crl"
```

### 2. Create PKI Role

```bash
# Create role for gateway certificates
vault write pki/roles/gateway-server \
    allowed_domains="example.com,*.example.com" \
    allow_subdomains=true \
    max_ttl="720h" \
    generate_lease=true

# Create role for client certificates (backend mTLS)
vault write pki/roles/gateway-client \
    allowed_domains="gateway.internal,*.gateway.internal" \
    allow_subdomains=true \
    max_ttl="24h" \
    generate_lease=true \
    client_flag=true
```

### 3. Configure Vault Policy

```hcl
# Gateway policy for PKI operations
path "pki/issue/gateway-server" {
  capabilities = ["create", "update"]
}

path "pki/issue/gateway-client" {
  capabilities = ["create", "update"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}
```

## Gateway Configuration

### Listener-Level TLS with Vault PKI

Configure the gateway's main TLS certificate from Vault:

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: vault-gateway
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      hosts: ["*"]
      tls:
        mode: SIMPLE
        minVersion: "1.2"
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: gateway.example.com
          altNames:
            - api.example.com
            - www.example.com
          ttl: 24h
        hsts:
          enabled: true
          maxAge: 31536000
          includeSubDomains: true
```

### Route-Level TLS with Vault PKI

Configure per-route certificates for multi-tenant scenarios:

```yaml
spec:
  routes:
    - name: tenant-a-api
      match:
        - uri:
            prefix: /api/tenant-a
      route:
        - destination:
            host: backend-a
            port: 8080
      tls:
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: tenant-a.example.com
          altNames:
            - api.tenant-a.example.com
          ttl: 24h
        sniHosts:
          - tenant-a.example.com
          - api.tenant-a.example.com
        minVersion: "1.2"

    - name: tenant-b-api
      match:
        - uri:
            prefix: /api/tenant-b
      route:
        - destination:
            host: backend-b
            port: 8080
      tls:
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: tenant-b.example.com
          ttl: 24h
        sniHosts:
          - tenant-b.example.com
        minVersion: "1.3"
```

### Backend mTLS with Vault PKI

Configure client certificates for backend authentication:

```yaml
spec:
  backends:
    - name: secure-backend
      hosts:
        - address: secure-api.example.com
          port: 8443
          weight: 1
      tls:
        enabled: true
        mode: MUTUAL
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-client
          commonName: gateway-client.example.com
          altNames:
            - gateway.internal
          ttl: 24h
        serverName: secure-api.example.com
      authentication:
        type: mtls
        mtls:
          enabled: true
          vault:
            enabled: true
            pkiMount: pki
            role: gateway-client
            commonName: gateway-client.example.com
```

## Helm Configuration

### Basic Vault PKI Setup

```yaml
# values.yaml
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: gateway-role
  
  # Vault PKI for listener TLS
  pki:
    enabled: true
    pkiMount: "pki"
    role: "gateway-server"
    commonName: "gateway.example.com"
    altNames:
      - "api.example.com"
      - "*.api.example.com"
    ttl: "24h"
    renewBefore: "1h"

gateway:
  listeners:
    http:
      enabled: true
      port: 8080
    https:
      enabled: true
      port: 8443
      tls:
        enabled: true
        vault:
          enabled: true

  routes:
    - name: tenant-a
      match:
        - uri:
            prefix: /api/tenant-a
      route:
        - destination:
            host: backend-a
            port: 8080
      tls:
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: tenant-a.example.com
          ttl: 24h
        sniHosts:
          - tenant-a.example.com

  backends:
    - name: secure-backend
      hosts:
        - address: secure-api.example.com
          port: 8443
      tls:
        enabled: true
        mode: MUTUAL
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-client
          commonName: gateway-client.example.com
          ttl: 24h
```

### Advanced Multi-Tenant Configuration

```yaml
# values.yaml for multi-tenant setup
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: gateway-role
  
  pki:
    enabled: true
    pkiMount: "pki"
    role: "gateway-server"
    commonName: "gateway.example.com"
    ttl: "24h"

gateway:
  routes:
    # Tenant A with Vault PKI
    - name: tenant-a-public
      match:
        - uri:
            prefix: /api/tenant-a/public
      route:
        - destination:
            host: tenant-a-backend
            port: 8080
      tls:
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: tenant-a.example.com
          ttl: 24h
        sniHosts:
          - tenant-a.example.com

    # Tenant A secure with mTLS
    - name: tenant-a-secure
      match:
        - uri:
            prefix: /api/tenant-a/secure
      route:
        - destination:
            host: tenant-a-secure-backend
            port: 8443
      tls:
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-server
          commonName: secure.tenant-a.example.com
          ttl: 24h
        sniHosts:
          - secure.tenant-a.example.com
        clientValidation:
          enabled: true
          vault:
            enabled: true
            pkiMount: pki
            role: client-ca

    # Tenant B with different PKI mount
    - name: tenant-b-api
      match:
        - uri:
            prefix: /api/tenant-b
      route:
        - destination:
            host: tenant-b-backend
            port: 8080
      tls:
        vault:
          enabled: true
          pkiMount: pki-tenant-b
          role: web-server
          commonName: tenant-b.example.com
          ttl: 12h
        sniHosts:
          - tenant-b.example.com

  backends:
    # Backend with Vault PKI client certificates
    - name: vault-mtls-backend
      hosts:
        - address: secure-backend.example.com
          port: 8443
      tls:
        enabled: true
        mode: MUTUAL
        vault:
          enabled: true
          pkiMount: pki
          role: gateway-client
          commonName: gateway-client.example.com
          ttl: 24h
        serverName: secure-backend.example.com
```

## Certificate Renewal

### Automatic Renewal

Certificates are automatically renewed when they approach expiration:

- **Default renewal window**: 1 hour before expiry
- **Configurable via**: `renewBefore` parameter
- **Renewal process**: Seamless hot-swap without service interruption
- **Failure handling**: Retries with exponential backoff

### Renewal Configuration

```yaml
vault:
  pki:
    enabled: true
    pkiMount: pki
    role: gateway-server
    commonName: gateway.example.com
    ttl: "24h"
    renewBefore: "1h"  # Renew 1 hour before expiry
```

### Manual Renewal

Force certificate renewal via API:

```bash
# Trigger renewal for listener certificate
curl -X POST http://localhost:9090/admin/tls/renew/listener

# Trigger renewal for specific route
curl -X POST http://localhost:9090/admin/tls/renew/route/tenant-a

# Trigger renewal for backend client certificate
curl -X POST http://localhost:9090/admin/tls/renew/backend/secure-backend
```

## Monitoring and Metrics

### Prometheus Metrics

The gateway exposes comprehensive metrics for certificate monitoring:

```prometheus
# Certificate expiry time (Unix timestamp)
gateway_tls_certificate_expiry_seconds{type="listener",name="https"} 1640995200

# Certificate expiry time for routes
gateway_tls_certificate_expiry_seconds{type="route",name="tenant-a"} 1640995200

# Certificate expiry time for backends
gateway_tls_certificate_expiry_seconds{type="backend",name="secure-backend"} 1640995200

# Certificate renewal operations
gateway_tls_certificate_renewals_total{type="listener",name="https",status="success"} 5
gateway_tls_certificate_renewals_total{type="route",name="tenant-a",status="failure"} 1

# Vault PKI operations
gateway_vault_pki_operations_total{operation="issue",status="success"} 10
gateway_vault_pki_operations_total{operation="issue",status="failure"} 2

# Certificate validity duration
gateway_tls_certificate_validity_seconds{type="listener",name="https"} 86400
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: gateway-tls
    rules:
      - alert: GatewayCertificateExpiringSoon
        expr: (gateway_tls_certificate_expiry_seconds - time()) < 3600
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Gateway certificate expiring soon"
          description: "Certificate {{ $labels.name }} ({{ $labels.type }}) expires in less than 1 hour"

      - alert: GatewayCertificateRenewalFailed
        expr: increase(gateway_tls_certificate_renewals_total{status="failure"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Gateway certificate renewal failed"
          description: "Certificate renewal failed for {{ $labels.name }} ({{ $labels.type }})"

      - alert: VaultPKIOperationsFailing
        expr: rate(gateway_vault_pki_operations_total{status="failure"}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Vault PKI operations failing"
          description: "High failure rate for Vault PKI operations: {{ $value }}/sec"
```

### Grafana Dashboard

Key metrics to monitor:

1. **Certificate Expiry Timeline** - Time until certificate expiration
2. **Renewal Success Rate** - Percentage of successful renewals
3. **Vault PKI Operations** - Success/failure rates for PKI operations
4. **Certificate Validity Duration** - How long certificates are valid
5. **SNI Certificate Selection** - Which certificates are being used

## Troubleshooting

### Common Issues

#### 1. Vault Authentication Failure

**Symptoms:**
```
ERROR: failed to authenticate with vault: permission denied
```

**Solutions:**
- Verify Vault role and policy configuration
- Check Kubernetes service account permissions
- Validate Vault address and connectivity
- Ensure correct authentication method configuration

#### 2. PKI Role Configuration Issues

**Symptoms:**
```
ERROR: failed to issue certificate: role "gateway-server" not found
```

**Solutions:**
- Verify PKI role exists: `vault read pki/roles/gateway-server`
- Check role permissions for requested domains
- Validate TTL limits in role configuration
- Ensure PKI secrets engine is enabled

#### 3. Certificate Renewal Failures

**Symptoms:**
```
ERROR: failed to renew certificate: certificate request denied
```

**Solutions:**
- Check Vault token expiration and renewal
- Verify PKI role still allows certificate parameters
- Monitor Vault server health and connectivity
- Review certificate request parameters

#### 4. SNI Certificate Selection Issues

**Symptoms:**
```
ERROR: no certificate found for SNI hostname: tenant-a.example.com
```

**Solutions:**
- Verify `sniHosts` configuration matches requested hostname
- Check certificate Subject Alternative Names (SANs)
- Ensure route-level TLS configuration is correct
- Test certificate issuance manually

### Debugging Commands

```bash
# Check Vault connectivity
vault status

# Test certificate issuance
vault write pki/issue/gateway-server \
    common_name="test.example.com" \
    ttl="1h"

# Verify certificate details
openssl x509 -in certificate.pem -text -noout

# Test SNI with specific hostname
openssl s_client -connect gateway.example.com:8443 \
    -servername tenant-a.example.com

# Check gateway certificate metrics
curl http://localhost:9090/metrics | grep gateway_tls_certificate

# View certificate expiry
curl http://localhost:9090/metrics | grep gateway_tls_certificate_expiry_seconds
```

### Log Analysis

Enable debug logging for detailed troubleshooting:

```yaml
observability:
  logging:
    level: debug
```

Look for these log patterns:
- `Vault PKI certificate issued` - Successful certificate issuance
- `Certificate renewed successfully` - Successful renewal
- `SNI hostname: <hostname>` - SNI hostname detection
- `Selected certificate for route: <route-name>` - Route certificate selection
- `Vault authentication successful` - Vault auth success

## Security Considerations

### Best Practices

1. **Use Short-Lived Certificates**
   - Recommended TTL: 24-48 hours for server certificates
   - Recommended TTL: 1-4 hours for client certificates
   - Enable automatic renewal well before expiry

2. **Secure Vault Access**
   - Use Kubernetes authentication in production
   - Implement least-privilege policies
   - Enable Vault audit logging
   - Use TLS for all Vault communications

3. **Certificate Validation**
   - Always validate certificate chains
   - Use proper hostname verification
   - Implement certificate pinning for high-security environments

4. **Monitoring and Alerting**
   - Monitor certificate expiry times
   - Alert on renewal failures
   - Track PKI operation metrics
   - Implement certificate transparency logging

### Production Deployment

```yaml
# Production-ready configuration
vault:
  enabled: true
  address: "https://vault.production.example.com:8200"
  authMethod: kubernetes
  role: gateway-production
  tls:
    enabled: true
    caSecretName: vault-ca-cert
    skipVerify: false
  
  pki:
    enabled: true
    pkiMount: "pki-production"
    role: "gateway-server-prod"
    commonName: "gateway.production.example.com"
    altNames:
      - "api.production.example.com"
      - "*.api.production.example.com"
    ttl: "24h"
    renewBefore: "2h"  # Renew 2 hours before expiry

gateway:
  observability:
    logging:
      level: info  # Avoid debug in production
    metrics:
      enabled: true
    tracing:
      enabled: true
      samplingRate: 0.1  # 10% sampling

  security:
    enabled: true
    headers:
      enabled: true
    hsts:
      enabled: true
      maxAge: 31536000
      includeSubDomains: true
      preload: true
```

This comprehensive Vault PKI integration enables secure, automated certificate management across all gateway components while maintaining high availability and security standards.