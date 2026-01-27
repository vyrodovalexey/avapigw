# Route-Level TLS Certificate Override

## Overview

The Ava API Gateway supports route-level TLS certificate override, enabling individual routes to serve their own TLS certificates based on Server Name Indication (SNI). This feature is essential for multi-tenant deployments where each tenant requires their own SSL certificate, or when different routes need different security configurations.

### Key Features

- **SNI-Based Certificate Selection**: Automatically select the appropriate certificate based on the requested hostname
- **Per-Route TLS Configuration**: Each route can have its own TLS settings including cipher suites and protocol versions
- **Client Certificate Validation (mTLS)**: Optional mutual TLS support with per-route CA certificates
- **Vault Integration**: Dynamic certificate provisioning from HashiCorp Vault PKI
- **File-Based Certificates**: Traditional certificate loading from files
- **Hot Reload**: Automatic detection and reloading of certificate changes

## Use Cases

### Multi-Tenant SaaS Applications
Serve different SSL certificates for each tenant's custom domain:
```
tenant-a.example.com → Certificate A
tenant-b.example.com → Certificate B
api.tenant-c.com    → Certificate C
```

### Different Security Requirements
Apply varying security policies per route:
- Public APIs with standard TLS
- Internal APIs with mutual TLS (mTLS)
- Legacy systems with relaxed cipher suites
- High-security endpoints with strict TLS 1.3 only

### Domain-Specific Certificates
Handle multiple domains with appropriate certificates:
- Wildcard certificates for subdomains
- Extended Validation (EV) certificates for payment endpoints
- Self-signed certificates for development environments

## Configuration Reference

### Route TLS Configuration

The route-level TLS configuration is defined in the `tls` section of a route:

```yaml
routes:
  - name: example-route
    match:
      - uri:
          prefix: /api/tenant-a
    route:
      - destination:
          host: backend-a
          port: 8080
    tls:
      enabled: true
      certFile: /app/certs/routes/tenant-a/tls.crt
      keyFile: /app/certs/routes/tenant-a/tls.key
      sniHosts:
        - tenant-a.example.com
        - api.tenant-a.example.com
      minVersion: "1.2"
      maxVersion: "1.3"
      cipherSuites:
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      clientValidation:
        enabled: true
        caFile: /app/certs/routes/tenant-a/ca.crt
        requireClientCert: true
        allowedCNs:
          - client.tenant-a.example.com
        allowedSANs:
          - client-api.tenant-a.example.com
```

### Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | boolean | Enable route-level TLS override | `false` |
| `certFile` | string | Path to certificate file (PEM format) | - |
| `keyFile` | string | Path to private key file (PEM format) | - |
| `vaultPath` | string | Vault path for certificate (alternative to files) | - |
| `sniHosts` | []string | SNI hostnames for certificate selection | - |
| `minVersion` | string | Minimum TLS version (`1.0`, `1.1`, `1.2`, `1.3`) | `1.2` |
| `maxVersion` | string | Maximum TLS version | `1.3` |
| `cipherSuites` | []string | Allowed cipher suites | Default secure suites |
| `clientValidation` | object | Client certificate validation config | - |

### Client Validation Configuration

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | boolean | Enable client certificate validation | `false` |
| `caFile` | string | Path to CA certificate file | - |
| `vaultPath` | string | Vault path for CA certificate | - |
| `requireClientCert` | boolean | Require client certificate | `false` |
| `allowedCNs` | []string | Allowed Common Names | All allowed |
| `allowedSANs` | []string | Allowed Subject Alternative Names | All allowed |

## Examples

### Basic File-Based TLS

Simple route with file-based certificate:

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: multi-tenant-gateway
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      hosts: ["*"]
      tls:
        mode: SIMPLE
        certFile: /app/certs/default/tls.crt
        keyFile: /app/certs/default/tls.key

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
        certFile: /app/certs/routes/tenant-a/tls.crt
        keyFile: /app/certs/routes/tenant-a/tls.key
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
        certFile: /app/certs/routes/tenant-b/tls.crt
        keyFile: /app/certs/routes/tenant-b/tls.key
        sniHosts:
          - tenant-b.example.com
        minVersion: "1.2"
        maxVersion: "1.3"
```

### Vault-Based Certificate Management

Using HashiCorp Vault for dynamic certificate provisioning:

```yaml
routes:
  - name: vault-managed-route
    match:
      - uri:
          prefix: /api/secure
    route:
      - destination:
          host: secure-backend
          port: 8443
    tls:
      vault:
        enabled: true
        pkiMount: pki
        role: web-server
        commonName: secure.example.com
        altNames:
          - api.secure.example.com
          - www.secure.example.com
        ttl: 24h
      sniHosts:
        - secure.example.com
        - api.secure.example.com
      minVersion: "1.3"
```

### Mutual TLS (mTLS) Configuration

Route with client certificate validation:

```yaml
routes:
  - name: mtls-api
    match:
      - uri:
          prefix: /api/secure
    route:
      - destination:
          host: secure-backend
          port: 8443
    tls:
      certFile: /app/certs/routes/secure/tls.crt
      keyFile: /app/certs/routes/secure/tls.key
      sniHosts:
        - secure.example.com
      minVersion: "1.2"
      cipherSuites:
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      clientValidation:
        enabled: true
        caFile: /app/certs/routes/secure/ca.crt
        requireClientCert: true
        allowedCNs:
          - client.secure.example.com
          - admin.secure.example.com
        allowedSANs:
          - client-api.secure.example.com
```

### Multi-Tenant Setup

Complete multi-tenant configuration with different security levels:

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: multi-tenant-gateway
  labels:
    app: avapigw
    environment: production
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      hosts: ["*"]
      tls:
        mode: SIMPLE
        certFile: /app/certs/default/tls.crt
        keyFile: /app/certs/default/tls.key
        minVersion: "1.2"

  routes:
    # Tenant A - Standard TLS
    - name: tenant-a-public
      match:
        - uri:
            prefix: /api/tenant-a/public
      route:
        - destination:
            host: tenant-a-backend
            port: 8080
      tls:
        certFile: /app/certs/routes/tenant-a/tls.crt
        keyFile: /app/certs/routes/tenant-a/tls.key
        sniHosts:
          - tenant-a.example.com
        minVersion: "1.2"

    # Tenant A - Secure API with mTLS
    - name: tenant-a-secure
      match:
        - uri:
            prefix: /api/tenant-a/secure
      route:
        - destination:
            host: tenant-a-secure-backend
            port: 8443
      tls:
        certFile: /app/certs/routes/tenant-a/secure-tls.crt
        keyFile: /app/certs/routes/tenant-a/secure-tls.key
        sniHosts:
          - secure.tenant-a.example.com
        minVersion: "1.3"
        clientValidation:
          enabled: true
          caFile: /app/certs/routes/tenant-a/ca.crt
          requireClientCert: true

    # Tenant B - Vault-managed certificates
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
          pkiMount: pki/tenant-b
          role: web-server
          commonName: tenant-b.example.com
          ttl: 24h
        sniHosts:
          - tenant-b.example.com
          - api.tenant-b.example.com
        minVersion: "1.2"

    # Legacy tenant - Relaxed security
    - name: legacy-tenant
      match:
        - uri:
            prefix: /api/legacy
      route:
        - destination:
            host: legacy-backend
            port: 8080
      tls:
        certFile: /app/certs/routes/legacy/tls.crt
        keyFile: /app/certs/routes/legacy/tls.key
        sniHosts:
          - legacy.example.com
        minVersion: "1.1"  # Relaxed for legacy clients
        cipherSuites:
          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
          - TLS_RSA_WITH_AES_256_GCM_SHA384  # Legacy cipher
```

## Kubernetes Deployment

### Helm Configuration

Configure route-level TLS certificates in your Helm values:

```yaml
# values.yaml
tls:
  enabled: true
  mountPath: /app/certs
  
  # Route-level TLS certificates
  routeCerts:
    - name: tenant-a
      secretName: tenant-a-tls
      caSecretName: tenant-a-ca  # Optional: for client validation
    - name: tenant-b
      secretName: tenant-b-tls
    - name: secure-api
      secretName: secure-api-tls
      caSecretName: secure-api-ca

gateway:
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
        certFile: /app/certs/routes/tenant-a/tls.crt
        keyFile: /app/certs/routes/tenant-a/tls.key
        sniHosts:
          - tenant-a.example.com
        minVersion: "1.2"
        clientValidation:
          enabled: true
          caFile: /app/certs/routes/tenant-a/ca.crt
          requireClientCert: true
```

### Creating TLS Secrets

Create Kubernetes secrets for route certificates:

```bash
# Create certificate secret for tenant-a
kubectl create secret tls tenant-a-tls \
  --cert=tenant-a.crt \
  --key=tenant-a.key

# Create CA secret for client validation (optional)
kubectl create secret generic tenant-a-ca \
  --from-file=ca.crt=tenant-a-ca.crt

# Create certificate secret for tenant-b
kubectl create secret tls tenant-b-tls \
  --cert=tenant-b.crt \
  --key=tenant-b.key
```

### Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: avapigw
spec:
  template:
    spec:
      containers:
        - name: avapigw
          image: ghcr.io/vyrodovalexey/avapigw:latest
          volumeMounts:
            - name: config
              mountPath: /app/configs
            - name: certs
              mountPath: /app/certs
              readOnly: true
            # Route-specific certificate mounts
            - name: tenant-a-certs
              mountPath: /app/certs/routes/tenant-a
              readOnly: true
            - name: tenant-b-certs
              mountPath: /app/certs/routes/tenant-b
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: avapigw-config
        - name: certs
          secret:
            secretName: avapigw-tls
        - name: tenant-a-certs
          projected:
            sources:
              - secret:
                  name: tenant-a-tls
                  items:
                    - key: tls.crt
                      path: tls.crt
                    - key: tls.key
                      path: tls.key
              - secret:
                  name: tenant-a-ca
                  items:
                    - key: ca.crt
                      path: ca.crt
                  optional: true
        - name: tenant-b-certs
          secret:
            secretName: tenant-b-tls
            items:
              - key: tls.crt
                path: tls.crt
              - key: tls.key
                path: tls.key
```

## Troubleshooting

### Common Issues

#### Certificate Not Found
**Problem**: Route certificate files not found
```
ERROR: failed to load route certificate: open /app/certs/routes/tenant-a/tls.crt: no such file or directory
```

**Solutions**:
1. Verify certificate secret exists: `kubectl get secret tenant-a-tls`
2. Check volume mount configuration in deployment
3. Ensure certificate paths match in route configuration
4. Verify secret contains `tls.crt` and `tls.key` keys

#### SNI Mismatch
**Problem**: Wrong certificate served for hostname
```
ERROR: certificate verification failed: hostname doesn't match certificate
```

**Solutions**:
1. Verify `sniHosts` configuration matches requested hostname
2. Check certificate Subject Alternative Names (SANs)
3. Ensure wildcard certificates are properly configured
4. Test with `openssl s_client -connect host:port -servername hostname`

#### Client Certificate Validation Fails
**Problem**: mTLS client authentication fails
```
ERROR: client certificate verification failed: certificate signed by unknown authority
```

**Solutions**:
1. Verify CA certificate is correctly mounted
2. Check client certificate is signed by the configured CA
3. Ensure `requireClientCert` is set appropriately
4. Validate `allowedCNs` and `allowedSANs` configuration

#### Vault Certificate Issues
**Problem**: Vault certificate provisioning fails
```
ERROR: failed to get certificate from vault: permission denied
```

**Solutions**:
1. Verify Vault authentication is working
2. Check PKI mount path and role configuration
3. Ensure Vault policy allows certificate generation
4. Validate TTL and certificate parameters

### Debugging Commands

```bash
# Check certificate details
openssl x509 -in /app/certs/routes/tenant-a/tls.crt -text -noout

# Test SNI with specific hostname
openssl s_client -connect gateway.example.com:8443 -servername tenant-a.example.com

# Verify certificate chain
openssl verify -CAfile /app/certs/routes/tenant-a/ca.crt /app/certs/routes/tenant-a/tls.crt

# Check certificate expiration
openssl x509 -in /app/certs/routes/tenant-a/tls.crt -noout -dates

# Test client certificate
openssl s_client -connect gateway.example.com:8443 \
  -cert client.crt -key client.key -servername secure.example.com
```

### Log Analysis

Enable debug logging to troubleshoot TLS issues:

```yaml
observability:
  logging:
    level: debug
```

Look for these log patterns:
- `TLS handshake completed` - Successful TLS negotiation
- `SNI hostname: <hostname>` - SNI hostname detection
- `Selected certificate for route: <route-name>` - Route certificate selection
- `Client certificate validation: <result>` - mTLS validation results

## Security Considerations

### Certificate Management Best Practices

1. **Use Strong Private Keys**
   - Minimum 2048-bit RSA or 256-bit ECDSA
   - Store private keys securely with restricted access
   - Consider Hardware Security Modules (HSMs) for production

2. **Certificate Rotation**
   - Implement automated certificate renewal
   - Use short-lived certificates (24-48 hours) with Vault
   - Monitor certificate expiration dates

3. **Access Control**
   - Restrict access to certificate files and secrets
   - Use Kubernetes RBAC for secret access
   - Implement audit logging for certificate operations

4. **Network Security**
   - Use TLS 1.2 or higher (disable TLS 1.0/1.1)
   - Configure secure cipher suites only
   - Enable Perfect Forward Secrecy (PFS)

### Recommended TLS Configuration

```yaml
tls:
  minVersion: "1.2"  # Minimum TLS 1.2
  maxVersion: "1.3"  # Prefer TLS 1.3
  cipherSuites:
    # TLS 1.3 cipher suites (preferred)
    - TLS_AES_256_GCM_SHA384
    - TLS_AES_128_GCM_SHA256
    - TLS_CHACHA20_POLY1305_SHA256
    # TLS 1.2 cipher suites (fallback)
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

### mTLS Security Guidelines

1. **Client Certificate Validation**
   - Always validate client certificates against trusted CAs
   - Use certificate pinning for high-security environments
   - Implement certificate revocation checking (CRL/OCSP)

2. **Access Control**
   - Restrict allowed Common Names and SANs
   - Implement role-based access using certificate attributes
   - Log all client certificate authentication attempts

3. **Certificate Lifecycle**
   - Use short-lived client certificates
   - Implement automated client certificate provisioning
   - Monitor and alert on certificate expiration

## Performance Considerations

### Certificate Caching
- Route certificates are cached in memory for performance
- Certificate reloading is triggered by file system events
- Vault certificates are cached according to their TTL

### SNI Performance
- SNI hostname matching is optimized with efficient algorithms
- Wildcard certificate matching has minimal performance impact
- Certificate selection occurs during TLS handshake

### Monitoring Metrics
Monitor these key metrics for route-level TLS:
- `tls_handshake_duration_seconds` - TLS handshake performance
- `tls_certificate_expiry_seconds` - Certificate expiration monitoring
- `tls_handshake_errors_total` - TLS handshake failures
- `route_certificate_reloads_total` - Certificate reload events

## Migration Guide

### From Listener-Level to Route-Level TLS

1. **Identify Routes Needing Custom Certificates**
   ```bash
   # Analyze current traffic patterns
   kubectl logs -l app=avapigw | grep "SNI hostname" | sort | uniq -c
   ```

2. **Prepare Route Certificates**
   ```bash
   # Create certificate secrets for each route
   kubectl create secret tls route-cert-1 --cert=cert1.crt --key=cert1.key
   kubectl create secret tls route-cert-2 --cert=cert2.crt --key=cert2.key
   ```

3. **Update Route Configuration**
   ```yaml
   # Add TLS configuration to existing routes
   routes:
     - name: existing-route
       # ... existing configuration ...
       tls:
         certFile: /app/certs/routes/route-cert-1/tls.crt
         keyFile: /app/certs/routes/route-cert-1/tls.key
         sniHosts:
           - specific.domain.com
   ```

4. **Deploy and Validate**
   ```bash
   # Deploy updated configuration
   helm upgrade avapigw ./helm/avapigw -f values.yaml
   
   # Test certificate selection
   openssl s_client -connect gateway:8443 -servername specific.domain.com
   ```

This comprehensive documentation provides everything needed to implement and manage route-level TLS certificate override in the Ava API Gateway, from basic configuration to advanced multi-tenant deployments with security best practices.