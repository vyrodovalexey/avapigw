# Configuration Reference - Vault PKI Integration

## Overview

This document provides a comprehensive reference for configuring Vault PKI integration in the AV API Gateway. The configuration supports three levels of certificate management:

1. **Listener-level TLS** - Gateway's own TLS certificates
2. **Route-level TLS** - Per-route certificates for SNI-based selection
3. **Backend mTLS** - Client certificates for backend authentication

## Vault Configuration

### Global Vault Settings

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: vault-gateway
spec:
  vault:
    # Vault server configuration
    address: "https://vault.example.com:8200"
    authMethod: kubernetes  # kubernetes, token, approle, aws, gcp
    role: gateway-role
    
    # Optional: Static token (development only)
    token: "hvs.CAESIJ..."
    
    # Optional: AppRole authentication
    appRole:
      roleId: "role-id"
      secretId: "secret-id"
    
    # Optional: AWS authentication
    aws:
      role: "vault-role"
      region: "us-west-2"
    
    # Optional: GCP authentication
    gcp:
      role: "vault-role"
      serviceAccount: "gateway@project.iam.gserviceaccount.com"
    
    # TLS configuration for Vault connection
    tls:
      enabled: true
      caFile: "/etc/ssl/certs/vault-ca.crt"
      certFile: "/etc/ssl/certs/vault-client.crt"
      keyFile: "/etc/ssl/private/vault-client.key"
      serverName: "vault.example.com"
      insecureSkipVerify: false
    
    # Connection settings
    timeout: 30s
    retries: 3
    retryDelay: 1s
    maxRetryDelay: 30s
```

## Listener-Level TLS Configuration

### Basic Vault PKI Configuration

```yaml
spec:
  listeners:
    - name: https
      port: 8443
      protocol: HTTPS
      hosts: ["*"]
      tls:
        mode: SIMPLE
        minVersion: "1.2"
        maxVersion: "1.3"
        
        # Vault PKI configuration
        vault:
          enabled: true
          pkiMount: "pki"                    # PKI secrets engine mount path
          role: "gateway-server"             # PKI role name
          commonName: "gateway.example.com"  # Certificate common name
          altNames:                          # Subject Alternative Names
            - "api.example.com"
            - "www.example.com"
            - "*.api.example.com"
          ipSans:                            # IP Subject Alternative Names
            - "10.0.1.100"
            - "192.168.1.100"
          ttl: "24h"                         # Certificate TTL
          renewBefore: "1h"                  # Renew before expiry
          
        # Optional: Custom cipher suites
        cipherSuites:
          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
          - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
          - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        
        # Optional: HSTS configuration
        hsts:
          enabled: true
          maxAge: 31536000
          includeSubDomains: true
          preload: true
```

### Advanced Listener Configuration

```yaml
spec:
  listeners:
    - name: https-advanced
      port: 8443
      protocol: HTTPS
      hosts: ["*.example.com"]
      tls:
        mode: MUTUAL  # Enable mutual TLS
        minVersion: "1.3"
        
        # Server certificate from Vault PKI
        vault:
          enabled: true
          pkiMount: "pki-server"
          role: "gateway-server"
          commonName: "gateway.example.com"
          altNames:
            - "api.example.com"
            - "admin.example.com"
          ttl: "12h"
          renewBefore: "30m"
          
          # Optional: Custom certificate parameters
          excludeCnFromSans: false
          format: "pem"
          privateKeyFormat: "pkcs8"
          
        # Client certificate validation
        clientValidation:
          enabled: true
          vault:
            enabled: true
            pkiMount: "pki-client"
            role: "client-ca"
          requireClientCert: true
          allowedCNs:
            - "client.example.com"
            - "admin.example.com"
          allowedSANs:
            - "*.client.example.com"
```

## Route-Level TLS Configuration

### Basic Route TLS with Vault PKI

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
      
      # Route-level TLS configuration
      tls:
        vault:
          enabled: true
          pkiMount: "pki"
          role: "web-server"
          commonName: "tenant-a.example.com"
          altNames:
            - "api.tenant-a.example.com"
            - "www.tenant-a.example.com"
          ttl: "24h"
          renewBefore: "2h"
        
        # SNI hostnames for certificate selection
        sniHosts:
          - "tenant-a.example.com"
          - "api.tenant-a.example.com"
          - "www.tenant-a.example.com"
        
        # TLS version constraints
        minVersion: "1.2"
        maxVersion: "1.3"
```

### Multi-Tenant Route Configuration

```yaml
spec:
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
        vault:
          enabled: true
          pkiMount: "pki"
          role: "tenant-server"
          commonName: "tenant-a.example.com"
          ttl: "24h"
        sniHosts:
          - "tenant-a.example.com"
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
        vault:
          enabled: true
          pkiMount: "pki"
          role: "secure-server"
          commonName: "secure.tenant-a.example.com"
          ttl: "12h"
        sniHosts:
          - "secure.tenant-a.example.com"
        minVersion: "1.3"
        clientValidation:
          enabled: true
          vault:
            enabled: true
            pkiMount: "pki-client"
            role: "tenant-a-clients"
          requireClientCert: true
          allowedCNs:
            - "client.tenant-a.example.com"

    # Tenant B - Different PKI mount
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
          pkiMount: "pki-tenant-b"  # Separate PKI mount
          role: "web-server"
          commonName: "tenant-b.example.com"
          ttl: "6h"
          renewBefore: "30m"
        sniHosts:
          - "tenant-b.example.com"
        minVersion: "1.2"
```

### Route TLS with File Fallback

```yaml
spec:
  routes:
    - name: hybrid-route
      match:
        - uri:
            prefix: /api/hybrid
      route:
        - destination:
            host: backend
            port: 8080
      tls:
        # Primary: Vault PKI
        vault:
          enabled: true
          pkiMount: "pki"
          role: "web-server"
          commonName: "hybrid.example.com"
          ttl: "24h"
        
        # Fallback: File-based certificates
        certFile: "/app/certs/routes/hybrid/tls.crt"
        keyFile: "/app/certs/routes/hybrid/tls.key"
        
        sniHosts:
          - "hybrid.example.com"
```

## Backend TLS Configuration

### Backend mTLS with Vault PKI

```yaml
spec:
  backends:
    - name: secure-backend
      hosts:
        - address: secure-api.example.com
          port: 8443
          weight: 1
      
      # Backend TLS configuration
      tls:
        enabled: true
        mode: MUTUAL
        
        # Client certificate from Vault PKI
        vault:
          enabled: true
          pkiMount: "pki-client"
          role: "gateway-client"
          commonName: "gateway-client.example.com"
          altNames:
            - "gateway.internal"
            - "client.gateway.internal"
          ttl: "24h"
          renewBefore: "1h"
        
        # Server verification
        serverName: "secure-api.example.com"
        caFile: "/etc/ssl/certs/backend-ca.crt"
        insecureSkipVerify: false
        
        # TLS version constraints
        minVersion: "1.2"
        maxVersion: "1.3"
```

### Backend with Authentication and TLS

```yaml
spec:
  backends:
    - name: authenticated-backend
      hosts:
        - address: auth-api.example.com
          port: 8443
      
      # Backend authentication
      authentication:
        type: mtls
        mtls:
          enabled: true
          vault:
            enabled: true
            pkiMount: "pki-client"
            role: "backend-client"
            commonName: "gateway-auth.example.com"
            ttl: "4h"
      
      # Backend TLS (separate from authentication)
      tls:
        enabled: true
        mode: SIMPLE
        serverName: "auth-api.example.com"
        caFile: "/etc/ssl/certs/backend-ca.crt"
        
      # Circuit breaker
      circuitBreaker:
        enabled: true
        threshold: 5
        timeout: 30s
        halfOpenRequests: 3
```

## VaultTLSConfig Reference

### Complete Configuration Schema

```yaml
vault:
  enabled: boolean                    # Enable Vault PKI integration
  pkiMount: string                    # PKI secrets engine mount path
  role: string                        # PKI role name
  commonName: string                  # Certificate common name
  altNames: []string                  # Subject Alternative Names (DNS)
  ipSans: []string                    # IP Subject Alternative Names
  uriSans: []string                   # URI Subject Alternative Names
  otherSans: []string                 # Other Subject Alternative Names
  ttl: duration                       # Certificate TTL (e.g., "24h", "720h")
  renewBefore: duration               # Renew before expiry (e.g., "1h", "30m")
  format: string                      # Certificate format ("pem", "der", "pem_bundle")
  privateKeyFormat: string            # Private key format ("der", "pkcs8")
  excludeCnFromSans: boolean          # Exclude CN from SANs
  
  # Advanced options
  serialNumber: string                # Certificate serial number
  keyType: string                     # Key type ("rsa", "ec", "ed25519")
  keyBits: integer                    # Key size in bits (for RSA)
  keyUsage: []string                  # Key usage extensions
  extKeyUsage: []string               # Extended key usage
  
  # Renewal settings
  autoRenew: boolean                  # Enable automatic renewal (default: true)
  renewJitter: duration               # Random jitter for renewal timing
  maxRetries: integer                 # Max renewal retry attempts
  retryDelay: duration                # Delay between retry attempts
```

### Field Descriptions

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | Yes | false | Enable Vault PKI integration |
| `pkiMount` | string | Yes | - | PKI secrets engine mount path |
| `role` | string | Yes | - | PKI role name for certificate issuance |
| `commonName` | string | Yes | - | Certificate common name (CN) |
| `altNames` | []string | No | [] | DNS Subject Alternative Names |
| `ipSans` | []string | No | [] | IP Subject Alternative Names |
| `uriSans` | []string | No | [] | URI Subject Alternative Names |
| `otherSans` | []string | No | [] | Other Subject Alternative Names |
| `ttl` | duration | No | 24h | Certificate time-to-live |
| `renewBefore` | duration | No | 1h | Renew certificate before expiry |
| `format` | string | No | pem | Certificate format |
| `privateKeyFormat` | string | No | pkcs8 | Private key format |
| `excludeCnFromSans` | boolean | No | false | Exclude CN from SANs |
| `autoRenew` | boolean | No | true | Enable automatic renewal |
| `renewJitter` | duration | No | 5m | Random jitter for renewal |
| `maxRetries` | integer | No | 3 | Max renewal retry attempts |
| `retryDelay` | duration | No | 30s | Delay between retries |

## Helm Values Reference

### Complete Vault PKI Configuration

```yaml
# values.yaml
vault:
  enabled: true
  address: "https://vault.example.com:8200"
  authMethod: kubernetes
  role: gateway-role
  
  # TLS for Vault connection
  tls:
    enabled: true
    caSecretName: vault-ca-cert
    skipVerify: false
  
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
    format: "pem"
    privateKeyFormat: "pkcs8"
    autoRenew: true
    renewJitter: "5m"
    maxRetries: 3
    retryDelay: "30s"

gateway:
  listeners:
    https:
      enabled: true
      port: 8443
      tls:
        enabled: true
        vault:
          enabled: true
        minVersion: "1.2"
        hsts:
          enabled: true
          maxAge: 31536000

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
          role: web-server
          commonName: tenant-a.example.com
          altNames:
            - api.tenant-a.example.com
          ttl: 24h
          renewBefore: 2h
        sniHosts:
          - tenant-a.example.com
          - api.tenant-a.example.com

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
          pkiMount: pki-client
          role: gateway-client
          commonName: gateway-client.example.com
          ttl: 24h
        serverName: secure-api.example.com
```

### Environment-Specific Configuration

```yaml
# Development environment
vault:
  enabled: true
  address: "http://vault.dev.local:8200"
  authMethod: token
  token: "dev-token"
  tls:
    enabled: false
  pki:
    enabled: true
    pkiMount: "pki-dev"
    role: "dev-server"
    commonName: "gateway.dev.local"
    ttl: "1h"
    renewBefore: "10m"

---
# Production environment
vault:
  enabled: true
  address: "https://vault.prod.example.com:8200"
  authMethod: kubernetes
  role: gateway-prod
  tls:
    enabled: true
    caSecretName: vault-prod-ca
    skipVerify: false
  pki:
    enabled: true
    pkiMount: "pki-prod"
    role: "gateway-server-prod"
    commonName: "gateway.prod.example.com"
    altNames:
      - "api.prod.example.com"
      - "*.api.prod.example.com"
    ttl: "24h"
    renewBefore: "2h"
    autoRenew: true
    maxRetries: 5
    retryDelay: "1m"
```

## Validation Rules

### Certificate Parameters

- `commonName`: Must be a valid DNS name or IP address
- `altNames`: Each entry must be a valid DNS name
- `ipSans`: Each entry must be a valid IP address
- `ttl`: Must be a valid duration string (e.g., "24h", "30m")
- `renewBefore`: Must be less than `ttl`

### PKI Role Requirements

- Role must exist in the specified PKI mount
- Role must allow the requested `commonName` and `altNames`
- Role TTL limits must accommodate the requested `ttl`
- For client certificates, role must have `client_flag=true`

### Authentication Requirements

- Vault token must have permissions for the PKI mount and role
- For Kubernetes auth, service account must be bound to the Vault role
- For AppRole auth, role ID and secret ID must be valid

## Migration Guide

### From File-Based to Vault PKI

1. **Prepare Vault PKI**
   ```bash
   # Enable PKI and create role
   vault secrets enable pki
   vault write pki/roles/gateway-server \
     allowed_domains="example.com" \
     allow_subdomains=true \
     max_ttl="720h"
   ```

2. **Update Configuration**
   ```yaml
   # Before (file-based)
   tls:
     certFile: /app/certs/tls.crt
     keyFile: /app/certs/tls.key
   
   # After (Vault PKI)
   tls:
     vault:
       enabled: true
       pkiMount: pki
       role: gateway-server
       commonName: gateway.example.com
       ttl: 24h
   ```

3. **Deploy and Validate**
   ```bash
   # Deploy updated configuration
   helm upgrade gateway ./helm/avapigw -f values.yaml
   
   # Verify certificate issuance
   curl -k https://gateway.example.com:8443/health
   
   # Check certificate details
   openssl s_client -connect gateway.example.com:8443 -servername gateway.example.com
   ```

This configuration reference provides comprehensive coverage of all Vault PKI integration options, enabling secure and automated certificate management across the entire gateway infrastructure.