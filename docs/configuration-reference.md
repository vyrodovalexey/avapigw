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
    grpc:
      enabled: true
      pkiMount: "pki-grpc-prod"
      role: "grpc-server-prod"
      commonName: "grpc.prod.example.com"
      ttl: "12h"
```

## Validation Rules

### Certificate Parameters

- `commonName`: Must be a valid DNS name or IP address
- `altNames`: Each entry must be a valid DNS name
- `ipSans`: Each entry must be a valid IP address
- `ttl`: Must be a valid duration string (e.g., "24h", "30m")
- `renewBefore`: Must be less than `ttl`

### TLS Version Validation

The gateway validates TLS versions and issues warnings for deprecated versions:

- **TLS 1.0** - Deprecated per RFC 8996, generates validation warning
- **TLS 1.1** - Deprecated per RFC 8996, generates validation warning
- **TLS 1.2** - Recommended minimum version (no warnings)
- **TLS 1.3** - Latest and most secure version (no warnings)

Example validation warning:
```
TLS version TLS10 is deprecated (RFC 8996), use TLS12 or TLS13
```

Use the `ValidateConfigWithWarnings()` API to retrieve these warnings:

```go
warnings, err := config.ValidateConfigWithWarnings(gatewayConfig)
if err != nil {
    // Handle validation errors
}
for _, warning := range warnings {
    log.Warn("Configuration warning", "path", warning.Path, "message", warning.Message)
}
```

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

## Route-Level Authentication

Route-level authentication allows you to secure specific routes with different authentication mechanisms.

### JWT Authentication

```yaml
spec:
  routes:
    - name: secure-api
      match:
        - uri:
            prefix: /api/v1/secure
      route:
        - destination:
            host: backend
            port: 8080
      authentication:
        enabled: true
        jwt:
          enabled: true
          issuer: "https://auth.example.com"
          audience: ["api.example.com"]
          jwksUrl: "https://auth.example.com/.well-known/jwks.json"
          algorithm: "RS256"
          claimMapping:
            roles: "roles"
            permissions: "permissions"
            email: "email"
            name: "name"
            groups: "groups"
            scopes: "scope"
        allowAnonymous: false
        skipPaths:
          - "/api/v1/secure/health"
          - "/api/v1/secure/metrics"
```

### API Key Authentication

```yaml
spec:
  routes:
    - name: api-key-route
      match:
        - uri:
            prefix: /api/v1/apikey
      authentication:
        enabled: true
        apiKey:
          enabled: true
          header: "X-API-Key"           # Header name for API key
          query: "api_key"              # Alternative: query parameter
          hashAlgorithm: "sha256"       # Hash algorithm for stored keys
          vaultPath: "secret/api-keys"  # Vault path for key storage
```

### mTLS Authentication

```yaml
spec:
  routes:
    - name: mtls-route
      match:
        - uri:
            prefix: /api/v1/mtls
      authentication:
        enabled: true
        mtls:
          enabled: true
          caFile: "/certs/client-ca.crt"
          extractIdentity: "cn"         # Extract identity from CN
          allowedCNs:
            - "client.example.com"
            - "admin.example.com"
          allowedOUs:
            - "Engineering"
            - "Operations"
```

### OIDC Authentication

```yaml
spec:
  routes:
    - name: oidc-route
      match:
        - uri:
            prefix: /api/v1/oidc
      authentication:
        enabled: true
        oidc:
          enabled: true
          providers:
            - name: "keycloak"
              issuerUrl: "https://keycloak.example.com/realms/myrealm"
              clientId: "api-client"
              clientSecretRef:
                name: "oidc-secret"
                key: "client-secret"
              scopes: ["openid", "profile", "email"]
            - name: "auth0"
              issuerUrl: "https://example.auth0.com/"
              clientId: "auth0-client"
              clientSecret: "auth0-secret"
              scopes: ["openid", "profile"]
```

## Route-Level Authorization

Route-level authorization provides fine-grained access control for your APIs.

### RBAC (Role-Based Access Control)

```yaml
spec:
  routes:
    - name: rbac-route
      match:
        - uri:
            prefix: /api/v1/rbac
      authorization:
        enabled: true
        defaultPolicy: "deny"
        rbac:
          enabled: true
          policies:
            - name: "admin-full-access"
              roles: ["admin", "super-admin"]
              resources: ["*"]
              actions: ["*"]
              effect: "allow"
              priority: 100
            - name: "user-read-access"
              roles: ["user"]
              resources: ["/api/v1/rbac/users/*"]
              actions: ["GET"]
              effect: "allow"
              priority: 50
            - name: "user-write-own"
              roles: ["user"]
              resources: ["/api/v1/rbac/users/{{.user.id}}/*"]
              actions: ["PUT", "PATCH"]
              effect: "allow"
              priority: 60
          roleHierarchy:
            super-admin: ["admin", "user", "viewer"]
            admin: ["user", "viewer"]
            user: ["viewer"]
        skipPaths:
          - "/api/v1/rbac/health"
        cache:
          enabled: true
          ttl: "5m"
          maxSize: 1000
          type: "memory"
```

### ABAC (Attribute-Based Access Control)

```yaml
spec:
  routes:
    - name: abac-route
      match:
        - uri:
            prefix: /api/v1/abac
      authorization:
        enabled: true
        defaultPolicy: "deny"
        abac:
          enabled: true
          policies:
            - name: "business-hours-only"
              expression: "request.time.getHours() >= 9 && request.time.getHours() <= 17"
              resources: ["/api/v1/abac/admin/*"]
              effect: "allow"
              priority: 80
            - name: "ip-whitelist"
              expression: "request.remote_addr in ['10.0.0.0/8', '192.168.0.0/16']"
              resources: ["/api/v1/abac/internal/*"]
              effect: "allow"
              priority: 90
            - name: "user-owns-resource"
              expression: "request.user.id == resource.owner_id"
              resources: ["/api/v1/abac/users/*/profile"]
              actions: ["PUT", "DELETE"]
              effect: "allow"
              priority: 70
```

### External Authorization (OPA)

```yaml
spec:
  routes:
    - name: opa-route
      match:
        - uri:
            prefix: /api/v1/opa
      authorization:
        enabled: true
        defaultPolicy: "deny"
        external:
          enabled: true
          opa:
            url: "http://opa.example.com:8181/v1/data/authz/allow"
            policy: "authz"
            headers:
              Authorization: "Bearer opa-token"
              Content-Type: "application/json"
          timeout: "5s"
          failOpen: false
```

## Backend Transformation

Backend transformation allows you to modify requests and responses at the backend level.

### HTTP Backend Transformation

```yaml
spec:
  backends:
    - name: transform-backend
      hosts:
        - address: api.internal
          port: 8080
      transform:
        request:
          template: |
            {
              "data": {{.Body}},
              "metadata": {
                "timestamp": "{{.Timestamp}}",
                "requestId": "{{.RequestID}}",
                "source": "gateway",
                "version": "v1",
                "user": {
                  "id": "{{.user.id}}",
                  "email": "{{.user.email}}"
                }
              }
            }
          headers:
            set:
              X-Gateway-Transform: "enabled"
              X-Request-ID: "{{.RequestID}}"
              X-User-ID: "{{.user.id}}"
            add:
              X-Forwarded-By: "avapigw"
            remove:
              - "X-Internal-Header"
              - "X-Debug-Info"
        response:
          allowFields:
            - "id"
            - "name"
            - "email"
            - "created_at"
            - "updated_at"
            - "status"
            - "profile"
          denyFields:
            - "password"
            - "secret"
            - "internal_id"
            - "private_key"
            - "ssn"
            - "credit_card"
          fieldMappings:
            created_at: "createdAt"
            updated_at: "updatedAt"
            user_id: "userId"
            first_name: "firstName"
            last_name: "lastName"
          headers:
            set:
              X-Response-Transform: "applied"
              X-Response-Time: "{{.ResponseTime}}"
            remove:
              - "Server"
              - "X-Powered-By"
```

### gRPC Backend Transformation

```yaml
spec:
  grpcBackends:
    - name: grpc-transform-backend
      hosts:
        - address: grpc-service.internal
          port: 9000
      transform:
        fieldMask:
          paths:
            - "user.id"
            - "user.name"
            - "user.email"
            - "user.profile.avatar"
            - "user.profile.bio"
            - "user.created_at"
            - "user.permissions"
        metadata:
          static:
            x-source: "gateway"
            x-version: "v1"
            x-backend: "user-service"
            x-environment: "production"
          dynamic:
            x-request-id: "{{.RequestID}}"
            x-timestamp: "{{.Timestamp}}"
            x-user-id: "{{.user.id}}"
            x-tenant-id: "{{.tenant.id}}"
            x-gateway-id: "{{.GatewayID}}"
```

## Backend Caching

Backend caching improves performance by caching responses at the backend level.

### Redis Cache Features

The gateway provides advanced Redis caching features for improved performance and reliability:

**TTL Jitter**
- Prevents thundering herd problems by adding random jitter to TTL values
- Configurable jitter percentage (0.0-1.0) applied as ±jitter% to cache TTL
- Example: `ttlJitter: 0.1` means TTL varies by ±10%
- Helps distribute cache expiration times to avoid simultaneous cache misses

**Hash Keys**
- SHA256 hashing of cache keys for privacy and length control
- Prevents key length issues with Redis key size limits
- Provides privacy by obscuring cache key contents
- Maintains cache key uniqueness while reducing storage overhead

**Vault Password Integration**
- Secure password management using HashiCorp Vault KV secrets
- Supports both standalone Redis and Redis Sentinel configurations
- Automatic password resolution from Vault at runtime
- Vault path format: `mount/path` (e.g., `secret/redis`)
- Secret must contain a `password` key

### HTTP Backend Caching

```yaml
spec:
  backends:
    - name: cached-backend
      hosts:
        - address: api.internal
          port: 8080
      cache:
        enabled: true
        ttl: "10m"                     # Cache for 10 minutes
        keyComponents:
          - "path"                     # Include request path
          - "query"                    # Include query parameters
          - "headers.Authorization"    # Include auth header
          - "headers.X-Tenant-ID"      # Include tenant header
          - "headers.Accept-Language"  # Include language header
        staleWhileRevalidate: "2m"     # Serve stale for 2 minutes while revalidating
        type: "memory"                 # Use in-memory cache
```

### Redis Backend Caching

#### Redis Standalone Configuration

```yaml
spec:
  backends:
    - name: redis-cached-backend
      hosts:
        - address: api.internal
          port: 8080
      cache:
        enabled: true
        ttl: "1h"
        keyComponents:
          - "path"
          - "query"
          - "headers.Authorization"
        staleWhileRevalidate: "5m"
        type: "redis"
          redis:
            address: "redis.cache.svc.cluster.local:6379"
            password: "redis-password"
            # Vault password integration
            passwordVaultPath: "secret/redis"
            db: 0
            maxRetries: 3
            poolSize: 10
            keyPrefix: "avapigw:cache:"
            # TTL jitter to prevent thundering herd
            ttlJitter: 0.1  # ±10% jitter on TTL values
            # Hash cache keys for privacy and length control
            hashKeys: true
            tls:
              enabled: true
              caFile: "/etc/ssl/certs/redis-ca.crt"
              certFile: "/etc/ssl/certs/redis-client.crt"
              keyFile: "/etc/ssl/private/redis-client.key"
              insecureSkipVerify: false
```

#### Redis Sentinel Configuration

```yaml
spec:
  backends:
    - name: redis-sentinel-cached-backend
      hosts:
        - address: api.internal
          port: 8080
      cache:
        enabled: true
        ttl: "1h"
        keyComponents:
          - "path"
          - "query"
          - "headers.Authorization"
        staleWhileRevalidate: "5m"
        type: "redis"
        redis:
          # Redis Sentinel configuration takes precedence over standalone
          sentinel:
            masterName: "mymaster"
            sentinelAddrs:
              - "sentinel1.cache.svc.cluster.local:26379"
              - "sentinel2.cache.svc.cluster.local:26379"
              - "sentinel3.cache.svc.cluster.local:26379"
            sentinelPassword: "sentinel-password"
            password: "redis-master-password"
            # Vault password integration for sentinel
            sentinelPasswordVaultPath: "secret/redis-sentinel"
            passwordVaultPath: "secret/redis-master"
            db: 0
          # Connection pool settings
          maxRetries: 3
          poolSize: 10
          keyPrefix: "avapigw:cache:"
          # TTL jitter to prevent thundering herd
          ttlJitter: 0.1  # ±10% jitter on TTL values
          # Hash cache keys for privacy and length control
          hashKeys: true
          # TLS configuration for Redis connections
          tls:
            enabled: true
            caFile: "/etc/ssl/certs/redis-ca.crt"
            certFile: "/etc/ssl/certs/redis-client.crt"
            keyFile: "/etc/ssl/private/redis-client.key"
            insecureSkipVerify: false
```

#### Redis Configuration Environment Variables

Redis cache configuration can be overridden using environment variables:

| Environment Variable | Description | Example |
|---------------------|-------------|---------|
| `REDIS_SENTINEL_MASTER_NAME` | Sentinel master name | `mymaster` |
| `REDIS_SENTINEL_ADDRS` | Comma-separated sentinel addresses | `sentinel1:26379,sentinel2:26379,sentinel3:26379` |
| `REDIS_SENTINEL_PASSWORD` | Sentinel authentication password | `sentinel-password` |
| `REDIS_MASTER_PASSWORD` | Redis master password | `redis-master-password` |
| `REDIS_SENTINEL_DB` | Redis database number | `0` |
| `REDIS_ADDRESS` | Redis standalone address (fallback) | `redis:6379` |
| `REDIS_PASSWORD` | Redis standalone password (fallback) | `redis-password` |
| `REDIS_DB` | Redis standalone database (fallback) | `0` |
| `REDIS_TTL_JITTER` | TTL jitter percentage (0.0-1.0) | `0.1` |
| `REDIS_HASH_KEYS` | Enable cache key hashing (true/false) | `true` |
| `REDIS_PASSWORD_VAULT_PATH` | Vault path for Redis password | `secret/redis` |
| `REDIS_SENTINEL_PASSWORD_VAULT_PATH` | Vault path for sentinel password | `secret/redis-sentinel` |
| `REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH` | Vault path for sentinel auth password | `secret/redis-sentinel-auth` |

**Configuration Precedence:**
1. Environment variables (highest priority)
2. Sentinel configuration in YAML
3. Standalone Redis configuration in YAML (lowest priority)

#### Redis Sentinel High Availability

Redis Sentinel provides automatic failover and high availability:

- **Automatic Failover**: When the master becomes unavailable, Sentinel promotes a replica to master
- **Service Discovery**: Gateway automatically discovers the current master through Sentinel
- **Connection Pooling**: Optimized connection pooling with exponential backoff retry
- **TLS Support**: Full TLS encryption for both Sentinel and Redis connections
- **Health Monitoring**: Continuous monitoring of Redis master and replica health

Example with full high availability configuration:

```yaml
spec:
  backends:
    - name: ha-redis-cached-backend
      hosts:
        - address: api.internal
          port: 8080
      cache:
        enabled: true
        ttl: "30m"
        keyComponents:
          - "path"
          - "query"
          - "headers.Authorization"
          - "headers.X-Tenant-ID"
        staleWhileRevalidate: "5m"
        type: "redis"
        redis:
          sentinel:
            masterName: "mymaster"
            sentinelAddrs:
              - "sentinel1.cache.svc.cluster.local:26379"
              - "sentinel2.cache.svc.cluster.local:26379"
              - "sentinel3.cache.svc.cluster.local:26379"
            sentinelPassword: "sentinel-password"
            password: "redis-master-password"
            db: 0
          # Performance tuning
          maxRetries: 5
          poolSize: 20
          minIdleConns: 5
          maxConnAge: "30m"
          poolTimeout: "5s"
          idleTimeout: "10m"
          idleCheckFrequency: "1m"
          # Cache key management
          keyPrefix: "avapigw:cache:v1:"
          # TLS for production security
          tls:
            enabled: true
            caFile: "/etc/ssl/certs/redis-ca.crt"
            certFile: "/etc/ssl/certs/redis-client.crt"
            keyFile: "/etc/ssl/private/redis-client.key"
            serverName: "redis.cache.internal"
            insecureSkipVerify: false
```

### gRPC Backend Caching

```yaml
spec:
  grpcBackends:
    - name: grpc-cached-backend
      hosts:
        - address: grpc-service.internal
          port: 9000
      cache:
        enabled: true
        ttl: "5m"
        keyComponents:
          - "service"                  # gRPC service name
          - "method"                   # gRPC method name
          - "metadata.x-tenant-id"     # Tenant metadata
          - "metadata.authorization"   # Auth metadata
          - "request.user_id"          # Request field
        staleWhileRevalidate: "1m"
        type: "memory"
```

## Backend Encoding

Backend encoding configures content type and compression for backend communication.

### HTTP Backend Encoding

```yaml
spec:
  backends:
    - name: encoded-backend
      hosts:
        - address: api.internal
          port: 8080
      encoding:
        request:
          contentType: "application/json"
          compression: "gzip"          # Compress requests
        response:
          contentType: "application/json"
          compression: "gzip"          # Compress responses
```

### Advanced Encoding Configuration

```yaml
spec:
  backends:
    - name: advanced-encoding-backend
      hosts:
        - address: api.internal
          port: 8080
      encoding:
        request:
          contentType: "application/json; charset=utf-8"
          compression: "br"            # Brotli compression
        response:
          contentType: "application/json; charset=utf-8"
          compression: "deflate"       # Deflate compression
```

### gRPC Backend Encoding

```yaml
spec:
  grpcBackends:
    - name: grpc-encoded-backend
      hosts:
        - address: grpc-service.internal
          port: 9000
      encoding:
        request:
          contentType: "application/grpc"
        response:
          contentType: "application/grpc"
```

## Configuration Level Hierarchy

### Route vs Backend Configuration

When the same configuration option is available at both route and backend levels, the route-level configuration takes precedence:

```yaml
# Example: Rate limiting at both levels
spec:
  routes:
    - name: example-route
      rateLimit:
        enabled: true
        requestsPerSecond: 100        # Route-level limit (takes precedence)
      route:
        - destination:
            host: example-backend
            port: 8080
  
  backends:
    - name: example-backend
      rateLimit:
        enabled: true
        requestsPerSecond: 500        # Backend-level limit (ignored for this route)
```

### Configuration Inheritance

Some configurations can be inherited from higher levels:

1. **Gateway Level** - Default configuration for all routes
2. **Route Level** - Overrides gateway defaults
3. **Backend Level** - Applies to all routes using this backend

```yaml
# Gateway-level defaults
spec:
  defaults:
    rateLimit:
      enabled: true
      requestsPerSecond: 1000
    authentication:
      enabled: false
  
  routes:
    - name: public-route
      # Inherits gateway defaults: 1000 RPS, no auth
      match:
        - uri:
            prefix: /public
    
    - name: secure-route
      # Overrides defaults: 100 RPS, JWT auth
      rateLimit:
        requestsPerSecond: 100
      authentication:
        enabled: true
        jwt:
          enabled: true
      match:
        - uri:
            prefix: /secure
```

## Security Features

### Open Redirect Protection

The AV API Gateway includes built-in protection against open redirect attacks by validating redirect URLs:

#### Automatic Redirect Validation

The gateway automatically validates all redirect URLs and blocks potentially unsafe schemes:

**Blocked Schemes:**
- `javascript:` - Prevents JavaScript execution
- `data:` - Prevents data URI exploitation
- `vbscript:` - Prevents VBScript execution
- `file:` - Prevents local file access
- `ftp:` - Prevents FTP redirects

**Allowed Schemes:**
- `http:` - Standard HTTP redirects
- `https:` - Secure HTTPS redirects
- Empty scheme - Relative redirects

#### Example Configuration

```yaml
spec:
  routes:
    - name: safe-redirect-route
      match:
        - uri:
            exact: /redirect
      redirect:
        uri: "https://safe.example.com/target"  # ✅ Safe - HTTPS scheme
        code: 302
    
    - name: relative-redirect-route
      match:
        - uri:
            exact: /relative
      redirect:
        uri: "/safe/path"                       # ✅ Safe - Relative redirect
        code: 302
```

#### Blocked Redirect Examples

The following redirect configurations would be automatically blocked:

```yaml
# ❌ These would be blocked by open redirect protection
redirect:
  uri: "javascript:alert('xss')"               # Blocked - JavaScript scheme
redirect:
  uri: "data:text/html,<script>alert(1)</script>"  # Blocked - Data URI
redirect:
  uri: "vbscript:msgbox('xss')"                # Blocked - VBScript scheme
```

#### Error Response

When an unsafe redirect is detected, the gateway returns:
- **HTTP Status**: 400 Bad Request
- **Response Body**: `{"error":"bad request","message":"unsafe redirect URL"}`
- **Logging**: Security event logged for monitoring

#### Monitoring Redirect Security

Monitor redirect security through metrics and logs:

```bash
# Check for blocked redirects in logs
kubectl logs -l app=avapigw | grep "unsafe redirect"

# Monitor redirect-related errors
curl http://localhost:9090/metrics | grep redirect
```

## Recent Updates

### Dependency Upgrades

The following dependencies have been upgraded for improved performance and security:

**Go Dependencies:**
- `go-redis` upgraded to v9.17.3 - Enhanced Redis client with improved connection pooling and Sentinel support
- `protobuf` upgraded to v1.36.11 - Latest Protocol Buffers implementation with performance improvements

**CI/CD Action Upgrades:**
- `actions/checkout` upgraded to v6.0.2 - Improved Git checkout performance and security
- `docker/login-action` upgraded to v3.7.0 - Enhanced Docker registry authentication
- `github/codeql-action` upgraded to v4.32.2 - Latest CodeQL security analysis
- `anchore/sbom-action` upgraded to v0.22.2 - Improved Software Bill of Materials generation
- `helm/kind-action` upgraded to v1.13.0 - Latest Kubernetes in Docker for testing

These upgrades provide enhanced security, performance improvements, and better compatibility with modern infrastructure.

This configuration reference provides comprehensive coverage of all route-level authentication, authorization, backend transformation, caching, encoding options, and security features, enabling secure and efficient API gateway operations.