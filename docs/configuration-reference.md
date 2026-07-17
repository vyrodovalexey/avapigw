# Configuration Reference - Vault PKI Integration

## Overview

This document provides a comprehensive reference for configuring Vault PKI integration in the AV API Gateway. The configuration supports three levels of certificate management:

1. **Listener-level TLS** - Gateway's own TLS certificates
2. **Route-level TLS** - Per-route certificates for SNI-based selection
3. **Backend mTLS** - Client certificates for backend authentication

## Vault Configuration

### Vault Client Connection (`spec.vault`)

The gateway-wide Vault **client connection** — how the gateway reaches and
authenticates against the Vault server — is configured through the
`spec.vault` section of the gateway configuration file, overlaid by `VAULT_*`
environment variables. This is **distinct** from the per-listener, per-route,
and per-backend [`tls.vault` PKI blocks](#listener-level-tls-configuration)
documented below: `tls.vault` requests certificate **issuance** from Vault PKI
and *requires* the client connection defined here.

> **`spec.vault` (client connection) vs. `tls.vault` (PKI issuance)**
>
> - `spec.vault` — one gateway-wide block: server address, auth method, TLS to
>   Vault, caching, retries. Consumed at startup to build the Vault client.
> - `tls.vault` — per-listener/route/backend blocks (`pkiMount`, `role`,
>   `commonName`, …) that issue serving/client certificates. They use the
>   client that `spec.vault` (or `VAULT_ADDR`) establishes.

The Vault client is initialized when `spec.vault.enabled` is `true`, when
`VAULT_ADDR` is set, or when any listener/route enables `tls.vault` PKI
issuance.

> **Operator note:** `spec.vault` is a **gateway-only** section. The operator
> configures its Vault client exclusively through `VAULT_*` environment
> variables and flags (see the [operator configuration](operator/configuration.md)).

#### `spec.vault` fields

Duration fields are strings such as `"5m"` or `"100ms"`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Turns the Vault client on. Absent section preserves legacy env-only behavior |
| `address` | string | - | Vault server address (e.g. `https://vault.example.com:8200`). Required when `enabled` (unless `VAULT_ADDR` is set) |
| `namespace` | string | - | Vault Enterprise namespace |
| `authMethod` | enum | `token` | `token`, `kubernetes`, or `approle` |
| `token` | string | - | Inline token for `token` auth. **Discouraged** in files (validation warning); prefer `tokenFile`/`VAULT_TOKEN`. Mutually exclusive with `tokenFile` |
| `tokenFile` | string | - | Path to a file containing the token (preferred file reference). Mutually exclusive with `token` |
| `kubernetes.role` | string | - | Vault role for `kubernetes` auth. **Required** for `kubernetes` |
| `kubernetes.mountPath` | string | `kubernetes` | Mount path of the Kubernetes auth method |
| `kubernetes.tokenPath` | string | `/var/run/secrets/kubernetes.io/serviceaccount/token` | ServiceAccount token file path |
| `appRole.roleId` | string | - | AppRole role ID. **Required** for `approle` |
| `appRole.secretId` | string | - | Inline AppRole secret ID. **Discouraged** in files (validation warning); prefer `secretIdFile`/`VAULT_APPROLE_SECRET_ID`. Mutually exclusive with `secretIdFile` |
| `appRole.secretIdFile` | string | - | Path to a file containing the secret ID (preferred). Mutually exclusive with `secretId` |
| `appRole.mountPath` | string | `approle` | Mount path of the AppRole auth method |
| `tls.caCert` | string | - | Path to a CA certificate file for verifying the Vault server |
| `tls.caPath` | string | - | Path to a directory of CA certificates |
| `tls.clientCert` | string | - | Client certificate for mTLS to Vault (requires `clientKey`) |
| `tls.clientKey` | string | - | Client key for mTLS to Vault (requires `clientCert`) |
| `tls.serverName` | string | host of `address` | TLS SNI/server name used to verify the Vault server certificate |
| `tls.skipVerify` | bool | `false` | Skip TLS verification of the Vault server (insecure; testing only) |
| `cache.enabled` | bool | `false` | Enable client-side secret caching |
| `cache.ttl` | duration | `5m` | Cache time-to-live |
| `cache.maxSize` | int | `1000` | Maximum number of cached entries |
| `retry.maxRetries` | int | `3` | Maximum request retry attempts |
| `retry.backoffBase` | duration | `100ms` | Base duration for exponential backoff |
| `retry.backoffMax` | duration | `5s` | Maximum backoff duration |
| `auth.maxRetries` | int | `3` | Maximum startup authentication retries |
| `auth.initialBackoff` | duration | `1s` | Initial backoff between authentication retries |
| `auth.maxBackoff` | duration | `10s` | Maximum backoff between authentication retries |
| `auth.timeout` | duration | `30s` | Overall timeout for the startup authentication retry loop |

Example (`spec.vault` with Kubernetes auth):

```yaml
spec:
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: kubernetes
    kubernetes:
      role: gateway-role
    tls:
      caCert: /etc/vault/ca.crt
    cache:
      enabled: true
      ttl: 5m
    retry:
      maxRetries: 3
      backoffBase: 100ms
      backoffMax: 5s
```

Vault authentication is retried with exponential backoff at startup (defaults:
3 retries, 1s–10s backoff, 30s overall timeout — tunable via `spec.vault.auth`),
so a briefly unavailable Vault does not fail gateway startup immediately.

#### Environment variable overlay and precedence

Each `spec.vault` field can be overridden by a `VAULT_*` environment variable.
The overlay is applied by `cmd/gateway` **before validation**, so the validated
(and running) configuration is always the *effective* one. Precedence is
**per-field**: `ENV > config file > defaults`.

| Environment Variable | Overrides | Default | Notes |
|-----------------------|-----------|---------|-------|
| `VAULT_ADDR` | `spec.vault.address` | - | Also **forces `enabled: true`** (legacy trigger) |
| `VAULT_AUTH_METHOD` | `spec.vault.authMethod` | `token` | |
| `VAULT_TOKEN` | `spec.vault.token` | - | **Clears `tokenFile`** so the env token wins per-field |
| `VAULT_NAMESPACE` | `spec.vault.namespace` | - | |
| `VAULT_CACERT` | `spec.vault.tls.caCert` | - | |
| `VAULT_CAPATH` | `spec.vault.tls.caPath` | - | |
| `VAULT_CLIENT_CERT` | `spec.vault.tls.clientCert` | - | |
| `VAULT_CLIENT_KEY` | `spec.vault.tls.clientKey` | - | |
| `VAULT_SKIP_VERIFY` | `spec.vault.tls.skipVerify` | `false` | Accepts `true/false/yes/no/1/0/on/off`; invalid values warn and keep the previous value |
| `VAULT_K8S_ROLE` | `spec.vault.kubernetes.role` | - | Applied only when the effective auth method is `kubernetes` |
| `VAULT_K8S_MOUNT_PATH` | `spec.vault.kubernetes.mountPath` | `kubernetes` | |
| `VAULT_K8S_TOKEN_PATH` | `spec.vault.kubernetes.tokenPath` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | |
| `VAULT_APPROLE_ROLE_ID` | `spec.vault.appRole.roleId` | - | Applied only when the effective auth method is `approle` |
| `VAULT_APPROLE_SECRET_ID` | `spec.vault.appRole.secretId` | - | **Clears `secretIdFile`** so the env secret ID wins per-field |
| `VAULT_APPROLE_MOUNT_PATH` | `spec.vault.appRole.mountPath` | `approle` | |

Only field **names** are logged when an override is applied — token/secret
**values** are never logged.

**Mixed-mode example** (Helm injects `VAULT_TOKEN` via a Secret-backed env; the
rest of the client lives in the file):

```yaml
# spec.vault in the gateway config file
spec:
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: token
    # No token / tokenFile here — supplied by the environment.
```

```bash
# Injected into the deployment (e.g. from a mounted Secret)
export VAULT_TOKEN="s.xxxxxxxxxxxxxxxx"
```

The effective config authenticates with the env-supplied token while every
other field comes from the file.

#### Validation rules

Validation runs on the **effective** (post-overlay) configuration:

- `authMethod` must be one of `token`, `kubernetes`, `approle` (empty defaults
  to `token`).
- `address` is required when `enabled` (or when `VAULT_ADDR` is set).
- Per-method required fields:
  - `token`: exactly one of `token` **or** `tokenFile`.
  - `kubernetes`: `kubernetes.role`.
  - `approle`: `appRole.roleId` **plus** exactly one of `secretId` **or**
    `secretIdFile`.
- Mutual exclusions: `token`/`tokenFile` and `secretId`/`secretIdFile` cannot
  both be set (error).
- An inline `token` or `secretId` present in the file emits a **warning** (not
  an error) recommending `tokenFile`/`secretIdFile`, the corresponding
  environment variable (Secret-mounted), or Kubernetes auth.
- `tls.clientCert` and `tls.clientKey` must be supplied together.
- Durations/counters (`cache`, `retry`, `auth`) cannot be negative and are
  type-checked even when the section is disabled.
- Sub-blocks for a non-selected auth method (e.g. `appRole` while
  `authMethod: kubernetes`) emit a **warning** that they are ignored.
- `enabled: false` while a `tls.vault` PKI block is configured is an **error**
  (`spec.vault.enabled`): PKI issuance needs the client. Because `VAULT_ADDR`
  forces `enabled: true` during the overlay, env-driven setups never hit this.

#### No hot-reload — restart required

The Vault client is created **once at startup**. Changing `spec.vault` on a
configuration reload logs a warning
(`spec.vault changed; vault client settings apply at startup — restart required`)
and is **skipped** — the running client keeps its startup settings. The skip is
counted by
`gateway_config_reload_component_total{component="vault",result="skipped"}`
(the counter line is pre-created at zero so it is visible on `/metrics` before
the first skipped reload). Apply Vault client changes by restarting the gateway.

The config watcher validates the **effective** configuration: the same
`VAULT_*` overlay used at boot is applied before each reload's validation, so an
env-mixed deployment (e.g. `VAULT_ADDR` only in the environment) does not fail
raw-file validation on every file change — hot reload keeps working for all
**other** sections. See
[Hot-Reload Limitations](hot-reload-limitations.md).

#### Backward compatibility

Omitting `spec.vault` preserves today's env-only behavior byte-for-byte: when
the section is absent and `VAULT_ADDR` is set, a client is synthesized purely
from the environment exactly as before.

> **Note:** The Helm chart's top-level `vault.*` values control the injection of
> the `VAULT_*` environment variables into the gateway deployment, gated by the
> `vault.injectEnv` flag (default `true`). Set `vault.injectEnv: false` and use
> `gateway.vault` to source the client connection purely from the rendered
> `spec.vault` file section. See [Helm Values Reference](#helm-values-reference)
> and the chart [README](../helm/avapigw/README.md).

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
          altNames:                          # Subject Alternative Names (DNS)
            - "api.example.com"
            - "www.example.com"
            - "*.api.example.com"
          ttl: "24h"                         # Certificate TTL
          
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

        # Client certificate validation (MUTUAL mode)
        caFile: "/etc/ssl/certs/client-ca.crt"
        requireClientCert: true
```

> **Note:** per-CN/SAN client filtering (`clientValidation` with
> `allowedCNs`/`allowedSANs`) is available at the **route** level — see
> [Route-Level TLS Configuration](#route-level-tls-configuration).

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
          caFile: "/etc/ssl/certs/tenant-a-client-ca.crt"
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

The same `vault` block shape is accepted under listener `tls`, gRPC listener
`tls`, route `tls`, and backend `tls` sections.

### Complete Configuration Schema

```yaml
vault:
  enabled: true                       # Enable Vault PKI integration
  pkiMount: "pki"                     # PKI secrets engine mount path
  role: "gateway-server"              # PKI role name
  commonName: "gateway.example.com"   # Certificate common name
  altNames:                           # Subject Alternative Names (DNS)
    - "api.example.com"
  ttl: "24h"                          # Certificate TTL (e.g., "24h", "720h")
```

### Field Descriptions

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | Yes | false | Enable Vault PKI integration |
| `pkiMount` | string | Yes | - | PKI secrets engine mount path |
| `role` | string | Yes | - | PKI role name for certificate issuance |
| `commonName` | string | Yes | - | Certificate common name (CN) |
| `altNames` | []string | No | [] | DNS Subject Alternative Names |
| `ttl` | duration string | No | provider default | Certificate time-to-live |

Certificate renewal is automatic: the Vault provider renews certificates
before expiry (10 minutes before expiry by default, with exponential backoff
on renewal failures) and the listener hot-reloads the renewed certificate
without a restart. Key type and SAN policy beyond `altNames` are controlled
by the **Vault PKI role**, not by gateway configuration.

## Helm Values Reference

The Helm chart's top-level `vault.*` values control **environment variable
injection** into the gateway deployment (`VAULT_ADDR`, `VAULT_AUTH_METHOD`,
`VAULT_K8S_ROLE`, ...) plus the Vault PKI blocks rendered into the generated
gateway configuration. The `vault.injectEnv` flag (default `true`) gates the
`VAULT_*` env injection.

To express the Vault client connection as a file section instead, set
`gateway.vault` (rendered verbatim as [`spec.vault`](#vault-client-connection-specvault)
in the generated ConfigMap). For a file-only setup, combine `gateway.vault`
with `vault.injectEnv: false` so no `VAULT_*` env is injected — see the
`values-vault-file.yaml` example shipped with the chart and the chart
[README](../helm/avapigw/README.md).

### Complete Vault PKI Configuration

```yaml
# values.yaml
vault:
  enabled: true
  address: "https://vault.example.com:8200"   # -> VAULT_ADDR
  authMethod: kubernetes                      # -> VAULT_AUTH_METHOD
  role: gateway-role                          # -> VAULT_K8S_ROLE
  kubernetesMountPath: kubernetes             # -> VAULT_K8S_MOUNT_PATH

  # TLS for Vault connection
  tls:
    enabled: true
    caSecretName: vault-ca-cert
    skipVerify: false                         # -> VAULT_SKIP_VERIFY

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
    # gRPC listener PKI overrides (inherit from vault.pki.* when empty)
    grpc:
      pkiMount: ""
      role: ""
      commonName: ""
      altNames: []
      ttl: ""

gateway:
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
- `ttl`: Must be a valid duration string (e.g., "24h", "30m")

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

#### HMAC Shared-Secret JWT (HS256/HS384/HS512)

For HMAC algorithms, configure a shared secret instead of a JWKS URL. The
`secret` value may be a raw string or a symmetric (`oct`) JWK:

```yaml
spec:
  routes:
    - name: hmac-api
      match:
        - uri:
            prefix: /api/v1/hmac
      authentication:
        enabled: true
        jwt:
          enabled: true
          algorithm: "HS256"            # HS256, HS384, or HS512
          secret: "shared-hmac-secret"  # Raw secret or oct JWK
          issuer: "https://auth.example.com"
```

- Tokens without a `kid` header fall back to the single configured HMAC key;
  tokens with a `kid` must match the configured key ID.
- Algorithm-confusion protection: asymmetric public keys are never accepted
  as HMAC secrets, so tokens re-signed with a public key under an `HS*`
  algorithm are rejected.
- JWKS-based validation is resilient to identity provider outages: refreshes
  are coalesced (singleflight) and bounded to 30 seconds, so one slow IdP
  cannot stall gateway-wide authentication.

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
          hashAlgorithm: "sha256"       # sha256 (default), sha512, bcrypt, plaintext (dev only)
          vaultPath: "secret/api-keys"  # Vault path for key storage
```

API key validation rules:

- **Hash-only static keys** (gateway-level `authentication.apiKey.store.keys`)
  may omit the raw `key` and carry only a pre-computed `hash`: a 64-hex SHA-256
  digest, a 128-hex SHA-512 digest (both case-insensitive), or a bcrypt hash
  (looked up by key `id` and verified against the presented key).
- **Load-time validation**: entries with neither a usable `key` nor a hash
  compatible with the configured `hashAlgorithm` are rejected when the
  configuration is loaded (previously they were accepted and silently failed
  every lookup).
- **Vault store matrix**: the Vault store addresses secrets by the
  deterministic digest of the presented key, so it supports `sha256` and
  `sha512` only; `hashAlgorithm: bcrypt` combined with the Vault store is
  rejected at load time (bcrypt hashes are salted and cannot address Vault
  paths).
- **Store outages vs. unknown keys**: Vault outages during validation surface
  as `gateway_apikey_validation_total{reason="store_error"}` (previously
  reported as `not_found`) — alert on `store_error` separately from
  genuine key misses.
- **Cache bound**: the validation cache honors `cache.maxSize` with LRU
  eviction; with `hashAlgorithm: plaintext` a warning is logged once at
  startup.

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

Response caching is configured at the **route level** (`routes[].cache`,
`grpcRoutes[].cache`, `graphqlRoutes[].cache` in gateway configuration, or
`spec.cache` on the corresponding CRDs). The redis examples in this section
show the cache schema, which is identical across those route kinds.

> **Note:** backend-level caching (CRD `Backend`/`GRPCBackend` `spec.cache`)
> is RESERVED — it is accepted with an admission warning but is not wired to
> the gateway data path. The gateway's file-based `backends[]` section has no
> `cache` field. Use route-level caching instead.

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
- With `hashKeys: true`, trace span attributes and logs record the hashed key instead of the raw key, so sensitive key components (e.g. Authorization-derived values) never leak into telemetry

**Vault Password Integration**
- Secure password management using HashiCorp Vault KV secrets
- Supports both standalone Redis and Redis Sentinel configurations
- Automatic password resolution from Vault at runtime
- Vault path format: `mount/path` (e.g., `secret/redis`)
- Secret must contain a `password` key

### HTTP Route Caching

```yaml
spec:
  routes:
    - name: cached-route
      match:
        - uri:
            prefix: /api/v1
      route:
        - destination:
            host: api.internal
            port: 8080
      cache:
        enabled: true
        ttl: "10m"                     # Cache for 10 minutes
        keyConfig:
          includeMethod: true          # Include HTTP method
          includePath: true            # Include request path
          includeQueryParams:          # Query parameters to include
            - "page"
            - "limit"
          includeHeaders:              # Headers to include
            - "Authorization"
            - "X-Tenant-ID"
            - "Accept-Language"
        staleWhileRevalidate: "2m"     # Serve stale for 2 minutes while revalidating
        type: "memory"                 # Use in-memory cache
        maxEntries: 10000              # Bound for the memory cache
```

### Redis Route Caching

#### Redis Standalone Configuration

```yaml
spec:
  routes:
    - name: redis-cached-route
      match:
        - uri:
            prefix: /api/v1
      route:
        - destination:
            host: api.internal
            port: 8080
      cache:
        enabled: true
        ttl: "1h"
        staleWhileRevalidate: "5m"
        type: "redis"
        redis:
          url: "redis://redis.cache.svc.cluster.local:6379/0"
          # Vault password integration
          passwordVaultPath: "secret/redis"
          poolSize: 10
          keyPrefix: "avapigw:cache:"
          # TTL jitter to prevent thundering herd
          ttlJitter: 0.1  # ±10% jitter on TTL values
          # Hash cache keys for privacy and length control
          hashKeys: true
          retry:
            maxRetries: 3
            initialBackoff: "100ms"
            maxBackoff: "30s"
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
  routes:
    - name: redis-sentinel-cached-route
      match:
        - uri:
            prefix: /api/v1
      route:
        - destination:
            host: api.internal
            port: 8080
      cache:
        enabled: true
        ttl: "1h"
        staleWhileRevalidate: "5m"
        type: "redis"
        redis:
          # Sentinel mode is mutually exclusive with the standalone url
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
          poolSize: 10
          keyPrefix: "avapigw:cache:"
          # TTL jitter to prevent thundering herd
          ttlJitter: 0.1  # ±10% jitter on TTL values
          # Hash cache keys for privacy and length control
          hashKeys: true
          retry:
            maxRetries: 3
            initialBackoff: "100ms"
            maxBackoff: "30s"
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

### gRPC Route Caching

```yaml
spec:
  grpcRoutes:
    - name: grpc-cached-route
      match:
        - service:
            exact: "api.v1.UserService"
      route:
        - destination:
            host: grpc-service.internal
            port: 9000
      cache:
        enabled: true
        ttl: "5m"
        staleWhileRevalidate: "1m"
        type: "memory"
```

> On GRPCRoute/GraphQLRoute CRDs, `cache.type: redis` is accepted for
> forward compatibility and produces an admission warning — redis-backed
> route caching is currently applied in the HTTP (APIRoute) data path.

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

### WebSocket Origin Allowlist

`spec.websocket.allowedOrigins` protects WebSocket routes against cross-site
WebSocket hijacking (CSWSH) by restricting which browser origins may complete
the upgrade handshake:

```yaml
spec:
  websocket:
    allowedOrigins:
      - "https://app.example.com"   # scheme://host[:port] entry
      - "internal.example.com"      # bare host[:port] entry (any scheme)
      # - "*"                       # explicit allow-all
```

#### Origin Matching Rules

| Configuration | Behavior |
|---------------|----------|
| Omitted / empty list | Every origin accepted (backward compatible); one warning logged at startup |
| Non-empty list | Only listed origins **and same-origin requests** accepted; others rejected with **403** during the handshake, before any backend connection |
| `"*"` entry | Explicitly allow every origin (no startup warning) |
| No `Origin` header | Always allowed (non-browser clients) |

Entries take the form `scheme://host[:port]` or bare `host[:port]`; `ws`/`wss`
schemes are normalized to `http`/`https` (browsers send the page origin during
the handshake). Wildcard hosts (e.g. `*.example.com`) are not supported —
entries with a wildcard in the host are rejected by configuration validation;
only the standalone `"*"` entry allows all origins. The allowlist applies to
both proxied WebSocket routes and GraphQL subscription (graphql-ws) upgrades.

## GraphQL Configuration

The AV API Gateway provides comprehensive GraphQL support with advanced features including query analysis, depth limiting, complexity analysis, introspection control, and WebSocket subscriptions.

### GraphQL Routes Configuration

GraphQL routes define how GraphQL requests are matched and routed to backend services.

#### Basic GraphQL Route

```yaml
spec:
  graphqlRoutes:
    - name: main-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-backend
            port: 4000
          weight: 100
      timeout: 30s
      depthLimit: 10
      complexityLimit: 100
      introspectionEnabled: true
      allowedOperations:
        - query
        - mutation
        - subscription
```

#### Advanced GraphQL Route Matching

```yaml
spec:
  graphqlRoutes:
    # Route by operation type
    - name: graphql-mutations
      match:
        - path:
            exact: "/graphql"
          operationType: mutation
      route:
        - destination:
            host: mutation-backend
            port: 4000
      timeout: 60s
      depthLimit: 5
      complexityLimit: 200
    
    # Route by operation name
    - name: user-operations
      match:
        - path:
            exact: "/graphql"
          operationName:
            prefix: "User"
      route:
        - destination:
            host: user-service
            port: 4000
    
    # Route by headers
    - name: admin-graphql
      match:
        - path:
            exact: "/graphql"
          headers:
            - name: "X-Admin-Token"
              present: true
            - name: "X-API-Version"
              exact: "v2"
      route:
        - destination:
            host: admin-backend
            port: 4000
      introspectionEnabled: false
      allowedOperations:
        - query
        - mutation
```

#### GraphQL Security and Limits

```yaml
spec:
  graphqlRoutes:
    - name: secure-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-backend
            port: 4000
      
      # Query analysis and protection
      depthLimit: 15                    # Maximum query depth
      complexityLimit: 1000             # Maximum query complexity
      introspectionEnabled: false       # Disable introspection in production
      allowedOperations:                # Restrict operation types
        - query
        - mutation
      
      # Authentication and authorization
      authentication:
        enabled: true
        jwt:
          enabled: true
          issuer: "https://auth.example.com"
          audience: "graphql-api"
      
      # Rate limiting
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
        perClient: true
      
      # CORS configuration
      cors:
        allowOrigins:
          - "https://app.example.com"
        allowMethods:
          - "POST"
        allowHeaders:
          - "Content-Type"
          - "Authorization"
      
      # Caching
      cache:
        enabled: true
        ttl: "5m"
        keyComponents:
          - "path"
          - "query"
          - "headers.Authorization"
```

### GraphQL Backends Configuration

GraphQL backends define the backend services that handle GraphQL requests.

#### Basic GraphQL Backend

```yaml
spec:
  graphqlBackends:
    - name: graphql-backend
      hosts:
        - address: "graphql-service.default.svc.cluster.local"
          port: 4000
          weight: 1
      healthCheck:
        enabled: true
        path: "/health"
        interval: 10s
        timeout: 5s
        healthyThreshold: 2
        unhealthyThreshold: 3
      loadBalancer:
        algorithm: roundRobin
```

#### Advanced GraphQL Backend

```yaml
spec:
  graphqlBackends:
    - name: ha-graphql-backend
      hosts:
        - address: "graphql-1.example.com"
          port: 4000
          weight: 1
        - address: "graphql-2.example.com"
          port: 4000
          weight: 1
        - address: "graphql-3.example.com"
          port: 4000
          weight: 1
      
      # Health checking
      healthCheck:
        enabled: true
        path: "/health"
        method: "GET"
        interval: 10s
        timeout: 5s
        healthyThreshold: 2
        unhealthyThreshold: 3
        expectedStatus: [200]
        headers:
          User-Agent: "avapigw-health-checker"
      
      # Load balancing
      loadBalancer:
        algorithm: roundRobin
        sessionAffinity:
          enabled: true
          cookieName: "GRAPHQL_SESSION"
          ttl: "3600s"
      
      # Circuit breaker
      circuitBreaker:
        enabled: true
        threshold: 5
        timeout: 30s
        halfOpenRequests: 3
        successThreshold: 2
      
      # TLS configuration
      tls:
        enabled: true
        mode: SIMPLE
        caFile: "/certs/graphql-ca.crt"
        serverName: "graphql.example.com"
        minVersion: "1.2"
      
      # Backend authentication
      authentication:
        jwt:
          enabled: true
          tokenSource: "oidc"
          oidc:
            issuerUrl: "https://keycloak.example.com/realms/backend"
            clientId: "graphql-backend"
            clientSecret: "backend-secret"
            scopes: ["openid", "graphql-access"]
          headerName: "Authorization"
          headerPrefix: "Bearer "
```

### GraphQL Configuration Reference

#### GraphQLRoute Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique name of the route |
| `match` | []GraphQLRouteMatch | Yes | - | Matching conditions |
| `route` | []RouteDestination | Yes | - | Backend destinations |
| `timeout` | duration | No | 30s | Request timeout |
| `retries` | RetryPolicy | No | - | Retry configuration |
| `headers` | HeaderManipulation | No | - | Header manipulation |
| `rateLimit` | RateLimitConfig | No | - | Rate limiting |
| `cache` | CacheConfig | No | - | Caching configuration |
| `cors` | CORSConfig | No | - | CORS configuration |
| `security` | SecurityConfig | No | - | Security headers |
| `tls` | RouteTLSConfig | No | - | Route-level TLS |
| `authentication` | AuthenticationConfig | No | - | Authentication |
| `authorization` | AuthorizationConfig | No | - | Authorization |
| `depthLimit` | int | No | 0 | Maximum query depth (0 = disabled) |
| `complexityLimit` | int | No | 0 | Maximum query complexity (0 = disabled) |
| `introspectionEnabled` | bool | No | true | Allow introspection queries |
| `allowedOperations` | []string | No | all | Allowed operation types |

#### GraphQLRouteMatch Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `path` | StringMatch | No | - | HTTP path matching |
| `operationType` | string | No | - | GraphQL operation type (query, mutation, subscription) |
| `operationName` | StringMatch | No | - | GraphQL operation name matching |
| `headers` | []HeaderMatchConfig | No | - | HTTP header matching |

#### GraphQLBackend Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique name of the backend |
| `hosts` | []BackendHost | Yes | - | Backend host configurations |
| `healthCheck` | HealthCheck | No | - | Health check configuration |
| `loadBalancer` | LoadBalancer | No | - | Load balancer configuration |
| `tls` | BackendTLSConfig | No | - | TLS configuration |
| `circuitBreaker` | CircuitBreakerConfig | No | - | Circuit breaker configuration |
| `authentication` | BackendAuthConfig | No | - | Backend authentication |

### GraphQL Middleware Features

#### Query Depth Limiting

Prevents deeply nested queries that could cause performance issues:

```yaml
spec:
  graphqlRoutes:
    - name: depth-limited-graphql
      depthLimit: 10  # Maximum nesting depth of 10 levels
```

Example of a query that would be blocked with `depthLimit: 3`:
```graphql
query DeepQuery {
  user {
    posts {
      comments {
        replies {  # This would exceed depth limit of 3
          author {
            name
          }
        }
      }
    }
  }
}
```

#### Query Complexity Analysis

Prevents complex queries that could consume excessive resources:

```yaml
spec:
  graphqlRoutes:
    - name: complexity-limited-graphql
      complexityLimit: 1000  # Maximum complexity score of 1000
```

Complexity is calculated by counting fields and their nesting levels. Each field adds to the complexity score, with nested fields contributing multiplicatively.

#### Introspection Control

Controls whether schema introspection is allowed:

```yaml
spec:
  graphqlRoutes:
    - name: production-graphql
      introspectionEnabled: false  # Disable introspection in production
    
    - name: development-graphql
      introspectionEnabled: true   # Allow introspection in development
```

#### Operation Type Filtering

Restricts which GraphQL operation types are allowed:

```yaml
spec:
  graphqlRoutes:
    - name: read-only-graphql
      allowedOperations:
        - query  # Only allow queries, block mutations and subscriptions
    
    - name: full-access-graphql
      allowedOperations:
        - query
        - mutation
        - subscription
```

### WebSocket Subscriptions

The gateway supports GraphQL subscriptions over WebSocket connections using the `graphql-ws` protocol.

#### Subscription Configuration

```yaml
spec:
  listeners:
    - name: graphql-ws
      port: 8080
      protocol: HTTP  # WebSocket upgrades over HTTP
  
  graphqlRoutes:
    - name: subscription-route
      match:
        - path:
            exact: "/graphql"
          operationType: subscription
      route:
        - destination:
            host: subscription-backend
            port: 4000
      allowedOperations:
        - subscription
```

#### WebSocket Protocol Support

- **Protocol**: `graphql-ws` (GraphQL over WebSocket Protocol)
- **Connection Management**: Automatic connection lifecycle management
- **Message Routing**: Bidirectional message proxying between client and backend
- **Error Handling**: Proper error propagation and connection cleanup

### GraphQL Metrics and Observability

The gateway provides comprehensive metrics for GraphQL operations:

#### GraphQL-Specific Metrics

```yaml
spec:
  observability:
    metrics:
      enabled: true
      graphql:
        enabled: true
        operations: true      # Track operation types and names
        complexity: true      # Track query complexity scores
        depth: true          # Track query depth
        introspection: true  # Track introspection attempts
        subscriptions: true  # Track WebSocket subscription metrics
```

#### Available GraphQL Metrics

- `graphql_requests_total` - Total GraphQL requests by operation type
- `graphql_request_duration_seconds` - Request duration histogram
- `graphql_query_depth` - Query depth distribution
- `graphql_query_complexity` - Query complexity distribution
- `graphql_introspection_requests_total` - Introspection request count
- `graphql_subscription_connections_active` - Active WebSocket connections
- `graphql_subscription_messages_total` - WebSocket message count
- `graphql_errors_total` - GraphQL error count by type

### Example Configurations

#### Production GraphQL Gateway

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: production-graphql-gateway
spec:
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        certFile: "/certs/tls.crt"
        keyFile: "/certs/tls.key"
  
  graphqlRoutes:
    - name: api-graphql
      match:
        - path:
            exact: "/graphql"
      route:
        - destination:
            host: graphql-api
            port: 4000
      
      # Security configuration
      depthLimit: 15
      complexityLimit: 1000
      introspectionEnabled: false
      allowedOperations:
        - query
        - mutation
      
      # Authentication
      authentication:
        enabled: true
        jwt:
          enabled: true
          issuer: "https://auth.company.com"
          audience: "api.company.com"
      
      # Rate limiting
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
        perClient: true
      
      # Caching
      cache:
        enabled: true
        ttl: "5m"
        type: "redis"
        redis:
          address: "redis.cache.svc.cluster.local:6379"
          keyPrefix: "graphql:cache:"
  
  graphqlBackends:
    - name: graphql-api
      hosts:
        - address: "graphql-api-1.prod.svc.cluster.local"
          port: 4000
          weight: 1
        - address: "graphql-api-2.prod.svc.cluster.local"
          port: 4000
          weight: 1
      
      healthCheck:
        enabled: true
        path: "/health"
        interval: 10s
        timeout: 5s
      
      circuitBreaker:
        enabled: true
        threshold: 5
        timeout: 30s
      
      tls:
        enabled: true
        mode: SIMPLE
        caFile: "/certs/backend-ca.crt"
```

## Recent Updates

### Dependency Upgrades

The project targets the **Go 1.26.5** toolchain (see `go.mod`, the Docker images, and CI). The
following dependencies have been upgraded for improved performance, security, and compatibility
with Go 1.26.5:

**Go Dependencies:**
- `github.com/redis/go-redis/v9` upgraded to v9.21.0 (from v9.20.1) - Enhanced Redis client with improved connection pooling and Sentinel support
- `protobuf` upgraded to v1.36.11 - Latest Protocol Buffers implementation with performance improvements
- **OpenTelemetry** upgraded to v1.44.0 - Latest observability framework with enhanced tracing capabilities and performance improvements. The v1.44.0 SDK line carries semantic-convention schema **v1.41.0**, so the tracer resource is built against `go.opentelemetry.io/otel/semconv/v1.41.0` (see [Observability](#opentelemetry-semconv-version) note below)
- `github.com/getkin/kin-openapi` upgraded to v0.142.0 (from v0.140.0) - OpenAPI request/response validation (transitively pulls `github.com/oasdiff/yaml` v0.1.0; `github.com/go-openapi/swag` and other transitive patch bumps came along)
- `github.com/vektah/gqlparser/v2` upgraded to v2.5.36 (from v2.5.35) - GraphQL schema/query parser used by the GraphQL proxy
- `github.com/google/cel-go` upgraded to v0.29.2 (from v0.28.1) - CEL expression evaluation used by ABAC authorization
- `github.com/golang-jwt/jwt/v5` upgraded to v5.3.1 (from v5.3.0) - JWT parsing and validation
- `github.com/lestrrat-go/jwx/v2` upgraded to v2.1.7 (from v2.1.6) - JWKS handling and JOSE primitives
- `golang.org/x/crypto` upgraded to v0.53.0 - Cryptographic primitives (TLS, JWT signing, certificate handling)
- `golang.org/x/text` upgraded to v0.38.0 - Text processing and encoding utilities
- `k8s.io/api`, `k8s.io/apimachinery`, and `k8s.io/client-go` upgraded to v0.36.2 - Kubernetes API types and client used by the operator and CRD modes
- `github.com/alicebob/miniredis/v2` upgraded to v2.38.0 - In-memory Redis used by the test suite (test-only dependency)

All quality gates (build, lint, vet, govulncheck, and the full unit, functional, integration, and e2e suites) pass after these upgrades, and performance was re-validated (see [test/performance/results](../test/performance/results) for the latest report).

**CI/CD Action Upgrades:**
- `actions/checkout` upgraded to v6.0.2 - Improved Git checkout performance and security
- `docker/login-action` upgraded to v3.7.0 - Enhanced Docker registry authentication
- `github/codeql-action` upgraded to v4.32.6 - Latest CodeQL security analysis (SHA pin aligned with the `# v4.32.6` version comment)
- `anchore/sbom-action` upgraded to v0.22.2 - Improved Software Bill of Materials generation
- `helm/kind-action` upgraded to v1.13.0 - Latest Kubernetes in Docker for testing

These upgrades provide enhanced security, performance improvements, and better compatibility with modern infrastructure.

## Metrics Configuration Reference

The AV API Gateway provides 54+ Prometheus metrics across all components. This section documents all available metrics configuration options.

### Core Gateway Metrics Configuration

```yaml
spec:
  observability:
    metrics:
      enabled: true
      path: /metrics
      port: 9090
      namespace: gateway        # Prometheus namespace for metrics
      
      # Core gateway metrics configuration
      core:
        enabled: true
        buildInfo: true         # Include build information
        uptime: true           # Include uptime metrics
        
      # Middleware metrics configuration
      middleware:
        enabled: true
        rateLimit: true        # Rate limiting metrics
        circuitBreaker: true   # Circuit breaker metrics
        timeout: true          # Request timeout metrics
        retry: true            # Retry attempt metrics
        bodyLimit: true        # Body size limit metrics
        maxSessions: true      # Max sessions metrics
        recovery: true         # Panic recovery metrics
        cors: true             # CORS request metrics
        
      # Cache metrics configuration
      cache:
        enabled: true
        hits: true             # Cache hit metrics
        misses: true           # Cache miss metrics
        evictions: true        # Cache eviction metrics
        size: true             # Cache size metrics
        duration: true         # Cache operation duration
        errors: true           # Cache error metrics
        
      # Authentication metrics configuration
      auth:
        enabled: true
        jwt: true              # JWT authentication metrics
        apiKey: true           # API key authentication metrics
        oidc: true             # OIDC authentication metrics
        mtls: true             # mTLS authentication metrics
        
      # Authorization metrics configuration
      authz:
        enabled: true
        rbac: true             # RBAC authorization metrics
        abac: true             # ABAC authorization metrics
        external: true         # External authorization metrics
        
      # TLS metrics configuration
      tls:
        enabled: true
        handshakes: true       # TLS handshake metrics: connections total and
                               # gateway_tls_handshake_duration_seconds, recorded
                               # for HTTPS listener AND gRPC TLS listener handshakes
        certificates: true     # Certificate lifecycle metrics
        
      # Vault metrics configuration
      vault:
        enabled: true
        requests: true         # Vault API request metrics
        auth: true             # Vault authentication metrics
        secrets: true          # Secret retrieval metrics
        
      # Backend authentication metrics
      backendAuth:
        enabled: true
        jwt: true              # Backend JWT auth metrics
        basic: true            # Backend basic auth metrics
        mtls: true             # Backend mTLS auth metrics
        
      # Proxy metrics configuration
      proxy:
        enabled: true
        errors: true           # Proxy error metrics
        duration: true         # Backend request duration
        
      # WebSocket metrics configuration
      websocket:
        enabled: true
        connections: true      # Connection metrics
        messages: true         # Message throughput metrics
        errors: true           # WebSocket error metrics
        
      # gRPC metrics configuration
      grpc:
        enabled: true
        requests: true         # gRPC request metrics
        streaming: true        # Streaming metrics
        methods: true          # Method-level metrics
        
      # Config reload metrics
      configReload:
        enabled: true
        success: true          # Successful reload metrics
        errors: true           # Reload error metrics
        duration: true         # Reload duration metrics
        
      # Health check metrics
      healthCheck:
        enabled: true
        probes: true           # Health probe metrics
        backends: true         # Backend health metrics
```

### Operator Metrics Configuration

Configure operator-specific metrics:

```yaml
operator:
  metrics:
    enabled: true
    port: 8080
    path: /metrics
    
    # Controller metrics
    controller:
      enabled: true
      reconciliation: true     # Reconciliation metrics
      errors: true             # Controller error metrics
      duration: true           # Reconciliation duration
      
    # Webhook metrics
    webhook:
      enabled: true
      requests: true           # Webhook request metrics
      validation: true         # Validation metrics
      duration: true           # Webhook processing duration
      
    # Certificate management metrics
    certificates:
      enabled: true
      renewals: true           # Certificate renewal metrics
      errors: true             # Certificate error metrics
      lifecycle: true          # Certificate lifecycle metrics
      
    # gRPC communication metrics
    grpc:
      enabled: true
      connections: true        # gRPC connection metrics
      requests: true           # gRPC request metrics
      errors: true             # gRPC error metrics
```

### Environment Variable Overrides

All metrics can be controlled via environment variables:

```bash
# Core metrics
export METRICS_ENABLED=true
export METRICS_PORT=9090
export METRICS_PATH=/metrics
export METRICS_NAMESPACE=gateway

# Middleware metrics
export METRICS_MIDDLEWARE_ENABLED=true
export METRICS_RATE_LIMIT_ENABLED=true
export METRICS_CIRCUIT_BREAKER_ENABLED=true
export METRICS_TIMEOUT_ENABLED=true
export METRICS_RETRY_ENABLED=true
export METRICS_BODY_LIMIT_ENABLED=true
export METRICS_MAX_SESSIONS_ENABLED=true
export METRICS_RECOVERY_ENABLED=true
export METRICS_CORS_ENABLED=true

# Cache metrics
export METRICS_CACHE_ENABLED=true
export METRICS_CACHE_HITS_ENABLED=true
export METRICS_CACHE_MISSES_ENABLED=true
export METRICS_CACHE_EVICTIONS_ENABLED=true
export METRICS_CACHE_SIZE_ENABLED=true
export METRICS_CACHE_DURATION_ENABLED=true
export METRICS_CACHE_ERRORS_ENABLED=true

# Authentication metrics
export METRICS_AUTH_ENABLED=true
export METRICS_AUTH_JWT_ENABLED=true
export METRICS_AUTH_APIKEY_ENABLED=true
export METRICS_AUTH_OIDC_ENABLED=true
export METRICS_AUTH_MTLS_ENABLED=true

# Authorization metrics
export METRICS_AUTHZ_ENABLED=true
export METRICS_AUTHZ_RBAC_ENABLED=true
export METRICS_AUTHZ_ABAC_ENABLED=true
export METRICS_AUTHZ_EXTERNAL_ENABLED=true

# TLS metrics
export METRICS_TLS_ENABLED=true
export METRICS_TLS_HANDSHAKES_ENABLED=true
export METRICS_TLS_CERTIFICATES_ENABLED=true

# Vault metrics
export METRICS_VAULT_ENABLED=true
export METRICS_VAULT_REQUESTS_ENABLED=true
export METRICS_VAULT_AUTH_ENABLED=true
export METRICS_VAULT_SECRETS_ENABLED=true

# Backend authentication metrics
export METRICS_BACKEND_AUTH_ENABLED=true
export METRICS_BACKEND_AUTH_JWT_ENABLED=true
export METRICS_BACKEND_AUTH_BASIC_ENABLED=true
export METRICS_BACKEND_AUTH_MTLS_ENABLED=true

# Proxy metrics
export METRICS_PROXY_ENABLED=true
export METRICS_PROXY_ERRORS_ENABLED=true
export METRICS_PROXY_DURATION_ENABLED=true

# WebSocket metrics
export METRICS_WEBSOCKET_ENABLED=true
export METRICS_WEBSOCKET_CONNECTIONS_ENABLED=true
export METRICS_WEBSOCKET_MESSAGES_ENABLED=true
export METRICS_WEBSOCKET_ERRORS_ENABLED=true

# gRPC metrics
export METRICS_GRPC_ENABLED=true
export METRICS_GRPC_REQUESTS_ENABLED=true
export METRICS_GRPC_STREAMING_ENABLED=true
export METRICS_GRPC_METHODS_ENABLED=true

# Config reload metrics
export METRICS_CONFIG_RELOAD_ENABLED=true
export METRICS_CONFIG_RELOAD_SUCCESS_ENABLED=true
export METRICS_CONFIG_RELOAD_ERRORS_ENABLED=true
export METRICS_CONFIG_RELOAD_DURATION_ENABLED=true

# Health check metrics
export METRICS_HEALTH_CHECK_ENABLED=true
export METRICS_HEALTH_CHECK_PROBES_ENABLED=true
export METRICS_HEALTH_CHECK_BACKENDS_ENABLED=true

# Operator metrics
export OPERATOR_METRICS_ENABLED=true
export OPERATOR_METRICS_PORT=8080
export OPERATOR_METRICS_PATH=/metrics
export OPERATOR_METRICS_CONTROLLER_ENABLED=true
export OPERATOR_METRICS_WEBHOOK_ENABLED=true
export OPERATOR_METRICS_CERTIFICATES_ENABLED=true
export OPERATOR_METRICS_GRPC_ENABLED=true
```

## OTLP Exporter TLS Configuration

<a id="opentelemetry-semconv-version"></a>

> **OpenTelemetry semantic-convention version:** The gateway tracks the OpenTelemetry
> SDK **v1.44.0** line, which builds `resource.Default()` against semantic-convention
> schema **v1.41.0**. The gateway's tracer initialization therefore imports
> `go.opentelemetry.io/otel/semconv/v1.41.0` so the tracer resource schema URL matches
> the SDK default. Mixing an older semconv import (e.g. `v1.40.0`) with the v1.44.0 SDK
> produces a fatal `conflicting Schema URL` error at gateway startup. With the aligned
> v1.41.0 import, tracer initialization succeeds and OTLP export to Tempo/Jaeger works.

The OpenTelemetry Protocol (OTLP) exporter supports comprehensive TLS configuration for secure trace export to collectors like Jaeger, Zipkin, or OTEL Collector.

### Basic TLS Configuration

```yaml
spec:
  observability:
    tracing:
      enabled: true
      otlpEndpoint: "https://jaeger-collector:14250"
      serviceName: avapigw
      
      # Enable secure connection (DEV-003)
      otlpInsecure: false
      
      # Server certificate verification
      otlpTLSCAFile: "/etc/ssl/certs/jaeger-ca.crt"
```

### Mutual TLS (mTLS) Configuration

```yaml
spec:
  observability:
    tracing:
      enabled: true
      otlpEndpoint: "https://jaeger-collector:14250"
      serviceName: avapigw
      
      # Enable secure connection with client authentication
      otlpInsecure: false
      
      # Client certificate and key for mTLS
      otlpTLSCertFile: "/etc/ssl/certs/gateway-client.crt"
      otlpTLSKeyFile: "/etc/ssl/private/gateway-client.key"
      
      # CA certificate for server verification
      otlpTLSCAFile: "/etc/ssl/certs/jaeger-ca.crt"
```

### Environment Variable Overrides

OTLP TLS configuration can be overridden using environment variables:

```bash
# Basic TLS settings
export OTLP_INSECURE=false
export OTLP_TLS_CA_FILE=/etc/ssl/certs/ca.crt

# mTLS settings
export OTLP_TLS_CERT_FILE=/etc/ssl/certs/client.crt
export OTLP_TLS_KEY_FILE=/etc/ssl/private/client.key
```

### OTLP Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `otlpInsecure` | boolean | true | Use insecure gRPC connection (plaintext) |
| `otlpTLSCertFile` | string | "" | Path to client certificate file for mTLS |
| `otlpTLSKeyFile` | string | "" | Path to client private key file for mTLS |
| `otlpTLSCAFile` | string | "" | Path to CA certificate file for server verification |

**Note:** For backward compatibility, `otlpInsecure` defaults to `true`. Set to `false` for production deployments with TLS-enabled OTLP collectors.

### Production Example with Vault PKI

```yaml
spec:
  observability:
    tracing:
      enabled: true
      otlpEndpoint: "https://otel-collector.monitoring.svc.cluster.local:4317"
      serviceName: avapigw
      
      # Secure connection with Vault-managed certificates
      otlpInsecure: false
      otlpTLSCertFile: "/vault/secrets/otlp-client.crt"
      otlpTLSKeyFile: "/vault/secrets/otlp-client.key"
      otlpTLSCAFile: "/vault/secrets/otlp-ca.crt"
```

## Middleware Configuration

The AV API Gateway implements a two-tier middleware architecture with global and per-route middleware chains.

### Global Middleware Configuration

Global middleware is applied to all requests and configured at the gateway level:

```yaml
spec:
  # Authentication (global middleware chain)
  authentication:
    enabled: true
    jwt:
      enabled: true
      issuer: "https://auth.example.com"
      audience: ["api.example.com"]
    allowAnonymous: false
    skipPaths:
      - "/health"
      - "/metrics"
  
  # Rate limiting (global middleware chain)
  rateLimit:
    enabled: true
    requestsPerSecond: 1000
    burst: 2000                    # Must be >= 1 when enabled
    perClient: true
    # Distributed rate limiting: share token buckets across gateway
    # instances through Redis standalone or Redis Sentinel.
    # store: redis                 # memory (default) | redis
    # redis:
    #   url: "redis://redis.cache.svc:6379/0"     # or sentinel: {...}
    #   readTimeout: 100ms         # Bounds each rate limit decision
    #   keyPrefix: "avapigw:"
    #   failOpen: true             # true (default): allow on Redis outage;
    #                              # false: reject with 429, fail hard at
    #                              # startup if Redis is unreachable
    #   retry:
    #     maxRetries: 3
    #     initialBackoff: 100ms
    #     maxBackoff: 30s
  
  # Circuit breaker (global middleware chain)
  circuitBreaker:
    enabled: true
    threshold: 5
    timeout: 30s
    halfOpenRequests: 3
  
  # Max sessions (global middleware chain)
  maxSessions:
    enabled: true
    maxConcurrent: 10000
    queueSize: 1000
    queueTimeout: 30s
  
  # CORS (global middleware chain)
  cors:
    allowOrigins: ["*"]
    allowMethods: ["GET", "POST", "PUT", "DELETE"]
    allowHeaders: ["Content-Type", "Authorization"]
```

### Per-Route Middleware Configuration

Per-route middleware is applied to specific routes and configured at the route level:

```yaml
spec:
  routes:
    - name: api-route
      match:
        - uri:
            prefix: /api/v1
      route:
        - destination:
            host: backend
            port: 8080
      
      # Security headers (per-route middleware)
      security:
        enabled: true
        headers:
          enabled: true
          xFrameOptions: "SAMEORIGIN"
          customHeaders:
            X-API-Version: "v1"
      
      # CORS override (per-route middleware)
      cors:
        allowOrigins: ["https://app.example.com"]
        allowMethods: ["GET", "POST"]
      
      # Rate limiting (per-route middleware; enforced for HTTP routes,
      # supports store: memory (default) or redis for distributed limiting)
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200
        perClient: true
      
      # Request limits (per-route middleware)
      requestLimits:
        maxBodySize: 10485760  # 10MB
        maxHeaderSize: 1048576 # 1MB
      
      # Headers manipulation (per-route middleware)
      headers:
        request:
          set:
            X-Route: "api-v1"
          add:
            X-Gateway: "avapigw"
          remove:
            - "X-Internal-Header"
        response:
          set:
            X-Response-Time: "{{.ResponseTime}}"
      
      # Cache (per-route middleware)
      cache:
        enabled: true
        ttl: "10m"
        type: "memory"
        keyComponents:
          - "path"
          - "query"
          - "headers.Authorization"
        staleWhileRevalidate: "2m"
      
      # Transform (per-route middleware)
      transform:
        request:
          template: |
            {
              "data": {{.Body}},
              "metadata": {
                "timestamp": "{{.Timestamp}}",
                "requestId": "{{.RequestID}}"
              }
            }
        response:
          allowFields:
            - "id"
            - "name"
            - "email"
          denyFields:
            - "password"
            - "secret"
          fieldMappings:
            created_at: "createdAt"
            updated_at: "updatedAt"
      
      # Encoding (per-route middleware)
      encoding:
        enableContentNegotiation: true
        request:
          contentType: "application/json"
        response:
          contentType: "application/json"
```

### Middleware Execution Order

#### Global Middleware Chain
```
Recovery → RequestID → Logging → Tracing → Audit → Metrics → 
CORS → MaxSessions → CircuitBreaker → RateLimit → Auth → [proxy]
```

#### Per-Route Middleware Chain
```
Auth → Authz → RateLimit → Security Headers → CORS → Body Limit → 
OpenAPI Validation → Headers → Cache → Transform → Encoding → [proxy to backend]
```

Authentication runs first (closest to the client), authorization needs the
identity from context, and rate limiting runs after auth so unauthenticated
requests get 401 before 429. If a route's authentication or authorization
middleware cannot be constructed, the route **fails closed**: every request
receives 503 Service Unavailable,
`gateway_route_auth_failures_total{reason="construction_failed"}` increments,
and the ERROR log `failed to build route security middleware, failing closed`
is emitted (treat it as page-worthy — the route stays unavailable until a
configuration reload yields a constructible middleware). Other routes keep
serving normally.

### Middleware Features and Limits

#### Cache Middleware
- **Body Size Limit**: 10MB maximum response body size for caching
- **Method Support**: Only GET requests are cached
- **Cache-Control**: Respects Cache-Control headers (no-store, no-cache)
- **Per-Route Isolation**: Each route gets its own cache namespace
- **Thread Safety**: Thread-safe cache factory with lazy initialization
- **Per-Request Header Stripping**: CORS headers (`Access-Control-*`), `Set-Cookie`, and hop-by-hop headers are stripped from cached entries; the live middleware headers win on replay, so a cache entry filled by one request never leaks another request's CORS grants or cookies
- **Decoupled Cache Fill**: the cache write is detached from the client's request context and bounded to 5 seconds, so a client disconnect cannot abort or poison the fill

#### Rate Limit Middleware
- **Token Bucket**: `requestsPerSecond` refill rate with `burst` capacity (`burst` must be >= 1)
- **Per-Client Buckets**: `perClient: true` keys buckets by client IP
- **Stores**: `memory` (per-instance, default) or `redis` (atomic Lua token bucket shared across gateway instances via Redis standalone or Sentinel)
- **Failure Policy**: `redis.failOpen: true` (default) allows requests on Redis outage with a rate-limited WARN and `gateway_middleware_redis_rate_limit_errors_total{policy="fail_open"}`; `failOpen: false` rejects with 429 and fails construction hard when Redis is unreachable at startup
- **Decision Bound**: each redis rate limit decision is bounded by `redis.readTimeout` (default 100ms)
- **Enforcement Scope**: the redis store applies to the gateway-level limit and HTTP/GraphQL route-level limits (GraphQL routes reuse the shared per-route chain); gRPC routes keep the in-memory limiter

#### Transform Middleware
- **Body Size Limit**: 10MB maximum request/response body size for transformation
- **Template Engine**: Go template engine for request transformation
- **Field Operations**: Allow/deny lists and field mappings for responses
- **JSON Support**: Optimized for JSON request/response transformation

#### Encoding Middleware
- **Content Negotiation**: Automatic content type negotiation based on Accept header
- **Metrics Recording**: Records negotiation results and content types
- **Format Support**: JSON, XML, YAML encoding support

### Configuration Precedence

Route-level middleware configuration takes precedence over global configuration:

1. **Route-level configuration** (highest precedence)
2. **Global configuration** (fallback)
3. **Default values** (lowest precedence)

Example:
```yaml
# Global CORS configuration
spec:
  cors:
    allowOrigins: ["*"]
    allowMethods: ["GET", "POST"]

  routes:
    - name: restricted-route
      # Route-level CORS overrides global
      cors:
        allowOrigins: ["https://trusted.example.com"]
        allowMethods: ["GET"]  # More restrictive than global
```

## Enhanced Configuration Reload

The AV API Gateway supports hot configuration reload with enhanced capabilities from the latest refactoring session (TASK-010).

### Enhanced Reload Behavior

The configuration reload system now supports reloading additional components without restart:

**Components Supporting Hot Reload:**
- **CORS Configuration** - Cross-Origin Resource Sharing settings
- **Security Headers** - Security header injection policies
- **Middleware Chains** - Both global and per-route middleware configurations
- **Cache Configuration** - Per-route cache settings and factory updates
- **Transform Configuration** - Request/response transformation templates
- **Encoding Configuration** - Content negotiation settings
- **Audit Configuration** - Audit logging settings and output destinations
- **Rate Limiting** - Rate limiting policies and thresholds
- **Max Sessions** - Concurrent session limits and queue settings
- **Backend Configuration** - Backend hosts, health checks, and load balancing
- **Route Configuration** - HTTP and gRPC route definitions

**Components Requiring Restart:**
- **gRPC Routes/Backends** - gRPC configuration changes require full restart (documented limitation)
- **Circuit Breaker** - Circuit breaker configuration requires restart (documented limitation)
- **TLS Listeners** - TLS certificate and listener changes require restart

### Configuration Reload Metrics

Monitor configuration reload operations with these metrics:

```prometheus
# Configuration reload attempts
gateway_config_reload_total{status="success"} 15
gateway_config_reload_total{status="failure"} 1

# Configuration reload duration
gateway_config_reload_duration_seconds 0.050

# Component-specific reload operations (label is `result`, not `status`)
gateway_config_reload_component_total{component="cors",result="success"} 8
gateway_config_reload_component_total{component="routes",result="success"} 6
gateway_config_reload_component_total{component="audit",result="success"} 4
# spec.vault is never hot-reloaded; a change is counted as skipped
gateway_config_reload_component_total{component="vault",result="skipped"} 0

# Configuration watcher status
gateway_config_watcher_running 1
```

### Reload Trigger Methods

**File-Based Reload:**
```bash
# Modify configuration file - automatic reload via file watcher
vim /app/configs/gateway.yaml

# Manual reload via API
curl -X POST http://localhost:9090/admin/reload
```

**CRD-Based Reload (with Operator):**
```bash
# Update CRD resources - automatic reload via operator
kubectl apply -f updated-apiroute.yaml
kubectl patch backend api-backend --type='merge' -p='{"spec":{"hosts":[{"address":"new-backend.com","port":8080}]}}'
```

### Reload Configuration

```yaml
spec:
  observability:
    # Enable configuration file watcher
    configWatcher:
      enabled: true
      debounceInterval: 1s
      
    # Reload-specific metrics
    metrics:
      configReload:
        enabled: true
        success: true
        errors: true
        duration: true
        components: true
```

### Best Practices

1. **Test Configuration** - Validate configuration before applying
2. **Monitor Reload Metrics** - Track reload success/failure rates
3. **Use Gradual Rollouts** - Apply changes incrementally
4. **Backup Configuration** - Keep backup of working configuration
5. **Plan for Restarts** - Some changes still require full restart

This configuration reference provides comprehensive coverage of all route-level authentication, authorization, backend transformation, caching, encoding options, security features, OTLP TLS configuration, enhanced configuration reload, and metrics configuration, enabling secure and efficient API gateway operations with full observability.