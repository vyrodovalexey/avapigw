# Vault PKI Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting information for Vault PKI integration issues in the AV API Gateway. It covers common problems, diagnostic procedures, and resolution steps.

## Common Issues and Solutions

### 1. Vault Authentication Failures

#### Symptoms
```
ERROR: failed to authenticate with vault: permission denied
ERROR: vault authentication failed: invalid role
ERROR: kubernetes auth failed: service account not authorized
```

#### Diagnostic Steps

1. **Check Vault Connectivity**
   ```bash
   # Test basic connectivity
   curl -k https://vault.example.com:8200/v1/sys/health
   
   # Check from gateway pod
   kubectl exec -it gateway-pod -- curl -k https://vault.example.com:8200/v1/sys/health
   ```

2. **Verify Authentication Method**
   ```bash
   # List enabled auth methods
   vault auth list
   
   # Check Kubernetes auth configuration
   vault read auth/kubernetes/config
   
   # Verify role configuration
   vault read auth/kubernetes/role/gateway-role
   ```

3. **Test Service Account Token**
   ```bash
   # Get service account token
   kubectl get secret $(kubectl get sa gateway-vault -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d
   
   # Test authentication manually
   vault write auth/kubernetes/login role=gateway-role jwt=<token>
   ```

#### Solutions

1. **Fix Kubernetes Authentication**
   ```bash
   # Configure Kubernetes auth
   vault auth enable kubernetes
   
   vault write auth/kubernetes/config \
     token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
     kubernetes_host="https://kubernetes.default.svc.cluster.local" \
     kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
   
   # Create role
   vault write auth/kubernetes/role/gateway-role \
     bound_service_account_names=gateway-vault \
     bound_service_account_namespaces=default \
     policies=gateway-pki \
     ttl=1h \
     max_ttl=24h
   ```

2. **Fix Service Account Permissions**
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: gateway-vault-auth
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: system:auth-delegator
   subjects:
   - kind: ServiceAccount
     name: gateway-vault
     namespace: default
   ```

3. **Update Vault Policy**
   ```hcl
   # gateway-pki.hcl
   path "pki/issue/gateway-server" {
     capabilities = ["create", "update"]
   }
   
   path "pki/issue/gateway-client" {
     capabilities = ["create", "update"]
   }
   
   path "pki/cert/ca" {
     capabilities = ["read"]
   }
   
   path "auth/token/renew-self" {
     capabilities = ["update"]
   }
   ```

### 2. PKI Configuration Issues

#### Symptoms
```
ERROR: failed to issue certificate: role "gateway-server" not found
ERROR: certificate request denied: domain not allowed
ERROR: PKI mount "pki" not found
```

#### Diagnostic Steps

1. **Verify PKI Mount**
   ```bash
   # List secrets engines
   vault secrets list
   
   # Check PKI mount status
   vault read sys/mounts/pki
   ```

2. **Check PKI Role Configuration**
   ```bash
   # List PKI roles
   vault list pki/roles
   
   # Read role configuration
   vault read pki/roles/gateway-server
   ```

3. **Test Certificate Issuance**
   ```bash
   # Test manual certificate issuance
   vault write pki/issue/gateway-server \
     common_name="test.example.com" \
     ttl="1h"
   ```

#### Solutions

1. **Enable and Configure PKI**
   ```bash
   # Enable PKI secrets engine
   vault secrets enable pki
   
   # Configure max lease TTL
   vault secrets tune -max-lease-ttl=8760h pki
   
   # Generate root CA
   vault write pki/root/generate/internal \
     common_name="Gateway Root CA" \
     ttl=8760h
   
   # Configure URLs
   vault write pki/config/urls \
     issuing_certificates="https://vault.example.com:8200/v1/pki/ca" \
     crl_distribution_points="https://vault.example.com:8200/v1/pki/crl"
   ```

2. **Create PKI Role**
   ```bash
   # Create server certificate role
   vault write pki/roles/gateway-server \
     allowed_domains="example.com,*.example.com" \
     allow_subdomains=true \
     max_ttl="720h" \
     generate_lease=true \
     key_type="rsa" \
     key_bits=2048
   
   # Create client certificate role
   vault write pki/roles/gateway-client \
     allowed_domains="gateway.internal,*.gateway.internal" \
     allow_subdomains=true \
     max_ttl="24h" \
     generate_lease=true \
     client_flag=true \
     key_type="rsa" \
     key_bits=2048
   ```

### 3. Certificate Renewal Failures

#### Symptoms
```
ERROR: failed to renew certificate: certificate request denied
ERROR: certificate renewal failed: vault token expired
WARN: certificate expires in 30 minutes, renewal failed
```

#### Diagnostic Steps

1. **Check Certificate Expiry**
   ```bash
   # Check certificate expiry metrics
   curl http://localhost:9090/metrics | grep gateway_tls_certificate_expiry_seconds
   
   # Check certificate details
   openssl x509 -in certificate.pem -text -noout | grep -A2 "Validity"
   ```

2. **Verify Vault Token Status**
   ```bash
   # Check token status
   vault token lookup
   
   # Check token TTL
   vault token lookup -format=json | jq '.data.ttl'
   ```

3. **Test Manual Renewal**
   ```bash
   # Force certificate renewal
   curl -X POST http://localhost:9090/admin/tls/renew/listener
   curl -X POST http://localhost:9090/admin/tls/renew/route/tenant-a
   ```

#### Solutions

1. **Fix Token Renewal**
   ```yaml
   # Increase token TTL in Vault role
   vault write auth/kubernetes/role/gateway-role \
     bound_service_account_names=gateway-vault \
     bound_service_account_namespaces=default \
     policies=gateway-pki \
     ttl=4h \
     max_ttl=24h \
     token_period=2h  # Enable periodic tokens
   ```

2. **Adjust Renewal Timing**
   ```yaml
   # Gateway configuration
   vault:
     pki:
       enabled: true
       pkiMount: pki
       role: gateway-server
       commonName: gateway.example.com
       ttl: "24h"
       renewBefore: "2h"  # Increase renewal window
       maxRetries: 5      # Increase retry attempts
       retryDelay: "1m"   # Increase retry delay
   ```

3. **Monitor Renewal Process**
   ```bash
   # Enable debug logging
   kubectl patch deployment gateway -p '{"spec":{"template":{"spec":{"containers":[{"name":"gateway","env":[{"name":"LOG_LEVEL","value":"debug"}]}]}}}}'
   
   # Watch renewal logs
   kubectl logs -f deployment/gateway | grep "certificate.*renew"
   ```

### 4. SNI Certificate Selection Issues

#### Symptoms
```
ERROR: no certificate found for SNI hostname: tenant-a.example.com
ERROR: certificate verification failed: hostname doesn't match certificate
WARN: using default certificate for SNI hostname
```

#### Diagnostic Steps

1. **Check SNI Configuration**
   ```bash
   # Test SNI with specific hostname
   openssl s_client -connect gateway.example.com:8443 -servername tenant-a.example.com
   
   # Check certificate SANs
   openssl x509 -in certificate.pem -text -noout | grep -A5 "Subject Alternative Name"
   ```

2. **Verify Route Configuration**
   ```bash
   # Check route TLS configuration
   kubectl get configmap gateway-config -o yaml | grep -A20 "tls:"
   ```

3. **Test Certificate Metrics**
   ```bash
   # Check route certificate metrics
   curl http://localhost:9090/metrics | grep 'gateway_tls_certificate_expiry_seconds{type="route"}'
   ```

#### Solutions

1. **Fix SNI Host Configuration**
   ```yaml
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
             - www.tenant-a.example.com
         sniHosts:
           - tenant-a.example.com      # Must match certificate CN/SANs
           - api.tenant-a.example.com  # Must match certificate SANs
           - www.tenant-a.example.com  # Must match certificate SANs
   ```

2. **Update PKI Role for Domains**
   ```bash
   # Update role to allow required domains
   vault write pki/roles/gateway-server \
     allowed_domains="example.com,tenant-a.example.com,*.tenant-a.example.com" \
     allow_subdomains=true \
     allow_bare_domains=true \
     max_ttl="720h"
   ```

### 5. Backend mTLS Issues

#### Symptoms
```
ERROR: backend connection failed: tls: bad certificate
ERROR: client certificate authentication failed
ERROR: x509: certificate signed by unknown authority
```

#### Diagnostic Steps

1. **Test Backend Connection**
   ```bash
   # Test mTLS connection manually
   openssl s_client -connect backend.example.com:8443 \
     -cert client.crt -key client.key -CAfile ca.crt
   ```

2. **Verify Client Certificate**
   ```bash
   # Check client certificate details
   openssl x509 -in client.crt -text -noout
   
   # Verify certificate chain
   openssl verify -CAfile ca.crt client.crt
   ```

3. **Check Backend TLS Configuration**
   ```bash
   # Check backend TLS metrics
   curl http://localhost:9090/metrics | grep 'gateway_backend_tls'
   ```

#### Solutions

1. **Fix Backend TLS Configuration**
   ```yaml
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
           altNames:
             - gateway.internal
         serverName: secure-api.example.com  # Must match backend certificate
         caFile: /etc/ssl/certs/backend-ca.crt  # Backend CA for verification
         insecureSkipVerify: false
   ```

2. **Create Client Certificate Role**
   ```bash
   # Create client certificate role in Vault
   vault write pki-client/roles/gateway-client \
     allowed_domains="gateway.internal,*.gateway.internal" \
     allow_subdomains=true \
     max_ttl="24h" \
     client_flag=true \
     key_usage="digital_signature,key_encipherment" \
     ext_key_usage="client_auth"
   ```

### 6. WebSocket Proxy Issues

#### Symptoms
```
ERROR: WebSocket connection failed: bad handshake
ERROR: WebSocket upgrade failed: hop-by-hop header handling
WARN: WebSocket connection dropped unexpectedly
```

#### Diagnostic Steps

1. **Check WebSocket Endpoint**
   ```bash
   # Test WebSocket endpoint manually
   wscat -c ws://127.0.0.1:8080/ws
   
   # Check WebSocket upgrade headers
   curl -H "Upgrade: websocket" -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: test" -H "Sec-WebSocket-Version: 13" \
        http://127.0.0.1:8080/ws
   ```

2. **Verify Header Handling**
   ```bash
   # Check if hop-by-hop headers are properly handled
   curl -v -H "Connection: keep-alive, upgrade" \
        -H "Upgrade: websocket" \
        http://127.0.0.1:8080/ws
   ```

#### Solutions

1. **Fix WebSocket Configuration**
   ```yaml
   routes:
     - name: websocket-route
       match:
         - uri:
             prefix: /ws
       route:
         - destination:
             host: websocket-backend
             port: 8080
       # Ensure proper WebSocket handling
       headers:
         request:
           # Preserve WebSocket upgrade headers
           preserve:
             - "Upgrade"
             - "Connection"
             - "Sec-WebSocket-Key"
             - "Sec-WebSocket-Version"
   ```

2. **Backend WebSocket Support**
   - Ensure backend properly handles WebSocket upgrade
   - Verify backend supports WebSocket protocol
   - Check backend WebSocket message handling

### 7. gRPC Plaintext Warnings

#### Symptoms
```
WARN: gRPC listener running in plaintext mode (no TLS)
WARN: gRPC connections are not encrypted
```

#### Solutions

1. **Enable gRPC TLS**
   ```yaml
   listeners:
     - name: grpc
       port: 9000
       protocol: GRPC
       tls:
         enabled: true
         mode: SIMPLE
         vault:
           enabled: true
           pkiMount: pki
           role: grpc-server
           commonName: grpc.example.com
   ```

2. **Accept Plaintext for Development**
   ```yaml
   # For development environments only
   listeners:
     - name: grpc-dev
       port: 9000
       protocol: GRPC
       # No TLS configuration = plaintext mode
       # Warning will be logged but connection allowed
   ```

### 8. Performance Issues

#### Symptoms
```
WARN: certificate renewal taking longer than expected
ERROR: TLS handshake timeout
WARN: high certificate renewal failure rate
```

#### Diagnostic Steps

1. **Check Renewal Performance**
   ```bash
   # Check renewal duration metrics
   curl http://localhost:9090/metrics | grep gateway_tls_renewal_duration_seconds
   
   # Check Vault operation metrics
   curl http://localhost:9090/metrics | grep gateway_vault_pki_operations
   ```

2. **Monitor Vault Performance**
   ```bash
   # Check Vault server metrics
   curl https://vault.example.com:8200/v1/sys/metrics
   
   # Check Vault audit logs
   vault audit list
   ```

#### Solutions

1. **Optimize Renewal Timing**
   ```yaml
   vault:
     pki:
       enabled: true
       renewBefore: "2h"      # Increase renewal window
       renewJitter: "10m"     # Add jitter to prevent thundering herd
       maxRetries: 3          # Limit retry attempts
       retryDelay: "30s"      # Reasonable retry delay
   ```

2. **Tune Vault Connection**
   ```yaml
   vault:
     enabled: true
     address: "https://vault.example.com:8200"
     timeout: 30s           # Increase timeout
     retries: 3             # Enable retries
     retryDelay: 1s         # Retry delay
     maxRetryDelay: 30s     # Max retry delay
   ```

## Diagnostic Commands

### Certificate Information

```bash
# Check certificate expiry
openssl x509 -in certificate.pem -noout -dates

# Check certificate details
openssl x509 -in certificate.pem -text -noout

# Check certificate chain
openssl verify -CAfile ca.crt certificate.pem

# Test TLS connection
openssl s_client -connect host:port -servername hostname

# Check certificate SANs
openssl x509 -in certificate.pem -text -noout | grep -A5 "Subject Alternative Name"
```

### Vault Operations

```bash
# Check Vault status
vault status

# Test authentication
vault auth -method=kubernetes role=gateway-role

# List PKI roles
vault list pki/roles

# Read PKI role
vault read pki/roles/gateway-server

# Test certificate issuance
vault write pki/issue/gateway-server common_name="test.example.com" ttl="1h"

# Check token status
vault token lookup

# Renew token
vault token renew
```

### Gateway Metrics

```bash
# Certificate expiry metrics
curl http://localhost:9090/metrics | grep gateway_tls_certificate_expiry_seconds

# Certificate renewal metrics
curl http://localhost:9090/metrics | grep gateway_tls_certificate_renewals_total

# Vault operation metrics
curl http://localhost:9090/metrics | grep gateway_vault_pki_operations_total

# TLS handshake metrics
curl http://localhost:9090/metrics | grep gateway_tls_handshake
```

### Kubernetes Diagnostics

```bash
# Check service account
kubectl get sa gateway-vault -o yaml

# Check service account token
kubectl get secret $(kubectl get sa gateway-vault -o jsonpath='{.secrets[0].name}') -o yaml

# Check pod logs
kubectl logs -f deployment/gateway

# Check configuration
kubectl get configmap gateway-config -o yaml

# Check secrets
kubectl get secrets | grep tls
```

## Log Analysis

### Enable Debug Logging

```yaml
observability:
  logging:
    level: debug
    format: json
```

### Key Log Patterns

**Successful Operations:**
```json
{"level":"info","component":"vault-tls-provider","operation":"certificate-issued","common_name":"gateway.example.com","ttl":"24h"}
{"level":"info","component":"vault-tls-provider","operation":"certificate-renewed","expires_at":"2024-01-16T10:30:00Z"}
{"level":"info","component":"route-tls-manager","operation":"sni-certificate-selected","hostname":"tenant-a.example.com","route":"tenant-a-api"}
```

**Error Patterns:**
```json
{"level":"error","component":"vault-client","operation":"authentication","error":"permission denied"}
{"level":"error","component":"vault-tls-provider","operation":"certificate-renewal","error":"role not found"}
{"level":"warn","component":"vault-tls-provider","operation":"certificate-expiring","expires_in":"30m"}
```

## Monitoring and Alerting

### Prometheus Alerts

```yaml
groups:
  - name: vault-pki
    rules:
      - alert: VaultPKICertificateExpiringSoon
        expr: (gateway_tls_certificate_expiry_seconds - time()) < 3600
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Vault PKI certificate expiring soon"
          description: "Certificate {{ $labels.name }} expires in less than 1 hour"

      - alert: VaultPKIRenewalFailed
        expr: increase(gateway_tls_certificate_renewals_total{status="failure"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Vault PKI certificate renewal failed"
          description: "Certificate renewal failed for {{ $labels.name }}"

      - alert: VaultPKIOperationsFailing
        expr: rate(gateway_vault_pki_operations_total{status="failure"}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Vault PKI operations failing"
          description: "High failure rate for Vault PKI operations"
```

### Health Checks

```bash
# Certificate health check
curl http://localhost:9090/health/certificates

# Vault connectivity check
curl http://localhost:9090/health/vault

# PKI operations check
curl http://localhost:9090/health/pki
```

## Recent Improvements

### Enhanced Boolean Environment Variable Parsing (DEV-006)

The latest refactoring session improved boolean environment variable parsing, including `VAULT_SKIP_VERIFY`:

**Supported Values:**
- **True values:** `true`, `TRUE`, `yes`, `YES`, `1`, `on`, `ON`
- **False values:** `false`, `FALSE`, `no`, `NO`, `0`, `off`, `OFF`

**Examples:**
```bash
# All of these are equivalent for enabling skip verify
export VAULT_SKIP_VERIFY=true
export VAULT_SKIP_VERIFY=yes
export VAULT_SKIP_VERIFY=1

# All of these are equivalent for disabling skip verify
export VAULT_SKIP_VERIFY=false
export VAULT_SKIP_VERIFY=no
export VAULT_SKIP_VERIFY=0
```

**Troubleshooting Boolean Parsing:**
```bash
# Check current environment variable value
echo $VAULT_SKIP_VERIFY

# Test with different boolean formats
export VAULT_SKIP_VERIFY=yes && ./bin/gateway -config config.yaml
export VAULT_SKIP_VERIFY=1 && ./bin/gateway -config config.yaml
export VAULT_SKIP_VERIFY=true && ./bin/gateway -config config.yaml
```

This troubleshooting guide provides comprehensive coverage of common Vault PKI integration issues and their solutions, enabling quick diagnosis and resolution of certificate management problems.