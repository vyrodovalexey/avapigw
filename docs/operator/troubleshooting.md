# AVAPIGW Operator Troubleshooting Guide

This guide helps diagnose and resolve common issues with the AVAPIGW Operator.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [Operator Runtime Issues](#operator-runtime-issues)
- [CRD and Webhook Issues](#crd-and-webhook-issues)
- [gRPC Communication Issues](#grpc-communication-issues)
- [Vault Integration Issues](#vault-integration-issues)
- [Performance Issues](#performance-issues)
- [Debugging Tools](#debugging-tools)
- [Common Error Messages](#common-error-messages)
- [Support and Escalation](#support-and-escalation)

## Quick Diagnostics

### Health Check Commands

Run these commands to quickly assess operator health:

```bash
# Check operator pod status
kubectl get pods -n avapigw-system -l app.kubernetes.io/name=avapigw-operator

# Check operator logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator --tail=50

# Check CRD status
kubectl get crd | grep avapigw

# Check webhook configuration
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator

# Check operator metrics
kubectl port-forward -n avapigw-system svc/avapigw-operator-metrics 8080:8080 &
curl http://localhost:8080/metrics | grep -E "(controller_runtime|avapigw_operator)"
```

### Status Overview

```bash
# Get comprehensive status
kubectl get apiroutes,grpcroutes,backends,grpcbackends --all-namespaces
kubectl describe apiroute <route-name> -n <namespace>
kubectl describe backend <backend-name> -n <namespace>
```

## Installation Issues

### Issue: Operator Pod Not Starting

**Symptoms:**
- Pod stuck in `Pending`, `CrashLoopBackOff`, or `ImagePullBackOff`
- Operator not responding to CRD changes

**Diagnosis:**
```bash
# Check pod status and events
kubectl describe pod -n avapigw-system -l app.kubernetes.io/name=avapigw-operator

# Check resource constraints
kubectl top pods -n avapigw-system

# Check node resources
kubectl describe nodes
```

**Common Causes and Solutions:**

1. **Image Pull Issues**
   ```bash
   # Check image pull secrets
   kubectl get secrets -n avapigw-system
   
   # Verify image exists
   docker pull ghcr.io/vyrodovalexey/avapigw-operator:latest
   
   # Solution: Update image tag or add pull secrets
   helm upgrade avapigw-operator ./helm/avapigw-operator \
     --set image.tag=v1.0.0 \
     --set imagePullSecrets[0].name=regcred
   ```

2. **Resource Constraints**
   ```bash
   # Check resource requests/limits
   kubectl get pod -n avapigw-system -o yaml | grep -A10 resources
   
   # Solution: Adjust resource limits
   helm upgrade avapigw-operator ./helm/avapigw-operator \
     --set resources.requests.memory=64Mi \
     --set resources.limits.memory=256Mi
   ```

3. **RBAC Issues**
   ```bash
   # Check service account and RBAC
   kubectl get serviceaccount avapigw-operator -n avapigw-system
   kubectl get clusterrole avapigw-operator-manager
   kubectl get clusterrolebinding avapigw-operator-manager
   
   # Solution: Reinstall with RBAC
   helm upgrade avapigw-operator ./helm/avapigw-operator \
     --set rbac.create=true
   ```

### Issue: CRDs Not Installing

**Symptoms:**
- `kubectl get crd | grep avapigw` returns no results
- Error: "no matches for kind APIRoute"

**Diagnosis:**
```bash
# Check CRD installation
kubectl get crd -o name | grep avapigw

# Check Helm release
helm status avapigw-operator -n avapigw-system

# Check CRD files
ls helm/avapigw-operator/crds/
```

**Solutions:**
```bash
# Manual CRD installation
kubectl apply -f helm/avapigw-operator/crds/

# Reinstall with CRDs
helm uninstall avapigw-operator -n avapigw-system
helm install avapigw-operator ./helm/avapigw-operator -n avapigw-system --create-namespace

# Verify CRD installation
kubectl get crd apiroutes.avapigw.io -o yaml
```

## Operator Runtime Issues

### Issue: Operator Not Reconciling Resources

**Symptoms:**
- CRDs created but status never updates
- No logs showing reconciliation activity
- Resources stuck in unknown state

**Diagnosis:**
```bash
# Check operator logs for reconciliation
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -i reconcil

# Check controller metrics
curl http://localhost:8080/metrics | grep controller_runtime_reconcile

# Check leader election
kubectl get lease -n avapigw-system
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep leader
```

**Solutions:**

1. **Leader Election Issues**
   ```bash
   # Check if multiple replicas are fighting for leadership
   kubectl get pods -n avapigw-system -l app.kubernetes.io/name=avapigw-operator
   
   # Scale down to 1 replica temporarily
   kubectl scale deployment avapigw-operator -n avapigw-system --replicas=1
   
   # Check leader election logs
   kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -E "(leader|election)"
   ```

2. **RBAC Permissions**
   ```bash
   # Test RBAC permissions
   kubectl auth can-i get apiroutes --as=system:serviceaccount:avapigw-system:avapigw-operator
   kubectl auth can-i update apiroutes/status --as=system:serviceaccount:avapigw-system:avapigw-operator
   
   # Check for permission errors in logs
   kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -i "forbidden\|unauthorized"
   ```

3. **Controller Configuration**
   ```bash
   # Enable debug logging
   kubectl patch deployment avapigw-operator -n avapigw-system \
     --type='json' \
     -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "LOG_LEVEL", "value": "debug"}}]'
   
   # Check reconciliation configuration
   kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -E "(reconcile|controller)"
   ```

### Issue: High Memory/CPU Usage

**Symptoms:**
- Operator pod consuming excessive resources
- Pod getting OOMKilled
- Slow reconciliation performance

**Diagnosis:**
```bash
# Check resource usage
kubectl top pod -n avapigw-system
kubectl describe pod -n avapigw-system -l app.kubernetes.io/name=avapigw-operator

# Check metrics for resource usage
curl http://localhost:8080/metrics | grep -E "(memory|cpu|goroutines)"

# Check for memory leaks
kubectl exec -n avapigw-system deployment/avapigw-operator -- /bin/sh -c "cat /proc/meminfo"
```

**Solutions:**
```bash
# Increase resource limits
helm upgrade avapigw-operator ./helm/avapigw-operator \
  --set resources.limits.memory=512Mi \
  --set resources.limits.cpu=1000m

# Tune reconciliation settings
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[
    {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "RECONCILE_WORKERS", "value": "3"}},
    {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "RECONCILE_RATE_LIMIT_QPS", "value": "10"}}
  ]'
```

## CRD and Webhook Issues

### Issue: CRD Validation Failures

**Symptoms:**
- "admission webhook denied the request" errors
- CRDs rejected during creation/update
- Validation errors in operator logs

**Diagnosis:**
```bash
# Check webhook configuration
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator -o yaml

# Test webhook connectivity
kubectl port-forward -n avapigw-system svc/avapigw-operator-webhook 9443:9443 &
curl -k https://localhost:9443/validate-apiroute

# Check webhook logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep webhook
```

**Solutions:**

1. **Webhook Certificate Issues**
   ```bash
   # Check webhook TLS certificate
   kubectl get secret -n avapigw-system | grep webhook
   
   # Regenerate webhook certificates
   kubectl delete secret avapigw-operator-webhook-certs -n avapigw-system
   kubectl rollout restart deployment/avapigw-operator -n avapigw-system
   ```

2. **Webhook Service Issues**
   ```bash
   # Check webhook service
   kubectl get svc avapigw-operator-webhook -n avapigw-system
   kubectl describe svc avapigw-operator-webhook -n avapigw-system
   
   # Test service connectivity
   kubectl run test-pod --image=curlimages/curl --rm -it -- \
     curl -k https://avapigw-operator-webhook.avapigw-system.svc:9443/validate-apiroute
   ```

3. **Validation Logic Issues**
   ```bash
   # Check specific validation errors
   kubectl apply -f your-crd.yaml --dry-run=server
   
   # Enable webhook debug logging
   kubectl patch deployment avapigw-operator -n avapigw-system \
     --type='json' \
     -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "WEBHOOK_LOG_LEVEL", "value": "debug"}}]'
   ```

### Issue: Duplicate Resource Detection

**Symptoms:**
- "duplicate route match found" errors
- Resources with similar configurations being rejected

**Diagnosis:**
```bash
# List all routes to check for duplicates
kubectl get apiroutes --all-namespaces -o yaml | grep -A10 -B5 "match:"

# Check operator logs for duplicate detection
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep duplicate
```

**Solutions:**
```bash
# Review and modify conflicting routes
kubectl get apiroutes --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace,MATCH:.spec.match[0].uri

# Update route matching to be more specific
kubectl patch apiroute conflicting-route -n namespace \
  --type='merge' \
  -p='{"spec":{"match":[{"uri":{"prefix":"/api/v2"},"methods":["GET"]}]}}'
```

## gRPC Communication Issues

### Issue: Operator-Gateway Communication Failures

**Symptoms:**
- Routes/backends not being applied to gateways
- "connection refused" errors in logs
- Gateway not receiving configuration updates

**Diagnosis:**
```bash
# Check gRPC server status
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep grpc

# Test gRPC connectivity
kubectl port-forward -n avapigw-system svc/avapigw-operator 9444:9444 &
grpcurl -insecure localhost:9444 list

# Check gateway logs for connection attempts
kubectl logs -n <gateway-namespace> -l app=avapigw | grep operator
```

**Solutions:**

1. **Network Connectivity**
   ```bash
   # Check service and endpoints
   kubectl get svc avapigw-operator -n avapigw-system
   kubectl get endpoints avapigw-operator -n avapigw-system
   
   # Test network connectivity from gateway pod
   kubectl exec -n <gateway-namespace> deployment/avapigw -- \
     nc -zv avapigw-operator.avapigw-system.svc 9444
   ```

2. **TLS Certificate Issues**
   ```bash
   # Check gRPC TLS certificates
   kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -E "(certificate|tls)"
   
   # Regenerate certificates if using self-signed
   kubectl delete secret avapigw-operator-grpc-certs -n avapigw-system
   kubectl rollout restart deployment/avapigw-operator -n avapigw-system
   ```

3. **Gateway Configuration**
   ```bash
   # Check gateway operator configuration
   kubectl get configmap avapigw-config -n <gateway-namespace> -o yaml
   
   # Verify operator endpoint in gateway config
   grep -A5 -B5 operator /path/to/gateway/config.yaml
   ```

### Issue: mTLS Authentication Failures

**Symptoms:**
- "certificate verify failed" errors
- "tls: bad certificate" in logs
- Mutual TLS handshake failures

**Diagnosis:**
```bash
# Check certificate details
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -E "(mtls|mutual|certificate)"

# Verify certificate chain
openssl s_client -connect operator:9444 -cert client.crt -key client.key -CAfile ca.crt
```

**Solutions:**
```bash
# Regenerate mTLS certificates
kubectl delete secret avapigw-operator-mtls-certs -n avapigw-system
kubectl rollout restart deployment/avapigw-operator -n avapigw-system

# Check certificate expiry
kubectl get secret avapigw-operator-mtls-certs -n avapigw-system -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates
```

## Vault Integration Issues

### Issue: Vault Authentication Failures

**Symptoms:**
- "permission denied" errors from Vault
- "authentication failed" in operator logs
- Certificates not being issued

**Diagnosis:**
```bash
# Check Vault authentication logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep vault

# Test Vault connectivity
kubectl exec -n avapigw-system deployment/avapigw-operator -- \
  curl -k $VAULT_ADDR/v1/sys/health

# Check service account token
kubectl get serviceaccount avapigw-operator -n avapigw-system -o yaml
```

**Solutions:**

1. **Kubernetes Auth Issues**
   ```bash
   # Verify Kubernetes auth configuration in Vault
   vault read auth/kubernetes/config
   
   # Check auth role binding
   vault read auth/kubernetes/role/avapigw-operator
   
   # Test authentication manually
   kubectl exec -n avapigw-system deployment/avapigw-operator -- sh -c '
     JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
     curl -k -X POST $VAULT_ADDR/v1/auth/kubernetes/login \
       -d "{\"jwt\":\"$JWT\",\"role\":\"avapigw-operator\"}"
   '
   ```

2. **Policy Issues**
   ```bash
   # Check Vault policies
   vault policy read avapigw-operator
   
   # Test policy permissions
   vault token lookup
   vault auth -method=kubernetes role=avapigw-operator
   vault write pki_int/issue/operator-server common_name=test
   ```

3. **Network Issues**
   ```bash
   # Check Vault connectivity
   kubectl exec -n avapigw-system deployment/avapigw-operator -- \
     nslookup vault.example.com
   
   # Test TLS connection
   kubectl exec -n avapigw-system deployment/avapigw-operator -- \
     openssl s_client -connect vault.example.com:8200
   ```

### Issue: Certificate Issuance Failures

**Symptoms:**
- "certificate request failed" errors
- PKI role not found errors
- Invalid certificate parameters

**Diagnosis:**
```bash
# Check PKI role configuration
vault read pki_int/roles/operator-server

# Check certificate request details
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -A10 -B10 "certificate.*request"

# Test manual certificate issuance
vault write pki_int/issue/operator-server \
  common_name=avapigw-operator.avapigw-system.svc \
  ttl=24h
```

**Solutions:**
```bash
# Update PKI role configuration
vault write pki_int/roles/operator-server \
  allowed_domains="avapigw-system.svc,avapigw-system.svc.cluster.local" \
  allow_subdomains=true \
  allow_localhost=true \
  allow_ip_sans=true \
  max_ttl=72h

# Check operator Vault configuration
kubectl get deployment avapigw-operator -n avapigw-system -o yaml | grep -A20 env
```

## Performance Issues

### Issue: Slow Reconciliation

**Symptoms:**
- Long delays between CRD changes and application
- High reconciliation duration metrics
- Timeouts during reconciliation

**Diagnosis:**
```bash
# Check reconciliation metrics
curl http://localhost:8080/metrics | grep controller_runtime_reconcile_time_seconds

# Check reconciliation queue depth
curl http://localhost:8080/metrics | grep workqueue

# Monitor reconciliation logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep -E "(reconcile|duration)"
```

**Solutions:**
```bash
# Increase worker count
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "RECONCILE_WORKERS", "value": "10"}}]'

# Adjust rate limiting
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[
    {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "RECONCILE_RATE_LIMIT_QPS", "value": "50"}},
    {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "RECONCILE_RATE_LIMIT_BURST", "value": "100"}}
  ]'

# Increase resource limits
helm upgrade avapigw-operator ./helm/avapigw-operator \
  --set resources.limits.cpu=2000m \
  --set resources.limits.memory=1Gi
```

### Issue: High Resource Usage

**Symptoms:**
- Operator consuming excessive CPU/memory
- Frequent garbage collection
- Pod restarts due to OOM

**Diagnosis:**
```bash
# Monitor resource usage
kubectl top pod -n avapigw-system --containers

# Check Go runtime metrics
curl http://localhost:8080/metrics | grep -E "(go_memstats|go_goroutines)"

# Enable pprof for detailed analysis
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "ENABLE_PPROF", "value": "true"}}]'

# Access pprof data
kubectl port-forward -n avapigw-system deployment/avapigw-operator 6060:6060 &
go tool pprof http://localhost:6060/debug/pprof/heap
```

**Solutions:**
```bash
# Optimize garbage collection
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "GOGC", "value": "100"}}]'

# Increase memory limits
helm upgrade avapigw-operator ./helm/avapigw-operator \
  --set resources.limits.memory=2Gi \
  --set resources.requests.memory=512Mi

# Reduce reconciliation frequency for stable resources
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "RECONCILE_RESYNC_PERIOD", "value": "10m"}}]'
```

## Debugging Tools

### Enable Debug Logging

```bash
# Enable debug logging
kubectl patch deployment avapigw-operator -n avapigw-system \
  --type='json' \
  -p='[
    {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "LOG_LEVEL", "value": "debug"}},
    {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "LOG_FORMAT", "value": "console"}}
  ]'

# Watch debug logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator -f
```

### Metrics Collection

```bash
# Port forward to metrics endpoint
kubectl port-forward -n avapigw-system svc/avapigw-operator-metrics 8080:8080 &

# Collect all metrics
curl http://localhost:8080/metrics > operator-metrics.txt

# Key metrics to monitor
curl http://localhost:8080/metrics | grep -E "(controller_runtime|avapigw_operator|go_)"
```

### Event Monitoring

```bash
# Watch Kubernetes events
kubectl get events -n avapigw-system --sort-by='.lastTimestamp' -w

# Filter operator-related events
kubectl get events --all-namespaces --field-selector involvedObject.kind=APIRoute

# Check CRD status events
kubectl describe apiroute <route-name> -n <namespace>
```

### Network Debugging

```bash
# Test network connectivity
kubectl run netshoot --image=nicolaka/netshoot --rm -it -- bash

# Inside netshoot pod:
# Test operator gRPC port
nc -zv avapigw-operator.avapigw-system.svc 9444

# Test webhook port
nc -zv avapigw-operator-webhook.avapigw-system.svc 9443

# Test Vault connectivity
curl -k https://vault.example.com:8200/v1/sys/health
```

## Common Error Messages

### "admission webhook denied the request"

**Cause:** Webhook validation failure
**Solution:**
```bash
# Check webhook logs
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep webhook

# Validate CRD manually
kubectl apply -f your-crd.yaml --dry-run=server

# Check webhook configuration
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator -o yaml
```

### "connection refused" (gRPC)

**Cause:** Network connectivity or service issues
**Solution:**
```bash
# Check service status
kubectl get svc avapigw-operator -n avapigw-system

# Check pod status
kubectl get pods -n avapigw-system -l app.kubernetes.io/name=avapigw-operator

# Test connectivity
kubectl port-forward -n avapigw-system svc/avapigw-operator 9444:9444
```

### "certificate verify failed"

**Cause:** TLS certificate issues
**Solution:**
```bash
# Check certificate status
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep certificate

# Regenerate certificates
kubectl delete secret avapigw-operator-tls-certs -n avapigw-system
kubectl rollout restart deployment/avapigw-operator -n avapigw-system
```

### "permission denied" (Vault)

**Cause:** Vault authentication or authorization issues
**Solution:**
```bash
# Check Vault authentication
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator | grep vault

# Verify Vault role and policy
vault read auth/kubernetes/role/avapigw-operator
vault policy read avapigw-operator
```

### "no matches for kind APIRoute"

**Cause:** CRDs not installed
**Solution:**
```bash
# Install CRDs manually
kubectl apply -f helm/avapigw-operator/crds/

# Verify CRD installation
kubectl get crd | grep avapigw
```

## Support and Escalation

### Collecting Debug Information

When reporting issues, collect the following information:

```bash
#!/bin/bash
# debug-info.sh - Collect operator debug information

echo "=== Operator Pod Status ==="
kubectl get pods -n avapigw-system -l app.kubernetes.io/name=avapigw-operator -o wide

echo "=== Operator Logs ==="
kubectl logs -n avapigw-system -l app.kubernetes.io/name=avapigw-operator --tail=100

echo "=== CRD Status ==="
kubectl get crd | grep avapigw

echo "=== Webhook Configuration ==="
kubectl get validatingwebhookconfigurations -l app.kubernetes.io/name=avapigw-operator

echo "=== Operator Configuration ==="
kubectl get deployment avapigw-operator -n avapigw-system -o yaml

echo "=== Events ==="
kubectl get events -n avapigw-system --sort-by='.lastTimestamp' | tail -20

echo "=== Metrics ==="
kubectl port-forward -n avapigw-system svc/avapigw-operator-metrics 8080:8080 &
sleep 2
curl -s http://localhost:8080/metrics | grep -E "(controller_runtime|avapigw_operator)" | head -20
pkill -f "port-forward"

echo "=== Resource Usage ==="
kubectl top pod -n avapigw-system
```

### Support Channels

- **GitHub Issues**: [https://github.com/vyrodovalexey/avapigw/issues](https://github.com/vyrodovalexey/avapigw/issues)
- **GitHub Discussions**: [https://github.com/vyrodovalexey/avapigw/discussions](https://github.com/vyrodovalexey/avapigw/discussions)
- **Documentation**: [docs/operator/](.)

### Issue Template

When reporting issues, include:

1. **Environment Information**
   - Kubernetes version
   - Operator version
   - Helm chart version
   - Infrastructure (cloud provider, on-premises)

2. **Problem Description**
   - What you were trying to do
   - What happened instead
   - Error messages and logs

3. **Reproduction Steps**
   - Minimal steps to reproduce the issue
   - Sample CRD configurations
   - Expected vs actual behavior

4. **Debug Information**
   - Output from debug-info.sh script
   - Relevant configuration files
   - Network topology (if relevant)

For urgent production issues, include "URGENT" in the issue title and provide detailed impact assessment.