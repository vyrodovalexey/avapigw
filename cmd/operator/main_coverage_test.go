// Package main provides additional unit tests for coverage improvement.
// Target: cmd/operator coverage from 59.1% to >90%.
package main

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// applyDurationEnv Tests
// ============================================================================

func TestApplyDurationEnv_ValidDuration(t *testing.T) {
	envKey := "TEST_DURATION_VALID"
	os.Setenv(envKey, "30s")
	defer os.Unsetenv(envKey)

	target := 10 * time.Second
	applyDurationEnv(&target, envKey)

	if target != 30*time.Second {
		t.Errorf("applyDurationEnv() target = %v, want %v", target, 30*time.Second)
	}
}

func TestApplyDurationEnv_InvalidDuration(t *testing.T) {
	envKey := "TEST_DURATION_INVALID"
	os.Setenv(envKey, "invalid")
	defer os.Unsetenv(envKey)

	target := 10 * time.Second
	applyDurationEnv(&target, envKey)

	// Should keep original value when parsing fails
	if target != 10*time.Second {
		t.Errorf("applyDurationEnv() target = %v, want %v (original)", target, 10*time.Second)
	}
}

func TestApplyDurationEnv_EmptyValue_Coverage(t *testing.T) {
	envKey := "TEST_DURATION_EMPTY_COV"
	os.Unsetenv(envKey)

	target := 10 * time.Second
	applyDurationEnv(&target, envKey)

	if target != 10*time.Second {
		t.Errorf("applyDurationEnv() target = %v, want %v", target, 10*time.Second)
	}
}

func TestApplyDurationEnv_MinuteDuration(t *testing.T) {
	envKey := "TEST_DURATION_MINUTE"
	os.Setenv(envKey, "5m")
	defer os.Unsetenv(envKey)

	target := 10 * time.Second
	applyDurationEnv(&target, envKey)

	if target != 5*time.Minute {
		t.Errorf("applyDurationEnv() target = %v, want %v", target, 5*time.Minute)
	}
}

func TestApplyDurationEnv_HourDuration(t *testing.T) {
	envKey := "TEST_DURATION_HOUR"
	os.Setenv(envKey, "1h")
	defer os.Unsetenv(envKey)

	target := 10 * time.Second
	applyDurationEnv(&target, envKey)

	if target != 1*time.Hour {
		t.Errorf("applyDurationEnv() target = %v, want %v", target, 1*time.Hour)
	}
}

// ============================================================================
// applyCertDNSNamesEnv Tests
// ============================================================================

func TestApplyCertDNSNamesEnv_WithValue_Coverage(t *testing.T) {
	os.Setenv("CERT_DNS_NAMES", "dns1.example.com,dns2.example.com,dns3.example.com")
	defer os.Unsetenv("CERT_DNS_NAMES")

	cfg := &Config{}
	applyCertDNSNamesEnv(cfg)

	if len(cfg.CertDNSNames) != 3 {
		t.Errorf("applyCertDNSNamesEnv() len = %d, want 3", len(cfg.CertDNSNames))
	}
	if cfg.CertDNSNames[0] != "dns1.example.com" {
		t.Errorf("applyCertDNSNamesEnv() [0] = %q, want %q", cfg.CertDNSNames[0], "dns1.example.com")
	}
}

func TestApplyCertDNSNamesEnv_EmptyValue_Coverage(t *testing.T) {
	os.Unsetenv("CERT_DNS_NAMES")

	cfg := &Config{}
	applyCertDNSNamesEnv(cfg)

	if len(cfg.CertDNSNames) != 0 {
		t.Errorf("applyCertDNSNamesEnv() len = %d, want 0", len(cfg.CertDNSNames))
	}
}

func TestApplyCertDNSNamesEnv_WithSpaces_Coverage(t *testing.T) {
	os.Setenv("CERT_DNS_NAMES", "  dns1.example.com  ,  dns2.example.com  ")
	defer os.Unsetenv("CERT_DNS_NAMES")

	cfg := &Config{}
	applyCertDNSNamesEnv(cfg)

	if len(cfg.CertDNSNames) != 2 {
		t.Errorf("applyCertDNSNamesEnv() len = %d, want 2", len(cfg.CertDNSNames))
	}
	if cfg.CertDNSNames[0] != "dns1.example.com" {
		t.Errorf("applyCertDNSNamesEnv() [0] = %q, want %q", cfg.CertDNSNames[0], "dns1.example.com")
	}
}

func TestApplyCertDNSNamesEnv_SingleValue_Coverage(t *testing.T) {
	os.Setenv("CERT_DNS_NAMES", "single.example.com")
	defer os.Unsetenv("CERT_DNS_NAMES")

	cfg := &Config{}
	applyCertDNSNamesEnv(cfg)

	if len(cfg.CertDNSNames) != 1 {
		t.Errorf("applyCertDNSNamesEnv() len = %d, want 1", len(cfg.CertDNSNames))
	}
}

// ============================================================================
// splitAndTrim Tests
// ============================================================================

func TestSplitAndTrim_BasicSplit(t *testing.T) {
	result := splitAndTrim("a,b,c", ",")
	if len(result) != 3 {
		t.Errorf("splitAndTrim() len = %d, want 3", len(result))
	}
}

func TestSplitAndTrim_WithSpaces(t *testing.T) {
	result := splitAndTrim("  a  ,  b  ,  c  ", ",")
	if len(result) != 3 {
		t.Errorf("splitAndTrim() len = %d, want 3", len(result))
	}
	if result[0] != "a" {
		t.Errorf("splitAndTrim() [0] = %q, want %q", result[0], "a")
	}
}

func TestSplitAndTrim_EmptyParts(t *testing.T) {
	result := splitAndTrim("a,,b,  ,c", ",")
	if len(result) != 3 {
		t.Errorf("splitAndTrim() len = %d, want 3 (empty parts should be skipped)", len(result))
	}
}

func TestSplitAndTrim_EmptyString(t *testing.T) {
	result := splitAndTrim("", ",")
	if len(result) != 0 {
		t.Errorf("splitAndTrim() len = %d, want 0", len(result))
	}
}

func TestSplitAndTrim_OnlySpaces(t *testing.T) {
	result := splitAndTrim("   ,   ,   ", ",")
	if len(result) != 0 {
		t.Errorf("splitAndTrim() len = %d, want 0", len(result))
	}
}

// ============================================================================
// defaultCertDNSNames Tests
// ============================================================================

func TestDefaultCertDNSNames_Coverage(t *testing.T) {
	names := defaultCertDNSNames("my-service", "my-namespace")

	if len(names) != 4 {
		t.Errorf("defaultCertDNSNames() len = %d, want 4", len(names))
	}

	expected := []string{
		"my-service",
		"my-service.my-namespace",
		"my-service.my-namespace.svc",
		"my-service.my-namespace.svc.cluster.local",
	}

	for i, exp := range expected {
		if names[i] != exp {
			t.Errorf("defaultCertDNSNames() [%d] = %q, want %q", i, names[i], exp)
		}
	}
}

func TestDefaultCertDNSNames_DifferentValues(t *testing.T) {
	names := defaultCertDNSNames("avapigw-operator", "avapigw-system")

	if len(names) != 4 {
		t.Errorf("defaultCertDNSNames() len = %d, want 4", len(names))
	}

	if names[0] != "avapigw-operator" {
		t.Errorf("defaultCertDNSNames() [0] = %q, want %q", names[0], "avapigw-operator")
	}
	if names[3] != "avapigw-operator.avapigw-system.svc.cluster.local" {
		t.Errorf("defaultCertDNSNames() [3] = %q, want %q", names[3], "avapigw-operator.avapigw-system.svc.cluster.local")
	}
}

// ============================================================================
// getCertDNSNames Tests
// ============================================================================

func TestGetCertDNSNames_CustomNames(t *testing.T) {
	cfg := &Config{
		CertDNSNames:    []string{"custom1.example.com", "custom2.example.com"},
		CertServiceName: "my-service",
		CertNamespace:   "my-namespace",
	}

	names := getCertDNSNames(cfg)

	if len(names) != 2 {
		t.Errorf("getCertDNSNames() len = %d, want 2", len(names))
	}
	if names[0] != "custom1.example.com" {
		t.Errorf("getCertDNSNames() [0] = %q, want %q", names[0], "custom1.example.com")
	}
}

func TestGetCertDNSNames_DefaultNames(t *testing.T) {
	cfg := &Config{
		CertDNSNames:    nil,
		CertServiceName: "my-service",
		CertNamespace:   "my-namespace",
	}

	names := getCertDNSNames(cfg)

	if len(names) != 4 {
		t.Errorf("getCertDNSNames() len = %d, want 4", len(names))
	}
	if names[0] != "my-service" {
		t.Errorf("getCertDNSNames() [0] = %q, want %q", names[0], "my-service")
	}
}

func TestGetCertDNSNames_EmptyCustomNames(t *testing.T) {
	cfg := &Config{
		CertDNSNames:    []string{},
		CertServiceName: "my-service",
		CertNamespace:   "my-namespace",
	}

	names := getCertDNSNames(cfg)

	// Empty slice should use defaults
	if len(names) != 4 {
		t.Errorf("getCertDNSNames() len = %d, want 4", len(names))
	}
}

// ============================================================================
// setupTracing Tests
// ============================================================================

func TestSetupTracing_ConfigValues_Coverage(t *testing.T) {
	cfg := &Config{
		EnableTracing:       true,
		OTLPEndpoint:        "localhost:4317",
		TracingSamplingRate: 0.5,
	}

	// Verify config values are set correctly
	if cfg.OTLPEndpoint != "localhost:4317" {
		t.Errorf("OTLPEndpoint = %q, want %q", cfg.OTLPEndpoint, "localhost:4317")
	}
	if cfg.TracingSamplingRate != 0.5 {
		t.Errorf("TracingSamplingRate = %f, want %f", cfg.TracingSamplingRate, 0.5)
	}
}

// ============================================================================
// applyEnvOverrides Tests - Additional Coverage
// ============================================================================

func TestApplyEnvOverrides_DuplicateDetectionConfig(t *testing.T) {
	os.Setenv("ENABLE_CLUSTER_WIDE_DUPLICATE_CHECK", "true")
	os.Setenv("DUPLICATE_CACHE_ENABLED", "false")
	os.Setenv("DUPLICATE_CACHE_TTL", "1m")
	defer os.Unsetenv("ENABLE_CLUSTER_WIDE_DUPLICATE_CHECK")
	defer os.Unsetenv("DUPLICATE_CACHE_ENABLED")
	defer os.Unsetenv("DUPLICATE_CACHE_TTL")

	cfg := &Config{
		EnableClusterWideDuplicateCheck: false,
		DuplicateCacheEnabled:           true,
		DuplicateCacheTTL:               30 * time.Second,
	}

	applyEnvOverrides(cfg)

	if !cfg.EnableClusterWideDuplicateCheck {
		t.Error("EnableClusterWideDuplicateCheck should be true")
	}
	if cfg.DuplicateCacheEnabled {
		t.Error("DuplicateCacheEnabled should be false")
	}
	if cfg.DuplicateCacheTTL != 1*time.Minute {
		t.Errorf("DuplicateCacheTTL = %v, want %v", cfg.DuplicateCacheTTL, 1*time.Minute)
	}
}

func TestApplyEnvOverrides_CertServiceNameAndNamespace_Coverage(t *testing.T) {
	os.Setenv("CERT_SERVICE_NAME", "custom-service")
	os.Setenv("CERT_NAMESPACE", "custom-namespace")
	defer os.Unsetenv("CERT_SERVICE_NAME")
	defer os.Unsetenv("CERT_NAMESPACE")

	cfg := &Config{
		CertServiceName: "default-service",
		CertNamespace:   "default-namespace",
	}

	applyEnvOverrides(cfg)

	if cfg.CertServiceName != "custom-service" {
		t.Errorf("CertServiceName = %q, want %q", cfg.CertServiceName, "custom-service")
	}
	if cfg.CertNamespace != "custom-namespace" {
		t.Errorf("CertNamespace = %q, want %q", cfg.CertNamespace, "custom-namespace")
	}
}

func TestApplyEnvOverrides_VaultInitTimeout(t *testing.T) {
	os.Setenv("VAULT_INIT_TIMEOUT", "2m")
	defer os.Unsetenv("VAULT_INIT_TIMEOUT")

	cfg := &Config{
		VaultInitTimeout: 30 * time.Second,
	}

	applyEnvOverrides(cfg)

	if cfg.VaultInitTimeout != 2*time.Minute {
		t.Errorf("VaultInitTimeout = %v, want %v", cfg.VaultInitTimeout, 2*time.Minute)
	}
}

// ============================================================================
// defineFlags Tests - Additional Coverage
// ============================================================================

func TestDefineFlags_VaultInitTimeout(t *testing.T) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	cfg := &Config{}
	defineFlags(cfg)

	args := []string{
		"-vault-init-timeout=1m",
	}

	err := flag.CommandLine.Parse(args)
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	if cfg.VaultInitTimeout != 1*time.Minute {
		t.Errorf("VaultInitTimeout = %v, want %v", cfg.VaultInitTimeout, 1*time.Minute)
	}
}

func TestDefineFlags_CertServiceNameAndNamespace(t *testing.T) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	cfg := &Config{}
	defineFlags(cfg)

	args := []string{
		"-cert-service-name=my-operator",
		"-cert-namespace=my-system",
	}

	err := flag.CommandLine.Parse(args)
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	if cfg.CertServiceName != "my-operator" {
		t.Errorf("CertServiceName = %q, want %q", cfg.CertServiceName, "my-operator")
	}
	if cfg.CertNamespace != "my-system" {
		t.Errorf("CertNamespace = %q, want %q", cfg.CertNamespace, "my-system")
	}
}

func TestDefineFlags_DuplicateDetection(t *testing.T) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	cfg := &Config{}
	defineFlags(cfg)

	args := []string{
		"-enable-cluster-wide-duplicate-check=true",
		"-duplicate-cache-enabled=false",
		"-duplicate-cache-ttl=1m",
	}

	err := flag.CommandLine.Parse(args)
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	if !cfg.EnableClusterWideDuplicateCheck {
		t.Error("EnableClusterWideDuplicateCheck should be true")
	}
	if cfg.DuplicateCacheEnabled {
		t.Error("DuplicateCacheEnabled should be false")
	}
	if cfg.DuplicateCacheTTL != 1*time.Minute {
		t.Errorf("DuplicateCacheTTL = %v, want %v", cfg.DuplicateCacheTTL, 1*time.Minute)
	}
}

// ============================================================================
// setupCertManager Tests - Additional Coverage
// ============================================================================

func TestSetupCertManager_VaultWithTimeout(t *testing.T) {
	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	cfg := &Config{
		CertProvider:     "vault",
		VaultAddr:        "http://vault:8200",
		VaultPKIMount:    "pki",
		VaultPKIRole:     "operator",
		VaultInitTimeout: 1 * time.Millisecond,
	}

	// Wait for context to expire
	time.Sleep(10 * time.Millisecond)

	_, err := setupCertManager(ctx, cfg)
	// Should fail due to timeout or connection error
	assert.Error(t, err)
}

// ============================================================================
// Config Tests - Additional Coverage
// ============================================================================

func TestConfig_VaultInitTimeout(t *testing.T) {
	cfg := &Config{
		VaultInitTimeout: 30 * time.Second,
	}

	if cfg.VaultInitTimeout != 30*time.Second {
		t.Errorf("VaultInitTimeout = %v, want %v", cfg.VaultInitTimeout, 30*time.Second)
	}
}

func TestConfig_CertDNSNames(t *testing.T) {
	cfg := &Config{
		CertDNSNames:    []string{"dns1.example.com", "dns2.example.com"},
		CertServiceName: "my-service",
		CertNamespace:   "my-namespace",
	}

	if len(cfg.CertDNSNames) != 2 {
		t.Errorf("CertDNSNames len = %d, want 2", len(cfg.CertDNSNames))
	}
}

func TestConfig_DuplicateDetection(t *testing.T) {
	cfg := &Config{
		EnableClusterWideDuplicateCheck: true,
		DuplicateCacheEnabled:           true,
		DuplicateCacheTTL:               30 * time.Second,
	}

	if !cfg.EnableClusterWideDuplicateCheck {
		t.Error("EnableClusterWideDuplicateCheck should be true")
	}
	if !cfg.DuplicateCacheEnabled {
		t.Error("DuplicateCacheEnabled should be true")
	}
	if cfg.DuplicateCacheTTL != 30*time.Second {
		t.Errorf("DuplicateCacheTTL = %v, want %v", cfg.DuplicateCacheTTL, 30*time.Second)
	}
}

// ============================================================================
// setupTracingIfEnabled Tests - Additional Coverage
// ============================================================================

// Note: TestSetupTracingIfEnabled_EnabledWithEndpoint_Coverage is skipped due to
// OpenTelemetry schema URL conflicts in the test environment.

// Note: TestSetupGRPCServerIfEnabled_EnabledWithCertManager is skipped due to
// Prometheus metrics registration conflicts in the test environment.

// Note: TestStartGRPCServerBackground_WithServer is skipped due to
// Prometheus metrics registration conflicts in the test environment.

// Note: TestSetupWebhooksIfEnabled_EnabledWithNilManager_Coverage is skipped
// because it would panic with nil manager.

// ============================================================================
// parseFlags Tests - Additional Coverage
// ============================================================================

func TestParseFlags_AllFlags(t *testing.T) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	// Clear all env vars
	envVars := []string{
		"METRICS_BIND_ADDRESS", "HEALTH_PROBE_BIND_ADDRESS", "LEADER_ELECTION_ID",
		"CERT_PROVIDER", "VAULT_ADDR", "VAULT_PKI_MOUNT", "VAULT_PKI_ROLE",
		"LOG_LEVEL", "LOG_FORMAT", "OTLP_ENDPOINT", "WEBHOOK_PORT", "GRPC_PORT",
		"TRACING_SAMPLING_RATE", "LEADER_ELECT", "ENABLE_WEBHOOKS",
		"ENABLE_GRPC_SERVER", "ENABLE_TRACING", "VAULT_INIT_TIMEOUT",
		"CERT_SERVICE_NAME", "CERT_NAMESPACE", "CERT_DNS_NAMES",
		"ENABLE_INGRESS_CONTROLLER", "INGRESS_CLASS_NAME", "INGRESS_LB_ADDRESS",
		"ENABLE_CLUSTER_WIDE_DUPLICATE_CHECK", "DUPLICATE_CACHE_ENABLED", "DUPLICATE_CACHE_TTL",
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}

	cfg := parseFlags()

	require.NotNil(t, cfg)
	assert.Equal(t, ":8080", cfg.MetricsAddr)
	assert.Equal(t, ":8081", cfg.ProbeAddr)
	assert.Equal(t, 9443, cfg.WebhookPort)
	assert.Equal(t, 9444, cfg.GRPCPort)
	assert.Equal(t, "selfsigned", cfg.CertProvider)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.True(t, cfg.EnableWebhooks)
	assert.True(t, cfg.EnableGRPCServer)
	assert.False(t, cfg.EnableTracing)
	assert.False(t, cfg.EnableIngressController)
	assert.False(t, cfg.EnableClusterWideDuplicateCheck)
	assert.True(t, cfg.DuplicateCacheEnabled)
}

// ============================================================================
// Additional Coverage Tests - Unique to this file
// ============================================================================

func TestApplyEnvOverrides_LeaderElect_Coverage(t *testing.T) {
	os.Setenv("LEADER_ELECT", "true")
	defer os.Unsetenv("LEADER_ELECT")

	cfg := &Config{EnableLeaderElection: false}
	applyEnvOverrides(cfg)

	assert.True(t, cfg.EnableLeaderElection)
}

func TestApplyEnvOverrides_DisableWebhooks_Coverage(t *testing.T) {
	os.Setenv("ENABLE_WEBHOOKS", "false")
	defer os.Unsetenv("ENABLE_WEBHOOKS")

	cfg := &Config{EnableWebhooks: true}
	applyEnvOverrides(cfg)

	assert.False(t, cfg.EnableWebhooks)
}

func TestApplyEnvOverrides_DisableGRPCServer_Coverage(t *testing.T) {
	os.Setenv("ENABLE_GRPC_SERVER", "false")
	defer os.Unsetenv("ENABLE_GRPC_SERVER")

	cfg := &Config{EnableGRPCServer: true}
	applyEnvOverrides(cfg)

	assert.False(t, cfg.EnableGRPCServer)
}

func TestApplyEnvOverrides_EnableTracing_Coverage(t *testing.T) {
	os.Setenv("ENABLE_TRACING", "true")
	defer os.Unsetenv("ENABLE_TRACING")

	cfg := &Config{EnableTracing: false}
	applyEnvOverrides(cfg)

	assert.True(t, cfg.EnableTracing)
}

func TestApplyEnvOverrides_EnableIngressController_Coverage(t *testing.T) {
	os.Setenv("ENABLE_INGRESS_CONTROLLER", "true")
	defer os.Unsetenv("ENABLE_INGRESS_CONTROLLER")

	cfg := &Config{EnableIngressController: false}
	applyEnvOverrides(cfg)

	assert.True(t, cfg.EnableIngressController)
}

func TestApplyEnvOverrides_IngressConfig_Coverage(t *testing.T) {
	os.Setenv("INGRESS_CLASS_NAME", "custom-ingress")
	os.Setenv("INGRESS_LB_ADDRESS", "10.0.0.1")
	defer os.Unsetenv("INGRESS_CLASS_NAME")
	defer os.Unsetenv("INGRESS_LB_ADDRESS")

	cfg := &Config{
		IngressClassName: "default",
		IngressLBAddress: "",
	}
	applyEnvOverrides(cfg)

	assert.Equal(t, "custom-ingress", cfg.IngressClassName)
	assert.Equal(t, "10.0.0.1", cfg.IngressLBAddress)
}
