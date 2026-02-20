// Package main provides iteration 3 unit tests for coverage improvement.
// Target: cmd/gateway coverage from 83.0% to >85%.
package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ============================================================
// mockVaultClient: implements vault.Client for shutdown tests
// ============================================================

// mockVaultClientForShutdown implements vault.Client for testing
// waitForShutdown vault client close paths.
type mockVaultClientForShutdown struct {
	closeErr error
}

func (m *mockVaultClientForShutdown) IsEnabled() bool                      { return true }
func (m *mockVaultClientForShutdown) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForShutdown) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForShutdown) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForShutdown) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClientForShutdown) KV() vault.KVClient           { return nil }
func (m *mockVaultClientForShutdown) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForShutdown) Close() error                 { return m.closeErr }

// ============================================================
// waitForShutdown: vault client close (success path)
// Covers shutdown.go lines 62-64 (2 stmts)
// ============================================================

// TestWaitForShutdown_VaultClientCloseSuccess tests waitForShutdown when
// vault client is present and Close() succeeds.
// Not parallel — sends SIGINT to process.
func TestWaitForShutdown_VaultClientCloseSuccess(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0,
					Protocol: config.ProtocolHTTP,
				},
			},
		},
	}

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithShutdownTimeout(1*time.Second),
	)
	require.NoError(t, err)

	err = gw.Start(context.Background())
	require.NoError(t, err)

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: backendReg,
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
		metrics:         observability.NewMetrics("test"),
		tracer:          tracer,
		config:          cfg,
		auditLogger:     audit.NewNoopLogger(),
		vaultClient:     &mockVaultClientForShutdown{closeErr: nil}, // Success path
	}

	done := make(chan struct{})
	go func() {
		waitForShutdown(app, nil, logger)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("waitForShutdown did not complete in time")
	}
}

// ============================================================
// waitForShutdown: vault client close (error path)
// Covers shutdown.go lines 64-66 (1 stmt)
// ============================================================

// TestWaitForShutdown_VaultClientCloseError tests waitForShutdown when
// vault client Close() returns an error.
// Not parallel — sends SIGINT to process.
func TestWaitForShutdown_VaultClientCloseError(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0,
					Protocol: config.ProtocolHTTP,
				},
			},
		},
	}

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithShutdownTimeout(1*time.Second),
	)
	require.NoError(t, err)

	err = gw.Start(context.Background())
	require.NoError(t, err)

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: backendReg,
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
		metrics:         observability.NewMetrics("test"),
		tracer:          tracer,
		config:          cfg,
		auditLogger:     audit.NewNoopLogger(),
		vaultClient:     &mockVaultClientForShutdown{closeErr: fmt.Errorf("mock vault close error")},
	}

	done := make(chan struct{})
	go func() {
		waitForShutdown(app, nil, logger)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success - vault close error was logged but didn't prevent shutdown
	case <-time.After(10 * time.Second):
		t.Fatal("waitForShutdown did not complete in time")
	}
}

// ============================================================
// initVaultClient: TLS config path (fast failure)
// Covers vault.go lines 60-68 (1 stmt)
// ============================================================

// TestInitVaultClient_WithTLSConfig tests initVaultClient when TLS env vars
// are set. The client creation still fails fast because VAULT_ADDR is empty,
// but the TLS config building code path is exercised.
// Not parallel — modifies package-level exitFunc and environment variables.
func TestInitVaultClient_WithTLSConfig(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Save and restore env vars
	envVars := []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AUTH_METHOD",
		"VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT",
		"VAULT_CLIENT_KEY", "VAULT_SKIP_VERIFY",
	}
	origValues := make(map[string]string)
	for _, key := range envVars {
		origValues[key] = os.Getenv(key)
	}
	defer func() {
		for _, key := range envVars {
			if origValues[key] != "" {
				os.Setenv(key, origValues[key])
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	// Set TLS env vars to trigger TLS config building
	os.Setenv("VAULT_ADDR", "") // Empty address causes fast failure
	os.Setenv("VAULT_TOKEN", "test-token")
	os.Setenv("VAULT_SKIP_VERIFY", "true") // Triggers TLS config block
	os.Unsetenv("VAULT_AUTH_METHOD")
	os.Unsetenv("VAULT_CACERT")
	os.Unsetenv("VAULT_CAPATH")
	os.Unsetenv("VAULT_CLIENT_CERT")
	os.Unsetenv("VAULT_CLIENT_KEY")

	logger := observability.NopLogger()

	client := initVaultClient(logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================
// initVaultClient: Kubernetes auth config path (fast failure)
// Covers vault.go lines 71-77 (1 stmt)
// ============================================================

// TestInitVaultClient_WithKubernetesAuth tests initVaultClient when
// VAULT_AUTH_METHOD=kubernetes. The client creation still fails fast
// because VAULT_ADDR is empty, but the Kubernetes config building
// code path is exercised.
// Not parallel — modifies package-level exitFunc and environment variables.
func TestInitVaultClient_WithKubernetesAuth(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Save and restore env vars
	envVars := []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AUTH_METHOD",
		"VAULT_K8S_ROLE", "VAULT_K8S_MOUNT_PATH", "VAULT_K8S_TOKEN_PATH",
		"VAULT_SKIP_VERIFY",
	}
	origValues := make(map[string]string)
	for _, key := range envVars {
		origValues[key] = os.Getenv(key)
	}
	defer func() {
		for _, key := range envVars {
			if origValues[key] != "" {
				os.Setenv(key, origValues[key])
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	os.Setenv("VAULT_ADDR", "")                  // Empty address causes fast failure
	os.Setenv("VAULT_AUTH_METHOD", "kubernetes") // Triggers Kubernetes config block
	os.Setenv("VAULT_K8S_ROLE", "test-role")
	os.Unsetenv("VAULT_K8S_MOUNT_PATH")
	os.Unsetenv("VAULT_K8S_TOKEN_PATH")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_SKIP_VERIFY")

	logger := observability.NopLogger()

	client := initVaultClient(logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================
// initVaultClient: AppRole auth config path (fast failure)
// Covers vault.go lines 80-86 (1 stmt)
// ============================================================

// TestInitVaultClient_WithAppRoleAuth tests initVaultClient when
// VAULT_AUTH_METHOD=approle. The client creation still fails fast
// because VAULT_ADDR is empty, but the AppRole config building
// code path is exercised.
// Not parallel — modifies package-level exitFunc and environment variables.
func TestInitVaultClient_WithAppRoleAuth(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Save and restore env vars
	envVars := []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AUTH_METHOD",
		"VAULT_APPROLE_ROLE_ID", "VAULT_APPROLE_SECRET_ID",
		"VAULT_APPROLE_MOUNT_PATH", "VAULT_SKIP_VERIFY",
	}
	origValues := make(map[string]string)
	for _, key := range envVars {
		origValues[key] = os.Getenv(key)
	}
	defer func() {
		for _, key := range envVars {
			if origValues[key] != "" {
				os.Setenv(key, origValues[key])
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	os.Setenv("VAULT_ADDR", "")               // Empty address causes fast failure
	os.Setenv("VAULT_AUTH_METHOD", "approle") // Triggers AppRole config block
	os.Setenv("VAULT_APPROLE_ROLE_ID", "test-role-id")
	os.Setenv("VAULT_APPROLE_SECRET_ID", "test-secret-id")
	os.Unsetenv("VAULT_APPROLE_MOUNT_PATH")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_SKIP_VERIFY")

	logger := observability.NopLogger()

	client := initVaultClient(logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================
// initVaultClient: combined TLS + Kubernetes auth (fast failure)
// Covers vault.go lines 60-68 AND 71-77 simultaneously
// ============================================================

// TestInitVaultClient_WithTLSAndKubernetesAuth tests initVaultClient when
// both TLS env vars and VAULT_AUTH_METHOD=kubernetes are set.
// Not parallel — modifies package-level exitFunc and environment variables.
func TestInitVaultClient_WithTLSAndKubernetesAuth(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Save and restore env vars
	envVars := []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AUTH_METHOD",
		"VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT",
		"VAULT_CLIENT_KEY", "VAULT_SKIP_VERIFY",
		"VAULT_K8S_ROLE", "VAULT_K8S_MOUNT_PATH", "VAULT_K8S_TOKEN_PATH",
	}
	origValues := make(map[string]string)
	for _, key := range envVars {
		origValues[key] = os.Getenv(key)
	}
	defer func() {
		for _, key := range envVars {
			if origValues[key] != "" {
				os.Setenv(key, origValues[key])
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	os.Setenv("VAULT_ADDR", "") // Empty address causes fast failure
	os.Setenv("VAULT_AUTH_METHOD", "kubernetes")
	os.Setenv("VAULT_CACERT", "/tmp/ca.pem") // Triggers TLS config block
	os.Setenv("VAULT_K8S_ROLE", "test-role")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_CAPATH")
	os.Unsetenv("VAULT_CLIENT_CERT")
	os.Unsetenv("VAULT_CLIENT_KEY")
	os.Unsetenv("VAULT_SKIP_VERIFY")
	os.Unsetenv("VAULT_K8S_MOUNT_PATH")
	os.Unsetenv("VAULT_K8S_TOKEN_PATH")

	logger := observability.NopLogger()

	client := initVaultClient(logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================
// initVaultClient: combined TLS + AppRole auth (fast failure)
// Covers vault.go lines 60-68 AND 80-86 simultaneously
// ============================================================

// TestInitVaultClient_WithTLSAndAppRoleAuth tests initVaultClient when
// both TLS env vars and VAULT_AUTH_METHOD=approle are set.
// Not parallel — modifies package-level exitFunc and environment variables.
func TestInitVaultClient_WithTLSAndAppRoleAuth(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Save and restore env vars
	envVars := []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AUTH_METHOD",
		"VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT",
		"VAULT_CLIENT_KEY", "VAULT_SKIP_VERIFY",
		"VAULT_APPROLE_ROLE_ID", "VAULT_APPROLE_SECRET_ID",
		"VAULT_APPROLE_MOUNT_PATH",
	}
	origValues := make(map[string]string)
	for _, key := range envVars {
		origValues[key] = os.Getenv(key)
	}
	defer func() {
		for _, key := range envVars {
			if origValues[key] != "" {
				os.Setenv(key, origValues[key])
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	os.Setenv("VAULT_ADDR", "") // Empty address causes fast failure
	os.Setenv("VAULT_AUTH_METHOD", "approle")
	os.Setenv("VAULT_CLIENT_CERT", "/tmp/client.pem") // Triggers TLS config block
	os.Setenv("VAULT_CLIENT_KEY", "/tmp/client-key.pem")
	os.Setenv("VAULT_APPROLE_ROLE_ID", "test-role-id")
	os.Setenv("VAULT_APPROLE_SECRET_ID", "test-secret-id")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_CACERT")
	os.Unsetenv("VAULT_CAPATH")
	os.Unsetenv("VAULT_SKIP_VERIFY")
	os.Unsetenv("VAULT_APPROLE_MOUNT_PATH")

	logger := observability.NopLogger()

	client := initVaultClient(logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================
// initAuditLogger: error path when audit.NewLogger fails
// Covers config_loader.go lines 94-97 (2 stmts)
// ============================================================

// TestInitAuditLogger_CreationError tests initAuditLogger when
// audit.NewLogger returns an error (invalid file output path).
// The function should fall back to a noop logger.
//
// Note: audit.NewLogger internally calls NewMetrics("gateway") which uses
// promauto to register Prometheus metrics. If metrics are already registered
// (from TestInitAuditLogger/enabled_with_all_options), promauto panics.
// We use recover to handle this gracefully and skip if needed.
func TestInitAuditLogger_CreationError(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Audit: &config.AuditConfig{
				Enabled: true,
				Output:  "/nonexistent/deeply/nested/path/that/cannot/exist/audit.log",
				Format:  "json",
				Level:   "info",
			},
		},
	}

	// Use a fresh Prometheus registry to avoid duplicate metric registration panics
	reg := prometheus.NewRegistry()
	auditLogger := initAuditLogger(cfg, logger, audit.WithLoggerRegisterer(reg))

	// Error path exercised: audit.NewLogger failed, noop logger returned
	assert.NotNil(t, auditLogger, "should return noop logger on creation error")
	assert.NoError(t, auditLogger.Close())
}
