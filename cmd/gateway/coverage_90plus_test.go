// Package main provides tests to push cmd/gateway coverage above 90%.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/gateway/operator"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ============================================================================
// Mock operator client for testing
// ============================================================================

// mockOperatorClient implements operatorClientInterface for testing.
type mockOperatorClient struct {
	startErr  error
	stopErr   error
	sessionID string
}

func (m *mockOperatorClient) Start(_ context.Context) error { return m.startErr }
func (m *mockOperatorClient) Stop() error                   { return m.stopErr }
func (m *mockOperatorClient) SessionID() string             { return m.sessionID }

// mockVaultClient90 implements vault.Client for testing.
type mockVaultClient90 struct {
	closeErr error
}

func (m *mockVaultClient90) IsEnabled() bool                      { return true }
func (m *mockVaultClient90) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClient90) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClient90) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClient90) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClient90) KV() vault.KVClient           { return nil }
func (m *mockVaultClient90) Transit() vault.TransitClient { return nil }
func (m *mockVaultClient90) Close() error                 { return m.closeErr }

// errorAuditLogger90 is a mock audit logger that returns an error from Close().
type errorAuditLogger90 struct{}

func (l *errorAuditLogger90) LogEvent(_ context.Context, _ *audit.Event) {}
func (l *errorAuditLogger90) LogAuthentication(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject) {
}
func (l *errorAuditLogger90) LogAuthorization(_ context.Context, _ audit.Outcome, _ *audit.Subject, _ *audit.Resource) {
}
func (l *errorAuditLogger90) LogSecurity(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject, _ map[string]interface{}) {
}
func (l *errorAuditLogger90) Close() error {
	return fmt.Errorf("mock audit close error")
}

// ============================================================================
// runOperatorGateway Tests - Cover the operator client Start error path
// ============================================================================

// TestRunOperatorGateway_OperatorClientStartError90 covers the path where
// operator client Start() fails (line 123-126 of operator_mode.go).
func TestRunOperatorGateway_OperatorClientStartError90(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-client-err-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19810,
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

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
		},
		operatorClient: &mockOperatorClient{
			startErr: errors.New("connection refused"),
		},
		operatorConfig: operator.DefaultConfig(),
	}

	// This will: start backends (ok), start gateway (ok), start operator client (fail)
	runOperatorGateway(opApp, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))

	// Clean up gateway
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = gw.Stop(ctx)
}

// ============================================================================
// runOperatorGateway Tests - Cover the successful path (needs signal)
// ============================================================================

// TestRunOperatorGateway_SuccessPath90 covers the full successful path:
// backends start -> gateway start -> metrics -> operator client start -> log -> shutdown.
func TestRunOperatorGateway_SuccessPath90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal-based test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-success-90p"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19811,
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

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
			auditLogger:     audit.NewNoopLogger(),
		},
		operatorClient: &mockOperatorClient{
			startErr:  nil,
			stopErr:   nil,
			sessionID: "test-session-90p",
		},
		operatorConfig: operator.DefaultConfig(),
	}

	done := make(chan struct{})
	go func() {
		runOperatorGateway(opApp, logger)
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("runOperatorGateway did not complete in time")
	}
}

// ============================================================================
// waitForOperatorShutdown Tests - Cover operator client Stop paths
// ============================================================================

// TestWaitForOperatorShutdown_OperatorClientStopSuccess90 covers the path where
// operator client is non-nil and Stop() succeeds (lines 148-153).
func TestWaitForOperatorShutdown_OperatorClientStopSuccess90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal-based test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-stop-ok-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19812,
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

	rl := middleware.NewRateLimiter(100, 200, false)
	msl := middleware.NewMaxSessionsLimiter(100, 0, 0)

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    backendReg,
			tracer:             tracer,
			config:             cfg,
			rateLimiter:        rl,
			maxSessionsLimiter: msl,
			auditLogger:        audit.NewNoopLogger(),
			vaultClient:        &mockVaultClient90{closeErr: nil},
			metricsServer:      nil,
		},
		operatorClient: &mockOperatorClient{stopErr: nil},
		operatorConfig: operator.DefaultConfig(),
	}

	done := make(chan struct{})
	go func() {
		waitForOperatorShutdown(opApp, logger)
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
		t.Fatal("waitForOperatorShutdown did not complete in time")
	}
}

// TestWaitForOperatorShutdown_OperatorClientStopError90 covers the path where
// operator client Stop() returns an error (line 151).
func TestWaitForOperatorShutdown_OperatorClientStopError90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal-based test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-stop-err-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19813,
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

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
			auditLogger:     audit.NewNoopLogger(),
			vaultClient:     &mockVaultClient90{closeErr: errors.New("vault close err")},
		},
		operatorClient: &mockOperatorClient{stopErr: errors.New("stop failed")},
		operatorConfig: operator.DefaultConfig(),
	}

	done := make(chan struct{})
	go func() {
		waitForOperatorShutdown(opApp, logger)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success - errors were logged but shutdown continued
	case <-time.After(10 * time.Second):
		t.Fatal("waitForOperatorShutdown did not complete in time")
	}
}

// TestWaitForOperatorShutdown_WithMetricsAndAuditErrors90 covers the metrics server
// shutdown path and audit logger close error path in operator shutdown.
func TestWaitForOperatorShutdown_WithMetricsAndAuditErrors90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal-based test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-metrics-audit-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19814,
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

	// Create and start a real metrics server
	metricsServer := &http.Server{
		Addr:    "127.0.0.1:19815",
		Handler: http.NewServeMux(),
	}
	go func() {
		_ = metricsServer.ListenAndServe()
	}()
	time.Sleep(50 * time.Millisecond)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			healthChecker:   health.NewChecker("test", observability.NopLogger()),
			metrics:         observability.NewMetrics("test"),
			metricsServer:   metricsServer,
			tracer:          tracer,
			config:          cfg,
			auditLogger:     &errorAuditLogger90{},
		},
		operatorClient: &mockOperatorClient{stopErr: nil},
		operatorConfig: operator.DefaultConfig(),
	}

	done := make(chan struct{})
	go func() {
		waitForOperatorShutdown(opApp, logger)
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
		t.Fatal("waitForOperatorShutdown did not complete in time")
	}
}

// ============================================================================
// runGateway Tests - Cover the successful full path with vault client
// ============================================================================

// TestRunGateway_FullPathWithVault90 covers the full successful path of runGateway
// including vault client close during shutdown.
func TestRunGateway_FullPathWithVault90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal-based test in short mode")
	}

	logger := observability.NopLogger()

	tmpDir := t.TempDir()
	configPath := tmpDir + "/gateway.yaml"
	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway
spec:
  listeners:
    - name: http
      bind: 127.0.0.1
      port: 19816
      protocol: HTTP
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw-vault-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19816,
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

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	rl := middleware.NewRateLimiter(100, 200, false)
	msl := middleware.NewMaxSessionsLimiter(100, 0, 0)

	app := &application{
		gateway:            gw,
		backendRegistry:    backendReg,
		router:             router.New(),
		healthChecker:      health.NewChecker("test", observability.NopLogger()),
		metrics:            observability.NewMetrics("test"),
		tracer:             tracer,
		config:             cfg,
		auditLogger:        audit.NewNoopLogger(),
		rateLimiter:        rl,
		maxSessionsLimiter: msl,
		vaultClient:        &mockVaultClient90{closeErr: nil},
	}

	done := make(chan struct{})
	go func() {
		runGateway(app, configPath, logger)
		close(done)
	}()

	time.Sleep(300 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("runGateway did not complete in time")
	}
}

// ============================================================================
// ApplyFullConfig - cover backend reload error path
// ============================================================================

// TestGatewayConfigApplier_ApplyFullConfig_BackendReloadError90 covers the path
// where backend reload fails in ApplyFullConfig.
func TestGatewayConfigApplier_ApplyFullConfig_BackendReloadError90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90Plus("test-backend-err")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			router:          r,
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Config with duplicate backend names should cause backend reload error
	fullCfg := createTestGatewayConfig90Plus("test-backend-err-updated")
	fullCfg.Spec.Backends = []config.Backend{
		{
			Name: "dup-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
		{
			Name: "dup-backend", // Duplicate
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8081},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.Error(t, err)
}

// ============================================================================
// Helper functions
// ============================================================================

func createTestGatewayConfig90Plus(name string) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: name},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes:   []config.Route{},
			Backends: []config.Backend{},
		},
	}
}
