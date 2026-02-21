package main

import (
	"context"
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
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestWaitForOperatorShutdown_WithOperatorClientP90 tests shutdown with a real operator client mock.
func TestWaitForOperatorShutdown_WithOperatorClientP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-client-p90"},
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

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
			auditLogger:     audit.NewAtomicAuditLogger(audit.NewNoopLogger()),
		},
		operatorClient: &mockOperatorClient{sessionID: "test-session-p90"},
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
		// Success - operator client Stop was called
	case <-time.After(10 * time.Second):
		t.Fatal("waitForOperatorShutdown did not complete in time")
	}
}

// TestWaitForOperatorShutdown_WithOperatorClientStopErrorP90 tests shutdown when operator client stop fails.
func TestWaitForOperatorShutdown_WithOperatorClientStopErrorP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-stop-err-p90"},
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

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
		},
		operatorClient: &mockOperatorClient{
			sessionID: "test-session-err-p90",
			stopErr:   assert.AnError,
		},
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
		// Should complete even with stop error
	case <-time.After(10 * time.Second):
		t.Fatal("waitForOperatorShutdown did not complete in time")
	}
}

// TestRunOperatorGateway_SuccessfulStartThenShutdownP90 tests the full operator gateway lifecycle.
func TestRunOperatorGateway_SuccessfulStartThenShutdownP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-lifecycle-p90"},
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
		operatorClient: &mockOperatorClient{sessionID: "lifecycle-p90"},
		operatorConfig: operator.DefaultConfig(),
	}

	done := make(chan struct{})
	go func() {
		runOperatorGateway(opApp, logger)
		close(done)
	}()

	// Wait for gateway to start
	time.Sleep(200 * time.Millisecond)

	// Send shutdown signal
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(15 * time.Second):
		t.Fatal("runOperatorGateway did not complete in time")
	}
}

// TestRunOperatorGateway_OperatorClientStartErrorP90 tests when operator client fails to start.
func TestRunOperatorGateway_OperatorClientStartErrorP90(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-start-err-p90"},
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
			sessionID: "err-p90",
			startErr:  assert.AnError,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	runOperatorGateway(opApp, logger)

	// Should have called exit because operator client Start fails
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// TestStartConfigWatcher_WithValidFileP90 tests config watcher with a real temp file.
func TestStartConfigWatcher_WithValidFileP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := config.DefaultConfig()
	cfg.Metadata.Name = "test-watcher-p90"

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: backend.NewRegistry(logger),
		config:          cfg,
	}

	// Create a temp config file
	tmpFile, err := os.CreateTemp("", "gateway-p90-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write valid config
	_, err = tmpFile.WriteString(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test
spec:
  listeners:
    - name: http
      bind: "127.0.0.1"
      port: 8080
      protocol: HTTP
`)
	require.NoError(t, err)
	tmpFile.Close()

	watcher := startConfigWatcher(context.Background(), app, tmpFile.Name(), logger)
	if watcher != nil {
		_ = watcher.Stop()
	}
}

// TestRunGateway_WithShutdownP90 tests runGateway with a quick shutdown.
func TestRunGateway_WithShutdownP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-run-gw-p90"},
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
		tracer:             tracer,
		config:             cfg,
		rateLimiter:        rl,
		maxSessionsLimiter: msl,
		auditLogger:        audit.NewAtomicAuditLogger(audit.NewNoopLogger()),
	}

	// Create a temp config file for the watcher
	tmpFile, err := os.CreateTemp("", "gateway-run-p90-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test
spec:
  listeners:
    - name: http
      bind: "127.0.0.1"
      port: 8080
      protocol: HTTP
`)
	require.NoError(t, err)
	tmpFile.Close()

	done := make(chan struct{})
	go func() {
		runGateway(app, tmpFile.Name(), logger)
		close(done)
	}()

	// Wait for gateway to start
	time.Sleep(200 * time.Millisecond)

	// Send shutdown signal
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(15 * time.Second):
		t.Fatal("runGateway did not complete in time")
	}
}

// TestReloadComponents_WithHTTPRouteChangeP90 tests reload when HTTP routes change.
func TestReloadComponents_WithHTTPRouteChangeP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := config.DefaultConfig()
	cfg.Metadata.Name = "test-reload-http-p90"

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: backend.NewRegistry(logger),
		config:          cfg,
	}

	// Create new config with same structure but different name
	newCfg := config.DefaultConfig()
	newCfg.Metadata.Name = "test-reload-http-p90"

	reloadComponents(context.Background(), app, newCfg, logger)

	// The stored config pointer should be updated to newCfg
	assert.Equal(t, newCfg, app.config)
}

// TestInitAuditLogger_WithDisabledConfigP90 tests audit logger init with disabled config.
func TestInitAuditLogger_WithDisabledConfigP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-audit-disabled-p90"},
		Spec: config.GatewaySpec{
			Audit: &config.AuditConfig{
				Enabled: false,
			},
		},
	}

	auditLogger := initAuditLogger(cfg, logger)
	assert.NotNil(t, auditLogger)
}

// TestWaitForOperatorShutdown_WithVaultClientP90 tests shutdown with vault client.
func TestWaitForOperatorShutdown_WithVaultClientP90(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-vault-p90"},
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

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    backendReg,
			tracer:             tracer,
			config:             cfg,
			vaultClient:        &mockVaultClient90{},
			auditLogger:        audit.NewAtomicAuditLogger(audit.NewNoopLogger()),
			rateLimiter:        middleware.NewRateLimiter(100, 200, false),
			maxSessionsLimiter: middleware.NewMaxSessionsLimiter(100, 0, 0),
		},
		operatorClient: &mockOperatorClient{sessionID: "vault-p90"},
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
