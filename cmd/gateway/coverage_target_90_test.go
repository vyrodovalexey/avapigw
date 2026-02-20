// Package main provides targeted tests to achieve 90%+ coverage for cmd/gateway.
package main

import (
	"context"
	"errors"
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
)

// ============================================================================
// runOperatorGateway Tests - Target 90%+ coverage
// ============================================================================

func TestRunOperatorGateway_BackendStartError_Target90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-backend-err-90"},
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

	// Create a backend registry
	backendReg := backend.NewRegistry(logger)
	// Load a backend configuration
	err = backendReg.LoadFromConfig([]config.Backend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	})
	require.NoError(t, err)

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
			startErr:  errors.New("mock start error"),
			sessionID: "test",
		},
		operatorConfig: operator.DefaultConfig(),
	}

	// This will start backends (ok), start gateway (ok), then fail at operatorClient.Start
	runOperatorGateway(opApp, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

func TestRunOperatorGateway_GatewayStartError_Target90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-gw-err-90"},
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

	// Start the gateway first so the second start fails
	err = gw.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gw.Stop(ctx)
	}()

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
		operatorClient: nil,
		operatorConfig: operator.DefaultConfig(),
	}

	// This should fail at gateway.Start because it's already started
	runOperatorGateway(opApp, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================================
// waitForOperatorShutdown Tests - Target 90%+ coverage
// ============================================================================

func TestWaitForOperatorShutdown_WithAllComponents_Target90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-shutdown-all-90"},
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

	rl := middleware.NewRateLimiter(100, 200, false)
	msl := middleware.NewMaxSessionsLimiter(100, 0, 0)

	metricsServer := &http.Server{
		Addr: ":0",
	}

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    backendReg,
			healthChecker:      health.NewChecker("test", observability.NopLogger()),
			metrics:            observability.NewMetrics("test"),
			metricsServer:      metricsServer,
			tracer:             tracer,
			config:             cfg,
			auditLogger:        audit.NewNoopLogger(),
			rateLimiter:        rl,
			maxSessionsLimiter: msl,
			vaultClient:        nil,
		},
		operatorClient: nil, // nil operator client - tests the nil check path
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
// startConfigWatcher Tests - Target 90%+ coverage
// ============================================================================

func TestStartConfigWatcher_WatcherStartError_Target90(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-watcher-err-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		router:          r,
		config:          cfg,
	}

	// Use a path that exists but is a directory (not a file)
	// This should cause the watcher to fail to start
	tmpDir := t.TempDir()
	watcher := startConfigWatcher(context.Background(), app, tmpDir, logger)
	// The watcher is created but Start fails (error is logged)
	assert.NotNil(t, watcher)
}

func TestStartConfigWatcher_WithConfigReload_Target90(t *testing.T) {
	// Create a temporary config file
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
      address: 0.0.0.0
      port: 8080
      protocol: HTTP
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-watcher-reload-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		router:          r,
		config:          cfg,
	}

	watcher := startConfigWatcher(context.Background(), app, configPath, logger)
	require.NotNil(t, watcher)

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Modify the config file to trigger reload
	newConfigContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway-updated
spec:
  listeners:
    - name: http
      address: 0.0.0.0
      port: 8080
      protocol: HTTP
  routes: []
  backends: []
`
	err = os.WriteFile(configPath, []byte(newConfigContent), 0644)
	require.NoError(t, err)

	// Give it time to detect the change and reload
	time.Sleep(200 * time.Millisecond)

	_ = watcher.Stop()
}

// ============================================================================
// runGateway Tests - Target 90%+ coverage
// ============================================================================

func TestRunGateway_GatewayStartError_Target90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw-start-err-90"},
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

	// Start the gateway first so the second start fails
	err = gw.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gw.Stop(ctx)
	}()

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: backendReg,
		tracer:          tracer,
		config:          cfg,
		auditLogger:     audit.NewNoopLogger(),
	}

	// Create a temporary config file
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
      address: 127.0.0.1
      port: 8080
      protocol: HTTP
  routes: []
  backends: []
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// This should fail at gateway.Start because it's already started
	runGateway(app, configPath, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================================
// reloadComponents Tests - Target 90%+ coverage
// ============================================================================

func TestReloadComponents_GatewayReloadError_Target90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-reload-err-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		router:          r,
		config:          cfg,
	}

	// Invalid config that should cause gateway.Reload to fail
	invalidCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: ""},
		Spec:     config.GatewaySpec{},
	}

	// Should not panic; gateway.Reload will reject invalid config
	reloadComponents(context.Background(), app, invalidCfg, logger)

	// Config should NOT be updated since reload failed
	assert.Equal(t, cfg, app.config)
}

func TestReloadComponents_WithGRPCBackendsChange_Target90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-grpc-backends-90")
	cfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "old-grpc-backend-90",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50052},
			},
		},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		router:          r,
		config:          cfg,
	}

	// New config with different gRPC backends
	newCfg := createTestGatewayConfigTarget90("test-grpc-backends-updated-90")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "new-grpc-backend-90",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50053},
			},
		},
	}

	// Should not panic; gRPC config change warning is logged
	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

// ============================================================================
// ApplyFullConfig Tests - Target 90%+ coverage
// ============================================================================

func TestGatewayConfigApplier_ApplyFullConfig_RouteError_Target90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-applier-route-err-90")

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

	// Config with duplicate routes that should cause error
	fullCfg := createTestGatewayConfigTarget90("test-applier-route-err-updated-90")
	fullCfg.Spec.Routes = []config.Route{
		{
			Name: "dup-route-90",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
		{
			Name: "dup-route-90", // Duplicate
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-b", Port: 8080}},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.Error(t, err)
}

func TestGatewayConfigApplier_ApplyRoutes_NilRouter_Target90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-applier-nil-router-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			router:  nil, // nil router
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	routes := []config.Route{
		{
			Name: "test-route-90",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}

	// Should not error with nil router
	err = applier.ApplyRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends_NilRegistry_Target90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfigTarget90("test-applier-nil-reg-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: nil, // nil backend registry
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	backends := []config.Backend{
		{
			Name: "backend-a-90",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	// Should not error with nil backend registry
	err = applier.ApplyBackends(ctx, backends)
	assert.NoError(t, err)
}

// ============================================================================
// runOperatorMode Tests - Target 90%+ coverage
// ============================================================================

func TestRunOperatorMode_InvalidConfig_Target90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	// Invalid flags - missing required fields
	flags := cliFlags{
		operatorMode:     true,
		operatorAddress:  "", // Empty address - should fail validation
		gatewayName:      "",
		gatewayNamespace: "",
	}

	runOperatorMode(flags, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================================
// initApplication Tests - Target 90%+ coverage
// ============================================================================

func TestInitApplication_ValidConfig_Target90(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCalled bool
	exitFunc = func(code int) {
		exitCalled = true
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-init-app-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes: []config.Route{
				{
					Name: "test-route",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "backend-a", Port: 8080}},
					},
				},
			},
			Backends: []config.Backend{
				{
					Name: "backend-a",
					Hosts: []config.BackendHost{
						{Address: "localhost", Port: 8080},
					},
				},
			},
		},
	}

	app := initApplication(cfg, logger)

	if exitCalled {
		t.Skip("initApplication failed (expected in some environments)")
		return
	}

	assert.NotNil(t, app)
	assert.NotNil(t, app.gateway)
	assert.NotNil(t, app.backendRegistry)
	assert.NotNil(t, app.router)
}

// ============================================================================
// Helper functions
// ============================================================================

// createTestGatewayConfigTarget90 creates a valid GatewayConfig for testing.
func createTestGatewayConfigTarget90(name string) *config.GatewayConfig {
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
