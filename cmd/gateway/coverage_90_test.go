// Package main provides additional unit tests to achieve 90%+ coverage for cmd/gateway.
package main

import (
	"context"
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
// runOperatorGateway Tests - Cover more paths
// ============================================================================

func TestRunOperatorGateway_SuccessfulStart_90(t *testing.T) {
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
		Metadata: config.Metadata{Name: "test-op-success-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19601,
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
		operatorClient: nil, // nil client will cause panic at Start
		operatorConfig: operator.DefaultConfig(),
	}

	// Start the gateway first so the second start fails
	err = gw.Start(context.Background())
	require.NoError(t, err)

	// Now runOperatorGateway will fail at gateway.Start because it's already started
	runOperatorGateway(opApp, logger)

	// Should have called exit
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================================
// waitForOperatorShutdown Tests - Cover more paths
// ============================================================================

func TestWaitForOperatorShutdown_WithOperatorClient_90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-client-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19602,
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
		Addr: ":19603",
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
		operatorClient: nil, // nil operator client
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

func TestWaitForOperatorShutdown_WithVaultClient_90(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-vault-90"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19604,
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
			// vaultClient is nil - tests the nil check path
		},
		operatorClient: nil,
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
// startConfigWatcher Tests - Cover more paths
// ============================================================================

func TestStartConfigWatcher_WithReload_90(t *testing.T) {
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
	cfg := createTestGatewayConfig90("test-watcher-90")

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

	watcher := startConfigWatcher(app, configPath, logger)
	if watcher != nil {
		// Give it a moment to start
		time.Sleep(50 * time.Millisecond)
		_ = watcher.Stop()
	}
}

// ============================================================================
// reloadComponents Tests - Cover more paths
// ============================================================================

func TestReloadComponents_WithAllComponents_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-reload-90")
	cfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
	}
	cfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 50,
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	rl := middleware.NewRateLimiter(
		100, 200, false,
		middleware.WithRateLimiterLogger(logger),
	)
	msl := middleware.NewMaxSessionsLimiter(50, 0, 0)
	r := router.New()
	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:            gw,
		backendRegistry:    reg,
		router:             r,
		config:             cfg,
		rateLimiter:        rl,
		maxSessionsLimiter: msl,
	}

	newCfg := createTestGatewayConfig90("test-reload-updated-90")
	newCfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 200,
		Burst:             400,
	}
	newCfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 100,
	}

	reloadComponents(app, newCfg, logger)

	// Verify config was updated
	assert.Equal(t, newCfg, app.config)
}

func TestReloadComponents_WithGRPCConfigChange_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-grpc-reload-90")
	cfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "old-grpc-route-90",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50052}},
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

	// New config with different gRPC routes
	newCfg := createTestGatewayConfig90("test-grpc-reload-updated-90")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "new-grpc-route-90",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.NewService"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50053}},
			},
		},
	}

	// Should not panic; gRPC config change warning is logged
	reloadComponents(app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

// ============================================================================
// gatewayConfigApplier Tests - Cover more paths
// ============================================================================

func TestGatewayConfigApplier_ApplyRoutes_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-routes-90")

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

	routes := []config.Route{
		{
			Name: "test-route-90",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}

	err = applier.ApplyRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-backends-90")

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

	backends := []config.Backend{
		{
			Name: "backend-a-90",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCRoutes_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-grpc-routes-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	grpcRoutes := []config.GRPCRoute{
		{
			Name: "grpc-route-90",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50052}},
			},
		},
	}

	// Should log warning but not error
	err = applier.ApplyGRPCRoutes(ctx, grpcRoutes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCBackends_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-grpc-backends-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	grpcBackends := []config.GRPCBackend{
		{
			Name: "grpc-backend-90",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50052},
			},
		},
	}

	// Should log warning but not error
	err = applier.ApplyGRPCBackends(ctx, grpcBackends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_WithRateLimiter_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-full-rl-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)
	rl := middleware.NewRateLimiter(100, 200, false)
	msl := middleware.NewMaxSessionsLimiter(50, 0, 0)

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    reg,
			router:             r,
			config:             cfg,
			rateLimiter:        rl,
			maxSessionsLimiter: msl,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	fullCfg := createTestGatewayConfig90("test-applier-full-updated-90")
	fullCfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 200,
		Burst:             400,
	}
	fullCfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 100,
	}
	fullCfg.Spec.Routes = []config.Route{
		{
			Name: "test-route-90",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}
	fullCfg.Spec.Backends = []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_WithGRPCConfig_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-full-grpc-90")

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

	fullCfg := createTestGatewayConfig90("test-applier-full-grpc-updated-90")
	fullCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "grpc-route-90",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50052}},
			},
		},
	}
	fullCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "grpc-backend-90",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50052},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_NilRouter_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-nil-router-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			router:          nil, // nil router
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	fullCfg := createTestGatewayConfig90("test-applier-nil-router-updated-90")
	fullCfg.Spec.Routes = []config.Route{
		{
			Name: "test-route-90",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_NilBackendRegistry_90(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig90("test-applier-nil-backend-90")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: nil, // nil backend registry
			router:          r,
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	fullCfg := createTestGatewayConfig90("test-applier-nil-backend-updated-90")
	fullCfg.Spec.Backends = []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.NoError(t, err)
}

// ============================================================================
// createMinimalConfig Tests
// ============================================================================

func TestCreateMinimalConfig_90(t *testing.T) {
	flags := cliFlags{
		gatewayName:      "test-gateway-90",
		gatewayNamespace: "test-namespace-90",
	}

	cfg := createMinimalConfig(flags)

	assert.NotNil(t, cfg)
	assert.Equal(t, "test-gateway-90", cfg.Metadata.Name)
}

// ============================================================================
// buildOperatorConfig Tests
// ============================================================================

func TestBuildOperatorConfig_WithTLS_90(t *testing.T) {
	flags := cliFlags{
		operatorAddress:    "localhost:9444",
		gatewayName:        "test-gateway-90",
		gatewayNamespace:   "test-namespace-90",
		operatorTLS:        true,
		operatorCAFile:     "/path/to/ca.crt",
		operatorCertFile:   "/path/to/cert.crt",
		operatorKeyFile:    "/path/to/key.key",
		operatorNamespaces: "ns1, ns2, ns3",
	}

	cfg := buildOperatorConfig(flags)

	assert.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "localhost:9444", cfg.Address)
	assert.Equal(t, "test-gateway-90", cfg.GatewayName)
	assert.Equal(t, "test-namespace-90", cfg.GatewayNamespace)
	assert.NotNil(t, cfg.TLS)
	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, "/path/to/ca.crt", cfg.TLS.CAFile)
	assert.Equal(t, "/path/to/cert.crt", cfg.TLS.CertFile)
	assert.Equal(t, "/path/to/key.key", cfg.TLS.KeyFile)
	assert.Equal(t, []string{"ns1", "ns2", "ns3"}, cfg.Namespaces)
}

func TestBuildOperatorConfig_WithoutTLS_90(t *testing.T) {
	flags := cliFlags{
		operatorAddress:  "localhost:9444",
		gatewayName:      "test-gateway-90",
		gatewayNamespace: "test-namespace-90",
		operatorTLS:      false,
	}

	cfg := buildOperatorConfig(flags)

	assert.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Nil(t, cfg.TLS)
}

// ============================================================================
// Helper functions
// ============================================================================

// createTestGatewayConfig90 creates a valid GatewayConfig for testing.
func createTestGatewayConfig90(name string) *config.GatewayConfig {
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
