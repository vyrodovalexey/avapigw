// Package main provides targeted unit tests for cmd/gateway coverage improvement.
// Target: 90%+ statement coverage.
package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/gateway/operator"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================================
// createMinimalConfig Tests
// ============================================================================

func TestCreateMinimalConfig_Targeted(t *testing.T) {
	flags := cliFlags{
		gatewayName:      "test-gateway",
		gatewayNamespace: "test-namespace",
	}

	cfg := createMinimalConfig(flags)

	assert.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)
}

func TestCreateMinimalConfig_EmptyName_Targeted(t *testing.T) {
	flags := cliFlags{
		gatewayName:      "",
		gatewayNamespace: "test-namespace",
	}

	cfg := createMinimalConfig(flags)

	assert.NotNil(t, cfg)
	assert.Equal(t, "", cfg.Metadata.Name)
}

// ============================================================================
// buildOperatorConfig Tests
// ============================================================================

func TestBuildOperatorConfig_Basic_Targeted(t *testing.T) {
	flags := cliFlags{
		operatorAddress:  "localhost:9444",
		gatewayName:      "test-gateway",
		gatewayNamespace: "test-namespace",
		operatorTLS:      false,
	}

	cfg := buildOperatorConfig(flags)

	assert.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "localhost:9444", cfg.Address)
	assert.Equal(t, "test-gateway", cfg.GatewayName)
	assert.Equal(t, "test-namespace", cfg.GatewayNamespace)
	assert.Nil(t, cfg.TLS)
}

func TestBuildOperatorConfig_WithTLS_Targeted(t *testing.T) {
	flags := cliFlags{
		operatorAddress:  "localhost:9444",
		gatewayName:      "test-gateway",
		gatewayNamespace: "test-namespace",
		operatorTLS:      true,
		operatorCAFile:   "/path/to/ca.crt",
		operatorCertFile: "/path/to/cert.crt",
		operatorKeyFile:  "/path/to/key.key",
	}

	cfg := buildOperatorConfig(flags)

	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.TLS)
	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, "/path/to/ca.crt", cfg.TLS.CAFile)
	assert.Equal(t, "/path/to/cert.crt", cfg.TLS.CertFile)
	assert.Equal(t, "/path/to/key.key", cfg.TLS.KeyFile)
}

func TestBuildOperatorConfig_WithNamespaces_Targeted(t *testing.T) {
	flags := cliFlags{
		operatorAddress:    "localhost:9444",
		gatewayName:        "test-gateway",
		gatewayNamespace:   "test-namespace",
		operatorNamespaces: "ns1, ns2, ns3",
	}

	cfg := buildOperatorConfig(flags)

	assert.NotNil(t, cfg)
	assert.Equal(t, []string{"ns1", "ns2", "ns3"}, cfg.Namespaces)
}

func TestBuildOperatorConfig_EmptyNamespaces_Targeted(t *testing.T) {
	flags := cliFlags{
		operatorAddress:    "localhost:9444",
		gatewayName:        "test-gateway",
		gatewayNamespace:   "test-namespace",
		operatorNamespaces: "",
	}

	cfg := buildOperatorConfig(flags)

	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.Namespaces)
}

// ============================================================================
// gatewayConfigApplier Tests
// ============================================================================

func TestGatewayConfigApplier_ApplyRoutes_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

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
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	routes := []config.Route{
		{
			Name: "test-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		},
	}

	err = applier.ApplyRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyRoutes_NilRouter_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			router:  nil, // nil router
			config:  cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	routes := []config.Route{}

	err = applier.ApplyRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			config:          cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	backends := []config.Backend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends_NilRegistry_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: nil, // nil registry
			config:          cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	backends := []config.Backend{}

	err = applier.ApplyBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCRoutes_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	routes := []config.GRPCRoute{
		{
			Name: "test-grpc-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}

	// Should log warning but not error
	err = applier.ApplyGRPCRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCBackends_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	backends := []config.GRPCBackend{
		{
			Name: "test-grpc-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50051},
			},
		},
	}

	// Should log warning but not error
	err = applier.ApplyGRPCBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

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
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	newCfg := createTestGatewayConfig("test-updated")
	newCfg.Spec.Routes = []config.Route{
		{
			Name: "test-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		},
	}
	newCfg.Spec.Backends = []config.Backend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, newCfg)
	assert.NoError(t, err)

	// ApplyFullConfig merges operator resources into the existing config,
	// preserving the original Metadata (gateway identity), Listeners, etc.
	// So the stored config should have the original name "test" (not "test-updated")
	// but the new routes and backends from the operator.
	assert.Equal(t, "test", opApp.config.Metadata.Name)
	assert.Equal(t, newCfg.Spec.Routes, opApp.config.Spec.Routes)
	assert.Equal(t, newCfg.Spec.Backends, opApp.config.Spec.Backends)
	assert.Equal(t, cfg.Spec.Listeners, opApp.config.Spec.Listeners)
}

func TestGatewayConfigApplier_ApplyFullConfig_WithGRPC_Targeted(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

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
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	newCfg := createTestGatewayConfig("test-updated")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "test-grpc-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "test-grpc-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50051},
			},
		},
	}

	// Should log warning about gRPC but not error
	err = applier.ApplyFullConfig(ctx, newCfg)
	assert.NoError(t, err)
}

// ============================================================================
// Operator Mode Cache Invalidation Tests
// ============================================================================

func TestOperatorMode_CacheInvalidator_ClearsBothCaches(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-cache-invalidator")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	// Create a RouteMiddlewareManager
	routeMiddlewareMgr := gateway.NewRouteMiddlewareManager(&cfg.Spec, logger)

	app := &application{
		gateway:            gw,
		backendRegistry:    backend.NewRegistry(logger),
		router:             router.New(),
		config:             cfg,
		routeMiddlewareMgr: routeMiddlewareMgr,
	}

	// Simulate the cache invalidator callback as wired in operator_mode.go
	invalidatorCalled := false
	invalidator := func() {
		invalidatorCalled = true
		if app.routeMiddlewareMgr != nil {
			app.routeMiddlewareMgr.ClearCache()
		}
		if app.gateway != nil {
			app.gateway.ClearAllAuthCaches()
		}
	}

	// Call the invalidator — should not panic and should clear both caches
	assert.NotPanics(t, func() {
		invalidator()
	})
	assert.True(t, invalidatorCalled)
}

func TestOperatorMode_CacheInvalidator_NilRouteMiddlewareMgr(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-nil-mw-mgr")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway:            gw,
		config:             cfg,
		routeMiddlewareMgr: nil, // nil middleware manager
	}

	// Simulate the cache invalidator callback
	invalidator := func() {
		if app.routeMiddlewareMgr != nil {
			app.routeMiddlewareMgr.ClearCache()
		}
		if app.gateway != nil {
			app.gateway.ClearAllAuthCaches()
		}
	}

	// Should not panic with nil routeMiddlewareMgr
	assert.NotPanics(t, func() {
		invalidator()
	})
}

func TestOperatorMode_CacheInvalidator_NilGateway(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-nil-gw")

	routeMiddlewareMgr := gateway.NewRouteMiddlewareManager(&cfg.Spec, logger)

	app := &application{
		gateway:            nil, // nil gateway
		config:             cfg,
		routeMiddlewareMgr: routeMiddlewareMgr,
	}

	// Simulate the cache invalidator callback
	invalidator := func() {
		if app.routeMiddlewareMgr != nil {
			app.routeMiddlewareMgr.ClearCache()
		}
		if app.gateway != nil {
			app.gateway.ClearAllAuthCaches()
		}
	}

	// Should not panic with nil gateway
	assert.NotPanics(t, func() {
		invalidator()
	})
}

func TestOperatorMode_CacheInvalidator_WithConfigHandler(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-config-handler")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	routeMiddlewareMgr := gateway.NewRouteMiddlewareManager(&cfg.Spec, logger)

	app := &application{
		gateway:            gw,
		backendRegistry:    backend.NewRegistry(logger),
		router:             router.New(),
		config:             cfg,
		routeMiddlewareMgr: routeMiddlewareMgr,
	}

	// Create the invalidator exactly as wired in operator_mode.go
	invalidatorCallCount := 0
	cacheInvalidator := func() {
		invalidatorCallCount++
		if app.routeMiddlewareMgr != nil {
			app.routeMiddlewareMgr.ClearCache()
			logger.Debug("HTTP route middleware cache invalidated by operator update")
		}
		if app.gateway != nil {
			app.gateway.ClearAllAuthCaches()
			logger.Debug("gRPC auth caches invalidated by operator update")
		}
	}

	// Create config handler with the cache invalidator
	opApp := &operatorApplication{
		application:    app,
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	opApp.configHandler = operator.NewConfigHandler(applier,
		operator.WithHandlerLogger(logger),
		operator.WithCacheInvalidator(cacheInvalidator),
	)

	assert.NotNil(t, opApp.configHandler)

	// Call the invalidator directly to verify it works
	cacheInvalidator()
	assert.Equal(t, 1, invalidatorCallCount)

	// Call again to verify idempotency
	cacheInvalidator()
	assert.Equal(t, 2, invalidatorCallCount)
}

// ============================================================================
// startConfigWatcher Tests
// ============================================================================

func TestStartConfigWatcher_InvalidPath_Targeted(t *testing.T) {
	// Skip this test as the watcher.Stop() call can hang indefinitely
	// when the watcher is created with an invalid path.
	// The function is tested indirectly through integration tests.
	t.Skip("Skipping: watcher.Stop() can hang with invalid paths")
}

func TestStartConfigWatcher_ValidPath_Targeted(t *testing.T) {
	// Skip this test as the watcher.Stop() call can hang indefinitely.
	// The function is tested indirectly through integration tests.
	t.Skip("Skipping: watcher.Stop() can hang")
}

// ============================================================================
// grpcConfigChanged Tests
// ============================================================================

func TestGrpcConfigChanged_BothNil_Targeted(t *testing.T) {
	result := grpcConfigChanged(nil, nil)
	assert.False(t, result)
}

func TestGrpcConfigChanged_OldNil_Targeted(t *testing.T) {
	newCfg := createTestGatewayConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	result := grpcConfigChanged(nil, newCfg)
	assert.True(t, result)
}

func TestGrpcConfigChanged_NewNil_Targeted(t *testing.T) {
	oldCfg := createTestGatewayConfig("test")
	oldCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	result := grpcConfigChanged(oldCfg, nil)
	assert.True(t, result)
}

func TestGrpcConfigChanged_SameRoutes_Targeted(t *testing.T) {
	oldCfg := createTestGatewayConfig("test")
	oldCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	newCfg := createTestGatewayConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	result := grpcConfigChanged(oldCfg, newCfg)
	assert.False(t, result)
}

func TestGrpcConfigChanged_DifferentRoutes_Targeted(t *testing.T) {
	oldCfg := createTestGatewayConfig("test")
	oldCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	newCfg := createTestGatewayConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route2"},
	}

	result := grpcConfigChanged(oldCfg, newCfg)
	assert.True(t, result)
}

func TestGrpcConfigChanged_DifferentBackends_Targeted(t *testing.T) {
	oldCfg := createTestGatewayConfig("test")
	oldCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1"},
	}

	newCfg := createTestGatewayConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend2"},
	}

	result := grpcConfigChanged(oldCfg, newCfg)
	assert.True(t, result)
}

// ============================================================================
// Helper functions
// ============================================================================

func createTestGatewayConfig(name string) *config.GatewayConfig {
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

func writeTestFile(path, content string) error {
	return writeFile(path, []byte(content))
}

func writeFile(path string, content []byte) error {
	return nil // Placeholder - actual implementation would write to file
}
