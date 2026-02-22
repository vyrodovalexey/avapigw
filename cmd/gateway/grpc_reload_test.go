// Package main provides unit tests for gRPC backend hot-reload functions.
package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// grpcRoutesChanged Tests
// ============================================================================

func TestGrpcRoutesChanged_BothNil(t *testing.T) {
	t.Parallel()

	result := grpcRoutesChanged(nil, nil)
	assert.False(t, result)
}

func TestGrpcRoutesChanged_OldNil(t *testing.T) {
	t.Parallel()

	newCfg := createTestGRPCConfig("test")
	result := grpcRoutesChanged(nil, newCfg)
	assert.True(t, result)
}

func TestGrpcRoutesChanged_NewNil(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	result := grpcRoutesChanged(oldCfg, nil)
	assert.True(t, result)
}

func TestGrpcRoutesChanged_Same(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	oldCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "route1",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}

	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "route1",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}

	result := grpcRoutesChanged(oldCfg, newCfg)
	assert.False(t, result)
}

func TestGrpcRoutesChanged_Different(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	oldCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route2"},
	}

	result := grpcRoutesChanged(oldCfg, newCfg)
	assert.True(t, result)
}

func TestGrpcRoutesChanged_EmptyVsNonEmpty(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	oldCfg.Spec.GRPCRoutes = nil

	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	result := grpcRoutesChanged(oldCfg, newCfg)
	assert.True(t, result)
}

// ============================================================================
// grpcBackendsChanged Tests
// ============================================================================

func TestGrpcBackendsChanged_BothNil(t *testing.T) {
	t.Parallel()

	result := grpcBackendsChanged(nil, nil)
	assert.False(t, result)
}

func TestGrpcBackendsChanged_OldNil(t *testing.T) {
	t.Parallel()

	newCfg := createTestGRPCConfig("test")
	result := grpcBackendsChanged(nil, newCfg)
	assert.True(t, result)
}

func TestGrpcBackendsChanged_NewNil(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	result := grpcBackendsChanged(oldCfg, nil)
	assert.True(t, result)
}

func TestGrpcBackendsChanged_Same(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	oldCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "backend1",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 50051},
			},
		},
	}

	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "backend1",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 50051},
			},
		},
	}

	result := grpcBackendsChanged(oldCfg, newCfg)
	assert.False(t, result)
}

func TestGrpcBackendsChanged_Different(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	oldCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1"},
	}

	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend2"},
	}

	result := grpcBackendsChanged(oldCfg, newCfg)
	assert.True(t, result)
}

func TestGrpcBackendsChanged_EmptyVsNonEmpty(t *testing.T) {
	t.Parallel()

	oldCfg := createTestGRPCConfig("test")
	oldCfg.Spec.GRPCBackends = nil

	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1"},
	}

	result := grpcBackendsChanged(oldCfg, newCfg)
	assert.True(t, result)
}

// ============================================================================
// reloadGRPCBackendsIfChanged Tests
// ============================================================================

func TestGrpcReloadBackendsIfChanged_NoChange(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")
	cfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1"},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)
	app := &application{
		gateway:             gw,
		grpcBackendRegistry: reg,
		config:              cfg,
	}

	// New config with same backends — no reload should happen
	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1"},
	}

	rm := ensureReloadMetrics(app)

	// Should be a no-op since backends haven't changed
	reloadGRPCBackendsIfChanged(context.Background(), app, newCfg, logger, rm)
}

func TestGrpcReloadBackendsIfChanged_NilRegistry(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")
	cfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1"},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway:             gw,
		grpcBackendRegistry: nil, // nil registry
		config:              cfg,
	}

	// New config with different backends
	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend2"},
	}

	rm := ensureReloadMetrics(app)

	// Should return early because registry is nil
	assert.NotPanics(t, func() {
		reloadGRPCBackendsIfChanged(context.Background(), app, newCfg, logger, rm)
	})
}

func TestGrpcReloadBackendsIfChanged_WithChange(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")
	cfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend1", Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 50051}}},
	}

	reg := backend.NewRegistry(logger)
	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithGatewayGRPCBackendRegistry(reg),
	)
	require.NoError(t, err)

	app := &application{
		gateway:             gw,
		grpcBackendRegistry: reg,
		config:              cfg,
	}

	// New config with different backends
	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{Name: "backend2", Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 50052}}},
	}

	rm := ensureReloadMetrics(app)

	// Should attempt reload (gateway has no gRPC listeners so ReloadGRPCBackends is a no-op)
	assert.NotPanics(t, func() {
		reloadGRPCBackendsIfChanged(context.Background(), app, newCfg, logger, rm)
	})
}

// ============================================================================
// warnGRPCRoutesChanged Tests
// ============================================================================

func TestGrpcWarnRoutesChanged_NoChange(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")
	cfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	app := &application{
		config: cfg,
	}

	// Same routes — should not warn
	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	assert.NotPanics(t, func() {
		warnGRPCRoutesChanged(app, newCfg, logger)
	})
}

func TestGrpcWarnRoutesChanged_WithChange(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")
	cfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route1"},
	}

	app := &application{
		config: cfg,
	}

	// Different routes — should warn (but not error)
	newCfg := createTestGRPCConfig("test")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{Name: "route2"},
	}

	assert.NotPanics(t, func() {
		warnGRPCRoutesChanged(app, newCfg, logger)
	})
}

// ============================================================================
// ApplyGRPCBackends with gRPC listeners Tests
// ============================================================================

func TestGrpcApplyGRPCBackends_WithGRPCListeners(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := backend.NewRegistry(logger)

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-grpc-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithGatewayGRPCBackendRegistry(reg),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	opApp := &operatorApplication{
		application: &application{
			gateway:             gw,
			grpcBackendRegistry: reg,
			config:              cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	backends := []config.GRPCBackend{
		{
			Name: "grpc-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50051},
			},
		},
	}

	err = applier.ApplyGRPCBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGrpcApplyGRPCBackends_NilGateway(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")

	opApp := &operatorApplication{
		application: &application{
			gateway: nil,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// With nil gateway, should succeed (no-op)
	err := applier.ApplyGRPCBackends(context.Background(), []config.GRPCBackend{
		{Name: "test", Hosts: []config.BackendHost{{Address: "localhost", Port: 50051}}},
	})
	assert.NoError(t, err)
}

// ============================================================================
// applyMergedGRPCComponents Tests
// ============================================================================

func TestGrpcApplyMergedGRPCComponents_EmptyGRPCRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGRPCConfig("test")

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

	merged := createTestGRPCConfig("test")
	merged.Spec.GRPCRoutes = nil
	merged.Spec.GRPCBackends = nil

	err = applier.applyMergedGRPCComponents(context.Background(), merged)
	assert.NoError(t, err)
}

func TestGrpcApplyMergedGRPCComponents_WithGRPCBackends(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := backend.NewRegistry(logger)

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-grpc-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithGatewayGRPCBackendRegistry(reg),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	opApp := &operatorApplication{
		application: &application{
			gateway:             gw,
			grpcBackendRegistry: reg,
			config:              cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	merged := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: cfg.Spec.Listeners,
			GRPCBackends: []config.GRPCBackend{
				{
					Name: "grpc-backend",
					Hosts: []config.BackendHost{
						{Address: "localhost", Port: 50051},
					},
				},
			},
		},
	}

	err = applier.applyMergedGRPCComponents(ctx, merged)
	assert.NoError(t, err)
}

// ============================================================================
// Helper functions
// ============================================================================

func createTestGRPCConfig(name string) *config.GatewayConfig {
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
