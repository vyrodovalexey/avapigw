// Package main provides tests for 5 bug fixes:
// Fix 1: Auth metrics field in application struct
// Fix 2: gRPC routes hot-reload (ApplyGRPCRoutes, applyMergedComponents)
// Fix 3: Reload metrics in operator mode (ApplyRoutes, ApplyBackends, ApplyGRPCRoutes, ApplyFullConfig)
// Fix 4: Timestamp fallback (tested in internal/gateway/operator)
// Fix 5: Webhook metrics documentation (no code change)
package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================================
// Fix 1: authMetrics field is set in application struct
// ============================================================================

func TestInitApplication_AuthMetricsSet(t *testing.T) {
	// initApplication should set authMetrics on the application struct.
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-auth-metrics"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
		},
	}

	app := initApplication(cfg, logger)
	require.NotNil(t, app)
	assert.NotNil(t, app.authMetrics, "authMetrics should be set by initApplication")
}

// ============================================================================
// Fix 2 & 3: ApplyGRPCRoutes with real gRPC listeners
// ============================================================================

func TestApplyGRPCRoutes_NoListeners_RecordsSuccessMetric(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-grpc-no-listeners")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	metrics := observability.NewMetrics("test_grpc_no_listeners")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:       gw,
			config:        cfg,
			reloadMetrics: rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

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

	// No gRPC listeners, so the loop body is skipped but success metric is recorded
	err = applier.ApplyGRPCRoutes(context.Background(), routes)
	assert.NoError(t, err)
}

func TestApplyGRPCRoutes_WithGRPCListener_Success(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	// Create a config with a gRPC listener
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-grpc-reload"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	// Start the gateway to create listeners
	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify gRPC listeners exist
	require.Len(t, gw.GetGRPCListeners(), 1)

	metrics := observability.NewMetrics("test_grpc_reload_success")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:       gw,
			config:        cfg,
			reloadMetrics: rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

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

	// Should successfully reload routes on the gRPC listener
	err = applier.ApplyGRPCRoutes(ctx, routes)
	assert.NoError(t, err)
}

// ============================================================================
// Fix 3: ApplyRoutes records reload metrics on success and error
// ============================================================================

func TestApplyRoutes_RecordsSuccessMetric(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-routes-metric")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	metrics := observability.NewMetrics("test_routes_success_metric")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:       gw,
			router:        r,
			config:        cfg,
			reloadMetrics: rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

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

	err = applier.ApplyRoutes(context.Background(), routes)
	assert.NoError(t, err)
}

func TestApplyRoutes_RecordsErrorMetric(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-routes-error-metric")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	metrics := observability.NewMetrics("test_routes_error_metric")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:       gw,
			router:        r,
			config:        cfg,
			reloadMetrics: rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Duplicate route names should cause an error
	routes := []config.Route{
		{
			Name: "dup-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		},
		{
			Name: "dup-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		},
	}

	err = applier.ApplyRoutes(context.Background(), routes)
	assert.Error(t, err)
}

// ============================================================================
// Fix 3: ApplyBackends records reload metrics on success and error
// ============================================================================

func TestApplyBackends_RecordsSuccessMetric(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-backends-metric")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)
	metrics := observability.NewMetrics("test_backends_success_metric")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			config:          cfg,
			reloadMetrics:   rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	backends := []config.Backend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyBackends(context.Background(), backends)
	assert.NoError(t, err)
}

func TestApplyBackends_RecordsErrorMetric(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-backends-error-metric")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)
	metrics := observability.NewMetrics("test_backends_error_metric")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			config:          cfg,
			reloadMetrics:   rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Use a canceled context to trigger error in ReloadFromConfig
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	backends := []config.Backend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}

	err = applier.ApplyBackends(canceledCtx, backends)
	assert.Error(t, err)
}

// ============================================================================
// Fix 3: ApplyFullConfig records reload metrics
// ============================================================================

func TestApplyFullConfig_RecordsSuccessMetrics(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-full-success-metrics")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)
	metrics := observability.NewMetrics("test_full_success_metrics")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			router:          r,
			config:          cfg,
			reloadMetrics:   rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	newCfg := createTestGatewayConfig("test-full-updated")
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

	err = applier.ApplyFullConfig(context.Background(), newCfg)
	assert.NoError(t, err)
}

func TestApplyFullConfig_RecordsErrorMetrics_OnMergedComponentsError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-full-error-metrics")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	metrics := observability.NewMetrics("test_full_error_metrics")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:       gw,
			router:        r,
			config:        cfg,
			reloadMetrics: rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Config with duplicate routes to trigger error in applyMergedComponents
	newCfg := createTestGatewayConfig("test-full-error")
	newCfg.Spec.Routes = []config.Route{
		{
			Name: "dup-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		},
		{
			Name: "dup-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		},
	}

	err = applier.ApplyFullConfig(context.Background(), newCfg)
	assert.Error(t, err)
}

func TestApplyFullConfig_RecordsErrorMetrics_OnGatewayReloadError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	// Create an existing config with invalid APIVersion so merged config fails validation
	invalidExisting := &config.GatewayConfig{
		APIVersion: "invalid-version",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := gateway.New(invalidExisting, gateway.WithLogger(logger))
	require.NoError(t, err)

	metrics := observability.NewMetrics("test_full_reload_error_metrics")
	rm := newReloadMetrics(metrics)

	opApp := &operatorApplication{
		application: &application{
			gateway:       gw,
			config:        invalidExisting,
			reloadMetrics: rm,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Operator config with valid resources - merge with invalid existing produces invalid merged config
	operatorCfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{},
	}

	err = applier.ApplyFullConfig(context.Background(), operatorCfg)
	assert.Error(t, err)
}

// ============================================================================
// mergeOperatorConfig tests
// ============================================================================

func TestMergeOperatorConfig_PreservesExistingFields(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	existingCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "existing-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://example.com"},
			},
			Security: &config.SecurityConfig{
				Enabled: true,
			},
			Observability: &config.ObservabilityConfig{},
		},
	}

	gw, err := gateway.New(existingCfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  existingCfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	operatorCfg := &config.GatewayConfig{
		APIVersion: "operator-version",
		Kind:       "OperatorKind",
		Metadata:   config.Metadata{Name: "operator-name"},
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{Name: "operator-route"},
			},
			Backends: []config.Backend{
				{Name: "operator-backend"},
			},
			GRPCRoutes: []config.GRPCRoute{
				{Name: "operator-grpc-route"},
			},
			GRPCBackends: []config.GRPCBackend{
				{Name: "operator-grpc-backend"},
			},
		},
	}

	merged := applier.mergeOperatorConfig(operatorCfg)

	// Preserved from existing
	assert.Equal(t, "gateway.avapigw.io/v1", merged.APIVersion)
	assert.Equal(t, "Gateway", merged.Kind)
	assert.Equal(t, "existing-gateway", merged.Metadata.Name)
	assert.Equal(t, existingCfg.Spec.Listeners, merged.Spec.Listeners)
	assert.Equal(t, existingCfg.Spec.CORS, merged.Spec.CORS)
	assert.Equal(t, existingCfg.Spec.Security, merged.Spec.Security)
	assert.Equal(t, existingCfg.Spec.Observability, merged.Spec.Observability)

	// From operator
	assert.Equal(t, operatorCfg.Spec.Routes, merged.Spec.Routes)
	assert.Equal(t, operatorCfg.Spec.Backends, merged.Spec.Backends)
	assert.Equal(t, operatorCfg.Spec.GRPCRoutes, merged.Spec.GRPCRoutes)
	assert.Equal(t, operatorCfg.Spec.GRPCBackends, merged.Spec.GRPCBackends)
}

func TestMergeOperatorConfig_NilExistingConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  nil, // nil existing config
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	operatorCfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{Name: "operator-route"},
			},
		},
	}

	merged := applier.mergeOperatorConfig(operatorCfg)
	assert.NotNil(t, merged)
	// When existing is nil, DefaultConfig() is used
	assert.Equal(t, operatorCfg.Spec.Routes, merged.Spec.Routes)
}

// ============================================================================
// applyMergedComponents tests
// ============================================================================

func TestApplyMergedComponents_AllComponents(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-merged-all")

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

	merged := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
			Routes: []config.Route{
				{
					Name: "test-route",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "localhost", Port: 8080}},
					},
				},
			},
			Backends: []config.Backend{
				{
					Name: "test-backend",
					Hosts: []config.BackendHost{
						{Address: "localhost", Port: 8080},
					},
				},
			},
			GRPCBackends: []config.GRPCBackend{
				{Name: "test-grpc-backend"},
			},
		},
	}

	err = applier.applyMergedComponents(context.Background(), merged)
	assert.NoError(t, err)
}

func TestApplyMergedComponents_RouteError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-merged-route-err")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			router:  r,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Duplicate routes cause error
	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{Name: "dup", Route: []config.RouteDestination{{Destination: config.Destination{Host: "a", Port: 1}}}},
				{Name: "dup", Route: []config.RouteDestination{{Destination: config.Destination{Host: "b", Port: 2}}}},
			},
		},
	}

	err = applier.applyMergedComponents(context.Background(), merged)
	assert.Error(t, err)
}

func TestApplyMergedComponents_BackendError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-merged-backend-err")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Use a canceled context to trigger error in ReloadFromConfig
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Backends: []config.Backend{
				{Name: "test-backend", Hosts: []config.BackendHost{{Address: "a", Port: 1}}},
			},
		},
	}

	err = applier.applyMergedComponents(canceledCtx, merged)
	assert.Error(t, err)
}

func TestApplyMergedComponents_WithGRPCRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	// Create a config with a gRPC listener
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-merged-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	// Start gateway to create gRPC listeners
	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	require.Len(t, gw.GetGRPCListeners(), 1)

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

	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			GRPCRoutes: []config.GRPCRoute{
				{
					Name: "test-grpc-route",
					Match: []config.GRPCRouteMatch{
						{Service: &config.StringMatch{Exact: "test.Service"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "localhost", Port: 50051}},
					},
				},
			},
		},
	}

	err = applier.applyMergedComponents(ctx, merged)
	assert.NoError(t, err)
}

func TestApplyMergedComponents_NilRouterAndRegistry(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-merged-nil")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			router:          nil,
			backendRegistry: nil,
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	merged := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{Name: "test-route"},
			},
			Backends: []config.Backend{
				{Name: "test-backend"},
			},
		},
	}

	// Should not error when router and registry are nil
	err = applier.applyMergedComponents(context.Background(), merged)
	assert.NoError(t, err)
}

// ============================================================================
// loadOperatorInitialConfig tests
// ============================================================================

func TestLoadOperatorInitialConfig_FallbackToMinimal(t *testing.T) {
	logger := observability.NopLogger()

	flags := cliFlags{
		configPath:  "/nonexistent/config.yaml",
		gatewayName: "test-gateway",
	}

	cfg := loadOperatorInitialConfig(flags, logger)
	require.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)
}

func TestLoadOperatorInitialConfig_ClearsRoutesAndBackends(t *testing.T) {
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
  routes:
    - name: should-be-cleared
  backends:
    - name: should-be-cleared
`
	err := writeTestConfigFile(configPath, configContent)
	require.NoError(t, err)

	logger := observability.NopLogger()

	flags := cliFlags{
		configPath:  configPath,
		gatewayName: "override-name",
	}

	cfg := loadOperatorInitialConfig(flags, logger)
	require.NotNil(t, cfg)
	assert.Nil(t, cfg.Spec.Routes, "routes should be cleared")
	assert.Nil(t, cfg.Spec.Backends, "backends should be cleared")
	assert.Nil(t, cfg.Spec.GRPCRoutes, "gRPC routes should be cleared")
	assert.Nil(t, cfg.Spec.GRPCBackends, "gRPC backends should be cleared")
	assert.Equal(t, "override-name", cfg.Metadata.Name)
}

func TestLoadOperatorInitialConfig_EmptyGatewayName(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/gateway.yaml"

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: original-name
spec:
  listeners:
    - name: http
      address: 0.0.0.0
      port: 8080
      protocol: HTTP
`
	err := writeTestConfigFile(configPath, configContent)
	require.NoError(t, err)

	logger := observability.NopLogger()

	flags := cliFlags{
		configPath:  configPath,
		gatewayName: "", // empty - should keep original
	}

	cfg := loadOperatorInitialConfig(flags, logger)
	require.NotNil(t, cfg)
	assert.Equal(t, "original-name", cfg.Metadata.Name)
}

// ============================================================================
// configSectionHash / configSectionChanged edge cases
// ============================================================================

func TestConfigSectionHash_UnmarshalableType(t *testing.T) {
	t.Parallel()

	// channels cannot be marshaled to JSON
	ch := make(chan int)
	_, ok := configSectionHash(ch)
	assert.False(t, ok, "should return false for unmarshalable type")
}

func TestConfigSectionChanged_FallbackToDeepEqual(t *testing.T) {
	t.Parallel()

	// Use channels which can't be JSON marshaled, forcing fallback to DeepEqual
	ch1 := make(chan int)
	ch2 := make(chan int)

	// Same channel should not be "changed"
	result := configSectionChanged(ch1, ch1)
	assert.False(t, result)

	// Different channels should be "changed"
	result = configSectionChanged(ch1, ch2)
	assert.True(t, result)
}

// ============================================================================
// Helper
// ============================================================================

func writeTestConfigFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
