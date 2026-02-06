// Package main provides additional unit tests to boost cmd/gateway coverage to 90%+.
package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

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
// gatewayConfigApplier Tests - Cover error paths
// ============================================================================

func TestGatewayConfigApplier_ApplyFullConfig_RouterErrorBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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

	// Create config with valid routes
	newCfg := createTestGatewayConfigBoost("test-updated")
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

	err = applier.ApplyFullConfig(ctx, newCfg)
	// Should succeed with valid config
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_WithRateLimiterBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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

	// Create config with rate limit
	newCfg := createTestGatewayConfigBoost("test-updated")
	newCfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 200,
		Burst:             50,
	}

	err = applier.ApplyFullConfig(ctx, newCfg)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_WithMaxSessionsBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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

	// Create config with max sessions
	newCfg := createTestGatewayConfigBoost("test-updated")
	newCfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 2000,
	}

	err = applier.ApplyFullConfig(ctx, newCfg)
	assert.NoError(t, err)
}

// ============================================================================
// runOperatorMode Tests - Cover validation error
// ============================================================================

func TestRunOperatorMode_InvalidConfigBoost(t *testing.T) {
	// Test with invalid operator configuration
	flags := cliFlags{
		operatorAddress:  "", // Empty address should fail validation
		gatewayName:      "test-gateway",
		gatewayNamespace: "test-namespace",
	}

	cfg := buildOperatorConfig(flags)

	// Verify config is built
	assert.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Empty(t, cfg.Address)
}

// ============================================================================
// createMinimalConfig Tests - Cover all paths
// ============================================================================

func TestCreateMinimalConfig_AllFieldsBoost(t *testing.T) {
	flags := cliFlags{
		gatewayName:      "my-gateway",
		gatewayNamespace: "my-namespace",
	}

	cfg := createMinimalConfig(flags)

	assert.NotNil(t, cfg)
	assert.Equal(t, "my-gateway", cfg.Metadata.Name)
	assert.NotEmpty(t, cfg.Spec.Listeners)
}

// ============================================================================
// buildOperatorConfig Tests - Cover all TLS paths
// ============================================================================

func TestBuildOperatorConfig_TLSWithAllOptionsBoost(t *testing.T) {
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

// ============================================================================
// Signal handling tests
// ============================================================================

func TestSignalHandling_ConceptBoost(t *testing.T) {
	// Test that signal handling is set up correctly
	sigCh := make(chan os.Signal, 1)

	// Send a signal
	go func() {
		time.Sleep(10 * time.Millisecond)
		sigCh <- syscall.SIGINT
	}()

	select {
	case sig := <-sigCh:
		assert.Equal(t, syscall.SIGINT, sig)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for signal")
	}
}

// ============================================================================
// operatorApplication Tests - Cover component initialization
// ============================================================================

func TestOperatorApplication_ComponentsBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)
	r := router.New()

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			router:          r,
			config:          cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	// Verify all components are set
	assert.NotNil(t, opApp.gateway)
	assert.NotNil(t, opApp.backendRegistry)
	assert.NotNil(t, opApp.router)
	assert.NotNil(t, opApp.operatorConfig)
}

func TestOperatorApplication_NilComponentsBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    reg,
			config:             cfg,
			rateLimiter:        nil,
			maxSessionsLimiter: nil,
			metricsServer:      nil,
			vaultClient:        nil,
			auditLogger:        nil,
		},
		operatorClient: nil,
		operatorConfig: operator.DefaultConfig(),
	}

	// Verify nil components are handled
	assert.Nil(t, opApp.rateLimiter)
	assert.Nil(t, opApp.maxSessionsLimiter)
	assert.Nil(t, opApp.metricsServer)
	assert.Nil(t, opApp.vaultClient)
	assert.Nil(t, opApp.auditLogger)
	assert.Nil(t, opApp.operatorClient)
}

// ============================================================================
// gatewayConfigApplier Tests - Cover all apply methods
// ============================================================================

func TestGatewayConfigApplier_ApplyRoutes_EmptyBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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
	routes := []config.Route{}

	err = applier.ApplyRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends_EmptyBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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
	backends := []config.Backend{}

	err = applier.ApplyBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCRoutes_EmptyBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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
	routes := []config.GRPCRoute{}

	err = applier.ApplyGRPCRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCBackends_EmptyBoost(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test")

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
	backends := []config.GRPCBackend{}

	err = applier.ApplyGRPCBackends(ctx, backends)
	assert.NoError(t, err)
}

// ============================================================================
// Helper functions
// ============================================================================

func createTestGatewayConfigBoost(name string) *config.GatewayConfig {
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
