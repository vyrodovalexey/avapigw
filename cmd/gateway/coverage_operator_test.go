// Package main provides additional unit tests to boost cmd/gateway operator mode coverage.
package main

import (
	"context"
	"net"
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
// waitForOperatorShutdown Tests - Cover more paths
// ============================================================================

func TestWaitForOperatorShutdown_WithMetricsServer(t *testing.T) {
	logger := observability.NopLogger()

	// Use port 0 to get a random available port
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-metrics"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0, // Use dynamic port
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

	// Create a real metrics server with dynamic port
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	metricsServer := &http.Server{}
	go func() {
		_ = metricsServer.Serve(metricsListener)
	}()
	time.Sleep(50 * time.Millisecond)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
			metricsServer:   metricsServer,
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

func TestWaitForOperatorShutdown_WithRateLimiter(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-rl"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0, // Use dynamic port
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

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: backendReg,
			tracer:          tracer,
			config:          cfg,
			rateLimiter:     rl,
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

func TestWaitForOperatorShutdown_WithMaxSessionsLimiter(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-msl"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0, // Use dynamic port
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

	msl := middleware.NewMaxSessionsLimiter(100, 0, 0)

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    backendReg,
			tracer:             tracer,
			config:             cfg,
			maxSessionsLimiter: msl,
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

func TestWaitForOperatorShutdown_WithAuditLoggerCoverage(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-audit-cov"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0, // Use dynamic port
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
// runOperatorGateway Tests - Cover more paths
// ============================================================================

func TestRunOperatorGateway_GatewayStartError(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-gw-err"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0, // Use dynamic port
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
		operatorClient: nil,
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
// gatewayConfigApplier Tests - Cover more paths
// ============================================================================

func TestGatewayConfigApplier_ApplyFullConfig_NilRouterAndRegistry(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigOperator("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: nil, // nil registry
			router:          nil, // nil router
			config:          cfg,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()
	newCfg := createTestGatewayConfigOperator("test-updated")
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
}

func TestGatewayConfigApplier_ApplyFullConfig_WithGRPCConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigOperator("test")

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
	newCfg := createTestGatewayConfigOperator("test-updated")
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
// operatorApplication Tests - Cover more fields
// ============================================================================

func TestOperatorApplication_AllFields(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigOperator("test-op-all")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)
	hc := health.NewChecker("test", logger)
	metrics := observability.NewMetrics("test")
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
			backendRegistry:    reg,
			router:             r,
			healthChecker:      hc,
			metrics:            metrics,
			tracer:             tracer,
			config:             cfg,
			auditLogger:        audit.NewAtomicAuditLogger(audit.NewNoopLogger()),
			rateLimiter:        rl,
			maxSessionsLimiter: msl,
		},
		operatorConfig: operator.DefaultConfig(),
	}

	assert.NotNil(t, opApp.application)
	assert.NotNil(t, opApp.gateway)
	assert.NotNil(t, opApp.backendRegistry)
	assert.NotNil(t, opApp.router)
	assert.NotNil(t, opApp.healthChecker)
	assert.NotNil(t, opApp.metrics)
	assert.NotNil(t, opApp.tracer)
	assert.NotNil(t, opApp.config)
	assert.NotNil(t, opApp.auditLogger)
	assert.NotNil(t, opApp.rateLimiter)
	assert.NotNil(t, opApp.maxSessionsLimiter)
	assert.NotNil(t, opApp.operatorConfig)
}

// ============================================================================
// Helper functions
// ============================================================================

func createTestGatewayConfigOperator(name string) *config.GatewayConfig {
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
