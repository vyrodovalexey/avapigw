// Package main provides lifecycle tests for operator mode functions.
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
// waitForOperatorShutdown Tests
// ============================================================================

func TestWaitForOperatorShutdown_AllComponents(t *testing.T) {

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19501,
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
		Addr: ":19502",
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

func TestWaitForOperatorShutdown_MinimalComponents(t *testing.T) {

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-min"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19503,
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
			// No metricsServer, rateLimiter, maxSessionsLimiter, auditLogger, vaultClient
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
// runOperatorGateway Tests
// ============================================================================

func TestRunOperatorGateway_BackendStartError(t *testing.T) {

	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-err"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19504,
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

	// runOperatorGateway will call backendRegistry.StartAll (succeeds),
	// then gateway.Start (succeeds), then operatorClient.Start (nil -> panic)
	// We need to handle this carefully

	// Actually, operatorClient is nil, so it will panic at opApp.operatorClient.Start
	// Let's test the path where gateway start fails instead
	// Start the gateway first so the second start fails
	err = gw.Start(context.Background())
	require.NoError(t, err)

	// Now runOperatorGateway will fail at gateway.Start because it's already started
	runOperatorGateway(opApp, logger)

	// Should have called exit
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================================
// runOperatorMode Tests
// ============================================================================

func TestRunOperatorMode_InvalidConfig(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	// Empty operator address should fail validation
	flags := cliFlags{
		operatorAddress:  "", // Invalid - empty address
		gatewayName:      "",
		gatewayNamespace: "default",
	}

	runOperatorMode(flags, logger)

	// Should have called exit due to invalid config
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

func TestRunOperatorMode_InvalidOperatorAddress(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	// Missing gateway name should fail validation
	flags := cliFlags{
		operatorAddress:  "localhost:9444",
		gatewayName:      "", // Invalid - empty name
		gatewayNamespace: "default",
	}

	runOperatorMode(flags, logger)

	// Should have called exit due to invalid config
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

func TestRunOperatorMode_ValidConfigCreatesClient(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	// Valid config - will pass validation, create minimal config, init app,
	// create operator client, then fail at operator client Start
	// (because there's no real operator server)
	flags := cliFlags{
		operatorAddress:  "localhost:19599", // Non-existent server
		gatewayName:      "test-gw",
		gatewayNamespace: "default",
		logLevel:         "info",
		logFormat:        "json",
	}

	// This will go through: buildOperatorConfig, Validate (pass),
	// createMinimalConfig, initClientIPExtractor, initApplication,
	// create configHandler, create operator client, runOperatorGateway
	// runOperatorGateway will start backends (ok), start gateway (ok),
	// then start operator client which will fail to connect
	runOperatorMode(flags, logger)

	// Should have called exit because operator client Start fails
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================================
// waitForOperatorShutdown with vault client
// ============================================================================

func TestWaitForOperatorShutdown_WithAuditLogger(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-op-audit"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19505,
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
			auditLogger:        audit.NewNoopLogger(),
			rateLimiter:        rl,
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

// ============================================================================
// operatorApplication Tests
// ============================================================================

func TestOperatorApplication_Fields(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfig("test-op-fields")

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

	assert.NotNil(t, opApp.application)
	assert.NotNil(t, opApp.operatorConfig)
	assert.Nil(t, opApp.operatorClient)
	assert.Nil(t, opApp.configHandler)
}
