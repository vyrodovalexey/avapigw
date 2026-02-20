package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// waitForDrain Tests
// ============================================================================

// TestWaitForDrain_NilHealthChecker tests that waitForDrain returns immediately
// when healthChecker is nil.
func TestWaitForDrain_NilHealthChecker(t *testing.T) {
	t.Parallel()

	app := &application{
		healthChecker: nil,
	}

	ctx := context.Background()
	logger := observability.NopLogger()

	// Should return immediately without panic
	waitForDrain(ctx, app, logger)
}

// TestWaitForDrain_NormalCompletion tests that waitForDrain completes normally
// when the drain timer fires before context expires.
func TestWaitForDrain_NormalCompletion(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	app := &application{
		healthChecker: checker,
	}

	// Use a context with a long timeout so the drain timer fires first
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	start := time.Now()
	waitForDrain(ctx, app, logger)
	elapsed := time.Since(start)

	// Should have waited approximately drainWaitDuration (5s)
	// But we can't wait that long in tests, so just verify it set draining
	assert.True(t, checker.IsDraining())
	// The drain wait is 5 seconds, so elapsed should be >= 5s
	assert.GreaterOrEqual(t, elapsed, 4*time.Second)
}

// TestWaitForDrain_ContextExpiry tests that waitForDrain returns early
// when the context expires before the drain wait completes.
func TestWaitForDrain_ContextExpiry(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	app := &application{
		healthChecker: checker,
	}

	// Use a very short context timeout so it expires before drain wait (5s)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	logger := observability.NopLogger()

	start := time.Now()
	waitForDrain(ctx, app, logger)
	elapsed := time.Since(start)

	// Should have returned early due to context expiry
	assert.True(t, checker.IsDraining())
	// Should have returned much faster than the 5s drain wait
	assert.Less(t, elapsed, 2*time.Second)
}

// TestWaitForDrain_AlreadyCancelledContext tests waitForDrain with an already
// cancelled context.
func TestWaitForDrain_AlreadyCancelledContext(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	app := &application{
		healthChecker: checker,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	logger := observability.NopLogger()

	start := time.Now()
	waitForDrain(ctx, app, logger)
	elapsed := time.Since(start)

	// Should return almost immediately
	assert.True(t, checker.IsDraining())
	assert.Less(t, elapsed, 1*time.Second)
}

// ============================================================================
// stopCoreServices Tests
// ============================================================================

// Uses mockVaultClientForShutdown and errorAuditLogger90 from other test files.

// TestStopCoreServices_AllComponents tests stopCoreServices with all components present.
func TestStopCoreServices_AllComponents(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-stop-all"},
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

	// Create and start a metrics server
	metricsServer := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}
	go func() {
		_ = metricsServer.ListenAndServe()
	}()
	time.Sleep(50 * time.Millisecond)

	app := &application{
		gateway:            gw,
		backendRegistry:    backendReg,
		tracer:             tracer,
		config:             cfg,
		rateLimiter:        rl,
		maxSessionsLimiter: msl,
		metricsServer:      metricsServer,
		vaultClient:        &mockVaultClientForShutdown{closeErr: nil},
		auditLogger:        audit.NewNoopLogger(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should not panic
	stopCoreServices(ctx, app, logger)
}

// TestStopCoreServices_WithErrors tests stopCoreServices when components return errors.
func TestStopCoreServices_WithErrors(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-stop-errors"},
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

	app := &application{
		gateway:         gw,
		backendRegistry: backendReg,
		tracer:          tracer,
		config:          cfg,
		vaultClient:     &mockVaultClientForShutdown{closeErr: errors.New("vault close error")},
		auditLogger:     &errorAuditLogger90{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should not panic even with errors
	stopCoreServices(ctx, app, logger)
}

// TestStopCoreServices_NilComponents tests stopCoreServices with nil optional components.
func TestStopCoreServices_NilComponents(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-stop-nil"},
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

	app := &application{
		gateway:            gw,
		backendRegistry:    backendReg,
		tracer:             tracer,
		config:             cfg,
		metricsServer:      nil, // nil metrics server
		vaultClient:        nil, // nil vault client
		rateLimiter:        nil, // nil rate limiter
		maxSessionsLimiter: nil, // nil max sessions limiter
		auditLogger:        nil, // nil audit logger
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should not panic with nil components
	stopCoreServices(ctx, app, logger)
}
