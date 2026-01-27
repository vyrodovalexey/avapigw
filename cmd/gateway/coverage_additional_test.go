// Package main provides additional unit tests for coverage improvement.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
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

// ============================================================
// startConfigWatcher coverage
// ============================================================

func TestStartConfigWatcher_ValidConfig(t *testing.T) {
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
      port: 8080
      protocol: HTTP
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	logger := observability.NopLogger()

	// Create a minimal gateway for the app
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     18080,
					Protocol: config.ProtocolHTTP,
				},
			},
		},
	}

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway: gw,
		config:  cfg,
	}

	watcher := startConfigWatcher(app, configPath, logger)
	assert.NotNil(t, watcher)

	// Clean up
	if watcher != nil {
		_ = watcher.Stop()
	}
}

// Note: Testing startConfigWatcher with invalid paths is not feasible because
// the config.Watcher is resilient and creates watchers even for non-existent paths.
// The valid path test above covers the main code path.

// ============================================================
// waitForShutdown coverage
// Note: These tests send SIGINT to the process, so they must
// run sequentially (not parallel) to avoid interference.
// ============================================================

func TestWaitForShutdown_AllPaths(t *testing.T) {
	// This test covers multiple paths of waitForShutdown sequentially
	// to avoid signal interference between parallel tests.

	t.Run("with_basic_shutdown", func(t *testing.T) {
		logger := observability.NopLogger()

		cfg := &config.GatewayConfig{
			Metadata: config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "http",
						Bind:     "127.0.0.1",
						Port:     19080,
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

		rateLimiter := middleware.NewRateLimiter(100, 200, false)
		maxSessionsLimiter := middleware.NewMaxSessionsLimiter(100, 0, 0)

		app := &application{
			gateway:            gw,
			backendRegistry:    backendReg,
			healthChecker:      health.NewChecker("test"),
			metrics:            observability.NewMetrics("test"),
			tracer:             tracer,
			config:             cfg,
			rateLimiter:        rateLimiter,
			maxSessionsLimiter: maxSessionsLimiter,
		}

		done := make(chan struct{})
		go func() {
			waitForShutdown(app, nil, logger)
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
			t.Fatal("waitForShutdown did not complete in time")
		}
	})

	t.Run("with_watcher_and_limiters", func(t *testing.T) {
		logger := observability.NopLogger()

		// Create a temp config file for the watcher
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
      port: 8080
      protocol: HTTP
  routes: []
  backends: []
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		cfg := &config.GatewayConfig{
			Metadata: config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "http",
						Bind:     "127.0.0.1",
						Port:     19082,
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

		// Create a watcher
		watcher, err := config.NewWatcher(configPath, func(newCfg *config.GatewayConfig) {
			// no-op callback
		}, config.WithLogger(logger))
		require.NoError(t, err)
		err = watcher.Start(context.Background())
		require.NoError(t, err)

		app := &application{
			gateway:         gw,
			backendRegistry: backendReg,
			healthChecker:   health.NewChecker("test"),
			metrics:         observability.NewMetrics("test"),
			tracer:          tracer,
			config:          cfg,
		}

		done := make(chan struct{})
		go func() {
			waitForShutdown(app, watcher, logger)
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
			t.Fatal("waitForShutdown did not complete in time")
		}
	})

	t.Run("with_metrics_server", func(t *testing.T) {
		logger := observability.NopLogger()

		cfg := &config.GatewayConfig{
			Metadata: config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "http",
						Bind:     "127.0.0.1",
						Port:     19081,
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

		metricsServer := &http.Server{
			Addr:    ":0",
			Handler: http.NewServeMux(),
		}

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		go func() { _ = metricsServer.Serve(listener) }()

		app := &application{
			gateway:         gw,
			backendRegistry: backendReg,
			healthChecker:   health.NewChecker("test"),
			metrics:         observability.NewMetrics("test"),
			metricsServer:   metricsServer,
			tracer:          tracer,
			config:          cfg,
		}

		done := make(chan struct{})
		go func() {
			waitForShutdown(app, nil, logger)
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
			t.Fatal("waitForShutdown did not complete in time")
		}
	})
}

// ============================================================
// initApplication coverage
// ============================================================

func TestInitApplication_ValidConfig(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-app"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19083,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes:   []config.Route{},
			Backends: []config.Backend{},
		},
	}

	app := initApplication(cfg, logger)
	assert.NotNil(t, app)
	assert.NotNil(t, app.gateway)
	assert.NotNil(t, app.backendRegistry)
	assert.NotNil(t, app.healthChecker)
	assert.NotNil(t, app.metrics)
	assert.NotNil(t, app.tracer)
	assert.Equal(t, cfg, app.config)

	// Clean up tracer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.tracer.Shutdown(ctx)
}

func TestInitApplication_WithObservability(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-app"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19084,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes:   []config.Route{},
			Backends: []config.Backend{},
			Observability: &config.ObservabilityConfig{
				Tracing: &config.TracingConfig{
					Enabled:     false,
					ServiceName: "test-service",
				},
			},
		},
	}

	app := initApplication(cfg, logger)
	assert.NotNil(t, app)
	assert.NotNil(t, app.tracer)

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.tracer.Shutdown(ctx)
}

func TestInitApplication_WithRateLimit(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-app"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19085,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes:   []config.Route{},
			Backends: []config.Backend{},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
		},
	}

	app := initApplication(cfg, logger)
	assert.NotNil(t, app)
	assert.NotNil(t, app.rateLimiter)

	// Clean up
	if app.rateLimiter != nil {
		app.rateLimiter.Stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.tracer.Shutdown(ctx)
}

func TestInitApplication_WithMaxSessions(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-app"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19086,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes:   []config.Route{},
			Backends: []config.Backend{},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 50,
			},
		},
	}

	app := initApplication(cfg, logger)
	assert.NotNil(t, app)
	assert.NotNil(t, app.maxSessionsLimiter)

	// Clean up
	if app.maxSessionsLimiter != nil {
		app.maxSessionsLimiter.Stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.tracer.Shutdown(ctx)
}

// ============================================================
// runMetricsServer coverage: error path
// ============================================================

func TestRunMetricsServer_ListenError(t *testing.T) {
	logger := observability.NopLogger()

	// Create a server on a port that's already in use
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port

	// Create a second server on the same port - this will fail
	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: http.NewServeMux(),
	}

	done := make(chan struct{})
	go func() {
		runMetricsServer(server, logger)
		close(done)
	}()

	// Wait for the error to occur
	select {
	case <-done:
		// Success - server exited with error
	case <-time.After(2 * time.Second):
		t.Fatal("runMetricsServer did not exit in time")
	}

	// Clean up the original listener
	listener.Close()
}

// ============================================================
// loadAndValidateConfig coverage: additional paths
// ============================================================

func TestLoadAndValidateConfig_WithMixedListeners(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/gateway.yaml"

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway-coverage
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
    - name: grpc
      port: 50051
      protocol: GRPC
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	logger := observability.NopLogger()
	cfg := loadAndValidateConfig(configPath, logger)

	assert.NotNil(t, cfg)
	assert.Equal(t, "test-gateway-coverage", cfg.Metadata.Name)
	assert.Len(t, cfg.Spec.Listeners, 2)
}

// ============================================================
// initTracer coverage: additional paths
// ============================================================

func TestInitTracer_WithEmptyServiceName(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Observability: &config.ObservabilityConfig{
				Tracing: &config.TracingConfig{
					Enabled:      false,
					ServiceName:  "", // Empty service name should use default
					SamplingRate: 1.0,
				},
			},
		},
	}

	tracer := initTracer(cfg, logger)
	assert.NotNil(t, tracer)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tracer.Shutdown(ctx)
}

// ============================================================
// initAuditLogger coverage
// ============================================================

// TestInitAuditLogger tests all initAuditLogger code paths.
// audit.NewLogger uses promauto which registers metrics with the global
// Prometheus registry and panics on duplicate registration. Therefore,
// only ONE subtest may create a real (enabled) audit logger. The enabled
// test covers all config mapping paths in a single call.
func TestInitAuditLogger(t *testing.T) {
	// Not parallel - audit logger creates global Prometheus metrics

	t.Run("nil_config", func(t *testing.T) {
		logger := observability.NopLogger()
		cfg := &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Audit: nil,
			},
		}

		auditLogger := initAuditLogger(cfg, logger)

		assert.NotNil(t, auditLogger)
		assert.NoError(t, auditLogger.Close())
	})

	t.Run("disabled", func(t *testing.T) {
		logger := observability.NopLogger()
		cfg := &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Audit: &config.AuditConfig{
					Enabled: false,
				},
			},
		}

		auditLogger := initAuditLogger(cfg, logger)

		assert.NotNil(t, auditLogger)
		assert.NoError(t, auditLogger.Close())
	})

	// This single test covers the full enabled path with all config options:
	// - Enabled=true (real logger creation)
	// - Empty output (defaults to stdout)
	// - Events config mapping
	// - SkipPaths mapping
	// - RedactFields mapping
	// Only ONE enabled test is allowed due to promauto global registration.
	t.Run("enabled_with_all_options", func(t *testing.T) {
		logger := observability.NopLogger()
		cfg := &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Audit: &config.AuditConfig{
					Enabled:      true,
					Output:       "", // Empty output should default to stdout
					Format:       "json",
					Level:        "info",
					SkipPaths:    []string{"/health", "/ready", "/metrics"},
					RedactFields: []string{"password", "token", "authorization"},
					Events: &config.AuditEventsConfig{
						Authentication: true,
						Authorization:  true,
						Request:        true,
						Response:       true,
						Configuration:  true,
						Security:       true,
					},
				},
			},
		}

		auditLogger := initAuditLogger(cfg, logger)

		assert.NotNil(t, auditLogger)
		assert.NoError(t, auditLogger.Close())
	})
}

// Verify that initAuditLogger is called during initApplication with audit disabled.
func TestInitApplication_WithAuditDisabled(t *testing.T) {
	// Not parallel - creates global Prometheus metrics
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-app-no-audit"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19088,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes:   []config.Route{},
			Backends: []config.Backend{},
			Audit: &config.AuditConfig{
				Enabled: false,
			},
		},
	}

	app := initApplication(cfg, logger)
	assert.NotNil(t, app)
	assert.NotNil(t, app.auditLogger) // Should be noop logger

	// Clean up
	_ = app.auditLogger.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.tracer.Shutdown(ctx)
}

// Verify the waitForShutdown closes audit logger.
func TestWaitForShutdown_WithAuditLogger(t *testing.T) {
	// Not parallel - sends SIGINT to process
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     19089,
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
		healthChecker:   health.NewChecker("test"),
		metrics:         observability.NewMetrics("test"),
		tracer:          tracer,
		config:          cfg,
		auditLogger:     audit.NewNoopLogger(),
	}

	done := make(chan struct{})
	go func() {
		waitForShutdown(app, nil, logger)
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
		t.Fatal("waitForShutdown did not complete in time")
	}
}
