// Package main provides additional unit tests for coverage improvement.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
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
					Port:     0,
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

	watcher := startConfigWatcher(context.Background(), app, configPath, logger)
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

		rateLimiter := middleware.NewRateLimiter(100, 200, false)
		maxSessionsLimiter := middleware.NewMaxSessionsLimiter(100, 0, 0)

		app := &application{
			gateway:            gw,
			backendRegistry:    backendReg,
			healthChecker:      health.NewChecker("test", observability.NopLogger()),
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
			healthChecker:   health.NewChecker("test", observability.NopLogger()),
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
			healthChecker:   health.NewChecker("test", observability.NopLogger()),
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
					Port:     0,
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
					Port:     0,
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
					Port:     0,
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
					Port:     0,
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

		// Use a fresh Prometheus registry to avoid duplicate metric registration panics
		reg := prometheus.NewRegistry()
		auditLogger := initAuditLogger(cfg, logger, audit.WithLoggerRegisterer(reg))

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
					Port:     0,
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

// ============================================================
// initClientIPExtractor coverage
// ============================================================

func TestInitClientIPExtractor_WithTrustedProxies(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
	}

	// Should not panic
	initClientIPExtractor(cfg, logger)

	// Verify the global extractor was set by making a request
	// from a trusted proxy with XFF header
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	clientIP := middleware.GetClientIP(req)
	assert.Equal(t, "203.0.113.50", clientIP)
}

func TestInitClientIPExtractor_NoTrustedProxies(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			TrustedProxies: nil,
		},
	}

	// Should not panic
	initClientIPExtractor(cfg, logger)

	// Without trusted proxies, XFF should be ignored
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	clientIP := middleware.GetClientIP(req)
	assert.Equal(t, "192.168.1.1", clientIP)
}

func TestInitClientIPExtractor_EmptyProxies(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			TrustedProxies: []string{},
		},
	}

	// Should not panic with empty proxies list
	assert.NotPanics(t, func() {
		initClientIPExtractor(cfg, logger)
	}, "initClientIPExtractor should not panic with empty proxies")
}

// ============================================================
// reloadComponents coverage: route reload error path
// ============================================================

func TestReloadComponents_NilRouter(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		router:          nil, // nil router
		config:          cfg,
	}

	newCfg := validGatewayConfig("test-updated")

	// Should not panic; router is nil so route reload is skipped
	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

func TestReloadComponents_WithRouterAndRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

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

	// Create new config with valid routes
	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.Routes = []config.Route{
		{
			Name: "test-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}

	// Should reload routes successfully
	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

func TestReloadComponents_NilBackendRegistry(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: nil, // nil backend registry
		config:          cfg,
	}

	newCfg := validGatewayConfig("test-updated")

	// Should not panic; backend registry is nil so backend reload is skipped
	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

func TestReloadComponents_BackendReloadError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		config:          cfg,
	}

	// Create new config with invalid backends (no hosts)
	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.Backends = []config.Backend{
		{
			Name:  "invalid-backend",
			Hosts: []config.BackendHost{}, // Invalid: no hosts
		},
	}

	// Should not panic; backend reload error is logged
	reloadComponents(context.Background(), app, newCfg, logger)
	// Config is still updated because gateway.Reload succeeded
	// but backend reload error is logged
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
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
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

// ============================================================
// fatalWithSync coverage (via injectable exitFunc)
// ============================================================

// TestFatalWithSync tests that fatalWithSync logs, syncs, and calls exitFunc.
// Not parallel — modifies package-level exitFunc.
func TestFatalWithSync(t *testing.T) {
	// Save and restore original exitFunc
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	fatalWithSync(logger, "test fatal message", observability.String("key", "value"))

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================
// initLogger error path coverage (via injectable exitFunc)
// ============================================================

// TestInitLogger_InvalidLevel tests initLogger with an invalid log level.
// Not parallel — modifies package-level exitFunc.
func TestInitLogger_InvalidLevel(t *testing.T) {
	// Save and restore original exitFunc
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	flags := cliFlags{
		logLevel:  "INVALID_LEVEL_XYZ",
		logFormat: "json",
	}

	result := initLogger(flags)

	// initLogger should have called exitFunc(1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	// result is nil because the mock exitFunc doesn't actually exit
	assert.Nil(t, result)
}

// ============================================================
// loadAndValidateConfig error paths coverage (via injectable exitFunc)
// ============================================================

// TestLoadAndValidateConfig_FileNotFound tests loadAndValidateConfig with missing file.
// Not parallel — modifies package-level exitFunc.
func TestLoadAndValidateConfig_FileNotFound(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	// This will fail to load config and call fatalWithSync -> exitFunc
	cfg := loadAndValidateConfig("/nonexistent/path/config.yaml", logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, cfg)
}

// TestLoadAndValidateConfig_InvalidConfig tests loadAndValidateConfig with invalid config.
// Not parallel — modifies package-level exitFunc.
func TestLoadAndValidateConfig_InvalidConfig(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Create a config file that loads but fails validation (missing required fields)
	tmpDir := t.TempDir()
	configPath := tmpDir + "/gateway.yaml"
	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: ""
spec:
  listeners: []
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	logger := observability.NopLogger()

	cfg := loadAndValidateConfig(configPath, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, cfg)
}

// ============================================================
// startConfigWatcher error paths coverage
// ============================================================

// Note: Testing startConfigWatcher error paths is not feasible because:
// 1. config.NewWatcher always succeeds for any valid filepath.Abs input
// 2. watcher.Start failure leaves the watcher in a state where Stop() blocks
//    forever (stoppedCh is never closed since watch goroutine was never started)
// The valid path test (TestStartConfigWatcher_ValidConfig) covers the main code path.

// ============================================================
// reloadComponents: route reload error path
// ============================================================

// TestReloadComponents_RouteLoadError tests reloadComponents when route loading fails.
func TestReloadComponents_RouteLoadError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

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

	// Create new config with duplicate route names — this triggers a route load error
	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.Routes = []config.Route{
		{
			Name:  "duplicate-route",
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend-a", Port: 8080}}},
		},
		{
			Name:  "duplicate-route", // Duplicate name causes error
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend-b", Port: 8080}}},
		},
	}

	// Should not panic; gateway.Reload may reject the config with duplicate routes,
	// or route reload error is logged. Either way, the function should not panic.
	reloadComponents(context.Background(), app, newCfg, logger)
}

// ============================================================
// reloadComponents: rate limiter and max sessions update paths
// ============================================================

// TestReloadComponents_RateLimiterUpdate tests reloadComponents updates rate limiter.
func TestReloadComponents_RateLimiterUpdate(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	rl := middleware.NewRateLimiter(100, 200, false)
	defer rl.Stop()

	app := &application{
		gateway:     gw,
		config:      cfg,
		rateLimiter: rl,
	}

	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 500,
		Burst:             1000,
	}

	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

// TestReloadComponents_MaxSessionsUpdate tests reloadComponents updates max sessions.
func TestReloadComponents_MaxSessionsUpdate(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	msl := middleware.NewMaxSessionsLimiter(50, 0, 0)
	defer msl.Stop()

	app := &application{
		gateway:            gw,
		config:             cfg,
		maxSessionsLimiter: msl,
	}

	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 200,
	}

	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

// ============================================================
// reloadComponents: gateway reload error path
// ============================================================

// TestReloadComponents_GatewayReloadError tests reloadComponents when gateway.Reload fails.
func TestReloadComponents_GatewayReloadError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway: gw,
		config:  cfg,
	}

	// Create an invalid config that will cause gateway.Reload to fail
	invalidCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: ""},
		Spec:     config.GatewaySpec{},
	}

	reloadComponents(context.Background(), app, invalidCfg, logger)

	// Config should NOT be updated since gateway.Reload failed
	assert.Equal(t, cfg, app.config)
}

// ============================================================
// initApplication error paths coverage (via injectable exitFunc)
// ============================================================

// TestInitApplication_BackendLoadError tests initApplication when backend loading fails.
// Not parallel — modifies package-level exitFunc.
func TestInitApplication_BackendLoadError(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-app"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0,
					Protocol: config.ProtocolHTTP,
				},
			},
			Routes: []config.Route{},
			Backends: []config.Backend{
				{
					Name:  "invalid-backend",
					Hosts: []config.BackendHost{}, // Invalid: no hosts
				},
			},
		},
	}

	result := initApplication(cfg, logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, result)
}

// Note: Testing initApplication route load error is difficult because
// router.LoadRoutes accepts most route configurations without error.
// The backend load error test above covers the fatalWithSync path in initApplication.

// Note: Testing initApplication gateway creation error is difficult because
// gateway.New accepts most configurations. The backend load error test above
// covers the fatalWithSync path in initApplication.

// ============================================================
// initAuditLogger error path coverage
// ============================================================

// Note: Testing initAuditLogger creation error is not feasible because
// audit.NewLogger uses promauto which registers global Prometheus metrics
// and panics on duplicate registration. The enabled test in TestInitAuditLogger
// already covers the creation path.

// ============================================================
// runGateway coverage (via injectable exitFunc)
// ============================================================

// TestRunGateway_HappyPath tests runGateway with a valid config and signal shutdown.
// Not parallel — sends SIGINT to process.
func TestRunGateway_HappyPath(t *testing.T) {
	logger := observability.NopLogger()

	// Create a valid config file for the watcher
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
      bind: 127.0.0.1
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

	reg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
		metrics:         observability.NewMetrics("test"),
		tracer:          tracer,
		config:          cfg,
	}

	done := make(chan struct{})
	go func() {
		runGateway(app, configPath, logger)
		close(done)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Send SIGINT to trigger shutdown
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("runGateway did not complete in time")
	}
}

// ============================================================
// waitForShutdown error paths coverage
// ============================================================

// TestRunGateway_GatewayStartError tests runGateway when gateway.Start fails.
// Not parallel — modifies package-level exitFunc.
func TestRunGateway_GatewayStartError(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
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

	// Start the gateway first so that runGateway's Start call will fail
	err = gw.Start(context.Background())
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	app := &application{
		gateway:         gw,
		backendRegistry: reg,
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
		metrics:         observability.NewMetrics("test"),
		tracer:          tracer,
		config:          cfg,
	}

	// runGateway should call fatalWithSync when gateway.Start fails
	runGateway(app, t.TempDir()+"/config.yaml", logger)

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = gw.Stop(ctx)
}

// TestWaitForShutdown_MetricsServerShutdownError tests waitForShutdown when
// metrics server shutdown fails.
func TestWaitForShutdown_MetricsServerShutdownError(t *testing.T) {
	// Not parallel — sends SIGINT to process
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
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

	// Create a metrics server that's already closed — Shutdown will fail
	metricsServer := &http.Server{
		Addr:    ":0",
		Handler: http.NewServeMux(),
	}
	// Start and immediately close the listener to put server in a bad state
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = metricsServer.Serve(listener) }()
	time.Sleep(50 * time.Millisecond)
	// Shutdown the server first, then try to shutdown again in waitForShutdown
	_ = metricsServer.Shutdown(context.Background())

	app := &application{
		gateway:         gw,
		backendRegistry: backendReg,
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
		metrics:         observability.NewMetrics("test"),
		metricsServer:   metricsServer,
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
