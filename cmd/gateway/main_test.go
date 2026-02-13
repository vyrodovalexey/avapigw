// Package main provides unit tests for the API Gateway entry point.
package main

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
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
	"github.com/vyrodovalexey/avapigw/internal/router"
)

func TestGetEnvOrDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		expected     string
	}{
		{
			name:         "returns default when env not set",
			key:          "TEST_GETENV_NOTSET",
			defaultValue: "default-value",
			setEnv:       false,
			expected:     "default-value",
		},
		{
			name:         "returns env value when set",
			key:          "TEST_GETENV_SET",
			defaultValue: "default-value",
			envValue:     "env-value",
			setEnv:       true,
			expected:     "env-value",
		},
		{
			name:         "returns default when env is empty string",
			key:          "TEST_GETENV_EMPTY",
			defaultValue: "default-value",
			envValue:     "",
			setEnv:       true,
			expected:     "default-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up env var after test
			defer os.Unsetenv(tt.key)

			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
			}

			result := getEnvOrDefault(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildMiddlewareChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		config        *config.GatewayConfig
		expectRateLim bool
		expectCORS    bool
		expectCircuit bool
	}{
		{
			name: "no optional middleware",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{},
			},
			expectRateLim: false,
			expectCORS:    false,
			expectCircuit: false,
		},
		{
			name: "with rate limiter enabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					RateLimit: &config.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 100,
						Burst:             200,
						PerClient:         false,
					},
				},
			},
			expectRateLim: true,
			expectCORS:    false,
			expectCircuit: false,
		},
		{
			name: "with rate limiter disabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					RateLimit: &config.RateLimitConfig{
						Enabled: false,
					},
				},
			},
			expectRateLim: false,
			expectCORS:    false,
			expectCircuit: false,
		},
		{
			name: "with CORS config",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					CORS: &config.CORSConfig{
						AllowOrigins: []string{"*"},
						AllowMethods: []string{"GET", "POST"},
					},
				},
			},
			expectRateLim: false,
			expectCORS:    true,
			expectCircuit: false,
		},
		{
			name: "with circuit breaker enabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					CircuitBreaker: &config.CircuitBreakerConfig{
						Enabled:          true,
						Threshold:        5,
						Timeout:          config.Duration(30 * time.Second),
						HalfOpenRequests: 3,
					},
				},
			},
			expectRateLim: false,
			expectCORS:    false,
			expectCircuit: true,
		},
		{
			name: "with circuit breaker disabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					CircuitBreaker: &config.CircuitBreakerConfig{
						Enabled: false,
					},
				},
			},
			expectRateLim: false,
			expectCORS:    false,
			expectCircuit: false,
		},
		{
			name: "with all middleware enabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					RateLimit: &config.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 100,
						Burst:             200,
					},
					CircuitBreaker: &config.CircuitBreakerConfig{
						Enabled:          true,
						Threshold:        5,
						Timeout:          config.Duration(30 * time.Second),
						HalfOpenRequests: 3,
					},
					CORS: &config.CORSConfig{
						AllowOrigins: []string{"*"},
					},
				},
			},
			expectRateLim: true,
			expectCORS:    true,
			expectCircuit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a simple handler
			baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			logger := observability.NopLogger()
			metrics := observability.NewMetrics("test")
			tracer, err := observability.NewTracer(observability.TracerConfig{
				ServiceName: "test",
				Enabled:     false,
			})
			require.NoError(t, err)

			result := buildMiddlewareChain(baseHandler, tt.config, logger, metrics, tracer, audit.NewNoopLogger())

			// Verify handler is not nil
			assert.NotNil(t, result.handler)

			// Verify rate limiter is returned when expected
			if tt.expectRateLim {
				assert.NotNil(t, result.rateLimiter, "expected rate limiter to be set")
			} else {
				assert.Nil(t, result.rateLimiter, "expected rate limiter to be nil")
			}

			// Test that the handler chain works
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			result.handler.ServeHTTP(rec, req)

			// Should get a response (may be 200 or other depending on middleware)
			assert.NotEqual(t, 0, rec.Code)
		})
	}
}

func TestCreateMetricsServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		port       int
		path       string
		expectAddr string
	}{
		{
			name:       "default port and path",
			port:       9090,
			path:       "/metrics",
			expectAddr: ":9090",
		},
		{
			name:       "custom port",
			port:       8080,
			path:       "/metrics",
			expectAddr: ":8080",
		},
		{
			name:       "custom path",
			port:       9090,
			path:       "/custom-metrics",
			expectAddr: ":9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			metrics := observability.NewMetrics("test")
			healthChecker := health.NewChecker("test-version", observability.NopLogger())

			server := createMetricsServer(tt.port, tt.path, metrics, healthChecker, logger)

			assert.NotNil(t, server)
			assert.Equal(t, tt.expectAddr, server.Addr)
			assert.NotNil(t, server.Handler)
			assert.Equal(t, 10*time.Second, server.ReadTimeout)
			assert.Equal(t, 5*time.Second, server.ReadHeaderTimeout)
			assert.Equal(t, 10*time.Second, server.WriteTimeout)
		})
	}
}

func TestCreateMetricsServer_Endpoints(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	healthChecker := health.NewChecker("test-version", observability.NopLogger())

	server := createMetricsServer(9090, "/metrics", metrics, healthChecker, logger)

	tests := []struct {
		name       string
		path       string
		expectCode int
	}{
		{
			name:       "metrics endpoint",
			path:       "/metrics",
			expectCode: http.StatusOK,
		},
		{
			name:       "health endpoint",
			path:       "/health",
			expectCode: http.StatusOK,
		},
		{
			name:       "ready endpoint",
			path:       "/ready",
			expectCode: http.StatusOK,
		},
		{
			name:       "live endpoint",
			path:       "/live",
			expectCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			server.Handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectCode, rec.Code)
		})
	}
}

func TestInitTracer(t *testing.T) {
	// Not parallel - tracer initialization may have global state

	tests := []struct {
		name   string
		config *config.GatewayConfig
	}{
		{
			name: "nil observability config",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Observability: nil,
				},
			},
		},
		{
			name: "nil tracing config",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Observability: &config.ObservabilityConfig{
						Tracing: nil,
					},
				},
			},
		},
		{
			name: "tracing disabled",
			config: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					Observability: &config.ObservabilityConfig{
						Tracing: &config.TracingConfig{
							Enabled: false,
						},
					},
				},
			},
		},
		// Note: We skip testing with tracing enabled as it would try to connect
		// to OTLP endpoints and may hang. The tracer initialization with disabled
		// tracing is sufficient for unit testing.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := observability.NopLogger()
			tracer := initTracer(tt.config, logger)

			assert.NotNil(t, tracer)

			// Clean up
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = tracer.Shutdown(ctx)
		})
	}
}

func TestPrintVersion(t *testing.T) {
	// This test just ensures printVersion doesn't panic
	// We can't easily capture stdout in a unit test without more complex setup
	// but we can verify the function exists and runs without error

	// Save original values
	origVersion := version
	origBuildTime := buildTime
	origGitCommit := gitCommit

	// Set test values
	version = "1.0.0-test"
	buildTime = "2024-01-01T00:00:00Z"
	gitCommit = "abc123"

	// Restore after test
	defer func() {
		version = origVersion
		buildTime = origBuildTime
		gitCommit = origGitCommit
	}()

	// Should not panic
	printVersion()
}

func TestCliFlags(t *testing.T) {
	t.Parallel()

	// Test the cliFlags struct
	flags := cliFlags{
		configPath:  "/path/to/config.yaml",
		logLevel:    "debug",
		logFormat:   "json",
		showVersion: true,
	}

	assert.Equal(t, "/path/to/config.yaml", flags.configPath)
	assert.Equal(t, "debug", flags.logLevel)
	assert.Equal(t, "json", flags.logFormat)
	assert.True(t, flags.showVersion)
}

func TestMiddlewareChainResult(t *testing.T) {
	t.Parallel()

	// Test the middlewareChainResult struct
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	result := middlewareChainResult{
		handler:     handler,
		rateLimiter: nil,
	}

	assert.NotNil(t, result.handler)
	assert.Nil(t, result.rateLimiter)
}

func TestApplication(t *testing.T) {
	t.Parallel()

	// Test the application struct fields
	app := &application{
		gateway:         nil,
		backendRegistry: nil,
		healthChecker:   health.NewChecker("test", observability.NopLogger()),
		metrics:         observability.NewMetrics("test"),
		metricsServer:   nil,
		tracer:          nil,
		config:          nil,
		rateLimiter:     nil,
	}

	assert.NotNil(t, app.healthChecker)
	assert.NotNil(t, app.metrics)
}

func TestInitLogger(t *testing.T) {
	// Not parallel - modifies global logger state

	tests := []struct {
		name      string
		flags     cliFlags
		expectErr bool
	}{
		{
			name: "valid json logger",
			flags: cliFlags{
				logLevel:  "info",
				logFormat: "json",
			},
			expectErr: false,
		},
		{
			name: "valid console logger",
			flags: cliFlags{
				logLevel:  "debug",
				logFormat: "console",
			},
			expectErr: false,
		},
		{
			name: "valid warn level",
			flags: cliFlags{
				logLevel:  "warn",
				logFormat: "json",
			},
			expectErr: false,
		},
		{
			name: "valid error level",
			flags: cliFlags{
				logLevel:  "error",
				logFormat: "json",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: initLogger calls os.Exit on error, so we can only test valid cases
			// For invalid cases, we would need to refactor the function or use a different approach

			logger := initLogger(tt.flags)
			assert.NotNil(t, logger)

			// Clean up
			_ = logger.Sync()
		})
	}

	// Reset global logger
	observability.SetGlobalLogger(nil)
}

func TestBuildMiddlewareChain_NilConfigs(t *testing.T) {
	t.Parallel()

	// Test with nil rate limit config
	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			RateLimit:      nil,
			CircuitBreaker: nil,
			CORS:           nil,
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer, audit.NewNoopLogger())

	assert.NotNil(t, result.handler)
	assert.Nil(t, result.rateLimiter)

	// Test the handler works
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	result.handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestBuildMiddlewareChain_PerClientRateLimiter(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
				PerClient:         true,
			},
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer, audit.NewNoopLogger())

	assert.NotNil(t, result.handler)
	assert.NotNil(t, result.rateLimiter)

	// Clean up rate limiter
	result.rateLimiter.Stop()
}

func TestBuildMiddlewareChain_WithMaxSessions(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
			},
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer, audit.NewNoopLogger())

	assert.NotNil(t, result.handler)
	assert.NotNil(t, result.maxSessionsLimiter)

	// Clean up max sessions limiter
	result.maxSessionsLimiter.Stop()
}

func TestBuildMiddlewareChain_WithMaxSessionsDisabled(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			MaxSessions: &config.MaxSessionsConfig{
				Enabled: false,
			},
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer, audit.NewNoopLogger())

	assert.NotNil(t, result.handler)
	assert.Nil(t, result.maxSessionsLimiter)
}

func TestInitTracer_WithCustomServiceName(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Observability: &config.ObservabilityConfig{
				Tracing: &config.TracingConfig{
					Enabled:      false,
					ServiceName:  "custom-service",
					SamplingRate: 0.5,
				},
			},
		},
	}

	tracer := initTracer(cfg, logger)
	assert.NotNil(t, tracer)

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tracer.Shutdown(ctx)
}

func TestInitTracer_WithOTLPEndpoint(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Observability: &config.ObservabilityConfig{
				Tracing: &config.TracingConfig{
					Enabled:      false, // Keep disabled to avoid connection attempts
					OTLPEndpoint: "localhost:4317",
					SamplingRate: 1.0,
				},
			},
		},
	}

	tracer := initTracer(cfg, logger)
	assert.NotNil(t, tracer)

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tracer.Shutdown(ctx)
}

func TestStartMetricsServerIfEnabled_Disabled(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: nil,
			},
		},
	}

	logger := observability.NopLogger()

	// Should not panic and should not start server
	startMetricsServerIfEnabled(app, logger)
	assert.Nil(t, app.metricsServer)
}

func TestStartMetricsServerIfEnabled_MetricsNil(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: &config.ObservabilityConfig{
					Metrics: nil,
				},
			},
		},
	}

	logger := observability.NopLogger()

	startMetricsServerIfEnabled(app, logger)
	assert.Nil(t, app.metricsServer)
}

func TestStartMetricsServerIfEnabled_MetricsDisabled(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: &config.ObservabilityConfig{
					Metrics: &config.MetricsConfig{
						Enabled: false,
					},
				},
			},
		},
	}

	logger := observability.NopLogger()

	startMetricsServerIfEnabled(app, logger)
	assert.Nil(t, app.metricsServer)
}

func TestStartMetricsServerIfEnabled_DefaultValues(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: &config.ObservabilityConfig{
					Metrics: &config.MetricsConfig{
						Enabled: true,
						// Path and Port are zero values
					},
				},
			},
		},
		metrics:       observability.NewMetrics("test"),
		healthChecker: health.NewChecker("test", observability.NopLogger()),
	}

	logger := observability.NopLogger()

	startMetricsServerIfEnabled(app, logger)
	assert.NotNil(t, app.metricsServer)
	assert.Equal(t, ":9090", app.metricsServer.Addr) // Default port

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.metricsServer.Shutdown(ctx)
}

func TestStartMetricsServerIfEnabled_CustomValues(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: &config.ObservabilityConfig{
					Metrics: &config.MetricsConfig{
						Enabled: true,
						Path:    "/custom-metrics",
						Port:    8888,
					},
				},
			},
		},
		metrics:       observability.NewMetrics("test"),
		healthChecker: health.NewChecker("test", observability.NopLogger()),
	}

	logger := observability.NopLogger()

	startMetricsServerIfEnabled(app, logger)
	assert.NotNil(t, app.metricsServer)
	assert.Equal(t, ":8888", app.metricsServer.Addr)

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = app.metricsServer.Shutdown(ctx)
}

func TestRunMetricsServer_ServerClosed(t *testing.T) {
	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	healthChecker := health.NewChecker("test", observability.NopLogger())

	server := createMetricsServer(19999, "/metrics", metrics, healthChecker, logger)

	// Start server in goroutine
	done := make(chan struct{})
	go func() {
		runMetricsServer(server, logger)
		close(done)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := server.Shutdown(ctx)
	assert.NoError(t, err)

	// Wait for goroutine to finish
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestParseFlags_Defaults(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Clear environment variables that might affect defaults
	os.Unsetenv("GATEWAY_CONFIG_PATH")
	os.Unsetenv("GATEWAY_LOG_LEVEL")
	os.Unsetenv("GATEWAY_LOG_FORMAT")

	// Set minimal args
	os.Args = []string{"gateway"}

	// Reset flag.CommandLine to allow re-parsing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flags := parseFlags()

	assert.Equal(t, "configs/gateway.yaml", flags.configPath)
	assert.Equal(t, "info", flags.logLevel)
	assert.Equal(t, "json", flags.logFormat)
	assert.False(t, flags.showVersion)
}

func TestParseFlags_WithEnvVars(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Set environment variables
	os.Setenv("GATEWAY_CONFIG_PATH", "/custom/config.yaml")
	os.Setenv("GATEWAY_LOG_LEVEL", "debug")
	os.Setenv("GATEWAY_LOG_FORMAT", "console")
	defer func() {
		os.Unsetenv("GATEWAY_CONFIG_PATH")
		os.Unsetenv("GATEWAY_LOG_LEVEL")
		os.Unsetenv("GATEWAY_LOG_FORMAT")
	}()

	// Set minimal args
	os.Args = []string{"gateway"}

	// Reset flag.CommandLine to allow re-parsing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flags := parseFlags()

	assert.Equal(t, "/custom/config.yaml", flags.configPath)
	assert.Equal(t, "debug", flags.logLevel)
	assert.Equal(t, "console", flags.logFormat)
}

func TestParseFlags_WithCommandLineArgs(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Clear environment variables
	os.Unsetenv("GATEWAY_CONFIG_PATH")
	os.Unsetenv("GATEWAY_LOG_LEVEL")
	os.Unsetenv("GATEWAY_LOG_FORMAT")

	// Set command line args
	os.Args = []string{
		"gateway",
		"-config", "/path/to/config.yaml",
		"-log-level", "warn",
		"-log-format", "console",
		"-version",
	}

	// Reset flag.CommandLine to allow re-parsing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flags := parseFlags()

	assert.Equal(t, "/path/to/config.yaml", flags.configPath)
	assert.Equal(t, "warn", flags.logLevel)
	assert.Equal(t, "console", flags.logFormat)
	assert.True(t, flags.showVersion)
}

func TestLoadAndValidateConfig_ValidConfig(t *testing.T) {
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

	cfg := loadAndValidateConfig(configPath, logger)

	assert.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)
}

func TestLoadAndValidateConfig_WithGRPCListeners(t *testing.T) {
	// Create a temporary config file with gRPC listeners
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
    - name: grpc
      address: 0.0.0.0
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
	assert.Len(t, cfg.Spec.Listeners, 2)
}

func TestInitTracer_WithAllOptions(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Observability: &config.ObservabilityConfig{
				Tracing: &config.TracingConfig{
					Enabled:      false, // Keep disabled to avoid connection attempts
					ServiceName:  "custom-service",
					SamplingRate: 0.5,
					OTLPEndpoint: "localhost:4317",
				},
			},
		},
	}

	tracer := initTracer(cfg, logger)
	assert.NotNil(t, tracer)

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tracer.Shutdown(ctx)
}

func TestBuildMiddlewareChain_AllMiddlewareEnabled(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
				PerClient:         true,
			},
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          config.Duration(30 * time.Second),
				HalfOpenRequests: 3,
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
			},
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
			},
		},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer, audit.NewNoopLogger())

	assert.NotNil(t, result.handler)
	assert.NotNil(t, result.rateLimiter)
	assert.NotNil(t, result.maxSessionsLimiter)

	// Clean up
	result.rateLimiter.Stop()
	result.maxSessionsLimiter.Stop()
}

func TestCreateMetricsServer_AllEndpoints(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test")
	healthChecker := health.NewChecker("test-version", observability.NopLogger())

	server := createMetricsServer(9091, "/custom-metrics", metrics, healthChecker, logger)

	// Test all endpoints
	endpoints := []struct {
		path       string
		expectCode int
	}{
		{"/custom-metrics", http.StatusOK},
		{"/health", http.StatusOK},
		{"/ready", http.StatusOK},
		{"/live", http.StatusOK},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep.path, nil)
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		assert.Equal(t, ep.expectCode, rec.Code, "endpoint %s should return %d", ep.path, ep.expectCode)
	}
}

func TestVersionVariables(t *testing.T) {
	// Test that version variables are accessible
	assert.NotEmpty(t, version)
	assert.NotEmpty(t, buildTime)
	assert.NotEmpty(t, gitCommit)
}

// ============================================================
// MUST-03: grpcConfigChanged() tests
// ============================================================

func TestGrpcConfigChanged(t *testing.T) {
	t.Parallel()

	cfgWithGRPCRoutes := func(names ...string) *config.GatewayConfig {
		routes := make([]config.GRPCRoute, len(names))
		for i, name := range names {
			routes[i] = config.GRPCRoute{
				Name: name,
				Match: []config.GRPCRouteMatch{
					{Service: &config.StringMatch{Exact: "test.Service"}},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 50052}},
				},
			}
		}
		return &config.GatewayConfig{
			Spec: config.GatewaySpec{
				GRPCRoutes: routes,
			},
		}
	}

	cfgWithGRPCBackends := func(names ...string) *config.GatewayConfig {
		backends := make([]config.GRPCBackend, len(names))
		for i, name := range names {
			backends[i] = config.GRPCBackend{
				Name: name,
				Hosts: []config.BackendHost{
					{Address: "localhost", Port: 50052},
				},
			}
		}
		return &config.GatewayConfig{
			Spec: config.GatewaySpec{
				GRPCBackends: backends,
			},
		}
	}

	cfgWithRoutesAndBackends := func(routeNames, backendNames []string) *config.GatewayConfig {
		routes := make([]config.GRPCRoute, len(routeNames))
		for i, name := range routeNames {
			routes[i] = config.GRPCRoute{
				Name: name,
				Match: []config.GRPCRouteMatch{
					{Service: &config.StringMatch{Exact: "test.Service"}},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 50052}},
				},
			}
		}
		backends := make([]config.GRPCBackend, len(backendNames))
		for i, name := range backendNames {
			backends[i] = config.GRPCBackend{
				Name: name,
				Hosts: []config.BackendHost{
					{Address: "localhost", Port: 50052},
				},
			}
		}
		return &config.GatewayConfig{
			Spec: config.GatewaySpec{
				GRPCRoutes:   routes,
				GRPCBackends: backends,
			},
		}
	}

	tests := []struct {
		name     string
		oldCfg   *config.GatewayConfig
		newCfg   *config.GatewayConfig
		expected bool
	}{
		{
			name:     "both nil - no change",
			oldCfg:   nil,
			newCfg:   nil,
			expected: false,
		},
		{
			name:     "old nil new has gRPC routes - changed",
			oldCfg:   nil,
			newCfg:   cfgWithGRPCRoutes("route-a"),
			expected: true,
		},
		{
			name:     "old has gRPC routes new nil - changed",
			oldCfg:   cfgWithGRPCRoutes("route-a"),
			newCfg:   nil,
			expected: true,
		},
		{
			name:     "same empty configs - no change",
			oldCfg:   &config.GatewayConfig{},
			newCfg:   &config.GatewayConfig{},
			expected: false,
		},
		{
			name:     "same gRPC routes count and names - no change",
			oldCfg:   cfgWithGRPCRoutes("route-a", "route-b"),
			newCfg:   cfgWithGRPCRoutes("route-a", "route-b"),
			expected: false,
		},
		{
			name:     "different gRPC routes count - changed",
			oldCfg:   cfgWithGRPCRoutes("route-a"),
			newCfg:   cfgWithGRPCRoutes("route-a", "route-b"),
			expected: true,
		},
		{
			name:     "same count but different route names - changed",
			oldCfg:   cfgWithGRPCRoutes("route-a"),
			newCfg:   cfgWithGRPCRoutes("route-b"),
			expected: true,
		},
		{
			name:     "same gRPC backends count and names - no change",
			oldCfg:   cfgWithGRPCBackends("backend-a", "backend-b"),
			newCfg:   cfgWithGRPCBackends("backend-a", "backend-b"),
			expected: false,
		},
		{
			name:     "different gRPC backends count - changed",
			oldCfg:   cfgWithGRPCBackends("backend-a"),
			newCfg:   cfgWithGRPCBackends("backend-a", "backend-b"),
			expected: true,
		},
		{
			name:     "same count but different backend names - changed",
			oldCfg:   cfgWithGRPCBackends("backend-a"),
			newCfg:   cfgWithGRPCBackends("backend-b"),
			expected: true,
		},
		{
			name:     "same routes and backends - no change",
			oldCfg:   cfgWithRoutesAndBackends([]string{"route-a"}, []string{"backend-a"}),
			newCfg:   cfgWithRoutesAndBackends([]string{"route-a"}, []string{"backend-a"}),
			expected: false,
		},
		{
			name:     "same routes different backends - changed",
			oldCfg:   cfgWithRoutesAndBackends([]string{"route-a"}, []string{"backend-a"}),
			newCfg:   cfgWithRoutesAndBackends([]string{"route-a"}, []string{"backend-b"}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := grpcConfigChanged(tt.oldCfg, tt.newCfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestReloadComponents_GRPCConfigChanged tests that reloadComponents logs a warning
// when gRPC configuration has changed.
func TestReloadComponents_GRPCConfigChanged(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")
	cfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "old-grpc-route",
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
	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "new-grpc-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.NewService"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50053}},
			},
		},
	}

	// Should not panic; gRPC config change warning is logged
	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

// validGatewayConfig creates a valid GatewayConfig for testing.
func validGatewayConfig(name string) *config.GatewayConfig {
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

func TestReloadComponents_AllComponents(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")
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

	newCfg := validGatewayConfig("test-updated")
	newCfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 200,
		Burst:             400,
	}
	newCfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 100,
	}

	reloadComponents(context.Background(), app, newCfg, logger)

	// Verify config was updated
	assert.Equal(t, newCfg, app.config)
}

func TestReloadComponents_NilMiddleware(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	// All middleware components are nil
	app := &application{
		gateway: gw,
		config:  cfg,
	}

	newCfg := validGatewayConfig("test-updated")

	// Should not panic with nil components
	reloadComponents(context.Background(), app, newCfg, logger)
	assert.Equal(t, newCfg, app.config)
}

func TestReloadComponents_InvalidConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway: gw,
		config:  cfg,
	}

	// Invalid config (missing required fields)
	invalidCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: ""},
		Spec:     config.GatewaySpec{},
	}

	// Should not panic; gateway.Reload will reject invalid config
	reloadComponents(context.Background(), app, invalidCfg, logger)

	// Config should NOT be updated since reload failed
	assert.Equal(t, cfg, app.config)
}
