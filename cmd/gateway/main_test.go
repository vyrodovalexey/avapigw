// Package main provides unit tests for the API Gateway entry point.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
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

			result := buildMiddlewareChain(baseHandler, tt.config, logger, metrics, tracer)

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
			healthChecker := health.NewChecker("test-version")

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
	healthChecker := health.NewChecker("test-version")

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
		healthChecker:   health.NewChecker("test"),
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

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer)

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

	result := buildMiddlewareChain(baseHandler, cfg, logger, metrics, tracer)

	assert.NotNil(t, result.handler)
	assert.NotNil(t, result.rateLimiter)

	// Clean up rate limiter
	result.rateLimiter.Stop()
}
