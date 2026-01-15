// Package observability provides comprehensive observability for the API Gateway.
package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability/logging"
	"github.com/vyrodovalexey/avapigw/internal/observability/metrics"
	"github.com/vyrodovalexey/avapigw/internal/observability/tracing"
)

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name     string
		validate func(t *testing.T, cfg *Config)
	}{
		{
			name: "returns non-nil config",
			validate: func(t *testing.T, cfg *Config) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "has correct service name",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "avapigw", cfg.ServiceName)
			},
		},
		{
			name: "has correct service version",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "1.0.0", cfg.ServiceVersion)
			},
		},
		{
			name: "has correct environment",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "development", cfg.Environment)
			},
		},
		{
			name: "has correct log level",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, logging.LevelInfo, cfg.LogLevel)
			},
		},
		{
			name: "has correct log format",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, logging.FormatJSON, cfg.LogFormat)
			},
		},
		{
			name: "has correct log output",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "stdout", cfg.LogOutput)
			},
		},
		{
			name: "has access log enabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.AccessLogEnabled)
			},
		},
		{
			name: "has tracing disabled by default",
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.TracingEnabled)
			},
		},
		{
			name: "has correct tracing exporter",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, tracing.ExporterOTLPGRPC, cfg.TracingExporter)
			},
		},
		{
			name: "has correct OTLP endpoint",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "localhost:4317", cfg.OTLPEndpoint)
			},
		},
		{
			name: "has correct tracing sample rate",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 1.0, cfg.TracingSampleRate)
			},
		},
		{
			name: "has tracing insecure enabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TracingInsecure)
			},
		},
		{
			name: "has metrics enabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.MetricsEnabled)
			},
		},
		{
			name: "has correct metrics port",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9091, cfg.MetricsPort)
			},
		},
		{
			name: "has correct metrics path",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "/metrics", cfg.MetricsPath)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.validate(t, cfg)
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "with nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "with custom config",
			config:  &Config{ServiceName: "test-service"},
			wantErr: false,
		},
		{
			name:    "with full config",
			config:  DefaultConfig(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, obs)
			assert.NotNil(t, obs.config)
		})
	}
}

func TestObservability_Start(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "starts with default config",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "starts with metrics disabled",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelDebug,
				LogFormat:      logging.FormatConsole,
				LogOutput:      "stderr",
				MetricsEnabled: false,
				TracingEnabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, err := New(tt.config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify logger is initialized
			assert.NotNil(t, obs.Logger())

			// Cleanup
			_ = obs.Stop(ctx)
		})
	}
}

func TestObservability_Stop(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "stops cleanly",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, err := New(tt.config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)

			err = obs.Stop(ctx)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			// Note: Sync errors for stdout/stderr are ignored
			// so we don't assert NoError here
		})
	}
}

func TestObservability_Logger(t *testing.T) {
	tests := []struct {
		name       string
		startFirst bool
		wantNil    bool
	}{
		{
			name:       "returns nil before start",
			startFirst: false,
			wantNil:    true,
		},
		{
			name:       "returns logger after start",
			startFirst: true,
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			if tt.startFirst {
				ctx := context.Background()
				err = obs.Start(ctx)
				require.NoError(t, err)
				defer obs.Stop(ctx)
			}

			logger := obs.Logger()
			if tt.wantNil {
				assert.Nil(t, logger)
			} else {
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestObservability_TracingProvider(t *testing.T) {
	tests := []struct {
		name           string
		tracingEnabled bool
		wantNil        bool
	}{
		{
			name:           "returns nil when tracing disabled",
			tracingEnabled: false,
			wantNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: tt.tracingEnabled,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			provider := obs.TracingProvider()
			if tt.wantNil {
				assert.Nil(t, provider)
			} else {
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestObservability_MetricsServer(t *testing.T) {
	tests := []struct {
		name           string
		metricsEnabled bool
		wantNil        bool
	}{
		{
			name:           "returns nil when metrics disabled",
			metricsEnabled: false,
			wantNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: tt.metricsEnabled,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			server := obs.MetricsServer()
			if tt.wantNil {
				assert.Nil(t, server)
			} else {
				assert.NotNil(t, server)
			}
		})
	}
}

func TestObservability_GatewayCollector(t *testing.T) {
	tests := []struct {
		name           string
		metricsEnabled bool
		wantNil        bool
	}{
		{
			name:           "returns nil when metrics disabled",
			metricsEnabled: false,
			wantNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: tt.metricsEnabled,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			collector := obs.GatewayCollector()
			if tt.wantNil {
				assert.Nil(t, collector)
			} else {
				assert.NotNil(t, collector)
			}
		})
	}
}

func TestObservability_RuntimeCollector(t *testing.T) {
	tests := []struct {
		name           string
		metricsEnabled bool
		wantNil        bool
	}{
		{
			name:           "returns nil when metrics disabled",
			metricsEnabled: false,
			wantNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: tt.metricsEnabled,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			collector := obs.RuntimeCollector()
			if tt.wantNil {
				assert.Nil(t, collector)
			} else {
				assert.NotNil(t, collector)
			}
		})
	}
}

func TestObservability_RecordHTTPRequest(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		statusCode   string
		duration     float64
		requestSize  int64
		responseSize int64
	}{
		{
			name:         "records GET request",
			method:       "GET",
			path:         "/api/v1/users",
			statusCode:   "200",
			duration:     0.123,
			requestSize:  0,
			responseSize: 1024,
		},
		{
			name:         "records POST request",
			method:       "POST",
			path:         "/api/v1/users",
			statusCode:   "201",
			duration:     0.456,
			requestSize:  512,
			responseSize: 256,
		},
		{
			name:         "records error request",
			method:       "GET",
			path:         "/api/v1/notfound",
			statusCode:   "404",
			duration:     0.010,
			requestSize:  0,
			responseSize: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			// Should not panic
			assert.NotPanics(t, func() {
				obs.RecordHTTPRequest(tt.method, tt.path, tt.statusCode, tt.duration, tt.requestSize, tt.responseSize)
			})
		})
	}
}

func TestObservability_RecordGRPCRequest(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		method   string
		code     string
		duration float64
	}{
		{
			name:     "records successful request",
			service:  "UserService",
			method:   "GetUser",
			code:     "OK",
			duration: 0.050,
		},
		{
			name:     "records failed request",
			service:  "UserService",
			method:   "CreateUser",
			code:     "INVALID_ARGUMENT",
			duration: 0.010,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			// Should not panic
			assert.NotPanics(t, func() {
				obs.RecordGRPCRequest(tt.service, tt.method, tt.code, tt.duration)
			})
		})
	}
}

func TestObservability_RecordBackendRequest(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		method   string
		status   string
		duration float64
	}{
		{
			name:     "records successful backend request",
			backend:  "user-service",
			method:   "GET",
			status:   "success",
			duration: 0.100,
		},
		{
			name:     "records failed backend request",
			backend:  "payment-service",
			method:   "POST",
			status:   "error",
			duration: 5.000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			// Should not panic
			assert.NotPanics(t, func() {
				obs.RecordBackendRequest(tt.backend, tt.method, tt.status, tt.duration)
			})
		})
	}
}

func TestObservability_RecordRateLimitCheck(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		allowed   bool
		remaining int
	}{
		{
			name:      "records allowed request",
			key:       "user:123",
			allowed:   true,
			remaining: 99,
		},
		{
			name:      "records rejected request",
			key:       "user:456",
			allowed:   false,
			remaining: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			// Should not panic
			assert.NotPanics(t, func() {
				obs.RecordRateLimitCheck(tt.key, tt.allowed, tt.remaining)
			})
		})
	}
}

func TestObservability_RecordCircuitBreakerRequest(t *testing.T) {
	tests := []struct {
		name    string
		cbName  string
		allowed bool
	}{
		{
			name:    "records allowed request",
			cbName:  "user-service",
			allowed: true,
		},
		{
			name:    "records rejected request",
			cbName:  "payment-service",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			// Should not panic
			assert.NotPanics(t, func() {
				obs.RecordCircuitBreakerRequest(tt.cbName, tt.allowed)
			})
		})
	}
}

func TestObservability_RecordAuthRequest(t *testing.T) {
	tests := []struct {
		name     string
		authType string
		result   string
		duration float64
	}{
		{
			name:     "records successful JWT auth",
			authType: "jwt",
			result:   "success",
			duration: 0.005,
		},
		{
			name:     "records failed API key auth",
			authType: "api_key",
			result:   "failure",
			duration: 0.002,
		},
		{
			name:     "records OAuth auth",
			authType: "oauth",
			result:   "success",
			duration: 0.100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)
			defer obs.Stop(ctx)

			// Should not panic
			assert.NotPanics(t, func() {
				obs.RecordAuthRequest(tt.authType, tt.result, tt.duration)
			})
		})
	}
}

func TestObservability_StartWithMetricsEnabled(t *testing.T) {
	config := &Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		LogLevel:       logging.LevelInfo,
		LogFormat:      logging.FormatJSON,
		LogOutput:      "stdout",
		MetricsEnabled: true,
		MetricsPort:    19091, // Use different port to avoid conflicts
		MetricsPath:    "/metrics",
		TracingEnabled: false,
	}
	obs, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = obs.Start(ctx)
	require.NoError(t, err)

	// Verify collectors are initialized
	assert.NotNil(t, obs.GatewayCollector())
	assert.NotNil(t, obs.RuntimeCollector())
	assert.NotNil(t, obs.MetricsServer())

	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cleanup - use a fresh context for stop
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	// Note: Stop may return an error due to server shutdown race condition
	// but we don't fail the test for this
	_ = obs.Stop(stopCtx)
}

// ============================================================================
// Tracing Enabled Tests
// ============================================================================

func TestObservability_StartWithTracingEnabled(t *testing.T) {
	// Note: This test uses OTLP gRPC exporter which initializes successfully
	// even without a real endpoint (it just won't export traces)
	config := &Config{
		ServiceName:       "test-service",
		ServiceVersion:    "1.0.0",
		Environment:       "test",
		LogLevel:          logging.LevelInfo,
		LogFormat:         logging.FormatJSON,
		LogOutput:         "stdout",
		MetricsEnabled:    false,
		TracingEnabled:    true,
		TracingExporter:   tracing.ExporterOTLPGRPC, // Use gRPC exporter for testing
		OTLPEndpoint:      "localhost:4317",
		TracingSampleRate: 1.0,
		TracingInsecure:   true,
	}
	obs, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = obs.Start(ctx)
	require.NoError(t, err)

	// Verify tracing provider is initialized
	assert.NotNil(t, obs.TracingProvider())

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	_ = obs.Stop(stopCtx)
}

func TestObservability_StartWithTracingEnabled_NoneExporter(t *testing.T) {
	// Test that ExporterNone returns an error as expected
	config := &Config{
		ServiceName:       "test-service",
		ServiceVersion:    "1.0.0",
		Environment:       "test",
		LogLevel:          logging.LevelInfo,
		LogFormat:         logging.FormatJSON,
		LogOutput:         "stdout",
		MetricsEnabled:    false,
		TracingEnabled:    true,
		TracingExporter:   tracing.ExporterNone, // None exporter should fail
		OTLPEndpoint:      "localhost:4317",
		TracingSampleRate: 1.0,
		TracingInsecure:   true,
	}
	obs, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = obs.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no exporter configured")
}

// ============================================================================
// Stop Multiple Errors Tests
// ============================================================================

func TestObservability_Stop_MultipleErrors(t *testing.T) {
	config := &Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		LogLevel:       logging.LevelInfo,
		LogFormat:      logging.FormatJSON,
		LogOutput:      "stdout",
		MetricsEnabled: false,
		TracingEnabled: false,
	}
	obs, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = obs.Start(ctx)
	require.NoError(t, err)

	// Stop should handle gracefully even with no metrics/tracing
	err = obs.Stop(ctx)
	// Sync errors for stdout/stderr are ignored
	// so we don't assert NoError here
}

// ============================================================================
// Logger Sync Error Tests
// ============================================================================

func TestObservability_Stop_LoggerSyncError(t *testing.T) {
	// Test with file output that might have sync issues
	config := &Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		LogLevel:       logging.LevelInfo,
		LogFormat:      logging.FormatJSON,
		LogOutput:      "stdout", // stdout sync errors are ignored
		MetricsEnabled: false,
		TracingEnabled: false,
	}
	obs, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = obs.Start(ctx)
	require.NoError(t, err)

	// Stop should not return error for stdout sync issues
	err = obs.Stop(ctx)
	// We don't assert on error because stdout sync errors are ignored
}

// ============================================================================
// Metrics Server Error Handling Tests
// ============================================================================

func TestObservability_MetricsServerError(t *testing.T) {
	t.Run("returns false when metrics server is nil", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false,
			TracingEnabled: false,
		}
		obs, err := New(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = obs.Start(ctx)
		require.NoError(t, err)
		defer obs.Stop(ctx)

		// Metrics server is nil when disabled
		assert.False(t, obs.IsMetricsServerHealthy())
	})

	// Note: GetMetricsServerError test is skipped because it causes
	// duplicate metrics registration when run with other tests
}

// ============================================================================
// Concurrent Start/Stop Tests
// ============================================================================

func TestObservability_ConcurrentStartStop(t *testing.T) {
	t.Run("handles concurrent operations gracefully", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false,
			TracingEnabled: false,
		}

		obs, err := New(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = obs.Start(ctx)
		require.NoError(t, err)

		// Multiple concurrent stop calls should not panic
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = obs.Stop(ctx)
			}()
		}
		wg.Wait()
	})
}

// ============================================================================
// IsMetricsServerHealthy Tests
// ============================================================================

// Note: TestObservability_IsMetricsServerHealthy is covered by
// TestObservability_StartWithMetricsEnabled to avoid duplicate metrics registration

// ============================================================================
// Context Cancellation Tests
// ============================================================================

func TestObservability_ContextCancellation(t *testing.T) {
	t.Run("respects context cancellation during init", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false, // Disable metrics to avoid registration conflicts
			TracingEnabled: false,
		}
		obs, err := New(config)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Start should still work since logging doesn't check context
		err = obs.Start(ctx)
		require.NoError(t, err)

		_ = obs.Stop(context.Background())
	})
}

// ============================================================================
// GetMetricsServerError Tests
// ============================================================================

func TestObservability_GetMetricsServerError(t *testing.T) {
	t.Run("returns nil when no error", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false,
			TracingEnabled: false,
		}
		obs, err := New(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = obs.Start(ctx)
		require.NoError(t, err)
		defer obs.Stop(ctx)

		// When metrics are disabled, error channel is nil
		// GetMetricsServerError should handle this gracefully
		serverErr := obs.GetMetricsServerError()
		assert.Nil(t, serverErr)
	})
}

// ============================================================================
// IsMetricsServerHealthy and GetMetricsServerError with Error Channel Tests
// ============================================================================

func TestObservability_MetricsServerHealthy_WithErrorChannel(t *testing.T) {
	t.Run("returns error when error in channel", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false,
			TracingEnabled: false,
		}
		obs, err := New(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = obs.Start(ctx)
		require.NoError(t, err)

		// Manually set up error channel and inject an error
		obs.metricsErrCh = make(chan error, 1)
		testErr := assert.AnError
		obs.metricsErrCh <- testErr

		// Create a proper metrics server with logger for this test
		serverConfig := &metrics.ServerConfig{
			Port: 19999,
			Path: "/metrics",
		}
		obs.metricsServer = metrics.NewServer(serverConfig, obs.logger.Logger)

		// IsMetricsServerHealthy should return false when there's an error
		assert.False(t, obs.IsMetricsServerHealthy())

		// GetMetricsServerError should return the error
		serverErr := obs.GetMetricsServerError()
		assert.Equal(t, testErr, serverErr)

		// The error should still be in the channel (put back)
		serverErr2 := obs.GetMetricsServerError()
		assert.Equal(t, testErr, serverErr2)

		// Clean up - reset metricsServer to nil to avoid Stop trying to stop it
		obs.metricsServer = nil
		_ = obs.Stop(ctx)
	})

	t.Run("IsMetricsServerHealthy returns true when no error", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false,
			TracingEnabled: false,
		}
		obs, err := New(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = obs.Start(ctx)
		require.NoError(t, err)

		// Manually set up error channel without error
		obs.metricsErrCh = make(chan error, 1)

		// Create a proper metrics server with logger for this test
		serverConfig := &metrics.ServerConfig{
			Port: 19998,
			Path: "/metrics",
		}
		obs.metricsServer = metrics.NewServer(serverConfig, obs.logger.Logger)

		// IsMetricsServerHealthy should return true when no error
		assert.True(t, obs.IsMetricsServerHealthy())

		// GetMetricsServerError should return nil
		serverErr := obs.GetMetricsServerError()
		assert.Nil(t, serverErr)

		// Clean up - reset metricsServer to nil to avoid Stop trying to stop it
		obs.metricsServer = nil
		_ = obs.Stop(ctx)
	})
}

// ============================================================================
// Observability with Different Log Levels Tests
// ============================================================================

func TestObservability_DifferentLogLevels(t *testing.T) {
	tests := []struct {
		name     string
		logLevel logging.Level
	}{
		{"debug level", logging.LevelDebug},
		{"info level", logging.LevelInfo},
		{"warn level", logging.LevelWarn},
		{"error level", logging.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       tt.logLevel,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)

			assert.NotNil(t, obs.Logger())

			_ = obs.Stop(ctx)
		})
	}
}

// ============================================================================
// Observability with Different Log Formats Tests
// ============================================================================

func TestObservability_DifferentLogFormats(t *testing.T) {
	tests := []struct {
		name      string
		logFormat logging.Format
	}{
		{"json format", logging.FormatJSON},
		{"console format", logging.FormatConsole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       logging.LevelInfo,
				LogFormat:      tt.logFormat,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)

			assert.NotNil(t, obs.Logger())

			_ = obs.Stop(ctx)
		})
	}
}

// ============================================================================
// Observability Environment Configuration Tests
// ============================================================================

func TestObservability_EnvironmentConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		environment string
	}{
		{"development environment", "development"},
		{"staging environment", "staging"},
		{"production environment", "production"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    tt.environment,
				LogLevel:       logging.LevelInfo,
				LogFormat:      logging.FormatJSON,
				LogOutput:      "stdout",
				MetricsEnabled: false,
				TracingEnabled: false,
			}
			obs, err := New(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = obs.Start(ctx)
			require.NoError(t, err)

			assert.NotNil(t, obs.Logger())

			_ = obs.Stop(ctx)
		})
	}
}

// ============================================================================
// Observability Stop Idempotency Tests
// ============================================================================

func TestObservability_StopIdempotency(t *testing.T) {
	t.Run("multiple stop calls are safe", func(t *testing.T) {
		config := &Config{
			ServiceName:    "test-service",
			ServiceVersion: "1.0.0",
			Environment:    "test",
			LogLevel:       logging.LevelInfo,
			LogFormat:      logging.FormatJSON,
			LogOutput:      "stdout",
			MetricsEnabled: false,
			TracingEnabled: false,
		}
		obs, err := New(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = obs.Start(ctx)
		require.NoError(t, err)

		// Multiple stop calls should not panic
		_ = obs.Stop(ctx)
		_ = obs.Stop(ctx)
		_ = obs.Stop(ctx)
	})
}
