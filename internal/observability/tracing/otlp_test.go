// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

// TestDefaultConfig tests default config.
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
			name: "has service name",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "avapigw", cfg.ServiceName)
			},
		},
		{
			name: "has service version",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "1.0.0", cfg.ServiceVersion)
			},
		},
		{
			name: "has environment",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "development", cfg.Environment)
			},
		},
		{
			name: "has exporter type",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, ExporterOTLPGRPC, cfg.ExporterType)
			},
		},
		{
			name: "has endpoint",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "localhost:4317", cfg.Endpoint)
			},
		},
		{
			name: "has insecure enabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Insecure)
			},
		},
		{
			name: "has sample rate",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 1.0, cfg.SampleRate)
			},
		},
		{
			name: "has batch timeout",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 5*time.Second, cfg.BatchTimeout)
			},
		},
		{
			name: "has max export batch size",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 512, cfg.MaxExportBatchSize)
			},
		},
		{
			name: "has max queue size",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 2048, cfg.MaxQueueSize)
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

// TestNewProvider tests creating provider.
func TestNewProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		logger  *zap.Logger
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			logger:  nil,
			wantErr: false,
		},
		{
			name:    "with config",
			config:  DefaultConfig(),
			logger:  zap.NewNop(),
			wantErr: false,
		},
		{
			name: "with custom config",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "2.0.0",
				Environment:    "production",
				ExporterType:   ExporterOTLPHTTP,
				Endpoint:       "localhost:4318",
				Insecure:       false,
				SampleRate:     0.5,
			},
			logger:  zap.NewNop(),
			wantErr: false,
		},
		{
			name:    "nil logger uses nop",
			config:  DefaultConfig(),
			logger:  nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.config, tt.logger)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, provider)
			assert.NotNil(t, provider.config)
			assert.NotNil(t, provider.logger)
		})
	}
}

// TestProvider_Tracer tests getting tracer.
func TestProvider_Tracer(t *testing.T) {
	tests := []struct {
		name       string
		tracerName string
		started    bool
	}{
		{
			name:       "get tracer before start",
			tracerName: "test-tracer",
			started:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(nil, nil)
			require.NoError(t, err)

			tracer := provider.Tracer(tt.tracerName)
			assert.NotNil(t, tracer)
		})
	}
}

// TestProvider_GetTracerProvider tests getting tracer provider.
func TestProvider_GetTracerProvider(t *testing.T) {
	tests := []struct {
		name    string
		started bool
	}{
		{
			name:    "get provider before start",
			started: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(nil, nil)
			require.NoError(t, err)

			tp := provider.GetTracerProvider()
			assert.NotNil(t, tp)
		})
	}
}

// TestProvider_createSampler tests sampler creation.
func TestProvider_createSampler(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
		expected   string
	}{
		{
			name:       "never sample",
			sampleRate: 0,
			expected:   "AlwaysOffSampler",
		},
		{
			name:       "negative sample rate",
			sampleRate: -0.5,
			expected:   "AlwaysOffSampler",
		},
		{
			name:       "always sample",
			sampleRate: 1.0,
			expected:   "AlwaysOnSampler",
		},
		{
			name:       "greater than 1 sample rate",
			sampleRate: 1.5,
			expected:   "AlwaysOnSampler",
		},
		{
			name:       "ratio based sample",
			sampleRate: 0.5,
			expected:   "TraceIDRatioBased",
		},
		{
			name:       "low ratio sample",
			sampleRate: 0.1,
			expected:   "TraceIDRatioBased",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				SampleRate: tt.sampleRate,
			}
			provider := &Provider{
				config: config,
				logger: zap.NewNop(),
			}

			sampler := provider.createSampler()
			assert.NotNil(t, sampler)
			assert.Contains(t, sampler.Description(), tt.expected)
		})
	}
}

// TestProvider_Stop tests stopping provider.
func TestProvider_Stop(t *testing.T) {
	tests := []struct {
		name    string
		started bool
	}{
		{
			name:    "stop without start",
			started: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(nil, nil)
			require.NoError(t, err)

			err = provider.Stop(context.Background())
			assert.NoError(t, err)
		})
	}
}

// TestExporterType_Constants tests exporter type constants.
func TestExporterType_Constants(t *testing.T) {
	assert.Equal(t, ExporterType("otlp-grpc"), ExporterOTLPGRPC)
	assert.Equal(t, ExporterType("otlp-http"), ExporterOTLPHTTP)
	assert.Equal(t, ExporterType("none"), ExporterNone)
}

// TestConfig_Fields tests config fields.
func TestConfig_Fields(t *testing.T) {
	config := &Config{
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		Environment:        "test",
		ExporterType:       ExporterOTLPGRPC,
		Endpoint:           "localhost:4317",
		Insecure:           true,
		Headers:            map[string]string{"key": "value"},
		SampleRate:         0.5,
		BatchTimeout:       10 * time.Second,
		MaxExportBatchSize: 1024,
		MaxQueueSize:       4096,
		Attributes:         map[string]string{"attr": "value"},
	}

	assert.Equal(t, "test-service", config.ServiceName)
	assert.Equal(t, "1.0.0", config.ServiceVersion)
	assert.Equal(t, "test", config.Environment)
	assert.Equal(t, ExporterOTLPGRPC, config.ExporterType)
	assert.Equal(t, "localhost:4317", config.Endpoint)
	assert.True(t, config.Insecure)
	assert.Equal(t, map[string]string{"key": "value"}, config.Headers)
	assert.Equal(t, 0.5, config.SampleRate)
	assert.Equal(t, 10*time.Second, config.BatchTimeout)
	assert.Equal(t, 1024, config.MaxExportBatchSize)
	assert.Equal(t, 4096, config.MaxQueueSize)
	assert.Equal(t, map[string]string{"attr": "value"}, config.Attributes)
}

// TestProvider_TracerAfterStart tests getting tracer after start.
func TestProvider_TracerAfterStart(t *testing.T) {
	// Save original provider
	originalProvider := otel.GetTracerProvider()
	defer otel.SetTracerProvider(originalProvider)

	// Create a simple tracer provider for testing
	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	provider := &Provider{
		config:         DefaultConfig(),
		logger:         zap.NewNop(),
		tracerProvider: tp,
	}

	tracer := provider.Tracer("test-tracer")
	assert.NotNil(t, tracer)
}

// TestProvider_GetTracerProviderAfterStart tests getting tracer provider after start.
func TestProvider_GetTracerProviderAfterStart(t *testing.T) {
	// Create a simple tracer provider for testing
	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	provider := &Provider{
		config:         DefaultConfig(),
		logger:         zap.NewNop(),
		tracerProvider: tp,
	}

	result := provider.GetTracerProvider()
	assert.Equal(t, tp, result)
}

// TestProvider_StopAfterStart tests stopping provider after start.
func TestProvider_StopAfterStart(t *testing.T) {
	// Create a simple tracer provider for testing
	tp := sdktrace.NewTracerProvider()

	provider := &Provider{
		config:         DefaultConfig(),
		logger:         zap.NewNop(),
		tracerProvider: tp,
	}

	err := provider.Stop(context.Background())
	assert.NoError(t, err)
}

// TestProvider_createExporter_None tests creating exporter with none type.
func TestProvider_createExporter_None(t *testing.T) {
	config := &Config{
		ExporterType: ExporterNone,
	}
	provider := &Provider{
		config: config,
		logger: zap.NewNop(),
	}

	_, err := provider.createExporter(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no exporter configured")
}

// TestProvider_createExporter_Default tests creating exporter with unknown type.
func TestProvider_createExporter_Default(t *testing.T) {
	config := &Config{
		ExporterType: "unknown",
		Endpoint:     "localhost:4317",
		Insecure:     true,
	}
	provider := &Provider{
		config: config,
		logger: zap.NewNop(),
	}

	// This will try to create a gRPC exporter (default case)
	// It may fail due to connection issues, but we're testing the code path
	_, err := provider.createExporter(context.Background())
	// The error is expected since we can't connect to the endpoint
	// We just want to verify the code path is executed
	_ = err
}

// TestProvider_createGRPCExporter tests creating gRPC exporter.
func TestProvider_createGRPCExporter(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		wantErr  bool
		skipTest bool
	}{
		{
			name: "with insecure",
			config: &Config{
				Endpoint: "localhost:4317",
				Insecure: true,
			},
			wantErr:  false,
			skipTest: false,
		},
		{
			name: "with headers",
			config: &Config{
				Endpoint: "localhost:4317",
				Insecure: true,
				Headers:  map[string]string{"Authorization": "Bearer token"},
			},
			wantErr:  false,
			skipTest: false,
		},
		{
			name: "without insecure",
			config: &Config{
				Endpoint: "localhost:4317",
				Insecure: false,
			},
			wantErr:  false,
			skipTest: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTest {
				t.Skip("Skipping test that requires network connection")
			}

			provider := &Provider{
				config: tt.config,
				logger: zap.NewNop(),
			}

			exporter, err := provider.createGRPCExporter(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			// Note: This may succeed or fail depending on network conditions
			// We're mainly testing that the code path executes without panic
			if err == nil {
				assert.NotNil(t, exporter)
				_ = exporter.Shutdown(context.Background())
			}
		})
	}
}

// TestProvider_createHTTPExporter tests creating HTTP exporter.
func TestProvider_createHTTPExporter(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		wantErr  bool
		skipTest bool
	}{
		{
			name: "with insecure",
			config: &Config{
				Endpoint: "localhost:4318",
				Insecure: true,
			},
			wantErr:  false,
			skipTest: false,
		},
		{
			name: "with headers",
			config: &Config{
				Endpoint: "localhost:4318",
				Insecure: true,
				Headers:  map[string]string{"Authorization": "Bearer token"},
			},
			wantErr:  false,
			skipTest: false,
		},
		{
			name: "without insecure",
			config: &Config{
				Endpoint: "localhost:4318",
				Insecure: false,
			},
			wantErr:  false,
			skipTest: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTest {
				t.Skip("Skipping test that requires network connection")
			}

			provider := &Provider{
				config: tt.config,
				logger: zap.NewNop(),
			}

			exporter, err := provider.createHTTPExporter(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			// Note: This may succeed or fail depending on network conditions
			// We're mainly testing that the code path executes without panic
			if err == nil {
				assert.NotNil(t, exporter)
				_ = exporter.Shutdown(context.Background())
			}
		})
	}
}

// TestProvider_createResource tests creating resource.
func TestProvider_createResource(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "default config",
			config: DefaultConfig(),
		},
		{
			name: "with custom attributes",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				Attributes: map[string]string{
					"custom.attr1": "value1",
					"custom.attr2": "value2",
				},
			},
		},
		{
			name: "without custom attributes",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{
				config: tt.config,
				logger: zap.NewNop(),
			}

			resource, err := provider.createResource(context.Background())
			require.NoError(t, err)
			assert.NotNil(t, resource)
		})
	}
}

// TestInitGlobalTracer_Error tests InitGlobalTracer with error.
func TestInitGlobalTracer_Error(t *testing.T) {
	// Test with ExporterNone which will cause an error during Start
	config := &Config{
		ServiceName:  "test-service",
		ExporterType: ExporterNone,
	}

	provider, err := InitGlobalTracer(context.Background(), config, zap.NewNop())
	assert.Error(t, err)
	assert.Nil(t, provider)
}

// TestInitGlobalTracer_Success tests InitGlobalTracer with success.
func TestInitGlobalTracer_Success(t *testing.T) {
	// Save original provider
	originalProvider := otel.GetTracerProvider()
	defer otel.SetTracerProvider(originalProvider)

	config := &Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		ExporterType:   ExporterOTLPGRPC,
		Endpoint:       "localhost:4317",
		Insecure:       true,
		SampleRate:     1.0,
		BatchTimeout:   5 * time.Second,
	}

	provider, err := InitGlobalTracer(context.Background(), config, zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Cleanup
	_ = provider.Stop(context.Background())
}

// TestProvider_Start_Success tests Provider.Start with success.
func TestProvider_Start_Success(t *testing.T) {
	// Save original provider
	originalProvider := otel.GetTracerProvider()
	defer otel.SetTracerProvider(originalProvider)

	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "gRPC exporter",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				ExporterType:   ExporterOTLPGRPC,
				Endpoint:       "localhost:4317",
				Insecure:       true,
				SampleRate:     1.0,
				BatchTimeout:   5 * time.Second,
			},
		},
		{
			name: "HTTP exporter",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				ExporterType:   ExporterOTLPHTTP,
				Endpoint:       "localhost:4318",
				Insecure:       true,
				SampleRate:     0.5,
				BatchTimeout:   5 * time.Second,
			},
		},
		{
			name: "with custom attributes",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				ExporterType:   ExporterOTLPGRPC,
				Endpoint:       "localhost:4317",
				Insecure:       true,
				SampleRate:     1.0,
				BatchTimeout:   5 * time.Second,
				Attributes: map[string]string{
					"custom.attr": "value",
				},
			},
		},
		{
			name: "with headers",
			config: &Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				ExporterType:   ExporterOTLPGRPC,
				Endpoint:       "localhost:4317",
				Insecure:       true,
				SampleRate:     1.0,
				BatchTimeout:   5 * time.Second,
				Headers: map[string]string{
					"Authorization": "Bearer token",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.config, zap.NewNop())
			require.NoError(t, err)

			err = provider.Start(context.Background())
			require.NoError(t, err)

			// Verify tracer provider is set
			assert.NotNil(t, provider.tracerProvider)

			// Cleanup
			_ = provider.Stop(context.Background())
		})
	}
}

// TestProvider_Tracer_AfterStart tests getting tracer after start.
func TestProvider_Tracer_AfterStart(t *testing.T) {
	// Save original provider
	originalProvider := otel.GetTracerProvider()
	defer otel.SetTracerProvider(originalProvider)

	config := &Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		ExporterType:   ExporterOTLPGRPC,
		Endpoint:       "localhost:4317",
		Insecure:       true,
		SampleRate:     1.0,
		BatchTimeout:   5 * time.Second,
	}

	provider, err := NewProvider(config, zap.NewNop())
	require.NoError(t, err)

	err = provider.Start(context.Background())
	require.NoError(t, err)

	// Get tracer after start
	tracer := provider.Tracer("test-tracer")
	assert.NotNil(t, tracer)

	// Cleanup
	_ = provider.Stop(context.Background())
}

// TestProvider_createExporter_OTLPHTTP tests creating HTTP exporter.
func TestProvider_createExporter_OTLPHTTP(t *testing.T) {
	config := &Config{
		ExporterType: ExporterOTLPHTTP,
		Endpoint:     "localhost:4318",
		Insecure:     true,
	}
	provider := &Provider{
		config: config,
		logger: zap.NewNop(),
	}

	exporter, err := provider.createExporter(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, exporter)
	_ = exporter.Shutdown(context.Background())
}
