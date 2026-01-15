// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestDefaultPropagatorConfig tests default config.
func TestDefaultPropagatorConfig(t *testing.T) {
	tests := []struct {
		name     string
		validate func(t *testing.T, cfg *PropagatorConfig)
	}{
		{
			name: "returns non-nil config",
			validate: func(t *testing.T, cfg *PropagatorConfig) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "has W3C propagator type",
			validate: func(t *testing.T, cfg *PropagatorConfig) {
				require.Len(t, cfg.Types, 1)
				assert.Equal(t, PropagatorW3C, cfg.Types[0])
			},
		},
		{
			name: "has baggage enabled",
			validate: func(t *testing.T, cfg *PropagatorConfig) {
				assert.True(t, cfg.EnableBaggage)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultPropagatorConfig()
			tt.validate(t, cfg)
		})
	}
}

// TestSetupPropagators tests setting up propagators.
func TestSetupPropagators(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	tests := []struct {
		name   string
		config *PropagatorConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "W3C propagator",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorW3C},
				EnableBaggage: true,
			},
		},
		{
			name: "B3 propagator",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorB3},
				EnableBaggage: false,
			},
		},
		{
			name: "B3 multi propagator",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorB3Multi},
				EnableBaggage: true,
			},
		},
		{
			name: "Jaeger propagator",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorJaeger},
				EnableBaggage: false,
			},
		},
		{
			name: "composite propagator",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorComposite},
				EnableBaggage: true,
			},
		},
		{
			name: "multiple propagators",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorW3C, PropagatorB3},
				EnableBaggage: true,
			},
		},
		{
			name: "unknown propagator type",
			config: &PropagatorConfig{
				Types:         []PropagatorType{"unknown"},
				EnableBaggage: false,
			},
		},
		{
			name: "without baggage",
			config: &PropagatorConfig{
				Types:         []PropagatorType{PropagatorW3C},
				EnableBaggage: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				SetupPropagators(tt.config)
			})

			// Verify propagator was set
			propagator := otel.GetTextMapPropagator()
			assert.NotNil(t, propagator)
		})
	}
}

// TestGetPropagator tests getting propagator.
func TestGetPropagator(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	// Setup propagators
	SetupPropagators(nil)

	propagator := GetPropagator()
	assert.NotNil(t, propagator)
}

// TestW3CTraceContextPropagator tests W3C propagator.
func TestW3CTraceContextPropagator(t *testing.T) {
	propagator := W3CTraceContextPropagator()
	assert.NotNil(t, propagator)

	// Verify it's a TraceContext propagator
	_, ok := propagator.(propagation.TraceContext)
	assert.True(t, ok)
}

// TestBaggagePropagator tests baggage propagator.
func TestBaggagePropagator(t *testing.T) {
	propagator := BaggagePropagator()
	assert.NotNil(t, propagator)

	// Verify it's a Baggage propagator
	_, ok := propagator.(propagation.Baggage)
	assert.True(t, ok)
}

// TestCompositePropagator tests composite propagator.
func TestCompositePropagator(t *testing.T) {
	propagator := CompositePropagator()
	assert.NotNil(t, propagator)

	// Verify it has fields (composite propagator)
	fields := propagator.Fields()
	assert.NotEmpty(t, fields)
}

// TestHeaderCarrier_Get tests getting header.
func TestHeaderCarrier_Get(t *testing.T) {
	tests := []struct {
		name     string
		carrier  HeaderCarrier
		key      string
		expected string
	}{
		{
			name: "existing key",
			carrier: HeaderCarrier{
				"Content-Type": []string{"application/json"},
			},
			key:      "Content-Type",
			expected: "application/json",
		},
		{
			name: "non-existing key",
			carrier: HeaderCarrier{
				"Content-Type": []string{"application/json"},
			},
			key:      "Accept",
			expected: "",
		},
		{
			name:     "empty carrier",
			carrier:  HeaderCarrier{},
			key:      "Content-Type",
			expected: "",
		},
		{
			name: "multiple values returns first",
			carrier: HeaderCarrier{
				"Accept": []string{"text/html", "application/json"},
			},
			key:      "Accept",
			expected: "text/html",
		},
		{
			name: "empty values slice",
			carrier: HeaderCarrier{
				"Empty": []string{},
			},
			key:      "Empty",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.carrier.Get(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHeaderCarrier_Set tests setting header.
func TestHeaderCarrier_Set(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected []string
	}{
		{
			name:     "set new key",
			key:      "Content-Type",
			value:    "application/json",
			expected: []string{"application/json"},
		},
		{
			name:     "set empty value",
			key:      "Empty",
			value:    "",
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			carrier := HeaderCarrier{}
			carrier.Set(tt.key, tt.value)
			assert.Equal(t, tt.expected, carrier[tt.key])
		})
	}
}

// TestHeaderCarrier_Set_Override tests that Set overrides existing values.
func TestHeaderCarrier_Set_Override(t *testing.T) {
	carrier := HeaderCarrier{
		"Content-Type": []string{"text/plain", "text/html"},
	}
	carrier.Set("Content-Type", "application/json")
	assert.Equal(t, []string{"application/json"}, carrier["Content-Type"])
}

// TestHeaderCarrier_Keys tests listing keys.
func TestHeaderCarrier_Keys(t *testing.T) {
	tests := []struct {
		name        string
		carrier     HeaderCarrier
		expectedLen int
	}{
		{
			name:        "empty carrier",
			carrier:     HeaderCarrier{},
			expectedLen: 0,
		},
		{
			name: "single key",
			carrier: HeaderCarrier{
				"Content-Type": []string{"application/json"},
			},
			expectedLen: 1,
		},
		{
			name: "multiple keys",
			carrier: HeaderCarrier{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"text/html"},
				"User-Agent":   []string{"test"},
			},
			expectedLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := tt.carrier.Keys()
			assert.Len(t, keys, tt.expectedLen)
		})
	}
}

// TestMapCarrier_Get tests getting from map.
func TestMapCarrier_Get(t *testing.T) {
	tests := []struct {
		name     string
		carrier  MapCarrier
		key      string
		expected string
	}{
		{
			name: "existing key",
			carrier: MapCarrier{
				"key1": "value1",
			},
			key:      "key1",
			expected: "value1",
		},
		{
			name: "non-existing key",
			carrier: MapCarrier{
				"key1": "value1",
			},
			key:      "key2",
			expected: "",
		},
		{
			name:     "empty carrier",
			carrier:  MapCarrier{},
			key:      "key1",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.carrier.Get(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMapCarrier_Set tests setting in map.
func TestMapCarrier_Set(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected string
	}{
		{
			name:     "set new key",
			key:      "key1",
			value:    "value1",
			expected: "value1",
		},
		{
			name:     "set empty value",
			key:      "empty",
			value:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			carrier := MapCarrier{}
			carrier.Set(tt.key, tt.value)
			assert.Equal(t, tt.expected, carrier[tt.key])
		})
	}
}

// TestMapCarrier_Set_Override tests that Set overrides existing values.
func TestMapCarrier_Set_Override(t *testing.T) {
	carrier := MapCarrier{
		"key1": "old-value",
	}
	carrier.Set("key1", "new-value")
	assert.Equal(t, "new-value", carrier["key1"])
}

// TestMapCarrier_Keys tests listing map keys.
func TestMapCarrier_Keys(t *testing.T) {
	tests := []struct {
		name        string
		carrier     MapCarrier
		expectedLen int
	}{
		{
			name:        "empty carrier",
			carrier:     MapCarrier{},
			expectedLen: 0,
		},
		{
			name: "single key",
			carrier: MapCarrier{
				"key1": "value1",
			},
			expectedLen: 1,
		},
		{
			name: "multiple keys",
			carrier: MapCarrier{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			expectedLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := tt.carrier.Keys()
			assert.Len(t, keys, tt.expectedLen)
		})
	}
}

// TestMetadataCarrier_Get tests getting metadata.
func TestMetadataCarrier_Get(t *testing.T) {
	tests := []struct {
		name     string
		carrier  MetadataCarrier
		key      string
		expected string
	}{
		{
			name: "existing key",
			carrier: MetadataCarrier{
				"key1": []string{"value1"},
			},
			key:      "key1",
			expected: "value1",
		},
		{
			name: "non-existing key",
			carrier: MetadataCarrier{
				"key1": []string{"value1"},
			},
			key:      "key2",
			expected: "",
		},
		{
			name:     "empty carrier",
			carrier:  MetadataCarrier{},
			key:      "key1",
			expected: "",
		},
		{
			name: "multiple values returns first",
			carrier: MetadataCarrier{
				"key1": []string{"value1", "value2"},
			},
			key:      "key1",
			expected: "value1",
		},
		{
			name: "empty values slice",
			carrier: MetadataCarrier{
				"key1": []string{},
			},
			key:      "key1",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.carrier.Get(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMetadataCarrier_Set tests setting metadata.
func TestMetadataCarrier_Set(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected []string
	}{
		{
			name:     "set new key",
			key:      "key1",
			value:    "value1",
			expected: []string{"value1"},
		},
		{
			name:     "set empty value",
			key:      "empty",
			value:    "",
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			carrier := MetadataCarrier{}
			carrier.Set(tt.key, tt.value)
			assert.Equal(t, tt.expected, carrier[tt.key])
		})
	}
}

// TestMetadataCarrier_Set_Override tests that Set overrides existing values.
func TestMetadataCarrier_Set_Override(t *testing.T) {
	carrier := MetadataCarrier{
		"key1": []string{"old-value1", "old-value2"},
	}
	carrier.Set("key1", "new-value")
	assert.Equal(t, []string{"new-value"}, carrier["key1"])
}

// TestMetadataCarrier_Keys tests listing metadata keys.
func TestMetadataCarrier_Keys(t *testing.T) {
	tests := []struct {
		name        string
		carrier     MetadataCarrier
		expectedLen int
	}{
		{
			name:        "empty carrier",
			carrier:     MetadataCarrier{},
			expectedLen: 0,
		},
		{
			name: "single key",
			carrier: MetadataCarrier{
				"key1": []string{"value1"},
			},
			expectedLen: 1,
		},
		{
			name: "multiple keys",
			carrier: MetadataCarrier{
				"key1": []string{"value1"},
				"key2": []string{"value2"},
				"key3": []string{"value3"},
			},
			expectedLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := tt.carrier.Keys()
			assert.Len(t, keys, tt.expectedLen)
		})
	}
}

// TestPropagatorType_Constants tests propagator type constants.
func TestPropagatorType_Constants(t *testing.T) {
	assert.Equal(t, PropagatorType("w3c"), PropagatorW3C)
	assert.Equal(t, PropagatorType("b3"), PropagatorB3)
	assert.Equal(t, PropagatorType("b3-multi"), PropagatorB3Multi)
	assert.Equal(t, PropagatorType("jaeger"), PropagatorJaeger)
	assert.Equal(t, PropagatorType("composite"), PropagatorComposite)
}

// TestPropagatorIntegration tests propagator integration with tracing.
func TestPropagatorIntegration(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// Save original provider and propagator
	originalProvider := otel.GetTracerProvider()
	originalPropagator := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(originalProvider)
		otel.SetTextMapPropagator(originalPropagator)
	}()

	otel.SetTracerProvider(tp)
	SetupPropagators(nil)

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject context into carrier
	carrier := MapCarrier{}
	propagator := GetPropagator()
	propagator.Inject(ctx, carrier)

	// Verify trace context was injected
	assert.NotEmpty(t, carrier.Keys())
}

// TestHeaderCarrier_TextMapCarrierInterface tests that HeaderCarrier implements TextMapCarrier.
func TestHeaderCarrier_TextMapCarrierInterface(t *testing.T) {
	var _ propagation.TextMapCarrier = HeaderCarrier{}
}

// TestMapCarrier_TextMapCarrierInterface tests that MapCarrier implements TextMapCarrier.
func TestMapCarrier_TextMapCarrierInterface(t *testing.T) {
	var _ propagation.TextMapCarrier = MapCarrier{}
}

// TestMetadataCarrier_TextMapCarrierInterface tests that MetadataCarrier implements TextMapCarrier.
func TestMetadataCarrier_TextMapCarrierInterface(t *testing.T) {
	var _ propagation.TextMapCarrier = MetadataCarrier{}
}
