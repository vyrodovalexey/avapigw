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

// TestB3SingleHeaderPropagator tests B3 single-header propagator
func TestB3SingleHeaderPropagator(t *testing.T) {
	t.Parallel()

	propagator := B3SingleHeaderPropagator()
	assert.NotNil(t, propagator)

	// Verify it has the expected fields
	fields := propagator.Fields()
	assert.NotEmpty(t, fields)

	// B3 single header should include "b3" field
	hasB3 := false
	for _, field := range fields {
		if field == "b3" {
			hasB3 = true
			break
		}
	}
	assert.True(t, hasB3, "B3 single header propagator should have 'b3' field")
}

// TestB3SingleHeaderPropagator_InjectExtract tests B3 single-header injection and extraction
func TestB3SingleHeaderPropagator_InjectExtract(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := B3SingleHeaderPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject into carrier
	carrier := MapCarrier{}
	propagator.Inject(ctx, carrier)

	// Verify B3 header was injected
	b3Header := carrier.Get("b3")
	assert.NotEmpty(t, b3Header, "B3 header should be injected")

	// Extract from carrier
	extractedCtx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, extractedCtx)
}

// TestB3MultiHeaderPropagator tests B3 multi-header propagator
func TestB3MultiHeaderPropagator(t *testing.T) {
	t.Parallel()

	propagator := B3MultiHeaderPropagator()
	assert.NotNil(t, propagator)

	// Verify it has the expected fields
	fields := propagator.Fields()
	assert.NotEmpty(t, fields)

	// B3 multi header should include trace-related fields
	expectedFields := []string{"x-b3-traceid", "x-b3-spanid", "x-b3-sampled"}
	for _, expected := range expectedFields {
		found := false
		for _, field := range fields {
			if field == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "B3 multi header propagator should have '%s' field", expected)
	}
}

// TestB3MultiHeaderPropagator_InjectExtract tests B3 multi-header injection and extraction
func TestB3MultiHeaderPropagator_InjectExtract(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := B3MultiHeaderPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject into carrier
	carrier := MapCarrier{}
	propagator.Inject(ctx, carrier)

	// Verify B3 headers were injected
	traceID := carrier.Get("x-b3-traceid")
	spanID := carrier.Get("x-b3-spanid")
	assert.NotEmpty(t, traceID, "x-b3-traceid header should be injected")
	assert.NotEmpty(t, spanID, "x-b3-spanid header should be injected")

	// Extract from carrier
	extractedCtx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, extractedCtx)
}

// TestJaegerPropagator tests Jaeger propagator
func TestJaegerPropagator(t *testing.T) {
	t.Parallel()

	propagator := JaegerPropagator()
	assert.NotNil(t, propagator)

	// Verify it has the expected fields
	fields := propagator.Fields()
	assert.NotEmpty(t, fields)

	// Jaeger propagator should include "uber-trace-id" field
	hasUberTraceID := false
	for _, field := range fields {
		if field == "uber-trace-id" {
			hasUberTraceID = true
			break
		}
	}
	assert.True(t, hasUberTraceID, "Jaeger propagator should have 'uber-trace-id' field")
}

// TestJaegerPropagator_InjectExtract tests Jaeger injection and extraction
func TestJaegerPropagator_InjectExtract(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := JaegerPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject into carrier
	carrier := MapCarrier{}
	propagator.Inject(ctx, carrier)

	// Verify uber-trace-id header was injected
	uberTraceID := carrier.Get("uber-trace-id")
	assert.NotEmpty(t, uberTraceID, "uber-trace-id header should be injected")

	// Extract from carrier
	extractedCtx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, extractedCtx)
}

// TestAllPropagators tests composite propagator with all formats
func TestAllPropagators(t *testing.T) {
	t.Parallel()

	propagator := AllPropagators()
	assert.NotNil(t, propagator)

	// Verify it has fields from all propagators
	fields := propagator.Fields()
	assert.NotEmpty(t, fields)

	// Should have W3C traceparent
	hasTraceparent := false
	// Should have B3 fields
	hasB3 := false
	// Should have Jaeger field
	hasUberTraceID := false
	// Should have baggage
	hasBaggage := false

	for _, field := range fields {
		switch field {
		case "traceparent":
			hasTraceparent = true
		case "b3", "x-b3-traceid":
			hasB3 = true
		case "uber-trace-id":
			hasUberTraceID = true
		case "baggage":
			hasBaggage = true
		}
	}

	assert.True(t, hasTraceparent, "AllPropagators should have W3C traceparent field")
	assert.True(t, hasB3, "AllPropagators should have B3 field")
	assert.True(t, hasUberTraceID, "AllPropagators should have Jaeger uber-trace-id field")
	assert.True(t, hasBaggage, "AllPropagators should have baggage field")
}

// TestAllPropagators_InjectExtract tests AllPropagators injection and extraction
func TestAllPropagators_InjectExtract(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := AllPropagators()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject into carrier
	carrier := MapCarrier{}
	propagator.Inject(ctx, carrier)

	// Verify headers from all propagators were injected
	assert.NotEmpty(t, carrier.Get("traceparent"), "W3C traceparent should be injected")
	assert.NotEmpty(t, carrier.Get("uber-trace-id"), "Jaeger uber-trace-id should be injected")
	// B3 can be either single or multi header
	hasB3 := carrier.Get("b3") != "" || carrier.Get("x-b3-traceid") != ""
	assert.True(t, hasB3, "B3 headers should be injected")

	// Extract from carrier
	extractedCtx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, extractedCtx)
}

// TestSetupPropagators_B3 tests SetupPropagators with B3
func TestSetupPropagators_B3(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	config := &PropagatorConfig{
		Types:         []PropagatorType{PropagatorB3},
		EnableBaggage: false,
	}

	SetupPropagators(config)

	propagator := otel.GetTextMapPropagator()
	assert.NotNil(t, propagator)

	// Verify B3 field is present
	fields := propagator.Fields()
	hasB3 := false
	for _, field := range fields {
		if field == "b3" {
			hasB3 = true
			break
		}
	}
	assert.True(t, hasB3, "SetupPropagators with B3 should include 'b3' field")
}

// TestSetupPropagators_B3Multi tests SetupPropagators with B3 multi-header
func TestSetupPropagators_B3Multi(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	config := &PropagatorConfig{
		Types:         []PropagatorType{PropagatorB3Multi},
		EnableBaggage: false,
	}

	SetupPropagators(config)

	propagator := otel.GetTextMapPropagator()
	assert.NotNil(t, propagator)

	// Verify B3 multi-header fields are present
	fields := propagator.Fields()
	hasTraceID := false
	for _, field := range fields {
		if field == "x-b3-traceid" {
			hasTraceID = true
			break
		}
	}
	assert.True(t, hasTraceID, "SetupPropagators with B3Multi should include 'x-b3-traceid' field")
}

// TestSetupPropagators_Jaeger tests SetupPropagators with Jaeger
func TestSetupPropagators_Jaeger(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	config := &PropagatorConfig{
		Types:         []PropagatorType{PropagatorJaeger},
		EnableBaggage: false,
	}

	SetupPropagators(config)

	propagator := otel.GetTextMapPropagator()
	assert.NotNil(t, propagator)

	// Verify Jaeger field is present
	fields := propagator.Fields()
	hasUberTraceID := false
	for _, field := range fields {
		if field == "uber-trace-id" {
			hasUberTraceID = true
			break
		}
	}
	assert.True(t, hasUberTraceID, "SetupPropagators with Jaeger should include 'uber-trace-id' field")
}

// TestSetupPropagators_AllTypes tests SetupPropagators with all propagator types
func TestSetupPropagators_AllTypes(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	config := &PropagatorConfig{
		Types:         []PropagatorType{PropagatorW3C, PropagatorB3, PropagatorB3Multi, PropagatorJaeger},
		EnableBaggage: true,
	}

	SetupPropagators(config)

	propagator := otel.GetTextMapPropagator()
	assert.NotNil(t, propagator)

	// Verify fields from all propagators are present
	fields := propagator.Fields()
	assert.NotEmpty(t, fields)
}

// TestB3Propagator_ExtractFromB3SingleHeader tests extraction from B3 single header format
func TestB3Propagator_ExtractFromB3SingleHeader(t *testing.T) {
	propagator := B3SingleHeaderPropagator()

	// Create a carrier with B3 single header format
	// Format: {TraceId}-{SpanId}-{SamplingState}-{ParentSpanId}
	carrier := MapCarrier{
		"b3": "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1",
	}

	// Extract context
	ctx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, ctx)
}

// TestB3Propagator_ExtractFromB3MultiHeader tests extraction from B3 multi-header format
func TestB3Propagator_ExtractFromB3MultiHeader(t *testing.T) {
	propagator := B3MultiHeaderPropagator()

	// Create a carrier with B3 multi-header format
	carrier := MapCarrier{
		"x-b3-traceid": "80f198ee56343ba864fe8b2a57d3eff7",
		"x-b3-spanid":  "e457b5a2e4d86bd1",
		"x-b3-sampled": "1",
	}

	// Extract context
	ctx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, ctx)
}

// TestJaegerPropagator_ExtractFromUberTraceID tests extraction from Jaeger uber-trace-id header
func TestJaegerPropagator_ExtractFromUberTraceID(t *testing.T) {
	propagator := JaegerPropagator()

	// Create a carrier with Jaeger uber-trace-id format
	// Format: {trace-id}:{span-id}:{parent-span-id}:{flags}
	carrier := MapCarrier{
		"uber-trace-id": "80f198ee56343ba864fe8b2a57d3eff7:e457b5a2e4d86bd1:0:1",
	}

	// Extract context
	ctx := propagator.Extract(context.Background(), carrier)
	assert.NotNil(t, ctx)
}

// TestPropagatorConfig_EmptyTypes tests PropagatorConfig with empty types
func TestPropagatorConfig_EmptyTypes(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	config := &PropagatorConfig{
		Types:         []PropagatorType{},
		EnableBaggage: true,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		SetupPropagators(config)
	})

	// Should still have baggage propagator
	propagator := otel.GetTextMapPropagator()
	assert.NotNil(t, propagator)
}

// TestHeaderCarrier_WithB3Propagator tests HeaderCarrier with B3 propagator
func TestHeaderCarrier_WithB3Propagator(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := B3SingleHeaderPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject into HeaderCarrier
	carrier := HeaderCarrier{}
	propagator.Inject(ctx, carrier)

	// Verify B3 header was injected
	b3Header := carrier.Get("b3")
	assert.NotEmpty(t, b3Header, "B3 header should be injected into HeaderCarrier")
}

// TestMetadataCarrier_WithJaegerPropagator tests MetadataCarrier with Jaeger propagator
func TestMetadataCarrier_WithJaegerPropagator(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := JaegerPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Inject into MetadataCarrier
	carrier := MetadataCarrier{}
	propagator.Inject(ctx, carrier)

	// Verify uber-trace-id header was injected
	uberTraceID := carrier.Get("uber-trace-id")
	assert.NotEmpty(t, uberTraceID, "uber-trace-id header should be injected into MetadataCarrier")
}

// TestPropagatorRoundTrip_B3 tests B3 propagator round-trip (inject then extract)
func TestPropagatorRoundTrip_B3(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := B3SingleHeaderPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	spanCtx := span.SpanContext()
	span.End()

	// Inject into carrier
	carrier := MapCarrier{}
	propagator.Inject(ctx, carrier)

	// Extract from carrier
	extractedCtx := propagator.Extract(context.Background(), carrier)

	// Create a new span from extracted context
	_, extractedSpan := tracer.Start(extractedCtx, "extracted-span")
	extractedSpanCtx := extractedSpan.SpanContext()
	extractedSpan.End()

	// Verify trace ID is preserved
	assert.Equal(t, spanCtx.TraceID(), extractedSpanCtx.TraceID(), "Trace ID should be preserved in round-trip")
}

// TestPropagatorRoundTrip_Jaeger tests Jaeger propagator round-trip (inject then extract)
func TestPropagatorRoundTrip_Jaeger(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	propagator := JaegerPropagator()

	// Create a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	spanCtx := span.SpanContext()
	span.End()

	// Inject into carrier
	carrier := MapCarrier{}
	propagator.Inject(ctx, carrier)

	// Extract from carrier
	extractedCtx := propagator.Extract(context.Background(), carrier)

	// Create a new span from extracted context
	_, extractedSpan := tracer.Start(extractedCtx, "extracted-span")
	extractedSpanCtx := extractedSpan.SpanContext()
	extractedSpan.End()

	// Verify trace ID is preserved
	assert.Equal(t, spanCtx.TraceID(), extractedSpanCtx.TraceID(), "Trace ID should be preserved in round-trip")
}
