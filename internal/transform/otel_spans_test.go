package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestTransform_OTELSpans verifies that OTEL spans are created during
// transform operations. These tests are NOT parallel because they modify
// the global OTEL tracer provider.
func TestTransform_OTELSpans(t *testing.T) {
	t.Run("request_transform_creates_span", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		transformTracer = otel.Tracer("avapigw/transform")
		defer func() {
			otel.SetTracerProvider(oldTP)
			transformTracer = otel.Tracer("avapigw/transform")
		}()

		rt := NewRequestTransformer(observability.NopLogger())

		cfg := &config.RequestTransformConfig{
			RemoveFields: []string{"secret"},
		}

		data := map[string]interface{}{
			"name":   "test",
			"secret": "hidden",
		}

		result, err := rt.TransformRequest(context.Background(), data, cfg)
		require.NoError(t, err)
		require.NotNil(t, result)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans, "expected at least one span")

		found := false
		for _, s := range spans {
			if s.Name == "transform.request" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Contains(t, attrs, "transform.passthrough")
				assert.Contains(t, attrs, "transform.remove_fields_count")
				break
			}
		}
		assert.True(t, found, "expected transform.request span")
	})

	t.Run("response_transform_creates_span", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		transformTracer = otel.Tracer("avapigw/transform")
		defer func() {
			otel.SetTracerProvider(oldTP)
			transformTracer = otel.Tracer("avapigw/transform")
		}()

		rt := NewResponseTransformer(observability.NopLogger())

		cfg := &config.ResponseTransformConfig{
			DenyFields: []string{"internal_id"},
		}

		data := map[string]interface{}{
			"name":        "test",
			"internal_id": "abc123",
		}

		result, err := rt.TransformResponse(context.Background(), data, cfg)
		require.NoError(t, err)
		require.NotNil(t, result)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans, "expected at least one span")

		found := false
		for _, s := range spans {
			if s.Name == "transform.response" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Contains(t, attrs, "transform.has_template")
				assert.Contains(t, attrs, "transform.deny_fields_count")
				break
			}
		}
		assert.True(t, found, "expected transform.response span")
	})

	t.Run("passthrough_creates_span", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		transformTracer = otel.Tracer("avapigw/transform")
		defer func() {
			otel.SetTracerProvider(oldTP)
			transformTracer = otel.Tracer("avapigw/transform")
		}()

		rt := NewRequestTransformer(observability.NopLogger())

		cfg := &config.RequestTransformConfig{
			PassthroughBody: true,
		}

		data := map[string]interface{}{"key": "value"}

		result, err := rt.TransformRequest(context.Background(), data, cfg)
		require.NoError(t, err)
		require.NotNil(t, result)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans)

		found := false
		for _, s := range spans {
			if s.Name == "transform.request" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Equal(t, true, attrs["transform.passthrough"])
				break
			}
		}
		assert.True(t, found, "expected transform.request span for passthrough")
	})
}
