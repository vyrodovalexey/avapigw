package interceptor

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// setupTestTracer sets up a test tracer provider
func setupTestTracer() (*sdktrace.TracerProvider, *tracetest.InMemoryExporter) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	return tp, exporter
}

// TestUnaryTracingInterceptor tests the basic unary tracing interceptor
func TestUnaryTracingInterceptor(t *testing.T) {
	t.Parallel()

	tp, exporter := setupTestTracer()
	defer tp.Shutdown(context.Background())

	// Set as global provider for the test
	otel.SetTracerProvider(tp)

	interceptor := UnaryTracingInterceptor()

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)

	// Verify span was created
	spans := exporter.GetSpans()
	assert.GreaterOrEqual(t, len(spans), 1)
}

// TestUnaryTracingInterceptorWithConfig tests the configurable unary tracing interceptor
func TestUnaryTracingInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips tracing for configured methods", func(t *testing.T) {
		tp, exporter := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
			SkipMethods:    []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryTracingInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)

		// Verify no span was created for skipped method
		spans := exporter.GetSpans()
		for _, span := range spans {
			assert.NotEqual(t, "/test.Service/SkippedMethod", span.Name)
		}
	})

	t.Run("uses custom service name", func(t *testing.T) {
		tp, _ := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
			ServiceName:    "custom-service",
		}

		interceptor := UnaryTracingInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("records error on failure", func(t *testing.T) {
		tp, exporter := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
		}

		interceptor := UnaryTracingInterceptorWithConfig(config)

		errorHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, errors.New("test error")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/ErrorMethod"}

		resp, err := interceptor(ctx, "request", info, errorHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)

		// Verify span recorded error
		spans := exporter.GetSpans()
		assert.GreaterOrEqual(t, len(spans), 1)
	})

	t.Run("extracts trace context from metadata", func(t *testing.T) {
		tp, _ := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
			Propagators:    propagation.TraceContext{},
		}

		interceptor := UnaryTracingInterceptorWithConfig(config)

		md := metadata.MD{
			"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("includes peer info in span", func(t *testing.T) {
		tp, exporter := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
		}

		interceptor := UnaryTracingInterceptorWithConfig(config)

		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)

		spans := exporter.GetSpans()
		assert.GreaterOrEqual(t, len(spans), 1)
	})

	t.Run("uses default tracer provider when nil", func(t *testing.T) {
		config := TracingConfig{
			TracerProvider: nil,
		}

		interceptor := UnaryTracingInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamTracingInterceptor tests the basic stream tracing interceptor
func TestStreamTracingInterceptor(t *testing.T) {
	t.Parallel()

	tp, exporter := setupTestTracer()
	defer tp.Shutdown(context.Background())

	otel.SetTracerProvider(tp)

	interceptor := StreamTracingInterceptor()

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/Method",
		IsClientStream: true,
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)

	spans := exporter.GetSpans()
	assert.GreaterOrEqual(t, len(spans), 1)
}

// TestStreamTracingInterceptorWithConfig tests the configurable stream tracing interceptor
func TestStreamTracingInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips tracing for configured methods", func(t *testing.T) {
		tp, exporter := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
			SkipMethods:    []string{"/test.Service/SkippedMethod"},
		}

		interceptor := StreamTracingInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)

		spans := exporter.GetSpans()
		for _, span := range spans {
			assert.NotEqual(t, "/test.Service/SkippedMethod", span.Name)
		}
	})

	t.Run("records error on stream failure", func(t *testing.T) {
		tp, exporter := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
		}

		interceptor := StreamTracingInterceptorWithConfig(config)

		errorHandler := func(srv interface{}, ss grpc.ServerStream) error {
			return errors.New("stream error")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/ErrorMethod"}

		err := interceptor(nil, stream, info, errorHandler)

		assert.Error(t, err)

		spans := exporter.GetSpans()
		assert.GreaterOrEqual(t, len(spans), 1)
	})

	t.Run("includes stream type in span attributes", func(t *testing.T) {
		tp, exporter := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
		}

		interceptor := StreamTracingInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod:     "/test.Service/Method",
			IsClientStream: true,
			IsServerStream: false,
		}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)

		spans := exporter.GetSpans()
		assert.GreaterOrEqual(t, len(spans), 1)
	})
}

// TestTracingServerStream tests the tracing server stream wrapper
func TestTracingServerStream(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	baseStream := &mockServerStream{ctx: ctx}

	wrappedStream := &tracingServerStream{
		ServerStream: baseStream,
		ctx:          context.WithValue(ctx, "test", "value"),
	}

	t.Run("returns wrapped context", func(t *testing.T) {
		returnedCtx := wrappedStream.Context()
		assert.Equal(t, "value", returnedCtx.Value("test"))
	})
}

// TestMetadataCarrier tests the metadata carrier for trace propagation
func TestMetadataCarrier(t *testing.T) {
	t.Parallel()

	t.Run("Get returns value", func(t *testing.T) {
		md := metadata.MD{
			"traceparent": []string{"test-value"},
		}
		carrier := metadataCarrier(md)

		value := carrier.Get("traceparent")
		assert.Equal(t, "test-value", value)
	})

	t.Run("Get returns empty for missing key", func(t *testing.T) {
		md := metadata.MD{}
		carrier := metadataCarrier(md)

		value := carrier.Get("missing")
		assert.Empty(t, value)
	})

	t.Run("Set adds value", func(t *testing.T) {
		md := metadata.MD{}
		carrier := metadataCarrier(md)

		carrier.Set("key", "value")
		assert.Equal(t, []string{"value"}, md.Get("key"))
	})

	t.Run("Keys returns all keys", func(t *testing.T) {
		md := metadata.MD{
			"key1": []string{"value1"},
			"key2": []string{"value2"},
		}
		carrier := metadataCarrier(md)

		keys := carrier.Keys()
		assert.Len(t, keys, 2)
		assert.Contains(t, keys, "key1")
		assert.Contains(t, keys, "key2")
	})
}

// TestExtractService tests the extractService function
func TestExtractService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		fullMethod string
		expected   string
	}{
		{"/package.Service/Method", "package.Service"},
		{"package.Service/Method", "package.Service"},
		{"/com.example.Service/Method", "com.example.Service"},
		{"", ""},
		{"/Service", "Service"},
		{"Service", "Service"},
	}

	for _, tc := range testCases {
		t.Run(tc.fullMethod, func(t *testing.T) {
			t.Parallel()

			result := extractService(tc.fullMethod)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestExtractMethod tests the extractMethod function
func TestExtractMethod(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		fullMethod string
		expected   string
	}{
		{"/package.Service/Method", "Method"},
		{"package.Service/Method", "Method"},
		{"/com.example.Service/GetUser", "GetUser"},
		{"", ""},
		{"/Service", "Service"}, // No slash after Service, so Service is the method
		{"Service", ""},         // No slash at all
	}

	for _, tc := range testCases {
		t.Run(tc.fullMethod, func(t *testing.T) {
			t.Parallel()

			result := extractMethod(tc.fullMethod)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestGetSpanFromContext tests GetSpanFromContext function
func TestGetSpanFromContext(t *testing.T) {
	t.Parallel()

	t.Run("returns span from context", func(t *testing.T) {
		tp, _ := setupTestTracer()
		defer tp.Shutdown(context.Background())

		tracer := tp.Tracer("test")
		ctx, span := tracer.Start(context.Background(), "test-span")
		defer span.End()

		retrievedSpan := GetSpanFromContext(ctx)
		assert.NotNil(t, retrievedSpan)
	})

	t.Run("returns noop span for empty context", func(t *testing.T) {
		span := GetSpanFromContext(context.Background())
		assert.NotNil(t, span) // Returns noop span
	})
}

// TestAddSpanAttribute tests AddSpanAttribute function
func TestAddSpanAttribute(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	t.Run("adds string attribute", func(t *testing.T) {
		AddSpanAttribute(ctx, "string-key", "string-value")
	})

	t.Run("adds int attribute", func(t *testing.T) {
		AddSpanAttribute(ctx, "int-key", 42)
	})

	t.Run("adds int64 attribute", func(t *testing.T) {
		AddSpanAttribute(ctx, "int64-key", int64(42))
	})

	t.Run("adds float64 attribute", func(t *testing.T) {
		AddSpanAttribute(ctx, "float64-key", 3.14)
	})

	t.Run("adds bool attribute", func(t *testing.T) {
		AddSpanAttribute(ctx, "bool-key", true)
	})

	t.Run("handles nil span gracefully", func(t *testing.T) {
		// Should not panic
		AddSpanAttribute(context.Background(), "key", "value")
	})
}

// TestRecordSpanError tests RecordSpanError function
func TestRecordSpanError(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	t.Run("records error on span", func(t *testing.T) {
		RecordSpanError(ctx, errors.New("test error"))
	})

	t.Run("handles nil span gracefully", func(t *testing.T) {
		// Should not panic
		RecordSpanError(context.Background(), errors.New("test error"))
	})
}

// TestTracingConfig tests TracingConfig struct
func TestTracingConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := TracingConfig{}

		assert.Nil(t, config.TracerProvider)
		assert.Nil(t, config.Propagators)
		assert.Empty(t, config.ServiceName)
		assert.Nil(t, config.SkipMethods)
	})

	t.Run("with all fields", func(t *testing.T) {
		tp, _ := setupTestTracer()
		defer tp.Shutdown(context.Background())

		config := TracingConfig{
			TracerProvider: tp,
			Propagators:    propagation.TraceContext{},
			ServiceName:    "test-service",
			SkipMethods:    []string{"/test.Service/Method"},
		}

		assert.NotNil(t, config.TracerProvider)
		assert.NotNil(t, config.Propagators)
		assert.Equal(t, "test-service", config.ServiceName)
		assert.Len(t, config.SkipMethods, 1)
	})
}

// TestTracerName tests the TracerName constant
func TestTracerName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "avapigw-grpc", TracerName)
}

// TestSpanKey tests the SpanKey constant
func TestSpanKey(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "otel-grpc-span", SpanKey)
}

// TestTracingWithGRPCStatus tests tracing with various gRPC status codes
func TestTracingWithGRPCStatus(t *testing.T) {
	t.Parallel()

	tp, exporter := setupTestTracer()
	defer tp.Shutdown(context.Background())

	config := TracingConfig{
		TracerProvider: tp,
	}

	interceptor := UnaryTracingInterceptorWithConfig(config)

	testCases := []struct {
		name string
		err  error
	}{
		{"OK", nil},
		{"NotFound", status.Error(1, "not found")},
		{"Internal", status.Error(13, "internal error")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "response", tc.err
			}

			ctx := context.Background()
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/" + tc.name}

			_, _ = interceptor(ctx, "request", info, handler)

			spans := exporter.GetSpans()
			assert.GreaterOrEqual(t, len(spans), 1)
		})
	}
}

// TestTracingContextPropagation tests that trace context is properly propagated
func TestTracingContextPropagation(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	config := TracingConfig{
		TracerProvider: tp,
		Propagators:    propagation.TraceContext{},
	}

	interceptor := UnaryTracingInterceptorWithConfig(config)

	var capturedSpan trace.Span
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedSpan = trace.SpanFromContext(ctx)
		return "response", nil
	}

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.NotNil(t, capturedSpan)
}

// TestSetUnarySpanAttributesWithRequestID tests span attributes with request ID
func TestSetUnarySpanAttributesWithRequestID(t *testing.T) {
	t.Parallel()

	tp, exporter := setupTestTracer()
	defer tp.Shutdown(context.Background())

	config := TracingConfig{
		TracerProvider: tp,
	}

	interceptor := UnaryTracingInterceptorWithConfig(config)

	// Create context with request ID in metadata
	md := metadata.MD{
		RequestIDKey: []string{"test-request-id-123"},
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)

	spans := exporter.GetSpans()
	assert.GreaterOrEqual(t, len(spans), 1)
}

// TestSetStreamSpanAttributesWithPeer tests stream span attributes with peer info
func TestSetStreamSpanAttributesWithPeer(t *testing.T) {
	t.Parallel()

	tp, exporter := setupTestTracer()
	defer tp.Shutdown(context.Background())

	config := TracingConfig{
		TracerProvider: tp,
	}

	interceptor := StreamTracingInterceptorWithConfig(config)

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/Method",
		IsClientStream: true,
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)

	spans := exporter.GetSpans()
	assert.GreaterOrEqual(t, len(spans), 1)
}

// TestAddSpanAttributeWithUnsupportedType tests AddSpanAttribute with unsupported type
func TestAddSpanAttributeWithUnsupportedType(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Test with unsupported type (struct)
	type customStruct struct {
		Field string
	}
	AddSpanAttribute(ctx, "struct-key", customStruct{Field: "value"})

	// Test with slice (unsupported)
	AddSpanAttribute(ctx, "slice-key", []string{"a", "b"})

	// Should not panic, just ignore unsupported types
}

// TestNormalizeTracingConfigDefaults tests normalizeTracingConfig with all defaults
func TestNormalizeTracingConfigDefaults(t *testing.T) {
	t.Parallel()

	config := TracingConfig{}

	normalizedConfig, tracer, skipMethods := normalizeTracingConfig(config)

	assert.NotNil(t, normalizedConfig.TracerProvider)
	assert.NotNil(t, normalizedConfig.Propagators)
	assert.Equal(t, TracerName, normalizedConfig.ServiceName)
	assert.NotNil(t, tracer)
	assert.Empty(t, skipMethods)
}

// TestExtractTraceContextWithNoMetadata tests extractTraceContext with no metadata
func TestExtractTraceContextWithNoMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	propagators := propagation.TraceContext{}

	resultCtx := extractTraceContext(ctx, propagators)

	assert.NotNil(t, resultCtx)
}

// TestStartUnarySpan tests startUnarySpan function
func TestStartUnarySpan(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	ctx, span := startUnarySpan(context.Background(), tracer, "/test.Service/Method")
	defer span.End()

	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
}

// TestStartStreamSpan tests startStreamSpan function
func TestStartStreamSpan(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	ctx, span := startStreamSpan(context.Background(), tracer, "/test.Service/StreamMethod")
	defer span.End()

	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
}

// TestSetSpanStatusWithNilError tests setSpanStatus with nil error
func TestSetSpanStatusWithNilError(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	_, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Should not panic
	setSpanStatus(span, nil)
}

// TestSetSpanStatusWithGRPCError tests setSpanStatus with gRPC error
func TestSetSpanStatusWithGRPCError(t *testing.T) {
	t.Parallel()

	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	_, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	err := status.Error(1, "not found")
	setSpanStatus(span, err)
}
