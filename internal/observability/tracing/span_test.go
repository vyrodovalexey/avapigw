// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// setupTestTracer sets up a test tracer provider with an in-memory exporter.
func setupTestTracer(t *testing.T) (*tracetest.InMemoryExporter, func()) {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Save original provider
	originalProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)

	cleanup := func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(originalProvider)
	}

	return exporter, cleanup
}

// TestWithSpanKind tests setting span kind.
func TestWithSpanKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     trace.SpanKind
		expected trace.SpanKind
	}{
		{
			name:     "server kind",
			kind:     trace.SpanKindServer,
			expected: trace.SpanKindServer,
		},
		{
			name:     "client kind",
			kind:     trace.SpanKindClient,
			expected: trace.SpanKindClient,
		},
		{
			name:     "internal kind",
			kind:     trace.SpanKindInternal,
			expected: trace.SpanKindInternal,
		},
		{
			name:     "producer kind",
			kind:     trace.SpanKindProducer,
			expected: trace.SpanKindProducer,
		},
		{
			name:     "consumer kind",
			kind:     trace.SpanKindConsumer,
			expected: trace.SpanKindConsumer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &spanOptions{}
			opt := WithSpanKind(tt.kind)
			opt(opts)
			assert.Equal(t, tt.expected, opts.kind)
		})
	}
}

// TestWithAttributes tests setting attributes.
func TestWithAttributes(t *testing.T) {
	tests := []struct {
		name     string
		attrs    []attribute.KeyValue
		expected int
	}{
		{
			name:     "single attribute",
			attrs:    []attribute.KeyValue{attribute.String("key", "value")},
			expected: 1,
		},
		{
			name: "multiple attributes",
			attrs: []attribute.KeyValue{
				attribute.String("key1", "value1"),
				attribute.Int("key2", 42),
				attribute.Bool("key3", true),
			},
			expected: 3,
		},
		{
			name:     "no attributes",
			attrs:    []attribute.KeyValue{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &spanOptions{}
			opt := WithAttributes(tt.attrs...)
			opt(opts)
			assert.Len(t, opts.attributes, tt.expected)
		})
	}
}

// TestWithAttributes_Append tests that attributes are appended.
func TestWithAttributes_Append(t *testing.T) {
	opts := &spanOptions{}

	// Apply first set of attributes
	opt1 := WithAttributes(attribute.String("key1", "value1"))
	opt1(opts)
	assert.Len(t, opts.attributes, 1)

	// Apply second set of attributes
	opt2 := WithAttributes(attribute.String("key2", "value2"))
	opt2(opts)
	assert.Len(t, opts.attributes, 2)
}

// TestWithLinks tests setting links.
func TestWithLinks(t *testing.T) {
	tests := []struct {
		name     string
		links    []trace.Link
		expected int
	}{
		{
			name: "single link",
			links: []trace.Link{
				{SpanContext: trace.NewSpanContext(trace.SpanContextConfig{})},
			},
			expected: 1,
		},
		{
			name: "multiple links",
			links: []trace.Link{
				{SpanContext: trace.NewSpanContext(trace.SpanContextConfig{})},
				{SpanContext: trace.NewSpanContext(trace.SpanContextConfig{})},
			},
			expected: 2,
		},
		{
			name:     "no links",
			links:    []trace.Link{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &spanOptions{}
			opt := WithLinks(tt.links...)
			opt(opts)
			assert.Len(t, opts.links, tt.expected)
		})
	}
}

// TestStartSpan tests starting span with options.
func TestStartSpan(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		spanName string
		opts     []SpanOption
		validate func(t *testing.T, spans tracetest.SpanStubs)
	}{
		{
			name:     "basic span",
			spanName: "test-span",
			opts:     nil,
			validate: func(t *testing.T, spans tracetest.SpanStubs) {
				require.Len(t, spans, 1)
				assert.Equal(t, "test-span", spans[0].Name)
				assert.Equal(t, trace.SpanKindInternal, spans[0].SpanKind)
			},
		},
		{
			name:     "span with server kind",
			spanName: "server-span",
			opts:     []SpanOption{WithSpanKind(trace.SpanKindServer)},
			validate: func(t *testing.T, spans tracetest.SpanStubs) {
				require.Len(t, spans, 1)
				assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
			},
		},
		{
			name:     "span with attributes",
			spanName: "attr-span",
			opts: []SpanOption{
				WithAttributes(
					attribute.String("key", "value"),
					attribute.Int("count", 42),
				),
			},
			validate: func(t *testing.T, spans tracetest.SpanStubs) {
				require.Len(t, spans, 1)
				attrs := spans[0].Attributes
				assert.GreaterOrEqual(t, len(attrs), 2)
			},
		},
		{
			name:     "span with multiple options",
			spanName: "multi-opt-span",
			opts: []SpanOption{
				WithSpanKind(trace.SpanKindClient),
				WithAttributes(attribute.String("service", "test")),
			},
			validate: func(t *testing.T, spans tracetest.SpanStubs) {
				require.Len(t, spans, 1)
				assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			ctx, span := StartSpan(context.Background(), tt.spanName, tt.opts...)
			assert.NotNil(t, ctx)
			assert.NotNil(t, span)
			span.End()

			spans := exporter.GetSpans()
			tt.validate(t, spans)
		})
	}
}

// TestStartServerSpan tests starting server span.
func TestStartServerSpan(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		spanName string
		attrs    []attribute.KeyValue
	}{
		{
			name:     "basic server span",
			spanName: "server-span",
			attrs:    nil,
		},
		{
			name:     "server span with attributes",
			spanName: "server-span-attrs",
			attrs: []attribute.KeyValue{
				attribute.String("http.method", "GET"),
				attribute.String("http.url", "/api/test"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			ctx, span := StartServerSpan(context.Background(), tt.spanName, tt.attrs...)
			assert.NotNil(t, ctx)
			assert.NotNil(t, span)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
			assert.Equal(t, tt.spanName, spans[0].Name)
		})
	}
}

// TestStartClientSpan tests starting client span.
func TestStartClientSpan(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		spanName string
		attrs    []attribute.KeyValue
	}{
		{
			name:     "basic client span",
			spanName: "client-span",
			attrs:    nil,
		},
		{
			name:     "client span with attributes",
			spanName: "client-span-attrs",
			attrs: []attribute.KeyValue{
				attribute.String("rpc.service", "TestService"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			ctx, span := StartClientSpan(context.Background(), tt.spanName, tt.attrs...)
			assert.NotNil(t, ctx)
			assert.NotNil(t, span)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)
		})
	}
}

// TestStartInternalSpan tests starting internal span.
func TestStartInternalSpan(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	ctx, span := StartInternalSpan(context.Background(), "internal-span", attribute.String("key", "value"))
	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, trace.SpanKindInternal, spans[0].SpanKind)
}

// TestStartProducerSpan tests starting producer span.
func TestStartProducerSpan(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	ctx, span := StartProducerSpan(context.Background(), "producer-span", attribute.String("queue", "test-queue"))
	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, trace.SpanKindProducer, spans[0].SpanKind)
}

// TestStartConsumerSpan tests starting consumer span.
func TestStartConsumerSpan(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	ctx, span := StartConsumerSpan(context.Background(), "consumer-span", attribute.String("topic", "test-topic"))
	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, trace.SpanKindConsumer, spans[0].SpanKind)
}

// TestSpanFromContext tests getting span from context.
func TestSpanFromContext(t *testing.T) {
	_, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name      string
		setupCtx  func() context.Context
		expectNil bool
	}{
		{
			name: "context with span",
			setupCtx: func() context.Context {
				ctx, _ := StartSpan(context.Background(), "test-span")
				return ctx
			},
			expectNil: false,
		},
		{
			name: "context without span",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectNil: false, // Returns noop span
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			span := SpanFromContext(ctx)
			assert.NotNil(t, span)
		})
	}
}

// TestContextWithSpan tests setting span in context.
func TestContextWithSpan(t *testing.T) {
	_, cleanup := setupTestTracer(t)
	defer cleanup()

	ctx := context.Background()
	_, span := StartSpan(ctx, "test-span")

	newCtx := ContextWithSpan(ctx, span)
	assert.NotNil(t, newCtx)

	retrievedSpan := SpanFromContext(newCtx)
	assert.Equal(t, span, retrievedSpan)
}

// TestSetSpanStatus tests setting span status.
func TestSetSpanStatus(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name        string
		code        codes.Code
		description string
	}{
		{
			name:        "OK status",
			code:        codes.Ok,
			description: "",
		},
		{
			name:        "Error status",
			code:        codes.Error,
			description: "something went wrong",
		},
		{
			name:        "Unset status",
			code:        codes.Unset,
			description: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			_, span := StartSpan(context.Background(), "test-span")
			SetSpanStatus(span, tt.code, tt.description)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, tt.code, spans[0].Status.Code)
		})
	}
}

// TestSetSpanOK tests setting OK status.
func TestSetSpanOK(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	_, span := StartSpan(context.Background(), "test-span")
	SetSpanOK(span)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Ok, spans[0].Status.Code)
}

// TestSetSpanError tests setting error status.
func TestSetSpanError(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name        string
		err         error
		expectError bool
	}{
		{
			name:        "with error",
			err:         errors.New("test error"),
			expectError: true,
		},
		{
			name:        "with nil error",
			err:         nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			_, span := StartSpan(context.Background(), "test-span")
			SetSpanError(span, tt.err)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			if tt.expectError {
				assert.Equal(t, codes.Error, spans[0].Status.Code)
				assert.NotEmpty(t, spans[0].Events)
			}
		})
	}
}

// TestRecordError tests recording error.
func TestRecordError(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name        string
		err         error
		expectEvent bool
	}{
		{
			name:        "with error",
			err:         errors.New("test error"),
			expectEvent: true,
		},
		{
			name:        "with nil error",
			err:         nil,
			expectEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			_, span := StartSpan(context.Background(), "test-span")
			RecordError(span, tt.err)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			if tt.expectEvent {
				assert.NotEmpty(t, spans[0].Events)
			}
		})
	}
}

// TestAddEvent tests adding event.
func TestAddEvent(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name      string
		eventName string
		attrs     []attribute.KeyValue
	}{
		{
			name:      "event without attributes",
			eventName: "test-event",
			attrs:     nil,
		},
		{
			name:      "event with attributes",
			eventName: "test-event-attrs",
			attrs: []attribute.KeyValue{
				attribute.String("key", "value"),
				attribute.Int("count", 42),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			_, span := StartSpan(context.Background(), "test-span")
			AddEvent(span, tt.eventName, tt.attrs...)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			events := spans[0].Events
			require.NotEmpty(t, events)
			assert.Equal(t, tt.eventName, events[0].Name)
		})
	}
}

// TestSetAttributes tests setting attributes.
func TestSetAttributes(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name  string
		attrs []attribute.KeyValue
	}{
		{
			name: "single attribute",
			attrs: []attribute.KeyValue{
				attribute.String("key", "value"),
			},
		},
		{
			name: "multiple attributes",
			attrs: []attribute.KeyValue{
				attribute.String("key1", "value1"),
				attribute.Int("key2", 42),
				attribute.Bool("key3", true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			_, span := StartSpan(context.Background(), "test-span")
			SetAttributes(span, tt.attrs...)
			span.End()

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.GreaterOrEqual(t, len(spans[0].Attributes), len(tt.attrs))
		})
	}
}

// TestStringAttr tests string attribute.
func TestStringAttr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected attribute.KeyValue
	}{
		{
			name:     "simple string",
			key:      "key",
			value:    "value",
			expected: attribute.String("key", "value"),
		},
		{
			name:     "empty value",
			key:      "empty",
			value:    "",
			expected: attribute.String("empty", ""),
		},
		{
			name:     "special characters",
			key:      "special",
			value:    "hello\nworld",
			expected: attribute.String("special", "hello\nworld"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := StringAttr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestIntAttr tests int attribute.
func TestIntAttr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    int
		expected attribute.KeyValue
	}{
		{
			name:     "positive int",
			key:      "count",
			value:    42,
			expected: attribute.Int("count", 42),
		},
		{
			name:     "zero",
			key:      "zero",
			value:    0,
			expected: attribute.Int("zero", 0),
		},
		{
			name:     "negative int",
			key:      "negative",
			value:    -100,
			expected: attribute.Int("negative", -100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := IntAttr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestInt64Attr tests int64 attribute.
func TestInt64Attr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    int64
		expected attribute.KeyValue
	}{
		{
			name:     "large int64",
			key:      "large",
			value:    9223372036854775807,
			expected: attribute.Int64("large", 9223372036854775807),
		},
		{
			name:     "zero",
			key:      "zero",
			value:    0,
			expected: attribute.Int64("zero", 0),
		},
		{
			name:     "negative int64",
			key:      "negative",
			value:    -9223372036854775808,
			expected: attribute.Int64("negative", -9223372036854775808),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := Int64Attr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestFloat64Attr tests float64 attribute.
func TestFloat64Attr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    float64
		expected attribute.KeyValue
	}{
		{
			name:     "positive float",
			key:      "rate",
			value:    3.14159,
			expected: attribute.Float64("rate", 3.14159),
		},
		{
			name:     "zero",
			key:      "zero",
			value:    0.0,
			expected: attribute.Float64("zero", 0.0),
		},
		{
			name:     "negative float",
			key:      "negative",
			value:    -2.71828,
			expected: attribute.Float64("negative", -2.71828),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := Float64Attr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestBoolAttr tests bool attribute.
func TestBoolAttr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    bool
		expected attribute.KeyValue
	}{
		{
			name:     "true",
			key:      "enabled",
			value:    true,
			expected: attribute.Bool("enabled", true),
		},
		{
			name:     "false",
			key:      "disabled",
			value:    false,
			expected: attribute.Bool("disabled", false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := BoolAttr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestStringSliceAttr tests string slice attribute.
func TestStringSliceAttr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    []string
		expected attribute.KeyValue
	}{
		{
			name:     "multiple strings",
			key:      "tags",
			value:    []string{"tag1", "tag2", "tag3"},
			expected: attribute.StringSlice("tags", []string{"tag1", "tag2", "tag3"}),
		},
		{
			name:     "empty slice",
			key:      "empty",
			value:    []string{},
			expected: attribute.StringSlice("empty", []string{}),
		},
		{
			name:     "single string",
			key:      "single",
			value:    []string{"only"},
			expected: attribute.StringSlice("single", []string{"only"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := StringSliceAttr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestIntSliceAttr tests int slice attribute.
func TestIntSliceAttr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    []int
		expected attribute.KeyValue
	}{
		{
			name:     "multiple ints",
			key:      "numbers",
			value:    []int{1, 2, 3, 4, 5},
			expected: attribute.IntSlice("numbers", []int{1, 2, 3, 4, 5}),
		},
		{
			name:     "empty slice",
			key:      "empty",
			value:    []int{},
			expected: attribute.IntSlice("empty", []int{}),
		},
		{
			name:     "single int",
			key:      "single",
			value:    []int{42},
			expected: attribute.IntSlice("single", []int{42}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := IntSliceAttr(tt.key, tt.value)
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestHTTPMethodAttr tests HTTP method attribute.
func TestHTTPMethodAttr(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{name: "GET", method: "GET"},
		{name: "POST", method: "POST"},
		{name: "PUT", method: "PUT"},
		{name: "DELETE", method: "DELETE"},
		{name: "PATCH", method: "PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := HTTPMethodAttr(tt.method)
			assert.Equal(t, attribute.Key("http.method"), attr.Key)
			assert.Equal(t, tt.method, attr.Value.AsString())
		})
	}
}

// TestHTTPStatusCodeAttr tests HTTP status code attribute.
func TestHTTPStatusCodeAttr(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{name: "OK", code: 200},
		{name: "Created", code: 201},
		{name: "Bad Request", code: 400},
		{name: "Not Found", code: 404},
		{name: "Internal Server Error", code: 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := HTTPStatusCodeAttr(tt.code)
			assert.Equal(t, attribute.Key("http.status_code"), attr.Key)
			assert.Equal(t, int64(tt.code), attr.Value.AsInt64())
		})
	}
}

// TestRPCSystemAttr tests RPC system attribute.
func TestRPCSystemAttr(t *testing.T) {
	tests := []struct {
		name   string
		system string
	}{
		{name: "gRPC", system: "grpc"},
		{name: "HTTP", system: "http"},
		{name: "custom", system: "custom-rpc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := RPCSystemAttr(tt.system)
			assert.Equal(t, attribute.Key("rpc.system"), attr.Key)
			assert.Equal(t, tt.system, attr.Value.AsString())
		})
	}
}

// TestHTTPURLAttr tests HTTP URL attribute.
func TestHTTPURLAttr(t *testing.T) {
	attr := HTTPURLAttr("https://example.com/api/test")
	assert.Equal(t, attribute.Key("http.url"), attr.Key)
	assert.Equal(t, "https://example.com/api/test", attr.Value.AsString())
}

// TestHTTPTargetAttr tests HTTP target attribute.
func TestHTTPTargetAttr(t *testing.T) {
	attr := HTTPTargetAttr("/api/test")
	assert.Equal(t, attribute.Key("http.target"), attr.Key)
	assert.Equal(t, "/api/test", attr.Value.AsString())
}

// TestHTTPHostAttr tests HTTP host attribute.
func TestHTTPHostAttr(t *testing.T) {
	attr := HTTPHostAttr("example.com")
	assert.Equal(t, attribute.Key("http.host"), attr.Key)
	assert.Equal(t, "example.com", attr.Value.AsString())
}

// TestHTTPSchemeAttr tests HTTP scheme attribute.
func TestHTTPSchemeAttr(t *testing.T) {
	attr := HTTPSchemeAttr("https")
	assert.Equal(t, attribute.Key("http.scheme"), attr.Key)
	assert.Equal(t, "https", attr.Value.AsString())
}

// TestHTTPUserAgentAttr tests HTTP user agent attribute.
func TestHTTPUserAgentAttr(t *testing.T) {
	attr := HTTPUserAgentAttr("Mozilla/5.0")
	assert.Equal(t, attribute.Key("http.user_agent"), attr.Key)
	assert.Equal(t, "Mozilla/5.0", attr.Value.AsString())
}

// TestHTTPRequestContentLengthAttr tests HTTP request content length attribute.
func TestHTTPRequestContentLengthAttr(t *testing.T) {
	attr := HTTPRequestContentLengthAttr(1024)
	assert.Equal(t, attribute.Key("http.request_content_length"), attr.Key)
	assert.Equal(t, int64(1024), attr.Value.AsInt64())
}

// TestHTTPResponseContentLengthAttr tests HTTP response content length attribute.
func TestHTTPResponseContentLengthAttr(t *testing.T) {
	attr := HTTPResponseContentLengthAttr(2048)
	assert.Equal(t, attribute.Key("http.response_content_length"), attr.Key)
	assert.Equal(t, int64(2048), attr.Value.AsInt64())
}

// TestNetPeerIPAttr tests network peer IP attribute.
func TestNetPeerIPAttr(t *testing.T) {
	attr := NetPeerIPAttr("192.168.1.1")
	assert.Equal(t, attribute.Key("net.peer.ip"), attr.Key)
	assert.Equal(t, "192.168.1.1", attr.Value.AsString())
}

// TestNetPeerPortAttr tests network peer port attribute.
func TestNetPeerPortAttr(t *testing.T) {
	attr := NetPeerPortAttr(8080)
	assert.Equal(t, attribute.Key("net.peer.port"), attr.Key)
	assert.Equal(t, int64(8080), attr.Value.AsInt64())
}

// TestRPCServiceAttr tests RPC service attribute.
func TestRPCServiceAttr(t *testing.T) {
	attr := RPCServiceAttr("TestService")
	assert.Equal(t, attribute.Key("rpc.service"), attr.Key)
	assert.Equal(t, "TestService", attr.Value.AsString())
}

// TestRPCMethodAttr tests RPC method attribute.
func TestRPCMethodAttr(t *testing.T) {
	attr := RPCMethodAttr("GetUser")
	assert.Equal(t, attribute.Key("rpc.method"), attr.Key)
	assert.Equal(t, "GetUser", attr.Value.AsString())
}

// TestRPCGRPCStatusCodeAttr tests gRPC status code attribute.
func TestRPCGRPCStatusCodeAttr(t *testing.T) {
	attr := RPCGRPCStatusCodeAttr(0)
	assert.Equal(t, attribute.Key("rpc.grpc.status_code"), attr.Key)
	assert.Equal(t, int64(0), attr.Value.AsInt64())
}

// TestRequestIDAttr tests request ID attribute.
func TestRequestIDAttr(t *testing.T) {
	attr := RequestIDAttr("req-123")
	assert.Equal(t, attribute.Key("request.id"), attr.Key)
	assert.Equal(t, "req-123", attr.Value.AsString())
}

// TestUserIDAttr tests user ID attribute.
func TestUserIDAttr(t *testing.T) {
	attr := UserIDAttr("user-456")
	assert.Equal(t, attribute.Key("user.id"), attr.Key)
	assert.Equal(t, "user-456", attr.Value.AsString())
}

// TestBackendAttr tests backend attribute.
func TestBackendAttr(t *testing.T) {
	attr := BackendAttr("backend-service")
	assert.Equal(t, attribute.Key("backend"), attr.Key)
	assert.Equal(t, "backend-service", attr.Value.AsString())
}

// TestRouteAttr tests route attribute.
func TestRouteAttr(t *testing.T) {
	attr := RouteAttr("/api/v1/users")
	assert.Equal(t, attribute.Key("route"), attr.Key)
	assert.Equal(t, "/api/v1/users", attr.Value.AsString())
}

// TestErrorTypeAttr tests error type attribute.
func TestErrorTypeAttr(t *testing.T) {
	attr := ErrorTypeAttr("ValidationError")
	assert.Equal(t, attribute.Key("error.type"), attr.Key)
	assert.Equal(t, "ValidationError", attr.Value.AsString())
}

// TestErrorMessageAttr tests error message attribute.
func TestErrorMessageAttr(t *testing.T) {
	attr := ErrorMessageAttr("invalid input")
	assert.Equal(t, attribute.Key("error.message"), attr.Key)
	assert.Equal(t, "invalid input", attr.Value.AsString())
}

// TestTraceIDFromContext tests getting trace ID.
func TestTraceIDFromContext(t *testing.T) {
	_, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantLen  int
	}{
		{
			name: "context with span",
			setupCtx: func() context.Context {
				ctx, span := StartSpan(context.Background(), "test-span")
				defer span.End()
				return ctx
			},
			wantLen: 32, // Trace ID is 32 hex characters
		},
		{
			name: "context without span",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantLen: 32, // Returns invalid trace ID string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			traceID := TraceIDFromContext(ctx)
			assert.Len(t, traceID, tt.wantLen)
		})
	}
}

// TestSpanIDFromContext tests getting span ID.
func TestSpanIDFromContext(t *testing.T) {
	_, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantLen  int
	}{
		{
			name: "context with span",
			setupCtx: func() context.Context {
				ctx, span := StartSpan(context.Background(), "test-span")
				defer span.End()
				return ctx
			},
			wantLen: 16, // Span ID is 16 hex characters
		},
		{
			name: "context without span",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantLen: 16, // Returns invalid span ID string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			spanID := SpanIDFromContext(ctx)
			assert.Len(t, spanID, tt.wantLen)
		})
	}
}

// TestIsTracingEnabled tests checking if tracing enabled.
func TestIsTracingEnabled(t *testing.T) {
	_, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		setupCtx func() context.Context
		expected bool
	}{
		{
			name: "context with sampled span",
			setupCtx: func() context.Context {
				ctx, span := StartSpan(context.Background(), "test-span")
				defer span.End()
				return ctx
			},
			expected: true,
		},
		{
			name: "context without span",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			enabled := IsTracingEnabled(ctx)
			assert.Equal(t, tt.expected, enabled)
		})
	}
}

// TestWrapError tests wrapping error with trace info.
func TestWrapError(t *testing.T) {
	_, cleanup := setupTestTracer(t)
	defer cleanup()

	tests := []struct {
		name     string
		setupCtx func() context.Context
		err      error
		wantNil  bool
	}{
		{
			name: "nil error",
			setupCtx: func() context.Context {
				ctx, span := StartSpan(context.Background(), "test-span")
				defer span.End()
				return ctx
			},
			err:     nil,
			wantNil: true,
		},
		{
			name: "error with span",
			setupCtx: func() context.Context {
				ctx, span := StartSpan(context.Background(), "test-span")
				defer span.End()
				return ctx
			},
			err:     errors.New("test error"),
			wantNil: false,
		},
		{
			name: "error without span",
			setupCtx: func() context.Context {
				return context.Background()
			},
			err:     errors.New("test error"),
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			wrappedErr := WrapError(ctx, tt.err)
			if tt.wantNil {
				assert.Nil(t, wrappedErr)
			} else {
				assert.NotNil(t, wrappedErr)
				assert.Contains(t, wrappedErr.Error(), "test error")
			}
		})
	}
}

// TestAddStackTrace tests adding stack trace.
func TestAddStackTrace(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	_, span := StartSpan(context.Background(), "test-span")
	AddStackTrace(span)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	events := spans[0].Events
	require.NotEmpty(t, events)

	// Find stack_trace event
	var found bool
	for _, event := range events {
		if event.Name == "stack_trace" {
			found = true
			// Check that stack attribute exists
			for _, attr := range event.Attributes {
				if attr.Key == "stack" {
					assert.NotEmpty(t, attr.Value.AsString())
				}
			}
		}
	}
	assert.True(t, found, "stack_trace event not found")
}

// TestDefaultTracerName tests the default tracer name constant.
func TestDefaultTracerName(t *testing.T) {
	assert.Equal(t, "avapigw", DefaultTracerName)
}

// TestStartSpan_WithLinks tests starting span with links.
func TestStartSpan_WithLinks(t *testing.T) {
	exporter, cleanup := setupTestTracer(t)
	defer cleanup()

	// Create a link span context
	linkSpanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:  trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
	})

	link := trace.Link{
		SpanContext: linkSpanCtx,
		Attributes:  []attribute.KeyValue{attribute.String("link.type", "test")},
	}

	ctx, span := StartSpan(context.Background(), "test-span-with-links", WithLinks(link))
	assert.NotNil(t, ctx)
	assert.NotNil(t, span)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	// Links are recorded in the span
	assert.NotEmpty(t, spans[0].Links)
}

// TestTraceIDFromContext_NilSpan tests TraceIDFromContext with nil span.
func TestTraceIDFromContext_NilSpan(t *testing.T) {
	// Context without any span
	ctx := context.Background()
	traceID := TraceIDFromContext(ctx)
	// Returns invalid trace ID string (all zeros)
	assert.Len(t, traceID, 32)
}

// TestSpanIDFromContext_NilSpan tests SpanIDFromContext with nil span.
func TestSpanIDFromContext_NilSpan(t *testing.T) {
	// Context without any span
	ctx := context.Background()
	spanID := SpanIDFromContext(ctx)
	// Returns invalid span ID string (all zeros)
	assert.Len(t, spanID, 16)
}

// TestIsTracingEnabled_NilSpan tests IsTracingEnabled with nil span.
func TestIsTracingEnabled_NilSpan(t *testing.T) {
	// Context without any span
	ctx := context.Background()
	enabled := IsTracingEnabled(ctx)
	assert.False(t, enabled)
}

// TestWrapError_NilSpan tests WrapError with nil span in context.
func TestWrapError_NilSpan(t *testing.T) {
	// Context without any span
	ctx := context.Background()
	err := errors.New("test error")
	wrappedErr := WrapError(ctx, err)

	// Should still wrap the error with trace info (invalid IDs)
	assert.NotNil(t, wrappedErr)
	assert.Contains(t, wrappedErr.Error(), "test error")
	assert.Contains(t, wrappedErr.Error(), "trace_id=")
	assert.Contains(t, wrappedErr.Error(), "span_id=")
}
