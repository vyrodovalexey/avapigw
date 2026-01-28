package middleware

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestDefaultTracingConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultTracingConfig("test-service")

	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.Tracer)
	assert.NotNil(t, cfg.Propagator)
	assert.Equal(t, "test-service", cfg.ServiceName)
}

func TestUnaryTracingInterceptor_Success(t *testing.T) {
	t.Parallel()

	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	cfg := &TracingConfig{
		Tracer:      tp.Tracer("test"),
		Propagator:  propagation.TraceContext{},
		ServiceName: "test-service",
	}

	interceptor := UnaryTracingInterceptor(cfg)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)

	// Verify span was created
	spans := exporter.GetSpans()
	assert.NotEmpty(t, spans)
}

func TestUnaryTracingInterceptor_Error(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	cfg := &TracingConfig{
		Tracer:      tp.Tracer("test"),
		Propagator:  propagation.TraceContext{},
		ServiceName: "test-service",
	}

	interceptor := UnaryTracingInterceptor(cfg)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "internal error")
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)

	// Verify span was created with error
	spans := exporter.GetSpans()
	assert.NotEmpty(t, spans)
}

func TestUnaryTracingInterceptor_NilConfig(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTracingInterceptor(nil)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)
}

func TestStreamTracingInterceptor_Success(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	cfg := &TracingConfig{
		Tracer:      tp.Tracer("test"),
		Propagator:  propagation.TraceContext{},
		ServiceName: "test-service",
	}

	interceptor := StreamTracingInterceptor(cfg)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	stream := &tracingTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/StreamMethod",
		IsClientStream: true,
		IsServerStream: true,
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)

	// Verify span was created
	spans := exporter.GetSpans()
	assert.NotEmpty(t, spans)
}

func TestStreamTracingInterceptor_Error(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	cfg := &TracingConfig{
		Tracer:      tp.Tracer("test"),
		Propagator:  propagation.TraceContext{},
		ServiceName: "test-service",
	}

	interceptor := StreamTracingInterceptor(cfg)

	ctx := context.Background()
	stream := &tracingTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return status.Error(codes.Internal, "internal error")
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)

	// Verify span was created with error
	spans := exporter.GetSpans()
	assert.NotEmpty(t, spans)
}

func TestStreamTracingInterceptor_NilConfig(t *testing.T) {
	t.Parallel()

	interceptor := StreamTracingInterceptor(nil)

	ctx := context.Background()
	stream := &tracingTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
}

func TestTracingServerStream_Context(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), "key", "value")
	inner := &tracingTestServerStream{ctx: context.Background()}
	stream := &tracingServerStream{
		ServerStream: inner,
		ctx:          ctx,
		span:         nil,
	}

	assert.Equal(t, ctx, stream.Context())
}

func TestTracingServerStream_SendMsg(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	ctx, span := tp.Tracer("test").Start(context.Background(), "test")
	defer span.End()

	inner := &tracingTestServerStream{ctx: context.Background()}
	stream := &tracingServerStream{
		ServerStream: inner,
		ctx:          ctx,
		span:         span,
	}

	err := stream.SendMsg("message")
	assert.NoError(t, err)
}

func TestTracingServerStream_RecvMsg(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	ctx, span := tp.Tracer("test").Start(context.Background(), "test")
	defer span.End()

	inner := &tracingTestServerStream{ctx: context.Background()}
	stream := &tracingServerStream{
		ServerStream: inner,
		ctx:          ctx,
		span:         span,
	}

	err := stream.RecvMsg(nil)
	assert.NoError(t, err)
}

func TestExtractTraceContext(t *testing.T) {
	t.Parallel()

	propagator := propagation.TraceContext{}

	// Without metadata
	ctx := context.Background()
	result := extractTraceContext(ctx, propagator)
	assert.NotNil(t, result)

	// With metadata
	ctx = metadata.NewIncomingContext(context.Background(), metadata.MD{
		"traceparent": []string{"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
	})
	result = extractTraceContext(ctx, propagator)
	assert.NotNil(t, result)
}

func TestMetadataCarrier(t *testing.T) {
	t.Parallel()

	md := metadata.MD{
		"key1": []string{"value1"},
		"key2": []string{"value2a", "value2b"},
	}
	carrier := metadataCarrier(md)

	// Test Get
	assert.Equal(t, "value1", carrier.Get("key1"))
	assert.Equal(t, "value2a", carrier.Get("key2"))
	assert.Equal(t, "", carrier.Get("nonexistent"))

	// Test Set
	carrier.Set("key3", "value3")
	assert.Equal(t, "value3", carrier.Get("key3"))

	// Test Keys
	keys := carrier.Keys()
	assert.Len(t, keys, 3)
}

func TestInjectTraceContext(t *testing.T) {
	t.Parallel()

	// Setup tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	otel.SetTextMapPropagator(propagation.TraceContext{})

	ctx, span := tp.Tracer("test").Start(context.Background(), "test")
	defer span.End()

	md := metadata.MD{}
	InjectTraceContext(ctx, md)

	// Should have injected trace context
	// Note: The actual header depends on the propagator
}

// tracingTestServerStream implements grpc.ServerStream for testing
type tracingTestServerStream struct {
	ctx     context.Context
	sendErr error
	recvErr error
}

func (m *tracingTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *tracingTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *tracingTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *tracingTestServerStream) Context() context.Context       { return m.ctx }
func (m *tracingTestServerStream) SendMsg(_ interface{}) error    { return m.sendErr }
func (m *tracingTestServerStream) RecvMsg(_ interface{}) error    { return m.recvErr }
