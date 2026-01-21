package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestUnaryRequestIDInterceptor_GeneratesID(t *testing.T) {
	t.Parallel()

	interceptor := UnaryRequestIDInterceptor()

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "response", nil
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)

	// Should have generated a request ID
	requestID := observability.RequestIDFromContext(capturedCtx)
	assert.NotEmpty(t, requestID)
}

func TestUnaryRequestIDInterceptor_UsesExistingID(t *testing.T) {
	t.Parallel()

	interceptor := UnaryRequestIDInterceptor()

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"x-request-id": []string{"existing-id"},
	})

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "response", nil
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)

	// Should use existing request ID
	requestID := observability.RequestIDFromContext(capturedCtx)
	assert.Equal(t, "existing-id", requestID)
}

func TestStreamRequestIDInterceptor_GeneratesID(t *testing.T) {
	t.Parallel()

	interceptor := StreamRequestIDInterceptor()

	ctx := context.Background()
	stream := &requestIDTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	var capturedCtx context.Context
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		capturedCtx = stream.Context()
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)

	// Should have generated a request ID
	requestID := observability.RequestIDFromContext(capturedCtx)
	assert.NotEmpty(t, requestID)
}

func TestStreamRequestIDInterceptor_UsesExistingID(t *testing.T) {
	t.Parallel()

	interceptor := StreamRequestIDInterceptor()

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"x-request-id": []string{"existing-id"},
	})

	stream := &requestIDTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	var capturedCtx context.Context
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		capturedCtx = stream.Context()
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)

	// Should use existing request ID
	requestID := observability.RequestIDFromContext(capturedCtx)
	assert.Equal(t, "existing-id", requestID)
}

func TestGetRequestID_FromObservabilityContext(t *testing.T) {
	t.Parallel()

	ctx := observability.ContextWithRequestID(context.Background(), "obs-request-id")

	requestID := GetRequestID(ctx)
	assert.Equal(t, "obs-request-id", requestID)
}

func TestGetRequestID_FromMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"x-request-id": []string{"metadata-request-id"},
	})

	requestID := GetRequestID(ctx)
	assert.Equal(t, "metadata-request-id", requestID)
}

func TestGetRequestID_NotPresent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	requestID := GetRequestID(ctx)
	assert.Empty(t, requestID)
}

func TestSetRequestIDInOutgoingContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = SetRequestIDInOutgoingContext(ctx, "outgoing-request-id")

	md, ok := metadata.FromOutgoingContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, []string{"outgoing-request-id"}, md.Get("x-request-id"))
}

func TestSetRequestIDInOutgoingContext_ExistingMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, metadata.MD{
		"x-custom": []string{"value"},
	})
	ctx = SetRequestIDInOutgoingContext(ctx, "outgoing-request-id")

	md, ok := metadata.FromOutgoingContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, []string{"outgoing-request-id"}, md.Get("x-request-id"))
	assert.Equal(t, []string{"value"}, md.Get("x-custom"))
}

func TestRequestIDServerStream_Context(t *testing.T) {
	t.Parallel()

	ctx := observability.ContextWithRequestID(context.Background(), "stream-request-id")
	inner := &requestIDTestServerStream{ctx: context.Background()}
	stream := &requestIDServerStream{
		ServerStream: inner,
		ctx:          ctx,
	}

	assert.Equal(t, ctx, stream.Context())
}

func TestRequestIDHeader_Constant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "x-request-id", RequestIDHeader)
}

func TestEnsureRequestID_EmptyExistingID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"x-request-id": []string{""},
	})

	newCtx := ensureRequestID(ctx)

	// Should generate a new ID since existing is empty
	requestID := observability.RequestIDFromContext(newCtx)
	assert.NotEmpty(t, requestID)
}

// requestIDTestServerStream implements grpc.ServerStream for testing
type requestIDTestServerStream struct {
	ctx context.Context
}

func (m *requestIDTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *requestIDTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *requestIDTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *requestIDTestServerStream) Context() context.Context       { return m.ctx }
func (m *requestIDTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *requestIDTestServerStream) RecvMsg(_ interface{}) error    { return nil }
