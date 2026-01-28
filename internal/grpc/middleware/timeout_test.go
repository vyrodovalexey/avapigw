package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryTimeoutInterceptor_Success(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTimeoutInterceptor(5 * time.Second)

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

func TestUnaryTimeoutInterceptor_Timeout(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTimeoutInterceptor(50 * time.Millisecond)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		time.Sleep(200 * time.Millisecond)
		return "response", nil
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestUnaryTimeoutInterceptor_ExistingDeadline_Shorter(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTimeoutInterceptor(5 * time.Second)

	// Create context with shorter deadline
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		time.Sleep(200 * time.Millisecond)
		return "response", nil
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
}

func TestUnaryTimeoutInterceptor_ExistingDeadline_Longer(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTimeoutInterceptor(50 * time.Millisecond)

	// Create context with longer deadline
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		time.Sleep(200 * time.Millisecond)
		return "response", nil
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestUnaryTimeoutInterceptor_Canceled(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTimeoutInterceptor(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		time.Sleep(200 * time.Millisecond)
		return "response", nil
	}

	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}

func TestUnaryTimeoutInterceptor_HandlerError(t *testing.T) {
	t.Parallel()

	interceptor := UnaryTimeoutInterceptor(5 * time.Second)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "internal error")
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestStreamTimeoutInterceptor_Success(t *testing.T) {
	t.Parallel()

	interceptor := StreamTimeoutInterceptor(5 * time.Second)

	ctx := context.Background()
	stream := &timeoutTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
}

func TestStreamTimeoutInterceptor_Timeout(t *testing.T) {
	t.Parallel()

	interceptor := StreamTimeoutInterceptor(50 * time.Millisecond)

	ctx := context.Background()
	stream := &timeoutTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestStreamTimeoutInterceptor_ExistingDeadline(t *testing.T) {
	t.Parallel()

	interceptor := StreamTimeoutInterceptor(5 * time.Second)

	// Create context with shorter deadline
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	stream := &timeoutTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
}

func TestStreamTimeoutInterceptor_Canceled(t *testing.T) {
	t.Parallel()

	interceptor := StreamTimeoutInterceptor(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	stream := &timeoutTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}

func TestStreamTimeoutInterceptor_HandlerError(t *testing.T) {
	t.Parallel()

	interceptor := StreamTimeoutInterceptor(5 * time.Second)

	ctx := context.Background()
	stream := &timeoutTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return status.Error(codes.Internal, "internal error")
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestTimeoutServerStream_Context(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	inner := &timeoutTestServerStream{ctx: context.Background()}
	stream := &timeoutServerStream{
		ServerStream: inner,
		ctx:          ctx,
	}

	assert.Equal(t, ctx, stream.Context())
}

// timeoutTestServerStream implements grpc.ServerStream for testing
type timeoutTestServerStream struct {
	ctx context.Context
}

func (m *timeoutTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *timeoutTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *timeoutTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *timeoutTestServerStream) Context() context.Context       { return m.ctx }
func (m *timeoutTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *timeoutTestServerStream) RecvMsg(_ interface{}) error    { return nil }
