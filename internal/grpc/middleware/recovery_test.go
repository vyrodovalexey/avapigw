package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestUnaryRecoveryInterceptor_Success(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := UnaryRecoveryInterceptor(logger)

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

func TestUnaryRecoveryInterceptor_Error(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := UnaryRecoveryInterceptor(logger)

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

func TestUnaryRecoveryInterceptor_Panic(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := UnaryRecoveryInterceptor(logger)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic("test panic")
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestUnaryRecoveryInterceptor_PanicWithError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := UnaryRecoveryInterceptor(logger)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic(status.Error(codes.Unavailable, "panic error"))
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestStreamRecoveryInterceptor_Success(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := StreamRecoveryInterceptor(logger)

	ctx := context.Background()
	stream := &recoveryTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
}

func TestStreamRecoveryInterceptor_Error(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := StreamRecoveryInterceptor(logger)

	ctx := context.Background()
	stream := &recoveryTestServerStream{ctx: ctx}
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

func TestStreamRecoveryInterceptor_Panic(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := StreamRecoveryInterceptor(logger)

	ctx := context.Background()
	stream := &recoveryTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		panic("test panic")
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestUnaryRecoveryInterceptorWithHandler_Success(t *testing.T) {
	t.Parallel()

	recoveryHandler := func(p interface{}) error {
		return status.Error(codes.Aborted, "custom recovery")
	}
	interceptor := UnaryRecoveryInterceptorWithHandler(recoveryHandler)

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

func TestUnaryRecoveryInterceptorWithHandler_Panic(t *testing.T) {
	t.Parallel()

	recoveryHandler := func(p interface{}) error {
		return status.Error(codes.Aborted, "custom recovery")
	}
	interceptor := UnaryRecoveryInterceptorWithHandler(recoveryHandler)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic("test panic")
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Aborted, st.Code())
}

func TestStreamRecoveryInterceptorWithHandler_Success(t *testing.T) {
	t.Parallel()

	recoveryHandler := func(p interface{}) error {
		return status.Error(codes.Aborted, "custom recovery")
	}
	interceptor := StreamRecoveryInterceptorWithHandler(recoveryHandler)

	ctx := context.Background()
	stream := &recoveryTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
}

func TestStreamRecoveryInterceptorWithHandler_Panic(t *testing.T) {
	t.Parallel()

	recoveryHandler := func(p interface{}) error {
		return status.Error(codes.Aborted, "custom recovery")
	}
	interceptor := StreamRecoveryInterceptorWithHandler(recoveryHandler)

	ctx := context.Background()
	stream := &recoveryTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		panic("test panic")
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Aborted, st.Code())
}

// recoveryTestServerStream implements grpc.ServerStream for testing
type recoveryTestServerStream struct {
	ctx context.Context
}

func (m *recoveryTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *recoveryTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *recoveryTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *recoveryTestServerStream) Context() context.Context       { return m.ctx }
func (m *recoveryTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *recoveryTestServerStream) RecvMsg(_ interface{}) error    { return nil }
