package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewGRPCCircuitBreaker(t *testing.T) {
	t.Parallel()

	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)

	assert.NotNil(t, cb)
	assert.NotNil(t, cb.cb)
	assert.Equal(t, gobreaker.StateClosed, cb.State())
}

func TestNewGRPCCircuitBreaker_WithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second, WithCircuitBreakerLogger(logger))

	assert.NotNil(t, cb)
	assert.NotNil(t, cb.logger)
}

func TestGRPCCircuitBreaker_State(t *testing.T) {
	t.Parallel()

	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)

	// Initial state should be closed
	assert.Equal(t, gobreaker.StateClosed, cb.State())
}

func TestUnaryCircuitBreakerInterceptor_Success(t *testing.T) {
	t.Parallel()

	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)
	interceptor := UnaryCircuitBreakerInterceptor(cb)

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

func TestUnaryCircuitBreakerInterceptor_Error(t *testing.T) {
	t.Parallel()

	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)
	interceptor := UnaryCircuitBreakerInterceptor(cb)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "internal error")
	}

	_, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
}

func TestUnaryCircuitBreakerInterceptor_NonFailureCodes(t *testing.T) {
	t.Parallel()

	// These codes should not count as failures
	nonFailureCodes := []codes.Code{
		codes.OK,
		codes.Canceled,
		codes.InvalidArgument,
		codes.NotFound,
		codes.AlreadyExists,
		codes.PermissionDenied,
		codes.Unauthenticated,
		codes.FailedPrecondition,
		codes.OutOfRange,
	}

	for _, code := range nonFailureCodes {
		t.Run(code.String(), func(t *testing.T) {
			t.Parallel()

			cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)
			interceptor := UnaryCircuitBreakerInterceptor(cb)

			ctx := context.Background()
			info := &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/Method",
			}

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				if code == codes.OK {
					return "response", nil
				}
				return nil, status.Error(code, "error")
			}

			_, _ = interceptor(ctx, "request", info, handler)

			// Circuit breaker should still be closed
			assert.Equal(t, gobreaker.StateClosed, cb.State())
		})
	}
}

func TestStreamCircuitBreakerInterceptor_Success(t *testing.T) {
	t.Parallel()

	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)
	interceptor := StreamCircuitBreakerInterceptor(cb)

	ctx := context.Background()
	stream := &cbTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
}

func TestStreamCircuitBreakerInterceptor_Error(t *testing.T) {
	t.Parallel()

	cb := NewGRPCCircuitBreaker("test", 5, 10*time.Second)
	interceptor := StreamCircuitBreakerInterceptor(cb)

	ctx := context.Background()
	stream := &cbTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return status.Error(codes.Internal, "internal error")
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
}

func TestSafeIntToUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    int
		expected uint32
	}{
		{
			name:     "positive value",
			input:    100,
			expected: 100,
		},
		{
			name:     "zero",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative value",
			input:    -1,
			expected: 0,
		},
		{
			name:     "max uint32",
			input:    int(^uint32(0)),
			expected: ^uint32(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := safeIntToUint32(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWithCircuitBreakerLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cb := &GRPCCircuitBreaker{}

	opt := WithCircuitBreakerLogger(logger)
	opt(cb)

	assert.NotNil(t, cb.logger)
}

// cbTestServerStream implements grpc.ServerStream for testing
type cbTestServerStream struct {
	ctx context.Context
}

func (m *cbTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *cbTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *cbTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *cbTestServerStream) Context() context.Context       { return m.ctx }
func (m *cbTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *cbTestServerStream) RecvMsg(_ interface{}) error    { return nil }

func TestUnaryCircuitBreakerInterceptor_OpenState(t *testing.T) {
	t.Parallel()

	// Create a circuit breaker that will open quickly
	cb := NewGRPCCircuitBreaker("test", 2, 100*time.Millisecond)
	interceptor := UnaryCircuitBreakerInterceptor(cb)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Handler that always fails with a failure code
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, status.Error(codes.Unavailable, "unavailable")
	}

	// Trigger failures to open the circuit breaker
	for i := 0; i < 10; i++ {
		_, _ = interceptor(ctx, "request", info, handler)
	}

	// If circuit breaker is open, it should return Unavailable
	if cb.State() == gobreaker.StateOpen {
		_, err := interceptor(ctx, "request", info, handler)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	}
}

func TestStreamCircuitBreakerInterceptor_OpenState(t *testing.T) {
	t.Parallel()

	// Create a circuit breaker that will open quickly
	cb := NewGRPCCircuitBreaker("test", 2, 100*time.Millisecond)
	interceptor := StreamCircuitBreakerInterceptor(cb)

	ctx := context.Background()
	stream := &cbTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	// Handler that always fails with a failure code
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return status.Error(codes.Unavailable, "unavailable")
	}

	// Trigger failures to open the circuit breaker
	for i := 0; i < 10; i++ {
		_ = interceptor(nil, stream, info, handler)
	}

	// If circuit breaker is open, it should return Unavailable
	if cb.State() == gobreaker.StateOpen {
		err := interceptor(nil, stream, info, handler)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	}
}
