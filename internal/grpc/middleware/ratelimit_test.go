package middleware

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewGRPCRateLimiter(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, false)

	assert.NotNil(t, limiter)
	assert.NotNil(t, limiter.limiter)
	assert.NotNil(t, limiter.clients)
	assert.False(t, limiter.perClient)
	assert.Equal(t, 100, limiter.rps)
	assert.Equal(t, 10, limiter.burst)
}

func TestNewGRPCRateLimiter_WithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	limiter := NewGRPCRateLimiter(100, 10, false, WithRateLimiterLogger(logger))

	assert.NotNil(t, limiter)
	assert.NotNil(t, limiter.logger)
}

func TestNewGRPCRateLimiter_PerClient(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)

	assert.NotNil(t, limiter)
	assert.True(t, limiter.perClient)
}

func TestGRPCRateLimiter_Allow_Global(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(1000, 100, false)

	// Should allow requests within limit
	for i := 0; i < 50; i++ {
		assert.True(t, limiter.Allow("client1"))
	}
}

func TestGRPCRateLimiter_Allow_PerClient(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(1000, 100, true)

	// Should allow requests within limit for each client
	for i := 0; i < 50; i++ {
		assert.True(t, limiter.Allow("client1"))
		assert.True(t, limiter.Allow("client2"))
	}
}

func TestGRPCRateLimiter_Allow_ExceedsLimit(t *testing.T) {
	t.Parallel()

	// Very low limit
	limiter := NewGRPCRateLimiter(1, 1, false)

	// First request should be allowed
	assert.True(t, limiter.Allow("client1"))

	// Subsequent requests should be rate limited
	allowed := 0
	for i := 0; i < 10; i++ {
		if limiter.Allow("client1") {
			allowed++
		}
	}
	// Some requests should be denied
	assert.Less(t, allowed, 10)
}

func TestGRPCRateLimiter_CleanupOldClients(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)

	// Add many clients
	for i := 0; i < 100; i++ {
		limiter.Allow("client" + string(rune('0'+i%10)))
	}

	// Cleanup should not panic
	limiter.CleanupOldClients()
}

func TestGRPCRateLimiter_CleanupOldClients_ManyClients(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)

	// Add more than 10000 clients to trigger cleanup
	for i := 0; i < 10001; i++ {
		limiter.clients["client"+string(rune(i))] = nil
	}

	limiter.CleanupOldClients()

	// Clients should be cleared
	assert.Empty(t, limiter.clients)
}

func TestUnaryRateLimitInterceptor(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(1000, 100, false)
	interceptor := UnaryRateLimitInterceptor(limiter)

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
}

func TestUnaryRateLimitInterceptor_Exceeded(t *testing.T) {
	t.Parallel()

	// Very low limit
	limiter := NewGRPCRateLimiter(1, 1, false)
	interceptor := UnaryRateLimitInterceptor(limiter)

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

	// First request should succeed
	_, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)

	// Subsequent requests may be rate limited
	rateLimited := false
	for i := 0; i < 10; i++ {
		_, err := interceptor(ctx, "request", info, handler)
		if err != nil {
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.ResourceExhausted {
				rateLimited = true
				break
			}
		}
	}
	assert.True(t, rateLimited)
}

func TestStreamRateLimitInterceptor(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(1000, 100, false)
	interceptor := StreamRateLimitInterceptor(limiter)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	stream := &rateLimitTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
}

func TestStreamRateLimitInterceptor_Exceeded(t *testing.T) {
	t.Parallel()

	// Very low limit
	limiter := NewGRPCRateLimiter(1, 1, false)
	interceptor := StreamRateLimitInterceptor(limiter)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	stream := &rateLimitTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	// First request should succeed
	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)

	// Subsequent requests may be rate limited
	rateLimited := false
	for i := 0; i < 10; i++ {
		err := interceptor(nil, stream, info, handler)
		if err != nil {
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.ResourceExhausted {
				rateLimited = true
				break
			}
		}
	}
	assert.True(t, rateLimited)
}

func TestGetClientAddrFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name: "with peer",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
			}),
			expected: "192.168.1.1:12345",
		},
		{
			name:     "without peer",
			ctx:      context.Background(),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := getClientAddrFromContext(tt.ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWithRateLimiterLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	limiter := &GRPCRateLimiter{}

	opt := WithRateLimiterLogger(logger)
	opt(limiter)

	assert.NotNil(t, limiter.logger)
}

// rateLimitTestServerStream implements grpc.ServerStream for testing
type rateLimitTestServerStream struct {
	ctx context.Context
}

func (m *rateLimitTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *rateLimitTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *rateLimitTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *rateLimitTestServerStream) Context() context.Context       { return m.ctx }
func (m *rateLimitTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *rateLimitTestServerStream) RecvMsg(_ interface{}) error    { return nil }
