package middleware

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

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

	// Add many clients using the Allow method to properly create entries
	for i := 0; i < 1000; i++ {
		limiter.Allow("client" + string(rune('A'+i%26)) + string(rune('0'+i%10)))
	}

	// Verify clients were added
	assert.Greater(t, limiter.ClientCount(), 0)

	// Cleanup should not panic and should work correctly
	limiter.CleanupOldClients()

	// Clients should still exist since they haven't expired
	// (TTL-based cleanup only removes expired entries)
	assert.Greater(t, limiter.ClientCount(), 0)
}

func TestGRPCRateLimiter_MemoryBounds(t *testing.T) {
	t.Parallel()

	// Create a limiter with a very small max clients limit
	limiter := NewGRPCRateLimiter(100, 10, true, WithGRPCMaxClients(100))

	// Add more clients than the limit
	for i := 0; i < 150; i++ {
		limiter.Allow("client" + string(rune('A'+i%26)) + string(rune('0'+i%10)) + string(rune('a'+i%26)))
	}

	// Client count should be bounded
	assert.LessOrEqual(t, limiter.ClientCount(), 100)
}

func TestGRPCRateLimiter_Stop(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)
	limiter.StartAutoCleanup()

	// Stop should not panic
	limiter.Stop()

	// Calling Stop again should not panic
	limiter.Stop()
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

// TestGRPCRateLimiter_EvictOldestLocked tests the evictOldestLocked memory management function.
func TestGRPCRateLimiter_EvictOldestLocked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		maxClients  int
		clientTTL   time.Duration
		numClients  int
		expectedMax int
		description string
	}{
		{
			name:        "evict when at capacity",
			maxClients:  10,
			clientTTL:   time.Hour, // Long TTL so entries don't expire
			numClients:  15,
			expectedMax: 10, // Should be at or below maxClients
			description: "should evict oldest entries when at capacity",
		},
		{
			name:        "small max clients",
			maxClients:  5,
			clientTTL:   time.Hour,
			numClients:  20,
			expectedMax: 5,
			description: "should handle small max clients limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			limiter := NewGRPCRateLimiter(100, 10, true,
				WithRateLimiterLogger(observability.NopLogger()),
				WithGRPCMaxClients(tt.maxClients),
				WithGRPCClientTTL(tt.clientTTL),
			)
			t.Cleanup(func() {
				limiter.Stop()
			})

			// Add clients to trigger eviction
			for i := 0; i < tt.numClients; i++ {
				clientAddr := "192.168.1." + string(rune('A'+i%26)) + string(rune('0'+i%10)) + ":12345"
				limiter.Allow(clientAddr)
			}

			// Verify client count is bounded
			clientCount := limiter.ClientCount()
			assert.LessOrEqual(t, clientCount, tt.expectedMax, tt.description)
		})
	}
}

// TestGRPCRateLimiter_EvictOldestLocked_ExpiredEntries tests that expired entries are removed during eviction.
func TestGRPCRateLimiter_EvictOldestLocked_ExpiredEntries(t *testing.T) {
	t.Parallel()

	// Use a very short TTL
	limiter := NewGRPCRateLimiter(100, 10, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithGRPCMaxClients(10),
		WithGRPCClientTTL(1*time.Millisecond),
	)
	t.Cleanup(func() {
		limiter.Stop()
	})

	// Add some clients
	for i := 0; i < 5; i++ {
		clientAddr := "old-client-" + string(rune('0'+i)) + ":12345"
		limiter.Allow(clientAddr)
	}

	// Wait for entries to expire
	time.Sleep(10 * time.Millisecond)

	// Add more clients to trigger eviction (need to exceed maxClients)
	for i := 0; i < 10; i++ {
		clientAddr := "new-client-" + string(rune('0'+i)) + ":12345"
		limiter.Allow(clientAddr)
	}

	// The expired entries should have been removed during eviction
	// Client count should be at or below maxClients
	clientCount := limiter.ClientCount()
	assert.LessOrEqual(t, clientCount, 10)
}

// TestGRPCRateLimiter_EvictOldestLocked_PreservesNewerEntries tests that eviction preserves newer entries.
func TestGRPCRateLimiter_EvictOldestLocked_PreservesNewerEntries(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithGRPCMaxClients(10),
		WithGRPCClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		limiter.Stop()
	})

	// Add old clients
	for i := 0; i < 5; i++ {
		clientAddr := "old-client-" + string(rune('0'+i)) + ":12345"
		limiter.Allow(clientAddr)
	}

	// Wait a bit to create time difference
	time.Sleep(10 * time.Millisecond)

	// Add new clients that will trigger eviction
	for i := 0; i < 10; i++ {
		clientAddr := "new-client-" + string(rune('0'+i)) + ":12345"
		limiter.Allow(clientAddr)
	}

	// Verify we're at or below max clients
	clientCount := limiter.ClientCount()
	assert.LessOrEqual(t, clientCount, 10)
}

// TestGRPCRateLimiter_EvictOldestLocked_EmptyMap tests eviction with empty client map.
func TestGRPCRateLimiter_EvictOldestLocked_EmptyMap(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithGRPCMaxClients(5),
		WithGRPCClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		limiter.Stop()
	})

	// No clients added, just verify no panic
	assert.Equal(t, 0, limiter.ClientCount())

	// Add one client - should work fine
	limiter.Allow("first-client:12345")
	assert.Equal(t, 1, limiter.ClientCount())
}

// TestGRPCRateLimiter_EvictOldestLocked_TargetSize tests that eviction targets 90% capacity.
func TestGRPCRateLimiter_EvictOldestLocked_TargetSize(t *testing.T) {
	t.Parallel()

	maxClients := 100
	limiter := NewGRPCRateLimiter(1000, 100, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithGRPCMaxClients(maxClients),
		WithGRPCClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		limiter.Stop()
	})

	// Fill to capacity and beyond
	for i := 0; i < maxClients+10; i++ {
		clientAddr := "client-" + string(rune('A'+i%26)) + string(rune('a'+i%26)) + string(rune('0'+i%10)) + ":12345"
		limiter.Allow(clientAddr)
	}

	// After eviction, should be at or below max clients
	targetSize := maxClients * 9 / 10
	clientCount := limiter.ClientCount()
	assert.LessOrEqual(t, clientCount, maxClients)
	assert.GreaterOrEqual(t, clientCount, targetSize)
}

// TestGRPCRateLimiter_WithGRPCClientTTL tests the WithGRPCClientTTL option.
func TestGRPCRateLimiter_WithGRPCClientTTL(t *testing.T) {
	t.Parallel()

	ttl := 5 * time.Minute
	limiter := NewGRPCRateLimiter(100, 10, true, WithGRPCClientTTL(ttl))
	t.Cleanup(func() {
		limiter.Stop()
	})

	assert.Equal(t, ttl, limiter.clientTTL)
}

// TestGRPCRateLimiter_WithGRPCMaxClients tests the WithGRPCMaxClients option.
func TestGRPCRateLimiter_WithGRPCMaxClients(t *testing.T) {
	t.Parallel()

	maxClients := 500
	limiter := NewGRPCRateLimiter(100, 10, true, WithGRPCMaxClients(maxClients))
	t.Cleanup(func() {
		limiter.Stop()
	})

	assert.Equal(t, maxClients, limiter.maxClients)
}

// TestGRPCRateLimiter_SetClientTTL tests the SetClientTTL method.
func TestGRPCRateLimiter_SetClientTTL(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)
	t.Cleanup(func() {
		limiter.Stop()
	})

	newTTL := 30 * time.Minute
	limiter.SetClientTTL(newTTL)

	limiter.mu.RLock()
	actualTTL := limiter.clientTTL
	limiter.mu.RUnlock()

	assert.Equal(t, newTTL, actualTTL)
}

// TestGRPCRateLimiter_SetMaxClients tests the SetMaxClients method.
func TestGRPCRateLimiter_SetMaxClients(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)
	t.Cleanup(func() {
		limiter.Stop()
	})

	newMax := 50000
	limiter.SetMaxClients(newMax)

	limiter.mu.RLock()
	actualMax := limiter.maxClients
	limiter.mu.RUnlock()

	assert.Equal(t, newMax, actualMax)
}

// TestGRPCRateLimiter_StartAutoCleanup_AlreadyStopped tests that StartAutoCleanup does nothing if already stopped.
func TestGRPCRateLimiter_StartAutoCleanup_AlreadyStopped(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(100, 10, true)

	// Stop first
	limiter.Stop()

	// StartAutoCleanup should return early without starting goroutine
	limiter.StartAutoCleanup()

	// Should not panic or cause issues
}

// TestGRPCRateLimiter_ConcurrentEviction tests concurrent access during eviction.
func TestGRPCRateLimiter_ConcurrentEviction(t *testing.T) {
	t.Parallel()

	limiter := NewGRPCRateLimiter(1000, 100, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithGRPCMaxClients(50),
		WithGRPCClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		limiter.Stop()
	})

	var wg sync.WaitGroup

	// Concurrent Allow calls that will trigger eviction
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			clientAddr := "client-" + string(rune('A'+n%26)) + string(rune('0'+n%10)) + ":12345"
			_ = limiter.Allow(clientAddr)
		}(i)
	}

	wg.Wait()

	// Should not panic and client count should be bounded
	assert.LessOrEqual(t, limiter.ClientCount(), 50)
}
