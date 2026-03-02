package proxy

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// --- NewRouteRateLimiterManager tests ---

func TestNewRouteRateLimiterManager(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager()

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.limiters)
	assert.Equal(t, 0, manager.LimiterCount())
}

func TestNewRouteRateLimiterManager_WithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(logger),
	)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.logger)
}

// --- Check tests ---

func TestRouteRateLimiterManager_Check_NilConfig(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager()

	err := manager.Check(context.Background(), "test-route", nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, manager.LimiterCount())
}

func TestRouteRateLimiterManager_Check_Disabled(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager()

	cfg := &config.RateLimitConfig{
		Enabled:           false,
		RequestsPerSecond: 10,
		Burst:             5,
	}

	err := manager.Check(context.Background(), "test-route", cfg)
	assert.NoError(t, err)
	assert.Equal(t, 0, manager.LimiterCount())
}

func TestRouteRateLimiterManager_Check_Allowed(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
	}

	// First request should be allowed
	err := manager.Check(context.Background(), "test-route", cfg)
	assert.NoError(t, err)
	assert.Equal(t, 1, manager.LimiterCount())
}

func TestRouteRateLimiterManager_Check_Rejected(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	// Very low rate limit: 1 request per second, burst of 1
	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
	}

	// First request should be allowed (uses the burst)
	err := manager.Check(context.Background(), "reject-route", cfg)
	require.NoError(t, err)

	// Subsequent requests should be rejected (burst exhausted)
	err = manager.Check(context.Background(), "reject-route", cfg)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.Contains(t, st.Message(), "rate limit exceeded")
}

func TestRouteRateLimiterManager_Check_PerClient(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		PerClient:         true,
	}

	// Create contexts with different peer addresses
	ctx1 := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234},
	})
	ctx2 := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5678},
	})

	// First request from client 1 should be allowed
	err := manager.Check(ctx1, "perclient-route", cfg)
	require.NoError(t, err)

	// First request from client 2 should also be allowed (different client)
	err = manager.Check(ctx2, "perclient-route", cfg)
	require.NoError(t, err)

	// Second request from client 1 should be rejected (burst exhausted)
	err = manager.Check(ctx1, "perclient-route", cfg)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
}

// --- GetOrCreate caching tests ---

func TestRouteRateLimiterManager_GetOrCreate_Caching(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
	}

	// First call creates the limiter
	limiter1 := manager.getOrCreateLimiter("cached-route", cfg)
	require.NotNil(t, limiter1)
	assert.Equal(t, 1, manager.LimiterCount())

	// Second call should return the cached limiter
	limiter2 := manager.getOrCreateLimiter("cached-route", cfg)
	require.NotNil(t, limiter2)
	assert.Equal(t, 1, manager.LimiterCount())

	// Both should be the same instance
	assert.Same(t, limiter1, limiter2)

	// Different route should create a new limiter
	limiter3 := manager.getOrCreateLimiter("different-route", cfg)
	require.NotNil(t, limiter3)
	assert.Equal(t, 2, manager.LimiterCount())
	assert.NotSame(t, limiter1, limiter3)
}

// --- Clear tests ---

func TestRouteRateLimiterManager_Clear(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
	}

	// Create some limiters
	err := manager.Check(context.Background(), "route-1", cfg)
	require.NoError(t, err)
	err = manager.Check(context.Background(), "route-2", cfg)
	require.NoError(t, err)

	assert.Equal(t, 2, manager.LimiterCount())

	// Clear all limiters
	manager.Clear()

	assert.Equal(t, 0, manager.LimiterCount())
}

func TestRouteRateLimiterManager_Clear_Empty(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager()

	// Clear on empty manager should not panic
	assert.NotPanics(t, func() {
		manager.Clear()
	})
	assert.Equal(t, 0, manager.LimiterCount())
}

// --- Concurrent access tests ---

func TestRouteRateLimiterManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1000,
		Burst:             1000,
	}

	const goroutines = 50
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			routeName := "concurrent-route"
			if idx%5 == 0 {
				routeName = "concurrent-route-alt"
			}
			_ = manager.Check(context.Background(), routeName, cfg)
		}(i)
	}

	wg.Wait()

	// Should have created at most 2 limiters (concurrent-route and concurrent-route-alt)
	assert.LessOrEqual(t, manager.LimiterCount(), 2)
	assert.GreaterOrEqual(t, manager.LimiterCount(), 1)
}

func TestRouteRateLimiterManager_ConcurrentCheckAndClear(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1000,
		Burst:             1000,
	}

	const goroutines = 30
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			if idx%3 == 0 {
				manager.Clear()
			} else {
				_ = manager.Check(context.Background(), "race-route", cfg)
			}
		}(i)
	}

	wg.Wait()

	// If we get here without a race condition or panic, the test passes
	assert.NotNil(t, manager.limiters)
}

// --- extractClientAddr tests ---

func TestExtractClientAddr_WithPeer(t *testing.T) {
	t.Parallel()

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9999},
	})

	addr := extractClientAddr(ctx)
	assert.Equal(t, "192.168.1.1:9999", addr)
}

func TestExtractClientAddr_NoPeer(t *testing.T) {
	t.Parallel()

	addr := extractClientAddr(context.Background())
	assert.Equal(t, "unknown", addr)
}

// --- LimiterCount tests ---

func TestRouteRateLimiterManager_LimiterCount(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	assert.Equal(t, 0, manager.LimiterCount())

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
	}

	_ = manager.Check(context.Background(), "route-a", cfg)
	assert.Equal(t, 1, manager.LimiterCount())

	_ = manager.Check(context.Background(), "route-b", cfg)
	assert.Equal(t, 2, manager.LimiterCount())

	// Same route should not increase count
	_ = manager.Check(context.Background(), "route-a", cfg)
	assert.Equal(t, 2, manager.LimiterCount())
}

// --- WithRateLimiterManagerLogger option test ---

func TestWithRateLimiterManagerLogger_Option(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	manager := NewRouteRateLimiterManager()

	opt := WithRateLimiterManagerLogger(logger)
	opt(manager)

	assert.NotNil(t, manager.logger)
}

// --- Multiple routes with different configs ---

func TestRouteRateLimiterManager_MultipleRoutes(t *testing.T) {
	t.Parallel()

	manager := NewRouteRateLimiterManager(
		WithRateLimiterManagerLogger(observability.NopLogger()),
	)
	defer manager.Clear()

	// Route 1: high rate limit
	cfg1 := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1000,
		Burst:             1000,
	}

	// Route 2: low rate limit
	cfg2 := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
	}

	// Route 1 should allow many requests
	for i := 0; i < 10; i++ {
		err := manager.Check(context.Background(), "high-rate-route", cfg1)
		assert.NoError(t, err)
	}

	// Route 2 should allow first request
	err := manager.Check(context.Background(), "low-rate-route", cfg2)
	assert.NoError(t, err)

	// Route 2 should reject second request
	err = manager.Check(context.Background(), "low-rate-route", cfg2)
	assert.Error(t, err)

	assert.Equal(t, 2, manager.LimiterCount())
}
