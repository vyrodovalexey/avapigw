package proxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewRouterDirector(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	assert.NotNil(t, director)
	assert.NotNil(t, director.router)
	assert.NotNil(t, director.connPool)
	assert.NotNil(t, director.logger)
}

func TestNewRouterDirector_WithOptions(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := NewRouterDirector(r, pool, WithDirectorLogger(logger))

	assert.NotNil(t, director)
}

func TestRouterDirector_Direct_NoMatchingRoute(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	_, _, err := director.Direct(ctx, "/test.Service/Method")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching route")
}

func TestRouterDirector_Direct_NoDestination(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Add route with no destinations
	err := r.AddRoute(config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool)

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	_, _, err = director.Direct(ctx, "/test.Service/Method")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no destination")
}

func TestRouterDirector_Direct_Success(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Add route with destination
	err := r.AddRoute(config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool)

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	outCtx, conn, err := director.Direct(ctx, "/test.Service/Method")
	require.NoError(t, err)
	assert.NotNil(t, outCtx)
	assert.NotNil(t, conn)
}

func TestRouterDirector_Direct_WithMetadata(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	err := r.AddRoute(config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool)

	ctx := context.Background()
	inMD := metadata.MD{
		"x-custom":   []string{"value"},
		"x-request":  []string{"123"},
		":authority": []string{"api.example.com"}, // Should be filtered
	}
	ctx = metadata.NewIncomingContext(ctx, inMD)

	outCtx, _, err := director.Direct(ctx, "/test.Service/Method")
	require.NoError(t, err)

	// Check outgoing metadata
	outMD, ok := metadata.FromOutgoingContext(outCtx)
	assert.True(t, ok)
	assert.Contains(t, outMD, "x-custom")
	assert.Contains(t, outMD, "x-request")
	assert.Contains(t, outMD, "x-gateway-route")
	assert.NotContains(t, outMD, ":authority") // Pseudo-headers should be filtered
}

func TestRouterDirector_SelectDestination_Single(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "backend1", Port: 8080}},
	}

	dest := director.selectDestination(destinations)
	assert.NotNil(t, dest)
	assert.Equal(t, "backend1", dest.Destination.Host)
}

func TestRouterDirector_SelectDestination_Empty(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	dest := director.selectDestination([]config.RouteDestination{})
	assert.Nil(t, dest)
}

func TestRouterDirector_SelectDestination_RoundRobin(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	// Equal weights should use round-robin
	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "backend1", Port: 8080}, Weight: 1},
		{Destination: config.Destination{Host: "backend2", Port: 8080}, Weight: 1},
	}

	// Call multiple times and verify distribution
	counts := make(map[string]int)
	for i := 0; i < 100; i++ {
		dest := director.selectDestination(destinations)
		counts[dest.Destination.Host]++
	}

	// Both backends should be selected
	assert.Greater(t, counts["backend1"], 0)
	assert.Greater(t, counts["backend2"], 0)
}

func TestRouterDirector_SelectDestination_Weighted(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	// Different weights
	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "backend1", Port: 8080}, Weight: 90},
		{Destination: config.Destination{Host: "backend2", Port: 8080}, Weight: 10},
	}

	// Call multiple times and verify weighted distribution
	counts := make(map[string]int)
	for i := 0; i < 1000; i++ {
		dest := director.selectDestination(destinations)
		counts[dest.Destination.Host]++
	}

	// backend1 should be selected more often
	assert.Greater(t, counts["backend1"], counts["backend2"])
}

func TestRouterDirector_SelectDestination_ZeroWeights(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	// Zero weights should default to 1
	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "backend1", Port: 8080}, Weight: 0},
		{Destination: config.Destination{Host: "backend2", Port: 8080}, Weight: 0},
	}

	// Should still work
	dest := director.selectDestination(destinations)
	assert.NotNil(t, dest)
}

func TestShouldForwardMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "regular header",
			key:      "x-custom",
			expected: true,
		},
		{
			name:     "pseudo header",
			key:      ":authority",
			expected: false,
		},
		{
			name:     "connection header",
			key:      "connection",
			expected: false,
		},
		{
			name:     "keep-alive header",
			key:      "keep-alive",
			expected: false,
		},
		{
			name:     "transfer-encoding header",
			key:      "transfer-encoding",
			expected: false,
		},
		{
			name:     "upgrade header",
			key:      "upgrade",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, shouldForwardMetadata(tt.key))
		})
	}
}

func TestNewStaticDirector(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := NewStaticDirector("localhost:50051", pool, logger)

	assert.NotNil(t, director)
	assert.Equal(t, "localhost:50051", director.target)
}

func TestStaticDirector_Direct(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := NewStaticDirector("localhost:50051", pool, logger)

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"x-custom": []string{"value"},
	})

	outCtx, conn, err := director.Direct(ctx, "/test.Service/Method")
	require.NoError(t, err)
	assert.NotNil(t, outCtx)
	assert.NotNil(t, conn)

	// Check metadata forwarding
	outMD, ok := metadata.FromOutgoingContext(outCtx)
	assert.True(t, ok)
	assert.Contains(t, outMD, "x-custom")
}

func TestStaticDirector_Direct_NoIncomingMetadata(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := NewStaticDirector("localhost:50051", pool, logger)

	ctx := context.Background()

	outCtx, conn, err := director.Direct(ctx, "/test.Service/Method")
	require.NoError(t, err)
	assert.NotNil(t, outCtx)
	assert.NotNil(t, conn)
}

func TestWithDirectorLogger(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := &RouterDirector{
		router:   r,
		connPool: pool,
	}

	opt := WithDirectorLogger(logger)
	opt(director)

	assert.NotNil(t, director.logger)
}

func BenchmarkRouterDirector_SelectDestination_Single(b *testing.B) {
	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "backend1", Port: 8080}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		director.selectDestination(destinations)
	}
}

func BenchmarkRouterDirector_SelectDestination_Weighted(b *testing.B) {
	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "backend1", Port: 8080}, Weight: 70},
		{Destination: config.Destination{Host: "backend2", Port: 8080}, Weight: 20},
		{Destination: config.Destination{Host: "backend3", Port: 8080}, Weight: 10},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		director.selectDestination(destinations)
	}
}
