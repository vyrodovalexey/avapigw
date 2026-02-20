package proxy

import (
	"context"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
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

func TestWithDirectorBackendRegistry(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	director := NewRouterDirector(r, pool, WithDirectorBackendRegistry(registry))

	assert.NotNil(t, director.backendRegistry)
	assert.Equal(t, registry, director.backendRegistry)
}

func TestRouterDirector_ResolveTarget_NoRegistry(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Director without backend registry
	director := NewRouterDirector(r, pool)

	dest := &config.RouteDestination{
		Destination: config.Destination{Host: "my-service", Port: 8080},
	}

	target, host, sb, err := director.resolveTarget(dest)
	require.NoError(t, err)
	assert.Equal(t, "my-service:8080", target)
	assert.Nil(t, host)
	assert.Nil(t, sb)
}

func TestRouterDirector_ResolveTarget_NoMatchingBackend(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Director with empty registry
	director := NewRouterDirector(r, pool,
		WithDirectorLogger(logger),
		WithDirectorBackendRegistry(registry),
	)

	dest := &config.RouteDestination{
		Destination: config.Destination{Host: "unknown-service", Port: 9090},
	}

	target, host, sb, err := director.resolveTarget(dest)
	require.NoError(t, err)
	assert.Equal(t, "unknown-service:9090", target)
	assert.Nil(t, host)
	assert.Nil(t, sb)
}

func TestRouterDirector_ResolveTarget_WithBackend(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Create and register a backend
	backendCfg := config.Backend{
		Name: "grpc-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 50051, Weight: 1},
		},
	}
	b, err := backend.NewBackend(backendCfg, backend.WithBackendLogger(logger))
	require.NoError(t, err)
	err = registry.Register(b)
	require.NoError(t, err)
	err = b.Start(t.Context())
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(logger),
		WithDirectorBackendRegistry(registry),
	)

	dest := &config.RouteDestination{
		Destination: config.Destination{
			Host: "grpc-backend",
			Port: 9999, // Should be ignored
		},
	}

	target, host, sb, err := director.resolveTarget(dest)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:50051", target)
	assert.NotNil(t, host)
	assert.NotNil(t, sb)
	assert.Equal(t, "10.0.0.1", host.Address)
	assert.Equal(t, 50051, host.Port)

	// Clean up: release the host
	sb.ReleaseHost(host)
}

func TestRouterDirector_ResolveTarget_UnhealthyBackend(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Create a backend with unhealthy hosts
	backendCfg := config.Backend{
		Name: "unhealthy-grpc-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 50051, Weight: 1},
		},
	}
	b, err := backend.NewBackend(backendCfg, backend.WithBackendLogger(logger))
	require.NoError(t, err)
	err = registry.Register(b)
	require.NoError(t, err)

	// Mark all hosts as unhealthy
	for _, host := range b.GetHosts() {
		host.SetStatus(backend.StatusUnhealthy)
	}

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(logger),
		WithDirectorBackendRegistry(registry),
	)

	dest := &config.RouteDestination{
		Destination: config.Destination{
			Host: "unhealthy-grpc-backend",
			Port: 50051,
		},
	}

	_, _, _, err = director.resolveTarget(dest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no available hosts")
}

func TestRouterDirector_GetServiceBackend_NilRegistry(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)

	sb := director.getServiceBackend("any-host")
	assert.Nil(t, sb)
}

func TestRouterDirector_GetServiceBackend_NotFound(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	director := NewRouterDirector(r, pool, WithDirectorBackendRegistry(registry))

	sb := director.getServiceBackend("nonexistent")
	assert.Nil(t, sb)
}

func TestRouterDirector_GetServiceBackend_Found(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	backendCfg := config.Backend{
		Name: "found-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 50051, Weight: 1},
		},
	}
	b, err := backend.NewBackend(backendCfg, backend.WithBackendLogger(logger))
	require.NoError(t, err)
	err = registry.Register(b)
	require.NoError(t, err)

	director := NewRouterDirector(r, pool, WithDirectorBackendRegistry(registry))

	sb := director.getServiceBackend("found-backend")
	assert.NotNil(t, sb)
	assert.Equal(t, "found-backend", sb.Name())
}

func TestRouterDirector_Direct_WithBackendRegistry(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Create and register a backend with localhost as host
	backendCfg := config.Backend{
		Name: "test-grpc-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 50051, Weight: 1},
		},
	}
	b, err := backend.NewBackend(backendCfg, backend.WithBackendLogger(logger))
	require.NoError(t, err)
	err = registry.Register(b)
	require.NoError(t, err)
	err = b.Start(t.Context())
	require.NoError(t, err)

	// Add route with backend name as destination host
	err = r.AddRoute(config.GRPCRoute{
		Name: "backend-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{
				Host: "test-grpc-backend", // Backend name, not actual host
				Port: 9999,                // Should be ignored
			}},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(logger),
		WithDirectorBackendRegistry(registry),
	)

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	outCtx, conn, err := director.Direct(ctx, "/test.Service/Method")
	require.NoError(t, err)
	assert.NotNil(t, outCtx)
	assert.NotNil(t, conn)
}

func TestRouterDirector_Direct_WithUnhealthyBackend(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Create a backend with unhealthy hosts
	backendCfg := config.Backend{
		Name: "unhealthy-direct-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 50051, Weight: 1},
		},
	}
	b, err := backend.NewBackend(backendCfg, backend.WithBackendLogger(logger))
	require.NoError(t, err)
	err = registry.Register(b)
	require.NoError(t, err)

	// Mark all hosts as unhealthy
	for _, host := range b.GetHosts() {
		host.SetStatus(backend.StatusUnhealthy)
	}

	// Add route
	err = r.AddRoute(config.GRPCRoute{
		Name: "unhealthy-direct-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "unhealthy."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{
				Host: "unhealthy-direct-backend",
				Port: 50051,
			}},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(logger),
		WithDirectorBackendRegistry(registry),
	)

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	_, _, err = director.Direct(ctx, "/unhealthy.Service/Method")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no available hosts")
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

// --- Mock types for per-route auth tests ---

// mockVaultClientForDirector implements vault.Client for director tests.
type mockVaultClientForDirector struct {
	enabled bool
}

func (m *mockVaultClientForDirector) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClientForDirector) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForDirector) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForDirector) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForDirector) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClientForDirector) KV() vault.KVClient           { return nil }
func (m *mockVaultClientForDirector) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForDirector) Close() error                 { return nil }

// --- Option tests ---

func TestWithDirectorAuthMetrics(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Create metrics with a private registry to avoid conflicts
	reg := prometheus.NewRegistry()
	metrics := auth.NewMetricsWithRegisterer("test_director", reg)

	director := &RouterDirector{
		router:    r,
		connPool:  pool,
		authCache: make(map[string]auth.GRPCAuthenticator),
	}

	opt := WithDirectorAuthMetrics(metrics)
	opt(director)

	assert.NotNil(t, director.authMetrics)
	assert.Equal(t, metrics, director.authMetrics)
}

func TestWithDirectorVaultClient(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	mockClient := &mockVaultClientForDirector{enabled: true}

	director := &RouterDirector{
		router:    r,
		connPool:  pool,
		authCache: make(map[string]auth.GRPCAuthenticator),
	}

	opt := WithDirectorVaultClient(mockClient)
	opt(director)

	assert.NotNil(t, director.vaultClient)
	assert.Equal(t, mockClient, director.vaultClient)
}

func TestWithDirectorAuthMetrics_ViaConstructor(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	reg := prometheus.NewRegistry()
	metrics := auth.NewMetricsWithRegisterer("test_director_ctor", reg)

	director := NewRouterDirector(r, pool, WithDirectorAuthMetrics(metrics))

	assert.NotNil(t, director.authMetrics)
	assert.Equal(t, metrics, director.authMetrics)
}

func TestWithDirectorVaultClient_ViaConstructor(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	mockClient := &mockVaultClientForDirector{enabled: true}

	director := NewRouterDirector(r, pool, WithDirectorVaultClient(mockClient))

	assert.NotNil(t, director.vaultClient)
	assert.Equal(t, mockClient, director.vaultClient)
}

// --- Per-route authentication tests ---

func TestRouterDirector_Direct_WithAuth_NoCredentials(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Add route with API key auth enabled.
	// Requests without credentials should be rejected.
	err := r.AddRoute(config.GRPCRoute{
		Name: "auth-route-nocreds",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.AuthService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			APIKey: &config.APIKeyAuthConfig{
				Enabled: true,
				Header:  "x-api-key",
			},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Request without any credentials
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	_, _, directErr := director.Direct(ctx, "/test.AuthService/Method")
	require.Error(t, directErr)

	st, ok := status.FromError(directErr)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "authentication required")
}

func TestRouterDirector_Direct_WithAuth_InvalidCredentials(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	err := r.AddRoute(config.GRPCRoute{
		Name: "auth-route-invalid",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.InvalidTokenService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			APIKey: &config.APIKeyAuthConfig{
				Enabled: true,
				Header:  "x-api-key",
			},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Request with an API key that doesn't match any stored key
	md := metadata.Pairs("x-api-key", "invalid-api-key")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, _, directErr := director.Direct(ctx, "/test.InvalidTokenService/Method")
	require.Error(t, directErr)

	st, ok := status.FromError(directErr)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "authentication failed")
}

func TestRouterDirector_Direct_WithAuth_Disabled(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Add route with auth config present but disabled
	err := r.AddRoute(config.GRPCRoute{
		Name: "auth-disabled-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.DisabledAuthService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Authentication: &config.AuthenticationConfig{
			Enabled: false, // Auth disabled
			APIKey: &config.APIKeyAuthConfig{
				Enabled: true,
				Header:  "x-api-key",
			},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Request without credentials — should pass because auth is disabled
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	outCtx, conn, directErr := director.Direct(ctx, "/test.DisabledAuthService/Method")
	require.NoError(t, directErr)
	assert.NotNil(t, outCtx)
	assert.NotNil(t, conn)
}

func TestRouterDirector_Direct_WithAuth_NilAuthConfig(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Add route with no auth config at all
	err := r.AddRoute(config.GRPCRoute{
		Name: "no-auth-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.NoAuthService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		// Authentication is nil
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Request without credentials — should pass because no auth config
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{})

	outCtx, conn, directErr := director.Direct(ctx, "/test.NoAuthService/Method")
	require.NoError(t, directErr)
	assert.NotNil(t, outCtx)
	assert.NotNil(t, conn)
}

func TestRouterDirector_Direct_WithAuth_ValidJWT(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Add route with API key auth — test that the auth flow processes credentials
	err := r.AddRoute(config.GRPCRoute{
		Name: "auth-route-apikey",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.APIKeyAuthService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			APIKey: &config.APIKeyAuthConfig{
				Enabled: true,
				Header:  "x-api-key",
			},
		},
	})
	require.NoError(t, err)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Request with API key header — the API key won't match any stored key,
	// so this will fail with "authentication failed" (not "authentication required").
	// This tests that the auth flow is invoked and processes the credential.
	md := metadata.Pairs("x-api-key", "some-api-key")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, _, directErr := director.Direct(ctx, "/test.APIKeyAuthService/Method")
	require.Error(t, directErr)

	st, ok := status.FromError(directErr)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	// The key is provided but invalid, so it should be "authentication failed"
	assert.Contains(t, st.Message(), "authentication failed")
}

// --- Authenticator caching tests ---

func TestRouterDirector_GetOrCreateAuthenticator_Caching(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Use API key auth config which doesn't require key parsing
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}

	// First call should create the authenticator
	auth1, err := director.getOrCreateAuthenticator("cached-route", authCfg)
	require.NoError(t, err)
	require.NotNil(t, auth1)

	// Second call should return the cached authenticator
	auth2, err := director.getOrCreateAuthenticator("cached-route", authCfg)
	require.NoError(t, err)
	require.NotNil(t, auth2)

	// Both should be the same instance (pointer equality)
	assert.Same(t, auth1, auth2, "second call should return cached authenticator")

	// Different route name should create a new authenticator
	auth3, err := director.getOrCreateAuthenticator("different-route", authCfg)
	require.NoError(t, err)
	require.NotNil(t, auth3)

	assert.NotSame(t, auth1, auth3, "different route should get different authenticator")
}

func TestRouterDirector_GetOrCreateAuthenticator_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}

	const goroutines = 10
	var wg sync.WaitGroup
	results := make([]auth.GRPCAuthenticator, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = director.getOrCreateAuthenticator("concurrent-route", authCfg)
		}(i)
	}
	wg.Wait()

	// All goroutines should succeed
	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d should not error", i)
		require.NotNil(t, results[i], "goroutine %d should return authenticator", i)
	}

	// All should return the same cached instance
	for i := 1; i < goroutines; i++ {
		assert.Same(t, results[0], results[i],
			"goroutine %d should return same cached authenticator", i)
	}
}

// --- Auth config error tests ---

func TestRouterDirector_AuthenticateRoute_ConfigError(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Create a route with JWT auth that has an invalid static key format.
	// This causes NewGRPCAuthenticator to fail during JWT validator creation,
	// which triggers the Internal error path in authenticateRoute.
	route := &router.CompiledGRPCRoute{
		Name: "bad-auth-route",
		Config: config.GRPCRoute{
			Name: "bad-auth-route",
			Authentication: &config.AuthenticationConfig{
				Enabled: true,
				JWT: &config.JWTAuthConfig{
					Enabled:   true,
					Algorithm: "HS256",
					// This secret will be converted to a StaticKey that fails parsing
					Secret: "not-a-valid-key-format",
				},
			},
		},
	}

	err := director.authenticateRoute(context.Background(), route)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "authentication configuration error")
}

func TestRouterDirector_AuthenticateRoute_NoCredentials(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Create a route with API key auth config (works without key parsing issues)
	route := &router.CompiledGRPCRoute{
		Name: "auth-nocreds-route",
		Config: config.GRPCRoute{
			Name: "auth-nocreds-route",
			Authentication: &config.AuthenticationConfig{
				Enabled: true,
				APIKey: &config.APIKeyAuthConfig{
					Enabled: true,
					Header:  "x-api-key",
				},
			},
		},
	}

	// Call authenticateRoute without any credentials in context
	ctx := context.Background()
	err := director.authenticateRoute(ctx, route)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "authentication required")
}

func TestRouterDirector_AuthenticateRoute_InvalidCredentials(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	route := &router.CompiledGRPCRoute{
		Name: "auth-invalid-route",
		Config: config.GRPCRoute{
			Name: "auth-invalid-route",
			Authentication: &config.AuthenticationConfig{
				Enabled: true,
				APIKey: &config.APIKeyAuthConfig{
					Enabled: true,
					Header:  "x-api-key",
				},
			},
		},
	}

	// Call authenticateRoute with an API key that doesn't match any stored key
	md := metadata.Pairs("x-api-key", "invalid-api-key")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := director.authenticateRoute(ctx, route)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "authentication failed")
}

func TestRouterDirector_GetOrCreateAuthenticator_WithMetrics(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	reg := prometheus.NewRegistry()
	metrics := auth.NewMetricsWithRegisterer("test_auth_metrics", reg)

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
		WithDirectorAuthMetrics(metrics),
	)

	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}

	authenticator, err := director.getOrCreateAuthenticator("metrics-route", authCfg)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestRouterDirector_GetOrCreateAuthenticator_WithVaultClient(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	mockClient := &mockVaultClientForDirector{enabled: true}

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
		WithDirectorVaultClient(mockClient),
	)

	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}

	authenticator, err := director.getOrCreateAuthenticator("vault-route", authCfg)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestRouterDirector_GetOrCreateAuthenticator_DisabledAuth(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Disabled auth config — ConvertFromGatewayConfig returns (nil, nil)
	authCfg := &config.AuthenticationConfig{
		Enabled: false,
	}

	_, err := director.getOrCreateAuthenticator("disabled-route", authCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestRouterDirector_GetOrCreateAuthenticator_NilConfig(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Nil auth config — ConvertFromGatewayConfig returns (nil, nil)
	_, err := director.getOrCreateAuthenticator("nil-config-route", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// --- ClearAuthCache tests ---

func TestRouterDirector_ClearAuthCache_EmptyCache(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// ClearAuthCache on empty cache should not panic
	assert.NotPanics(t, func() {
		director.ClearAuthCache()
	})

	// Verify cache is still a valid (empty) map after clearing
	director.authCacheMu.RLock()
	assert.NotNil(t, director.authCache)
	assert.Len(t, director.authCache, 0)
	director.authCacheMu.RUnlock()
}

func TestRouterDirector_ClearAuthCache_WithCachedEntries(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Pre-populate the auth cache by creating authenticators
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}

	auth1, err := director.getOrCreateAuthenticator("route-1", authCfg)
	require.NoError(t, err)
	require.NotNil(t, auth1)

	auth2, err := director.getOrCreateAuthenticator("route-2", authCfg)
	require.NoError(t, err)
	require.NotNil(t, auth2)

	// Verify cache has entries
	director.authCacheMu.RLock()
	assert.Len(t, director.authCache, 2)
	director.authCacheMu.RUnlock()

	// Clear the cache
	director.ClearAuthCache()

	// Verify cache is empty
	director.authCacheMu.RLock()
	assert.Len(t, director.authCache, 0)
	director.authCacheMu.RUnlock()

	// Verify next auth request creates a new authenticator (not the cached one)
	auth1New, err := director.getOrCreateAuthenticator("route-1", authCfg)
	require.NoError(t, err)
	require.NotNil(t, auth1New)

	// The new authenticator should be a different instance than the original
	assert.NotSame(t, auth1, auth1New, "after cache clear, a new authenticator should be created")
}

func TestRouterDirector_ClearAuthCache_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}

	const goroutines = 20
	var wg sync.WaitGroup

	// Run ClearAuthCache concurrently with getOrCreateAuthenticator
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				// Half the goroutines clear the cache
				director.ClearAuthCache()
			} else {
				// Half the goroutines create authenticators
				routeName := "concurrent-route-" + string(rune('a'+idx%5))
				_, _ = director.getOrCreateAuthenticator(routeName, authCfg)
			}
		}(i)
	}

	wg.Wait()

	// If we get here without a race condition or panic, the test passes.
	// The cache should be in a valid state (either empty or with some entries).
	director.authCacheMu.RLock()
	assert.NotNil(t, director.authCache)
	director.authCacheMu.RUnlock()
}
