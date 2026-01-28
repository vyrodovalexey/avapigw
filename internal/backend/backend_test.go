package backend

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestStatus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   Status
		expected string
	}{
		{StatusUnknown, "unknown"},
		{StatusHealthy, "healthy"},
		{StatusUnhealthy, "unhealthy"},
		{Status(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestNewHost(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 50)

	assert.Equal(t, "10.0.0.1", host.Address)
	assert.Equal(t, 8080, host.Port)
	assert.Equal(t, 50, host.Weight)
	assert.Equal(t, StatusUnknown, host.Status())
}

func TestHost_URL(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)
	assert.Equal(t, "http://10.0.0.1:8080", host.URL())
}

func TestHost_Status(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	assert.Equal(t, StatusUnknown, host.Status())

	host.SetStatus(StatusHealthy)
	assert.Equal(t, StatusHealthy, host.Status())

	host.SetStatus(StatusUnhealthy)
	assert.Equal(t, StatusUnhealthy, host.Status())
}

func TestHost_Connections(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	assert.Equal(t, int64(0), host.Connections())

	host.IncrementConnections()
	assert.Equal(t, int64(1), host.Connections())

	host.IncrementConnections()
	assert.Equal(t, int64(2), host.Connections())

	host.DecrementConnections()
	assert.Equal(t, int64(1), host.Connections())
}

func TestHost_LastUsed(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	// Initially zero
	assert.True(t, host.LastUsed().IsZero() || host.LastUsed().Before(time.Now().Add(-time.Hour)))

	// After increment, should be recent
	host.IncrementConnections()
	assert.True(t, time.Since(host.LastUsed()) < time.Second)
}

func TestNewBackend(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080, Weight: 50},
			{Address: "10.0.0.2", Port: 8080, Weight: 50},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	assert.Equal(t, "test-backend", backend.Name())
	assert.Len(t, backend.hosts, 2)
	assert.NotNil(t, backend.loadBalancer)
	assert.NotNil(t, backend.pool)
}

func TestNewBackend_MissingName(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	_, err := NewBackend(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestNewBackend_NoHosts(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name:  "test-backend",
		Hosts: []config.BackendHost{},
	}

	_, err := NewBackend(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "host")
}

func TestNewBackend_WithOptions(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	logger := observability.NopLogger()
	lb := NewRoundRobinBalancer(nil)
	pool := NewConnectionPool(DefaultPoolConfig())

	backend, err := NewBackend(cfg,
		WithBackendLogger(logger),
		WithLoadBalancer(lb),
		WithConnectionPool(pool),
	)
	require.NoError(t, err)

	assert.Equal(t, lb, backend.loadBalancer)
	assert.Equal(t, pool, backend.pool)
}

func TestNewBackend_DefaultWeight(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080, Weight: 0}, // Zero weight
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Weight should default to 1
	assert.Equal(t, 1, backend.hosts[0].Weight)
}

func TestNewBackend_LoadBalancerAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algorithm string
	}{
		{config.LoadBalancerRoundRobin},
		{config.LoadBalancerWeighted},
		{config.LoadBalancerLeastConn},
		{config.LoadBalancerRandom},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			t.Parallel()
			cfg := config.Backend{
				Name: "test-backend",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8080},
				},
				LoadBalancer: &config.LoadBalancer{Algorithm: tt.algorithm},
			}

			backend, err := NewBackend(cfg)
			require.NoError(t, err)
			assert.NotNil(t, backend.loadBalancer)
		})
	}
}

func TestServiceBackend_GetHost(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Mark host as healthy
	backend.hosts[0].SetStatus(StatusHealthy)

	host, err := backend.GetHost()
	require.NoError(t, err)
	assert.NotNil(t, host)
	assert.Equal(t, int64(1), host.Connections())
}

func TestServiceBackend_GetHost_NoHealthyHosts(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Mark host as unhealthy
	backend.hosts[0].SetStatus(StatusUnhealthy)

	_, err = backend.GetHost()
	assert.Error(t, err)
}

func TestServiceBackend_ReleaseHost(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	backend.hosts[0].SetStatus(StatusHealthy)

	host, err := backend.GetHost()
	require.NoError(t, err)
	assert.Equal(t, int64(1), host.Connections())

	backend.ReleaseHost(host)
	assert.Equal(t, int64(0), host.Connections())
}

func TestServiceBackend_ReleaseHost_Nil(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Should not panic
	backend.ReleaseHost(nil)
}

func TestServiceBackend_Status(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	assert.Equal(t, StatusUnknown, backend.Status())
}

func TestServiceBackend_StartStop(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	err = backend.Start(ctx)
	require.NoError(t, err)
	assert.Equal(t, StatusHealthy, backend.Status())

	// Without health check, hosts should be marked healthy
	assert.Equal(t, StatusHealthy, backend.hosts[0].Status())

	err = backend.Stop(ctx)
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, backend.Status())
}

func TestServiceBackend_GetHosts(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
			{Address: "10.0.0.2", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	hosts := backend.GetHosts()
	assert.Len(t, hosts, 2)
}

func TestServiceBackend_GetHealthyHosts(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
			{Address: "10.0.0.2", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Mark one host as healthy
	backend.hosts[0].SetStatus(StatusHealthy)
	backend.hosts[1].SetStatus(StatusUnhealthy)

	healthy := backend.GetHealthyHosts()
	assert.Len(t, healthy, 1)
	assert.Equal(t, "10.0.0.1", healthy[0].Address)
}

func TestServiceBackend_HTTPClient(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	client := backend.HTTPClient()
	assert.NotNil(t, client)
}

func TestNewRegistry(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	assert.NotNil(t, registry)
	assert.NotNil(t, registry.backends)
}

func TestRegistry_Register(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	// Duplicate registration should fail
	err = registry.Register(backend)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegistry_Unregister(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	err = registry.Unregister("test-backend")
	require.NoError(t, err)

	// Unregister non-existent should fail
	err = registry.Unregister("test-backend")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_Get(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	// Found
	result, exists := registry.Get("test-backend")
	assert.True(t, exists)
	assert.Equal(t, "test-backend", result.Name())

	// Not found
	_, exists = registry.Get("nonexistent")
	assert.False(t, exists)
}

func TestRegistry_GetAll(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	for i := 0; i < 3; i++ {
		cfg := config.Backend{
			Name: "backend-" + string(rune('a'+i)),
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		err = registry.Register(backend)
		require.NoError(t, err)
	}

	all := registry.GetAll()
	assert.Len(t, all, 3)
}

func TestRegistry_StartAll(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	ctx := context.Background()
	err = registry.StartAll(ctx)
	require.NoError(t, err)
}

func TestRegistry_StopAll(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	ctx := context.Background()
	err = registry.StartAll(ctx)
	require.NoError(t, err)

	err = registry.StopAll(ctx)
	require.NoError(t, err)
}

func TestRegistry_LoadFromConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	backends := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
		{
			Name: "backend-b",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 8080},
			},
		},
	}

	err := registry.LoadFromConfig(backends)
	require.NoError(t, err)

	all := registry.GetAll()
	assert.Len(t, all, 2)
}

func TestRegistry_LoadFromConfig_Error(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	backends := []config.Backend{
		{
			Name:  "", // Invalid - missing name
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 8080}},
		},
	}

	err := registry.LoadFromConfig(backends)
	assert.Error(t, err)
}

func TestRegistry_LoadFromConfig_DuplicateError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	backends := []config.Backend{
		{
			Name:  "backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 8080}},
		},
		{
			Name:  "backend", // Duplicate
			Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 8080}},
		},
	}

	err := registry.LoadFromConfig(backends)
	assert.Error(t, err)
}

func TestHost_MaxSessions(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	// Initially max sessions is disabled
	assert.False(t, host.IsMaxSessionsEnabled())
	assert.Equal(t, 0, host.MaxSessions())
	assert.True(t, host.HasCapacity())

	// Enable max sessions
	host.SetMaxSessions(2)
	assert.True(t, host.IsMaxSessionsEnabled())
	assert.Equal(t, 2, host.MaxSessions())
	assert.True(t, host.HasCapacity())

	// Add connections
	host.IncrementConnections()
	assert.True(t, host.HasCapacity())

	host.IncrementConnections()
	assert.False(t, host.HasCapacity())

	// Release one
	host.DecrementConnections()
	assert.True(t, host.HasCapacity())
}

func TestHost_RateLimiter(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	// Initially rate limiting is disabled
	assert.False(t, host.IsRateLimitEnabled())
	assert.True(t, host.AllowRequest())

	// Enable rate limiting with 2 RPS and burst of 2
	host.SetRateLimiter(2, 2)
	assert.True(t, host.IsRateLimitEnabled())

	// First two requests should be allowed (burst)
	assert.True(t, host.AllowRequest())
	assert.True(t, host.AllowRequest())

	// Third request should be denied (burst exhausted)
	assert.False(t, host.AllowRequest())

	// Wait for token replenishment
	time.Sleep(600 * time.Millisecond)
	assert.True(t, host.AllowRequest())
}

func TestHost_IsAvailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		status      Status
		maxSessions int
		connections int64
		expected    bool
	}{
		{
			name:        "healthy host without limits",
			status:      StatusHealthy,
			maxSessions: 0,
			connections: 0,
			expected:    true,
		},
		{
			name:        "unknown host without limits",
			status:      StatusUnknown,
			maxSessions: 0,
			connections: 0,
			expected:    true,
		},
		{
			name:        "unhealthy host",
			status:      StatusUnhealthy,
			maxSessions: 0,
			connections: 0,
			expected:    false,
		},
		{
			name:        "healthy host with capacity",
			status:      StatusHealthy,
			maxSessions: 10,
			connections: 5,
			expected:    true,
		},
		{
			name:        "healthy host at capacity",
			status:      StatusHealthy,
			maxSessions: 10,
			connections: 10,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host := NewHost("10.0.0.1", 8080, 1)
			host.SetStatus(tt.status)
			if tt.maxSessions > 0 {
				host.SetMaxSessions(tt.maxSessions)
			}
			for i := int64(0); i < tt.connections; i++ {
				host.IncrementConnections()
			}
			assert.Equal(t, tt.expected, host.IsAvailable())
		})
	}
}

func TestHostRateLimiter(t *testing.T) {
	t.Parallel()

	rl := NewHostRateLimiter(10, 5)

	// Should allow burst requests
	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow(), "request %d should be allowed", i)
	}

	// Next request should be denied
	assert.False(t, rl.Allow())

	// Wait for token replenishment
	time.Sleep(200 * time.Millisecond)
	assert.True(t, rl.Allow())
}

func TestNewBackend_WithMaxSessions(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
			{Address: "10.0.0.2", Port: 8080},
		},
		MaxSessions: &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 100,
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// All hosts should have max sessions configured
	for _, host := range backend.hosts {
		assert.True(t, host.IsMaxSessionsEnabled())
		assert.Equal(t, 100, host.MaxSessions())
	}
}

func TestNewBackend_WithRateLimit(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		RateLimit: &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             50,
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Host should have rate limiting configured
	assert.True(t, backend.hosts[0].IsRateLimitEnabled())
}

func TestServiceBackend_GetAvailableHost(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
			{Address: "10.0.0.2", Port: 8080},
		},
		MaxSessions: &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1,
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Mark hosts as healthy
	for _, host := range backend.hosts {
		host.SetStatus(StatusHealthy)
	}

	// First request should succeed
	host1, err := backend.GetAvailableHost()
	require.NoError(t, err)
	assert.NotNil(t, host1)

	// Second request should succeed (different host)
	host2, err := backend.GetAvailableHost()
	require.NoError(t, err)
	assert.NotNil(t, host2)

	// Third request should fail (both hosts at capacity)
	_, err = backend.GetAvailableHost()
	assert.Error(t, err)

	// Release one host
	backend.ReleaseHost(host1)

	// Now should succeed again
	host3, err := backend.GetAvailableHost()
	require.NoError(t, err)
	assert.NotNil(t, host3)
}

func TestServiceBackend_GetHost_RateLimited(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		RateLimit: &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			Burst:             1,
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)

	// Mark host as healthy
	backend.hosts[0].SetStatus(StatusHealthy)

	// First request should succeed
	host, err := backend.GetHost()
	require.NoError(t, err)
	backend.ReleaseHost(host)

	// Second request should be rate limited
	_, err = backend.GetHost()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")
}

func TestHost_TLSURL(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8443, 1)
	assert.Equal(t, "https://10.0.0.1:8443", host.TLSURL())
}

func TestHost_URLWithScheme(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	assert.Equal(t, "http://10.0.0.1:8080", host.URLWithScheme(false))
	assert.Equal(t, "https://10.0.0.1:8080", host.URLWithScheme(true))
}

func TestRegistry_ReloadFromConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := NewRegistry(logger)
	ctx := context.Background()

	// Load initial backends
	initial := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := reg.LoadFromConfig(initial)
	require.NoError(t, err)

	_, exists := reg.Get("backend-a")
	assert.True(t, exists)

	// Reload with different backends
	updated := []config.Backend{
		{
			Name: "backend-b",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 9090},
			},
		},
		{
			Name: "backend-c",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.3", Port: 7070},
			},
		},
	}
	err = reg.ReloadFromConfig(ctx, updated)
	require.NoError(t, err)

	// Old backend should be gone
	_, exists = reg.Get("backend-a")
	assert.False(t, exists)

	// New backends should exist
	_, exists = reg.Get("backend-b")
	assert.True(t, exists)
	_, exists = reg.Get("backend-c")
	assert.True(t, exists)
}

func TestRegistry_ReloadFromConfig_Empty(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := NewRegistry(logger)
	ctx := context.Background()

	// Load initial backends
	initial := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := reg.LoadFromConfig(initial)
	require.NoError(t, err)

	// Reload with empty list
	err = reg.ReloadFromConfig(ctx, []config.Backend{})
	require.NoError(t, err)

	all := reg.GetAll()
	assert.Empty(t, all)
}

func TestRegistry_ReloadFromConfig_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := NewRegistry(logger)
	ctx := context.Background()

	// Load initial backends
	initial := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := reg.LoadFromConfig(initial)
	require.NoError(t, err)

	// Start all backends
	err = reg.StartAll(ctx)
	require.NoError(t, err)

	// Concurrently read from registry while reloading
	var wg sync.WaitGroup
	const numReaders = 50
	const numReloads = 5

	// Start readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				// These should not panic or return empty results during reload
				all := reg.GetAll()
				_ = all
				_, _ = reg.Get("backend-a")
				_, _ = reg.Get("backend-b")
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Start reloaders
	for i := 0; i < numReloads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			time.Sleep(time.Duration(idx) * 5 * time.Millisecond)
			updated := []config.Backend{
				{
					Name: "backend-b",
					Hosts: []config.BackendHost{
						{Address: "10.0.0.2", Port: 9090},
					},
				},
			}
			_ = reg.ReloadFromConfig(ctx, updated)
		}(i)
	}

	wg.Wait()

	// After all reloads, registry should be in a consistent state
	all := reg.GetAll()
	assert.NotEmpty(t, all)
}

func TestRegistry_ReloadFromConfig_OldBackendsStopped(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := NewRegistry(logger)
	ctx := context.Background()

	// Load initial backends
	initial := []config.Backend{
		{
			Name: "backend-old",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := reg.LoadFromConfig(initial)
	require.NoError(t, err)

	// Start all backends
	err = reg.StartAll(ctx)
	require.NoError(t, err)

	// Get old backend and verify it's healthy
	oldBackend, exists := reg.Get("backend-old")
	assert.True(t, exists)
	assert.Equal(t, StatusHealthy, oldBackend.Status())

	// Reload with new backends
	updated := []config.Backend{
		{
			Name: "backend-new",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 9090},
			},
		},
	}
	err = reg.ReloadFromConfig(ctx, updated)
	require.NoError(t, err)

	// Old backend should have been stopped (status unknown)
	assert.Equal(t, StatusUnknown, oldBackend.Status())

	// New backend should exist and be started
	newBackend, exists := reg.Get("backend-new")
	assert.True(t, exists)
	assert.Equal(t, StatusHealthy, newBackend.Status())
}

func TestRegistry_ReloadFromConfig_InvalidBackend(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	reg := NewRegistry(logger)
	ctx := context.Background()

	// Reload with invalid backend (no hosts)
	invalid := []config.Backend{
		{
			Name:  "invalid",
			Hosts: []config.BackendHost{},
		},
	}
	err := reg.ReloadFromConfig(ctx, invalid)
	assert.Error(t, err)
}
