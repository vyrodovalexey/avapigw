package backend

import (
	"context"
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
