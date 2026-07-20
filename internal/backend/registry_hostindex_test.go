package backend

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// newHostIndexBackend builds a started-free ServiceBackend for host-index tests.
func newHostIndexBackend(t *testing.T, name string, hosts ...config.BackendHost) *ServiceBackend {
	t.Helper()
	b, err := NewBackend(config.Backend{Name: name, Hosts: hosts})
	require.NoError(t, err)
	return b
}

func TestHostPortKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		port    int
		want    string
	}{
		{name: "hostname", address: "host.docker.internal", port: 8813, want: "host.docker.internal:8813"},
		{name: "hostname is lowercased", address: "Host.Docker.Internal", port: 8813, want: "host.docker.internal:8813"},
		{name: "ipv4 literal", address: "192.168.65.254", port: 8813, want: "192.168.65.254:8813"},
		{name: "ipv6 literal is bracketed", address: "fdc4:f303:9324::254", port: 8813, want: "[fdc4:f303:9324::254]:8813"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, HostPortKey(tt.address, tt.port))
		})
	}
}

func TestRegistry_GetByHostPort_SingleMatch(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(observability.NopLogger())
	b := newHostIndexBackend(t, "grpc-backend-mtls",
		config.BackendHost{Address: "host.docker.internal", Port: 8813})
	require.NoError(t, registry.Register(b))

	got, matches, ok := registry.GetByHostPort("host.docker.internal", 8813)
	require.True(t, ok)
	assert.Equal(t, 1, matches)
	assert.Equal(t, "grpc-backend-mtls", got.Name())

	// Case-insensitive address lookup resolves to the same backend.
	got, _, ok = registry.GetByHostPort("HOST.DOCKER.INTERNAL", 8813)
	require.True(t, ok)
	assert.Equal(t, "grpc-backend-mtls", got.Name())
}

func TestRegistry_GetByHostPort_NoMatch(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(observability.NopLogger())
	b := newHostIndexBackend(t, "grpc-backend",
		config.BackendHost{Address: "host.docker.internal", Port: 8813})
	require.NoError(t, registry.Register(b))

	// Same address, different port — no match.
	_, matches, ok := registry.GetByHostPort("host.docker.internal", 8811)
	assert.False(t, ok)
	assert.Zero(t, matches)

	// Unknown address — no match.
	_, _, ok = registry.GetByHostPort("unknown.example.com", 8813)
	assert.False(t, ok)
}

func TestRegistry_GetByHostPort_AmbiguousDeterministic(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(observability.NopLogger())
	// Register in non-lexicographic order to prove the deterministic
	// choice comes from sorting, not insertion order.
	require.NoError(t, registry.Register(newHostIndexBackend(t, "zeta-backend",
		config.BackendHost{Address: "10.0.0.1", Port: 50051})))
	require.NoError(t, registry.Register(newHostIndexBackend(t, "alpha-backend",
		config.BackendHost{Address: "10.0.0.1", Port: 50051})))

	got, matches, ok := registry.GetByHostPort("10.0.0.1", 50051)
	require.True(t, ok)
	assert.Equal(t, 2, matches)
	assert.Equal(t, "alpha-backend", got.Name(),
		"ambiguous endpoint must resolve to the lexicographically smallest backend name")
}

func TestRegistry_GetByHostPort_UnregisterUpdatesIndex(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(observability.NopLogger())
	require.NoError(t, registry.Register(newHostIndexBackend(t, "backend-a",
		config.BackendHost{Address: "10.0.0.1", Port: 50051})))

	_, _, ok := registry.GetByHostPort("10.0.0.1", 50051)
	require.True(t, ok)

	require.NoError(t, registry.Unregister("backend-a"))
	_, _, ok = registry.GetByHostPort("10.0.0.1", 50051)
	assert.False(t, ok, "unregistered backend must be removed from the host index")
}

func TestRegistry_GetByHostPort_ReloadUpdatesIndex(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(observability.NopLogger())
	require.NoError(t, registry.LoadFromConfig([]config.Backend{
		{Name: "old-backend", Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 50051}}},
	}))

	_, _, ok := registry.GetByHostPort("10.0.0.1", 50051)
	require.True(t, ok)

	require.NoError(t, registry.ReloadFromConfig(context.Background(), []config.Backend{
		{Name: "new-backend", Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 50052}}},
	}))
	defer func() { _ = registry.StopAll(context.Background()) }()

	_, _, ok = registry.GetByHostPort("10.0.0.1", 50051)
	assert.False(t, ok, "reload must drop stale endpoints from the host index")

	got, matches, ok := registry.GetByHostPort("10.0.0.2", 50052)
	require.True(t, ok)
	assert.Equal(t, 1, matches)
	assert.Equal(t, "new-backend", got.Name())
}

func TestRegistry_GetByHostPort_MultiHostBackend(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(observability.NopLogger())
	require.NoError(t, registry.Register(newHostIndexBackend(t, "multi-host",
		config.BackendHost{Address: "10.0.0.1", Port: 50051},
		config.BackendHost{Address: "10.0.0.2", Port: 50052})))

	for _, endpoint := range []struct {
		address string
		port    int
	}{
		{"10.0.0.1", 50051},
		{"10.0.0.2", 50052},
	} {
		got, matches, ok := registry.GetByHostPort(endpoint.address, endpoint.port)
		require.True(t, ok, "endpoint %s:%d must resolve", endpoint.address, endpoint.port)
		assert.Equal(t, 1, matches)
		assert.Equal(t, "multi-host", got.Name())
	}
}
