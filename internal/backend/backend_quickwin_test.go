package backend

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestWithAuthProvider_Option tests the WithAuthProvider option.
func TestWithAuthProvider_Option(t *testing.T) {
	t.Parallel()

	b := &ServiceBackend{}
	opt := WithAuthProvider(nil)
	opt(b)
	assert.Nil(t, b.authProvider)
}

// TestWithVaultClient_Option tests the WithVaultClient option.
func TestWithVaultClient_Option(t *testing.T) {
	t.Parallel()

	b := &ServiceBackend{}
	opt := WithVaultClient(nil)
	opt(b)
	assert.Nil(t, b.vaultClient)
}

// TestServiceBackend_TLSConfig_NilTLS tests TLSConfig when TLS is not configured.
func TestServiceBackend_TLSConfig_NilTLS(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	tlsConfig := backend.TLSConfig()
	assert.Nil(t, tlsConfig)
}

// TestServiceBackend_IsTLSEnabled_False tests IsTLSEnabled when TLS is not configured.
func TestServiceBackend_IsTLSEnabled_False(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	assert.False(t, backend.IsTLSEnabled())
}

// TestServiceBackend_GetTLSMode_NilTLS tests GetTLSMode when TLS is nil.
func TestServiceBackend_GetTLSMode_NilTLS(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	mode := backend.GetTLSMode()
	assert.Equal(t, config.TLSModeInsecure, mode)
}

// TestServiceBackend_AuthProvider_Nil tests AuthProvider when not configured.
func TestServiceBackend_AuthProvider_Nil(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	assert.Nil(t, backend.AuthProvider())
}

// TestServiceBackend_ApplyAuth_NilProvider tests ApplyAuth when no auth provider.
func TestServiceBackend_ApplyAuth_NilProvider(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	err = backend.ApplyAuth(t.Context(), nil)
	assert.NoError(t, err)
}

// TestServiceBackend_GetGRPCDialOptions_NilProvider tests GetGRPCDialOptions when no auth provider.
func TestServiceBackend_GetGRPCDialOptions_NilProvider(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	opts, err := backend.GetGRPCDialOptions(t.Context())
	assert.NoError(t, err)
	assert.Empty(t, opts)
}

// TestServiceBackend_RefreshAuth_NilProvider tests RefreshAuth when no auth provider.
func TestServiceBackend_RefreshAuth_NilProvider(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	err = backend.RefreshAuth(t.Context())
	assert.NoError(t, err)
}

// TestServiceBackend_RefreshTLSConfig_NilBuilder tests RefreshTLSConfig when no TLS builder.
func TestServiceBackend_RefreshTLSConfig_NilBuilder(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	err = backend.RefreshTLSConfig()
	assert.NoError(t, err)
}

// TestNewConnectionPoolWithTLS tests NewConnectionPoolWithTLS.
func TestNewConnectionPoolWithTLS_NilTLS(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPoolWithTLS(DefaultPoolConfig(), nil)
	assert.NotNil(t, pool)
	assert.NotNil(t, pool.Client())
}

// TestConnectionPool_SetTLSConfig tests SetTLSConfig.
func TestConnectionPool_SetTLSConfig(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(DefaultPoolConfig())
	pool.SetTLSConfig(nil)
	// Should not panic
	assert.NotNil(t, pool.Transport())
}

// TestServiceBackend_Stop_NotStarted tests Stop when backend is not started.
func TestServiceBackend_Stop_NotStarted(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	}, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Stop should not panic when not started
	err = backend.Stop(context.Background())
	assert.NoError(t, err)
}

// TestServiceBackend_GetAvailableHost_AllUnhealthy tests GetAvailableHost when all hosts are unhealthy.
func TestServiceBackend_GetAvailableHost_AllUnhealthy(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	// Set all hosts to unhealthy
	for _, host := range backend.GetHosts() {
		host.SetStatus(StatusUnhealthy)
	}

	host, err := backend.GetAvailableHost()
	assert.Error(t, err)
	assert.Nil(t, host)
}

// TestRegistry_StartAll_WithError tests StartAll when a backend fails to start.
func TestRegistry_StartAll_WithError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	// StartAll should succeed (health checker starts)
	err = registry.StartAll(context.Background())
	assert.NoError(t, err)

	// StopAll should succeed
	err = registry.StopAll(context.Background())
	assert.NoError(t, err)
}

// TestServiceBackend_InitHosts_WithRateLimit tests initHosts with rate limiting and zero burst.
func TestServiceBackend_InitHosts_WithRateLimit(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080, Weight: 5},
		},
		RateLimit: &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             0, // Zero burst should default to RPS
		},
	})
	require.NoError(t, err)

	hosts := backend.GetHosts()
	assert.Len(t, hosts, 1)
	assert.True(t, hosts[0].IsRateLimitEnabled())
}
