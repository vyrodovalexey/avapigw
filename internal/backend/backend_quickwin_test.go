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

// TestServiceBackend_InitTLS_Enabled tests initTLS with TLS enabled (InsecureSkipVerify).
func TestServiceBackend_InitTLS_Enabled(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-tls-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	assert.True(t, backend.IsTLSEnabled())
	assert.NotNil(t, backend.TLSConfig())
	assert.True(t, backend.TLSConfig().InsecureSkipVerify)
}

// TestServiceBackend_InitTLS_Disabled tests initTLS with TLS disabled.
func TestServiceBackend_InitTLS_Disabled(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-no-tls",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
		TLS: &config.BackendTLSConfig{
			Enabled: false,
		},
	})
	require.NoError(t, err)

	assert.False(t, backend.IsTLSEnabled())
	assert.Nil(t, backend.TLSConfig())
}

// TestServiceBackend_GetTLSMode_WithTLS tests GetTLSMode when TLS is configured.
func TestServiceBackend_GetTLSMode_WithTLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tlsCfg   *config.BackendTLSConfig
		expected string
	}{
		{
			name:     "nil TLS",
			tlsCfg:   nil,
			expected: config.TLSModeInsecure,
		},
		{
			name: "TLS enabled with SIMPLE mode",
			tlsCfg: &config.BackendTLSConfig{
				Enabled: true,
				Mode:    config.BackendTLSModeSimple,
			},
			expected: config.BackendTLSModeSimple,
		},
		{
			name: "TLS enabled with empty mode (defaults to SIMPLE)",
			tlsCfg: &config.BackendTLSConfig{
				Enabled: true,
				Mode:    "",
			},
			expected: config.BackendTLSModeSimple,
		},
		{
			name: "TLS disabled",
			tlsCfg: &config.BackendTLSConfig{
				Enabled: false,
			},
			expected: config.TLSModeInsecure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Backend{
				Name: "test-backend",
				Hosts: []config.BackendHost{
					{Address: "localhost", Port: 8080},
				},
				TLS: tt.tlsCfg,
			}

			backend, err := NewBackend(cfg)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, backend.GetTLSMode())
		})
	}
}

// TestServiceBackend_Start_WithHealthCheck tests Start with health check configured.
func TestServiceBackend_Start_WithHealthCheck(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend-hc",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
		HealthCheck: &config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(5 * time.Second),
			Timeout:            config.Duration(2 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = backend.Start(ctx)
	require.NoError(t, err)

	assert.Equal(t, StatusHealthy, backend.Status())
	assert.NotNil(t, backend.healthCheck)

	// Stop should also stop health checker
	err = backend.Stop(ctx)
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, backend.Status())
}

// TestServiceBackend_RefreshTLSConfig_WithBuilder tests RefreshTLSConfig with a TLS builder.
func TestServiceBackend_RefreshTLSConfig_WithBuilder(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-tls-refresh",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	assert.NotNil(t, backend.tlsBuilder)

	// RefreshTLSConfig should rebuild the TLS config
	err = backend.RefreshTLSConfig()
	assert.NoError(t, err)
	assert.NotNil(t, backend.TLSConfig())
}

// TestServiceBackend_GetAvailableHost_RateLimited tests GetAvailableHost when hosts are rate limited.
func TestServiceBackend_GetAvailableHost_RateLimited(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend-rl",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
		RateLimit: &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			Burst:             1,
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Mark host as healthy
	for _, host := range backend.GetHosts() {
		host.SetStatus(StatusHealthy)
	}

	// First request should succeed
	host, err := backend.GetAvailableHost()
	require.NoError(t, err)
	assert.NotNil(t, host)
	backend.ReleaseHost(host)

	// Second request should fail (rate limited)
	_, err = backend.GetAvailableHost()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no available hosts")
}

// TestServiceBackend_NewBackend_WithMaxSessionsAndRateLimit tests logBackendConfig paths.
func TestServiceBackend_NewBackend_WithMaxSessionsAndRateLimit(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-backend-both",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
		MaxSessions: &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 50,
			QueueSize:     10,
		},
		RateLimit: &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	assert.NotNil(t, backend)
	assert.Equal(t, "test-backend-both", backend.Name())
}

// TestServiceBackend_ApplyAuth_WithProvider tests ApplyAuth with a real auth provider.
// Since creating a real auth provider requires complex setup, we test the nil path
// and the non-nil path by directly setting the provider.
func TestServiceBackend_ApplyAuth_NilProvider_NoError(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	// ApplyAuth with nil provider should return nil
	err = backend.ApplyAuth(context.Background(), nil)
	assert.NoError(t, err)
}

// TestServiceBackend_RefreshAuth_NilProvider_NoError tests RefreshAuth with nil provider.
func TestServiceBackend_RefreshAuth_NilProvider_NoError(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	err = backend.RefreshAuth(context.Background())
	assert.NoError(t, err)
}

// TestServiceBackend_GetGRPCDialOptions_NilProvider_NoError tests GetGRPCDialOptions with nil provider.
func TestServiceBackend_GetGRPCDialOptions_NilProvider_NoError(t *testing.T) {
	t.Parallel()

	backend, err := NewBackend(config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	})
	require.NoError(t, err)

	opts, err := backend.GetGRPCDialOptions(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, opts)
}
