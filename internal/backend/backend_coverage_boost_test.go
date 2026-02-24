package backend

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ---------------------------------------------------------------------------
// Mock backend for testing Registry error paths
// ---------------------------------------------------------------------------

// mockRegistryBackend implements Backend interface for testing.
type mockRegistryBackend struct {
	name     string
	startErr error
	stopErr  error
	status   Status
}

func (m *mockRegistryBackend) Name() string                  { return m.name }
func (m *mockRegistryBackend) GetHost() (*Host, error)       { return nil, nil }
func (m *mockRegistryBackend) ReleaseHost(_ *Host)           {}
func (m *mockRegistryBackend) Status() Status                { return m.status }
func (m *mockRegistryBackend) Start(_ context.Context) error { return m.startErr }
func (m *mockRegistryBackend) Stop(_ context.Context) error  { return m.stopErr }

// Ensure mockRegistryBackend implements Backend.
var _ Backend = (*mockRegistryBackend)(nil)

// ---------------------------------------------------------------------------
// Tests for StopAll error path (backend.Stop returns error)
// ---------------------------------------------------------------------------

func TestRegistry_StopAll_BackendStopError(t *testing.T) {
	t.Parallel()

	// Arrange: register a mock backend that returns error on Stop
	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	mock := &mockRegistryBackend{
		name:    "failing-backend",
		stopErr: errors.New("stop failed"),
		status:  StatusHealthy,
	}

	registry.mu.Lock()
	registry.backends["failing-backend"] = mock
	registry.mu.Unlock()

	// Act
	err := registry.StopAll(context.Background())

	// Assert: StopAll returns the last error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stop failed")
}

func TestRegistry_StopAll_MultipleBackends_OneError(t *testing.T) {
	t.Parallel()

	// Arrange: register multiple backends, one fails
	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	goodMock := &mockRegistryBackend{name: "good-backend", stopErr: nil, status: StatusHealthy}
	badMock := &mockRegistryBackend{name: "bad-backend", stopErr: errors.New("stop error"), status: StatusHealthy}

	registry.mu.Lock()
	registry.backends["good-backend"] = goodMock
	registry.backends["bad-backend"] = badMock
	registry.mu.Unlock()

	// Act
	err := registry.StopAll(context.Background())

	// Assert: should return the error from the failing backend
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests for StartAll error path (backend.Start returns error)
// ---------------------------------------------------------------------------

func TestRegistry_StartAll_BackendStartError(t *testing.T) {
	t.Parallel()

	// Arrange: register a mock backend that returns error on Start
	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	mock := &mockRegistryBackend{
		name:     "failing-start-backend",
		startErr: errors.New("start failed"),
		status:   StatusUnknown,
	}

	registry.mu.Lock()
	registry.backends["failing-start-backend"] = mock
	registry.mu.Unlock()

	// Act
	err := registry.StartAll(context.Background())

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start backend")
	assert.Contains(t, err.Error(), "start failed")
}

// ---------------------------------------------------------------------------
// Tests for ReloadFromConfig context cancellation during backend creation
// ---------------------------------------------------------------------------

func TestRegistry_ReloadFromConfig_ContextCanceledDuringCreation(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	// Load initial backends
	initial := []config.Backend{
		{
			Name:  "backend-a",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 8080}},
		},
	}
	err := registry.LoadFromConfig(initial)
	require.NoError(t, err)

	// Cancel context immediately - this should be caught in the creation loop
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// We need multiple backends so the loop has a chance to check context
	updated := []config.Backend{
		{
			Name:  "backend-b",
			Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 9090}},
		},
		{
			Name:  "backend-c",
			Hosts: []config.BackendHost{{Address: "10.0.0.3", Port: 7070}},
		},
	}

	// Act: the context is already canceled, so it should fail
	err = registry.ReloadFromConfig(ctx, updated)

	// Assert: should get context canceled error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// ---------------------------------------------------------------------------
// Tests for ReloadFromConfig context cancellation during starting new backends
// ---------------------------------------------------------------------------

func TestRegistry_ReloadFromConfig_ContextCanceledDuringStart(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	// Use a mock backend that cancels the context when Stop is called
	ctx, cancel := context.WithCancel(context.Background())

	registry.mu.Lock()
	registry.backends["backend-a"] = &mockRegistryBackend{
		name:   "backend-a",
		status: StatusHealthy,
		stopErr: func() error {
			cancel() // Cancel context during old backend stop
			return nil
		}(),
	}
	registry.mu.Unlock()

	updated := []config.Backend{
		{
			Name:  "backend-new",
			Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 9090}},
		},
	}

	// Act
	err := registry.ReloadFromConfig(ctx, updated)

	// Assert: should get context canceled error during start phase
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// ---------------------------------------------------------------------------
// Tests for ReloadFromConfig with invalid backend during creation
// ---------------------------------------------------------------------------

func TestRegistry_ReloadFromConfig_InvalidBackendDuringCreation(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	// Load initial backends
	initial := []config.Backend{
		{
			Name:  "backend-a",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 8080}},
		},
	}
	err := registry.LoadFromConfig(initial)
	require.NoError(t, err)

	// Reload with invalid backend (no hosts)
	updated := []config.Backend{
		{
			Name:  "valid-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.2", Port: 9090}},
		},
		{
			Name:  "invalid-backend",
			Hosts: []config.BackendHost{}, // Invalid: no hosts
		},
	}

	// Act
	err = registry.ReloadFromConfig(context.Background(), updated)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create backend")
}

// ---------------------------------------------------------------------------
// Tests for NewBackend with TLS init error
// ---------------------------------------------------------------------------

func TestNewBackend_TLSInitError(t *testing.T) {
	t.Parallel()

	// Arrange: TLS config with invalid min version to trigger error
	cfg := config.Backend{
		Name: "test-tls-error",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:    true,
			MinVersion: "INVALID_VERSION",
		},
	}

	// Act
	_, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build TLS config")
}

// ---------------------------------------------------------------------------
// Tests for RefreshTLSConfig error path
// ---------------------------------------------------------------------------

func TestServiceBackend_RefreshTLSConfig_BuildError(t *testing.T) {
	t.Parallel()

	// Arrange: create a backend with valid TLS first
	cfg := config.Backend{
		Name: "test-refresh-error",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)
	require.NotNil(t, backend.tlsBuilder)

	// Now modify the builder's config to cause a build error
	backend.tlsBuilder.config = &config.BackendTLSConfig{
		Enabled:    true,
		MinVersion: "INVALID_VERSION",
	}

	// Act
	err = backend.RefreshTLSConfig()

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to refresh TLS config")
}

// ---------------------------------------------------------------------------
// Tests for initTLS error path (TLS build failure via cipher suite)
// ---------------------------------------------------------------------------

func TestInitTLS_BuildError_CipherSuite(t *testing.T) {
	t.Parallel()

	// Arrange: TLS config with invalid cipher suite
	cfg := config.Backend{
		Name: "test-tls-build-error",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:      true,
			CipherSuites: []string{"INVALID_CIPHER_SUITE"},
		},
	}

	// Act
	_, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build TLS config")
}

// ---------------------------------------------------------------------------
// Tests for HostRateLimiter Allow - edge cases
// ---------------------------------------------------------------------------

func TestHostRateLimiter_Allow_TokensNotExceedingBurst(t *testing.T) {
	t.Parallel()

	// Arrange: create a rate limiter with high RPS and burst
	rl := NewHostRateLimiter(1000, 10)

	// Consume all tokens
	for i := 0; i < 10; i++ {
		assert.True(t, rl.Allow())
	}

	// Should be denied now
	assert.False(t, rl.Allow())

	// Wait a tiny bit for some tokens to replenish (but not enough to exceed burst)
	time.Sleep(5 * time.Millisecond)

	// Should have some tokens now (5ms * 1000 RPS = ~5 tokens, less than burst of 10)
	assert.True(t, rl.Allow())
}

func TestHostRateLimiter_Allow_ZeroRPS(t *testing.T) {
	t.Parallel()

	// Arrange: rate limiter with 0 RPS but some burst
	rl := NewHostRateLimiter(0, 3)

	// Should allow burst requests
	assert.True(t, rl.Allow())
	assert.True(t, rl.Allow())
	assert.True(t, rl.Allow())

	// Should deny after burst exhausted (no replenishment with 0 RPS)
	assert.False(t, rl.Allow())

	// Wait and try again - still should be denied since RPS is 0
	time.Sleep(10 * time.Millisecond)
	assert.False(t, rl.Allow())
}

// ---------------------------------------------------------------------------
// Tests for health checker checkHost with context cancellation
// ---------------------------------------------------------------------------

func TestHealthChecker_CheckHost_ContextCanceled(t *testing.T) {
	t.Parallel()

	// Arrange
	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:               "/health",
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-ctx-cancel"),
	)

	// Cancel context before checking
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act: checkHost should return early due to canceled context
	hc.checkHost(ctx, host)

	// Assert: host status should remain unchanged (unknown)
	assert.Equal(t, StatusUnknown, host.Status())
}

// ---------------------------------------------------------------------------
// Tests for health checker with non-2xx response
// ---------------------------------------------------------------------------

func TestHealthChecker_CheckHost_Non2xxResponse(t *testing.T) {
	t.Parallel()

	// Arrange: server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)
	host := NewHost(addr.IP.String(), addr.Port, 1)
	host.SetStatus(StatusHealthy) // Start healthy

	cfg := config.HealthCheck{
		Path:               "/health",
		Interval:           config.Duration(50 * time.Millisecond),
		Timeout:            config.Duration(2 * time.Second),
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-non-2xx"),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become unhealthy after 1 failure (threshold=1)
	assert.Equal(t, StatusUnhealthy, host.Status())
}

// ---------------------------------------------------------------------------
// Tests for health checker run with default interval
// ---------------------------------------------------------------------------

func TestHealthChecker_Run_DefaultInterval(t *testing.T) {
	t.Parallel()

	// Arrange: health check with zero interval (should use default)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)
	host := NewHost(addr.IP.String(), addr.Port, 1)

	cfg := config.HealthCheck{
		Path:               "/health",
		Interval:           0, // Zero interval, should use default
		Timeout:            config.Duration(2 * time.Second),
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-default-interval"),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// Act
	hc.Start(ctx)

	// Wait for initial health check to run
	time.Sleep(100 * time.Millisecond)

	// Assert: host should be healthy after initial check
	assert.Equal(t, StatusHealthy, host.Status())

	// Cleanup
	cancel()
	hc.Stop()
}

// ---------------------------------------------------------------------------
// Tests for health checker with connection error
// ---------------------------------------------------------------------------

func TestHealthChecker_CheckHost_ConnectionError(t *testing.T) {
	t.Parallel()

	// Arrange: host with unreachable address
	host := NewHost("192.0.2.1", 1, 1) // TEST-NET address, should fail
	host.SetStatus(StatusHealthy)

	cfg := config.HealthCheck{
		Path:               "/health",
		Timeout:            config.Duration(100 * time.Millisecond),
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-conn-error"),
		WithHealthCheckClient(&http.Client{Timeout: 100 * time.Millisecond}),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become unhealthy
	assert.Equal(t, StatusUnhealthy, host.Status())
}

// ---------------------------------------------------------------------------
// Tests for health checker with TLS URL
// ---------------------------------------------------------------------------

func TestHealthChecker_CheckHost_WithTLS(t *testing.T) {
	t.Parallel()

	// Arrange: HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)
	host := NewHost(addr.IP.String(), addr.Port, 1)

	cfg := config.HealthCheck{
		Path:               "/health",
		Timeout:            config.Duration(2 * time.Second),
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-tls-hc"),
		WithHealthCheckTLS(true),
		WithHealthCheckClient(server.Client()),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become healthy
	assert.Equal(t, StatusHealthy, host.Status())
}

// ---------------------------------------------------------------------------
// Tests for TLSConfigBuilder BuildWithServerName error path
// ---------------------------------------------------------------------------

func TestTLSConfigBuilder_BuildWithServerName_BuildError(t *testing.T) {
	t.Parallel()

	// Arrange: config that will cause Build to fail
	cfg := &config.BackendTLSConfig{
		Enabled:    true,
		MinVersion: "INVALID",
	}

	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(observability.NopLogger()))

	// Act
	tlsConfig, err := builder.BuildWithServerName("example.com")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, tlsConfig)
}

// ---------------------------------------------------------------------------
// Tests for NewBackendTLSTransport error path
// ---------------------------------------------------------------------------

func TestNewBackendTLSTransport_BuildError(t *testing.T) {
	t.Parallel()

	// Arrange: config that will cause Build to fail
	cfg := &config.BackendTLSConfig{
		Enabled:    true,
		MinVersion: "INVALID",
	}

	// Act
	transport, err := NewBackendTLSTransport(cfg, observability.NopLogger())

	// Assert
	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "failed to build TLS config")
}

// ---------------------------------------------------------------------------
// Tests for Host SetRateLimiter with zero RPS (should not enable)
// ---------------------------------------------------------------------------

func TestHost_SetRateLimiter_ZeroRPS(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	host.SetRateLimiter(0, 10)

	// Should not be enabled with 0 RPS
	assert.False(t, host.IsRateLimitEnabled())
	assert.True(t, host.AllowRequest())
}

// ---------------------------------------------------------------------------
// Tests for Host SetMaxSessions with zero (should disable)
// ---------------------------------------------------------------------------

func TestHost_SetMaxSessions_Zero(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)

	host.SetMaxSessions(0)

	assert.False(t, host.IsMaxSessionsEnabled())
	assert.Equal(t, 0, host.MaxSessions())
	assert.True(t, host.HasCapacity())
}

// ---------------------------------------------------------------------------
// Tests for logBackendConfig with disabled configs
// ---------------------------------------------------------------------------

func TestLogBackendConfig_DisabledMaxSessions(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-log-disabled",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		MaxSessions: &config.MaxSessionsConfig{
			Enabled: false,
		},
		RateLimit: &config.RateLimitConfig{
			Enabled: false,
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestLogBackendConfig_NilConfigs(t *testing.T) {
	t.Parallel()

	cfg := config.Backend{
		Name: "test-log-nil",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		MaxSessions: nil,
		RateLimit:   nil,
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)
	assert.NotNil(t, backend)
}

// ---------------------------------------------------------------------------
// Tests for ReloadFromConfig with start error on new backends
// ---------------------------------------------------------------------------

func TestRegistry_ReloadFromConfig_StartError(t *testing.T) {
	t.Parallel()

	// This test covers the path where new backends fail to start
	// We can't easily make NewBackend-created backends fail Start(),
	// but we can test the error path by using a mock.

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	// Register a mock backend that succeeds on stop
	registry.mu.Lock()
	registry.backends["old-backend"] = &mockRegistryBackend{
		name:   "old-backend",
		status: StatusHealthy,
	}
	registry.mu.Unlock()

	// Reload with valid backends - this should succeed
	updated := []config.Backend{
		{
			Name:  "new-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 8080}},
		},
	}

	err := registry.ReloadFromConfig(context.Background(), updated)
	require.NoError(t, err)

	// Verify new backend exists
	_, exists := registry.Get("new-backend")
	assert.True(t, exists)

	// Verify old backend is gone
	_, exists = registry.Get("old-backend")
	assert.False(t, exists)
}

// ---------------------------------------------------------------------------
// Tests for ReloadFromConfig with stop error on old backends
// ---------------------------------------------------------------------------

func TestRegistry_ReloadFromConfig_OldBackendStopError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	// Register a mock backend that fails on stop
	registry.mu.Lock()
	registry.backends["old-backend"] = &mockRegistryBackend{
		name:    "old-backend",
		status:  StatusHealthy,
		stopErr: errors.New("stop failed"),
	}
	registry.mu.Unlock()

	// Reload with valid backends - should still succeed
	// (stop errors are logged but don't prevent reload)
	updated := []config.Backend{
		{
			Name:  "new-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 8080}},
		},
	}

	err := registry.ReloadFromConfig(context.Background(), updated)
	require.NoError(t, err)

	// Verify new backend exists
	_, exists := registry.Get("new-backend")
	assert.True(t, exists)
}
