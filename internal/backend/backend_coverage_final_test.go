package backend

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ---------------------------------------------------------------------------
// 1. Functional options at 0% coverage
// ---------------------------------------------------------------------------

func TestWithMetrics_Option(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics("test")

	b := &ServiceBackend{}
	opt := WithMetrics(metrics)
	opt(b)

	assert.Same(t, metrics, b.metrics)
}

func TestWithMetrics_Option_Nil(t *testing.T) {
	t.Parallel()

	b := &ServiceBackend{}
	opt := WithMetrics(nil)
	opt(b)

	assert.Nil(t, b.metrics)
}

func TestWithRegistryMetrics_Option(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics("test_registry")

	r := &Registry{}
	opt := WithRegistryMetrics(metrics)
	opt(r)

	assert.Same(t, metrics, r.metrics)
}

func TestWithRegistryMetrics_Option_Nil(t *testing.T) {
	t.Parallel()

	r := &Registry{}
	opt := WithRegistryMetrics(nil)
	opt(r)

	assert.Nil(t, r.metrics)
}

func TestWithCircuitBreakerManagerStateCallback_Option(t *testing.T) {
	t.Parallel()

	var called atomic.Bool
	callback := func(name string, state int) {
		called.Store(true)
	}

	manager := NewCircuitBreakerManager(nil,
		WithCircuitBreakerManagerStateCallback(callback),
	)

	assert.NotNil(t, manager.stateCallback)

	// Verify the callback is actually the one we set by invoking it
	manager.stateCallback("test", 0)
	assert.True(t, called.Load())
}

func TestWithHealthStatusCallback_Option(t *testing.T) {
	t.Parallel()

	var calledBackend, calledHost string
	var calledHealthy bool

	callback := func(backendName, hostAddress string, healthy bool) {
		calledBackend = backendName
		calledHost = hostAddress
		calledHealthy = healthy
	}

	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:             "/health",
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthStatusCallback(callback),
		WithBackendName("my-backend"),
	)

	assert.NotNil(t, hc.onStatusChange)

	// Trigger the callback through recordSuccess
	hc.recordSuccess(host)

	assert.Equal(t, "my-backend", calledBackend)
	assert.Equal(t, "10.0.0.1:8080", calledHost)
	assert.True(t, calledHealthy)
}

// ---------------------------------------------------------------------------
// 2. NewCircuitBreakerManager with state callback
// ---------------------------------------------------------------------------

func TestNewCircuitBreakerManager_WithStateCallback(t *testing.T) {
	t.Parallel()

	var capturedName string
	var capturedState int
	callback := func(name string, state int) {
		capturedName = name
		capturedState = state
	}

	manager := NewCircuitBreakerManager(
		observability.NopLogger(),
		WithCircuitBreakerManagerStateCallback(callback),
	)

	require.NotNil(t, manager)
	require.NotNil(t, manager.stateCallback)

	// Create a circuit breaker with the manager that has the callback
	backend := &config.Backend{
		Name: "cb-test",
		CircuitBreaker: &config.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 1,
			Timeout:   config.Duration(100 * time.Millisecond),
		},
	}

	cb := manager.GetOrCreate(backend)
	require.NotNil(t, cb)

	// The state callback should be wired through to the circuit breaker.
	// Trigger failures to open the circuit breaker and invoke the callback.
	for i := 0; i < 2; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})
	}

	// The callback should have been invoked with the circuit breaker name
	// and a non-zero state (open = 1 in the middleware package).
	assert.Contains(t, capturedName, "cb-test")
	assert.NotEqual(t, 0, capturedState)
	_ = capturedName
	_ = capturedState
}

// ---------------------------------------------------------------------------
// 3. Start with metrics callback paths
// ---------------------------------------------------------------------------

func TestServiceBackend_Start_WithMetrics_NoHealthCheck(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics("test_start_metrics")

	cfg := config.Backend{
		Name: "metrics-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
			{Address: "10.0.0.2", Port: 8081},
		},
	}

	backend, err := NewBackend(cfg,
		WithBackendLogger(observability.NopLogger()),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = backend.Start(ctx)
	require.NoError(t, err)

	// Without health check, all hosts should be marked healthy
	for _, host := range backend.hosts {
		assert.Equal(t, StatusHealthy, host.Status())
	}

	assert.Equal(t, StatusHealthy, backend.Status())

	err = backend.Stop(ctx)
	require.NoError(t, err)
}

func TestServiceBackend_Start_WithMetrics_WithHealthCheck(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics("test_start_hc_metrics")

	// Create a test server for health checks
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)

	cfg := config.Backend{
		Name: "metrics-hc-backend",
		Hosts: []config.BackendHost{
			{Address: addr.IP.String(), Port: addr.Port},
		},
		HealthCheck: &config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(50 * time.Millisecond),
			Timeout:            config.Duration(2 * time.Second),
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		},
	}

	backend, err := NewBackend(cfg,
		WithBackendLogger(observability.NopLogger()),
		WithMetrics(metrics),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = backend.Start(ctx)
	require.NoError(t, err)

	// The health checker should have been created with the status callback
	assert.NotNil(t, backend.healthCheck)
	assert.NotNil(t, backend.healthCheck.onStatusChange)

	// Wait for health check to run
	time.Sleep(200 * time.Millisecond)

	err = backend.Stop(ctx)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// 4. Registry with metrics option
// ---------------------------------------------------------------------------

func TestNewRegistry_WithMetrics(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics("test_registry_metrics")
	logger := observability.NopLogger()

	registry := NewRegistry(logger, WithRegistryMetrics(metrics))

	require.NotNil(t, registry)
	assert.Same(t, metrics, registry.metrics)

	// LoadFromConfig should pass metrics to backends
	backends := []config.Backend{
		{
			Name: "backend-with-metrics",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}

	err := registry.LoadFromConfig(backends)
	require.NoError(t, err)

	b, exists := registry.Get("backend-with-metrics")
	assert.True(t, exists)

	// The backend should have metrics set
	sb, ok := b.(*ServiceBackend)
	require.True(t, ok)
	assert.Same(t, metrics, sb.metrics)
}

func TestNewRegistry_WithMetrics_ReloadFromConfig(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics("test_registry_reload_metrics")
	logger := observability.NopLogger()

	registry := NewRegistry(logger, WithRegistryMetrics(metrics))

	ctx := context.Background()

	// Load initial
	initial := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := registry.LoadFromConfig(initial)
	require.NoError(t, err)

	// Reload with new backends - metrics should be passed through
	updated := []config.Backend{
		{
			Name: "backend-b",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 9090},
			},
		},
	}
	err = registry.ReloadFromConfig(ctx, updated)
	require.NoError(t, err)

	b, exists := registry.Get("backend-b")
	assert.True(t, exists)

	sb, ok := b.(*ServiceBackend)
	require.True(t, ok)
	assert.Same(t, metrics, sb.metrics)
}

// ---------------------------------------------------------------------------
// 5. Context cancellation paths
// ---------------------------------------------------------------------------

func TestRegistry_StartAll_ContextCanceled(t *testing.T) {
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

	// Cancel context before calling StartAll
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = registry.StartAll(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestRegistry_StopAll_ContextCanceled(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	cfg := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(logger))
	require.NoError(t, err)

	err = registry.Register(backend)
	require.NoError(t, err)

	// Start first
	err = registry.StartAll(context.Background())
	require.NoError(t, err)

	// Cancel context before calling StopAll
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// StopAll should still succeed (it continues cleanup even with canceled context)
	err = registry.StopAll(ctx)
	assert.NoError(t, err)
}

func TestRegistry_ReloadFromConfig_ContextCanceledBeforeReload(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	registry := NewRegistry(logger)

	// Load initial backends
	initial := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := registry.LoadFromConfig(initial)
	require.NoError(t, err)

	// Cancel context before calling ReloadFromConfig
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	updated := []config.Backend{
		{
			Name: "backend-b",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 9090},
			},
		},
	}

	err = registry.ReloadFromConfig(ctx, updated)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled before reload")
}

// ---------------------------------------------------------------------------
// 6. Health checker with status callback
// ---------------------------------------------------------------------------

func TestHealthChecker_RecordSuccess_WithCallback(t *testing.T) {
	t.Parallel()

	type callRecord struct {
		backendName string
		hostAddr    string
		healthy     bool
	}

	var calls []callRecord
	callback := func(backendName, hostAddress string, healthy bool) {
		calls = append(calls, callRecord{backendName, hostAddress, healthy})
	}

	host := NewHost("10.0.0.5", 9090, 1)
	cfg := config.HealthCheck{
		Path:             "/health",
		HealthyThreshold: 2,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthStatusCallback(callback),
		WithBackendName("svc-alpha"),
	)

	// First success: threshold not met, no callback
	hc.recordSuccess(host)
	assert.Empty(t, calls)
	assert.Equal(t, StatusUnknown, host.Status())

	// Second success: threshold met, host transitions to healthy, callback fires
	hc.recordSuccess(host)
	assert.Equal(t, StatusHealthy, host.Status())
	require.Len(t, calls, 1)
	assert.Equal(t, "svc-alpha", calls[0].backendName)
	assert.Equal(t, net.JoinHostPort("10.0.0.5", strconv.Itoa(9090)), calls[0].hostAddr)
	assert.True(t, calls[0].healthy)

	// Third success: host already healthy, no additional callback
	hc.recordSuccess(host)
	assert.Len(t, calls, 1)
}

func TestHealthChecker_RecordFailure_WithCallback(t *testing.T) {
	t.Parallel()

	type callRecord struct {
		backendName string
		hostAddr    string
		healthy     bool
	}

	var calls []callRecord
	callback := func(backendName, hostAddress string, healthy bool) {
		calls = append(calls, callRecord{backendName, hostAddress, healthy})
	}

	host := NewHost("10.0.0.6", 7070, 1)
	host.SetStatus(StatusHealthy) // Start healthy

	cfg := config.HealthCheck{
		Path:               "/health",
		UnhealthyThreshold: 2,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthStatusCallback(callback),
		WithBackendName("svc-beta"),
	)

	// First failure: threshold not met, no callback
	hc.recordFailure(host, nil)
	assert.Empty(t, calls)
	assert.Equal(t, StatusHealthy, host.Status())

	// Second failure: threshold met, host transitions to unhealthy, callback fires
	hc.recordFailure(host, nil)
	assert.Equal(t, StatusUnhealthy, host.Status())
	require.Len(t, calls, 1)
	assert.Equal(t, "svc-beta", calls[0].backendName)
	assert.Equal(t, net.JoinHostPort("10.0.0.6", strconv.Itoa(7070)), calls[0].hostAddr)
	assert.False(t, calls[0].healthy)

	// Third failure: host already unhealthy, no additional callback
	hc.recordFailure(host, nil)
	assert.Len(t, calls, 1)
}

func TestHealthChecker_RecordSuccess_WithCallback_Integration(t *testing.T) {
	t.Parallel()

	// Integration test: verify callback fires through actual health check flow
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)
	host := NewHost(addr.IP.String(), addr.Port, 1)

	var callbackFired atomic.Bool
	callback := func(_, _ string, healthy bool) {
		if healthy {
			callbackFired.Store(true)
		}
	}

	cfg := config.HealthCheck{
		Path:               "/health",
		Interval:           config.Duration(50 * time.Millisecond),
		Timeout:            config.Duration(2 * time.Second),
		HealthyThreshold:   1,
		UnhealthyThreshold: 3,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthStatusCallback(callback),
		WithBackendName("integration-svc"),
		WithHealthCheckLogger(observability.NopLogger()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc.Start(ctx)

	// Wait for health check to run and callback to fire
	assert.Eventually(t, func() bool {
		return callbackFired.Load()
	}, 2*time.Second, 50*time.Millisecond)

	hc.Stop()
}

// ---------------------------------------------------------------------------
// Additional edge case: circuit breaker manager with callback creates CB
// that propagates state changes
// ---------------------------------------------------------------------------

func TestCircuitBreakerManager_CreateFromConfig_WithCallback(t *testing.T) {
	t.Parallel()

	var stateChanges []struct {
		name  string
		state int
	}

	callback := func(name string, state int) {
		stateChanges = append(stateChanges, struct {
			name  string
			state int
		}{name, state})
	}

	manager := NewCircuitBreakerManager(
		observability.NopLogger(),
		WithCircuitBreakerManagerStateCallback(callback),
	)

	backends := []config.Backend{
		{
			Name: "cb-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 1,
				Timeout:   config.Duration(100 * time.Millisecond),
			},
		},
	}

	manager.CreateFromConfig(backends)

	cb := manager.Get("cb-backend")
	require.NotNil(t, cb)

	// Trigger state change by exceeding threshold
	_, _ = cb.Execute(func() (interface{}, error) {
		return nil, assert.AnError
	})
	_, _ = cb.Execute(func() (interface{}, error) {
		return nil, assert.AnError
	})

	// Callback should have been invoked
	assert.NotEmpty(t, stateChanges)
}

// ---------------------------------------------------------------------------
// Verify WithCircuitBreakerManagerStateCallback creates a valid option
// ---------------------------------------------------------------------------

func TestWithCircuitBreakerManagerStateCallback_NilCallback(t *testing.T) {
	t.Parallel()

	// Passing nil should not panic
	manager := NewCircuitBreakerManager(nil,
		WithCircuitBreakerManagerStateCallback(nil),
	)

	assert.NotNil(t, manager)
	assert.Nil(t, manager.stateCallback)
}

// ---------------------------------------------------------------------------
// Verify createCircuitBreaker with and without stateCallback
// ---------------------------------------------------------------------------

func TestCircuitBreakerManager_CreateCircuitBreaker_WithCallback(t *testing.T) {
	t.Parallel()

	called := false
	callback := middleware.CircuitBreakerStateFunc(func(_ string, _ int) {
		called = true
	})

	manager := NewCircuitBreakerManager(
		observability.NopLogger(),
		WithCircuitBreakerManagerStateCallback(callback),
	)

	backend := &config.Backend{
		Name: "test-cb-callback",
		CircuitBreaker: &config.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 1,
			Timeout:   config.Duration(50 * time.Millisecond),
		},
	}

	cb := manager.GetOrCreate(backend)
	require.NotNil(t, cb)

	// Trigger failures to open the circuit breaker
	for i := 0; i < 3; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})
	}

	assert.True(t, called, "state callback should have been invoked")
}

func TestCircuitBreakerManager_CreateCircuitBreaker_WithoutCallback(t *testing.T) {
	t.Parallel()

	// Manager without callback
	manager := NewCircuitBreakerManager(observability.NopLogger())

	backend := &config.Backend{
		Name: "test-cb-no-callback",
		CircuitBreaker: &config.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
			Timeout:   config.Duration(10 * time.Second),
		},
	}

	cb := manager.GetOrCreate(backend)
	require.NotNil(t, cb)

	// Should work fine without callback
	result, err := cb.Execute(func() (interface{}, error) {
		return "ok", nil
	})
	assert.NoError(t, err)
	assert.Equal(t, "ok", result)
}
