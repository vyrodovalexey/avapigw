package main

// Tests for T3.G1 (review M9): readiness dependency checks are registered
// and /ready reflects vault/redis/backend health.

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// readinessVaultClient is a controllable vault.Client fake.
type readinessVaultClient struct {
	enabled bool
	status  *vault.HealthStatus
	err     error
}

func (m *readinessVaultClient) IsEnabled() bool                    { return m.enabled }
func (m *readinessVaultClient) Authenticate(context.Context) error { return nil }
func (m *readinessVaultClient) RenewToken(context.Context) error   { return nil }
func (m *readinessVaultClient) Health(context.Context) (*vault.HealthStatus, error) {
	return m.status, m.err
}
func (m *readinessVaultClient) PKI() vault.PKIClient         { return nil }
func (m *readinessVaultClient) KV() vault.KVClient           { return nil }
func (m *readinessVaultClient) Transit() vault.TransitClient { return nil }
func (m *readinessVaultClient) Close() error                 { return nil }

// readinessRedisLimiter is a controllable redis limiter fake implementing
// RateLimiterHandle + redisReadinessPinger.
type readinessRedisLimiter struct {
	pingErr  error
	failOpen bool
}

func (m *readinessRedisLimiter) Stop()                                {}
func (m *readinessRedisLimiter) UpdateConfig(*config.RateLimitConfig) {}
func (m *readinessRedisLimiter) Ping(context.Context) error           { return m.pingErr }
func (m *readinessRedisLimiter) IsFailOpen() bool                     { return m.failOpen }

func TestEvaluateVaultHealth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		client   *readinessVaultClient
		expected health.Status
	}{
		{
			name:     "healthy",
			client:   &readinessVaultClient{enabled: true, status: &vault.HealthStatus{Initialized: true}},
			expected: health.StatusHealthy,
		},
		{
			name:     "sealed",
			client:   &readinessVaultClient{enabled: true, status: &vault.HealthStatus{Initialized: true, Sealed: true}},
			expected: health.StatusUnhealthy,
		},
		{
			name:     "uninitialized",
			client:   &readinessVaultClient{enabled: true, status: &vault.HealthStatus{}},
			expected: health.StatusUnhealthy,
		},
		{
			name:     "unreachable",
			client:   &readinessVaultClient{enabled: true, err: errors.New("connection refused")},
			expected: health.StatusUnhealthy,
		},
		{
			name:     "nil status without error degrades",
			client:   &readinessVaultClient{enabled: true},
			expected: health.StatusDegraded,
		},
		{
			name: "standby is healthy",
			client: &readinessVaultClient{enabled: true,
				status: &vault.HealthStatus{Initialized: true, Standby: true}},
			expected: health.StatusHealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			check := evaluateVaultHealth(context.Background(), tt.client)
			assert.Equal(t, tt.expected, check.Status)
		})
	}
}

func TestEvaluateRedisRateLimitHealth(t *testing.T) {
	t.Parallel()

	t.Run("reachable is healthy", func(t *testing.T) {
		t.Parallel()
		check := evaluateRedisRateLimitHealth(context.Background(), &readinessRedisLimiter{})
		assert.Equal(t, health.StatusHealthy, check.Status)
	})

	t.Run("down fail-closed is unhealthy", func(t *testing.T) {
		t.Parallel()
		check := evaluateRedisRateLimitHealth(context.Background(),
			&readinessRedisLimiter{pingErr: errors.New("refused"), failOpen: false})
		assert.Equal(t, health.StatusUnhealthy, check.Status,
			"redis down + fail-closed limiter rejects all traffic → pod not ready")
	})

	t.Run("down fail-open is degraded", func(t *testing.T) {
		t.Parallel()
		check := evaluateRedisRateLimitHealth(context.Background(),
			&readinessRedisLimiter{pingErr: errors.New("refused"), failOpen: true})
		assert.Equal(t, health.StatusDegraded, check.Status)
	})
}

// readinessFakeBackend is a minimal backend.Backend with a fixed status.
type readinessFakeBackend struct {
	name   string
	status backend.Status
}

func (b *readinessFakeBackend) Name() string                    { return b.name }
func (b *readinessFakeBackend) GetHost() (*backend.Host, error) { return nil, errors.New("no host") }
func (b *readinessFakeBackend) ReleaseHost(*backend.Host)       {}
func (b *readinessFakeBackend) Status() backend.Status          { return b.status }
func (b *readinessFakeBackend) Start(context.Context) error     { return nil }
func (b *readinessFakeBackend) Stop(context.Context) error      { return nil }

// newBackendRegistryWith builds a registry containing one fake backend per
// given status.
func newBackendRegistryWith(t *testing.T, prefix string, statuses ...backend.Status) *backend.Registry {
	t.Helper()

	reg := backend.NewRegistry(observability.NopLogger())
	for i, status := range statuses {
		require.NoError(t, reg.Register(&readinessFakeBackend{
			name:   fmt.Sprintf("%s-%d", prefix, i),
			status: status,
		}))
	}
	return reg
}

// TestEvaluateBackendHealth covers the M9 aggregation semantics: no
// backends → healthy, all unhealthy → unhealthy, some unhealthy → degraded,
// aggregated across multiple (HTTP + gRPC) registries.
func TestEvaluateBackendHealth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		registries      func(t *testing.T) []*backend.Registry
		expectedStatus  health.Status
		expectedMessage string
	}{
		{
			name:           "no registries healthy",
			registries:     func(*testing.T) []*backend.Registry { return nil },
			expectedStatus: health.StatusHealthy,
		},
		{
			name: "empty registry healthy",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{backend.NewRegistry(observability.NopLogger())}
			},
			expectedStatus: health.StatusHealthy,
		},
		{
			name: "all backends healthy",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{
					newBackendRegistryWith(t, "http", backend.StatusHealthy, backend.StatusHealthy),
				}
			},
			expectedStatus: health.StatusHealthy,
		},
		{
			name: "unknown status does not count as unhealthy",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{
					newBackendRegistryWith(t, "http", backend.StatusUnknown, backend.StatusHealthy),
				}
			},
			expectedStatus: health.StatusHealthy,
		},
		{
			name: "all backends unhealthy",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{
					newBackendRegistryWith(t, "http", backend.StatusUnhealthy, backend.StatusUnhealthy),
				}
			},
			expectedStatus:  health.StatusUnhealthy,
			expectedMessage: "all 2 backends unhealthy",
		},
		{
			name: "some backends unhealthy",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{
					newBackendRegistryWith(t, "http",
						backend.StatusHealthy, backend.StatusUnhealthy, backend.StatusHealthy),
				}
			},
			expectedStatus:  health.StatusDegraded,
			expectedMessage: "1 of 3 backends unhealthy",
		},
		{
			name: "mixed across HTTP and gRPC registries degrades",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{
					newBackendRegistryWith(t, "http", backend.StatusHealthy),
					newBackendRegistryWith(t, "grpc", backend.StatusUnhealthy),
				}
			},
			expectedStatus:  health.StatusDegraded,
			expectedMessage: "1 of 2 backends unhealthy",
		},
		{
			name: "all unhealthy across HTTP and gRPC registries",
			registries: func(t *testing.T) []*backend.Registry {
				return []*backend.Registry{
					newBackendRegistryWith(t, "http", backend.StatusUnhealthy),
					newBackendRegistryWith(t, "grpc", backend.StatusUnhealthy, backend.StatusUnhealthy),
				}
			},
			expectedStatus:  health.StatusUnhealthy,
			expectedMessage: "all 3 backends unhealthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			check := evaluateBackendHealth(tt.registries(t))

			assert.Equal(t, tt.expectedStatus, check.Status)
			assert.Equal(t, tt.expectedMessage, check.Message)
		})
	}
}

// TestRegisterBackendReadinessCheck_AllUnhealthyReflectedInReady is the
// other half of the M9 acceptance criterion: with every backend unhealthy,
// /ready reports unhealthy through the registered check.
func TestRegisterBackendReadinessCheck_AllUnhealthyReflectedInReady(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	registerBackendReadinessCheck(checker,
		newBackendRegistryWith(t, "http", backend.StatusUnhealthy, backend.StatusUnhealthy))

	readiness := checker.Readiness()
	assert.Equal(t, health.StatusUnhealthy, readiness.Status,
		"all backends unhealthy must surface as unhealthy readiness")
	require.Contains(t, readiness.Checks, readinessCheckBackends)
	assert.Equal(t, "all 2 backends unhealthy", readiness.Checks[readinessCheckBackends].Message)
}

// TestRegisterReadinessChecks_WiresReadyEndpoint is the M9 acceptance
// criterion: after registration, /ready reflects dependency health.
func TestRegisterReadinessChecks_WiresReadyEndpoint(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	app := &application{
		healthChecker:   checker,
		backendRegistry: backend.NewRegistry(observability.NopLogger()),
		vaultClient: &readinessVaultClient{
			enabled: true,
			status:  &vault.HealthStatus{Initialized: true, Sealed: true},
		},
		rateLimiter: &readinessRedisLimiter{pingErr: errors.New("refused"), failOpen: false},
	}

	registry := registerReadinessChecks(app, observability.NopLogger())
	require.NotNil(t, registry, "cached checks (vault + redis) must yield a registry")
	defer registry.stop()

	readiness := checker.Readiness()
	assert.Equal(t, health.StatusUnhealthy, readiness.Status,
		"sealed vault + down fail-closed redis must surface as unhealthy readiness")

	require.Contains(t, readiness.Checks, readinessCheckVault)
	assert.Equal(t, health.StatusUnhealthy, readiness.Checks[readinessCheckVault].Status)
	require.Contains(t, readiness.Checks, readinessCheckRedisRateLimit)
	assert.Equal(t, health.StatusUnhealthy, readiness.Checks[readinessCheckRedisRateLimit].Status)
	require.Contains(t, readiness.Checks, readinessCheckBackends)
	assert.Equal(t, health.StatusHealthy, readiness.Checks[readinessCheckBackends].Status)
}

func TestRegisterReadinessChecks_NoDependencies(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	app := &application{
		healthChecker:   checker,
		backendRegistry: backend.NewRegistry(observability.NopLogger()),
		rateLimiter:     nil, // in-memory limiter: no pinger
	}

	registry := registerReadinessChecks(app, observability.NopLogger())
	assert.Nil(t, registry, "no cached checks → no background refresher")
	// stop must be nil-safe.
	registry.stop()

	readiness := checker.Readiness()
	assert.Equal(t, health.StatusHealthy, readiness.Status)
	assert.Contains(t, readiness.Checks, readinessCheckBackends)
	assert.NotContains(t, readiness.Checks, readinessCheckVault)
}

func TestRegisterReadinessChecks_NilApp(t *testing.T) {
	t.Parallel()

	assert.Nil(t, registerReadinessChecks(nil, observability.NopLogger()))
	assert.Nil(t, registerReadinessChecks(&application{}, observability.NopLogger()))
}

// TestReadinessRegistry_StopIsIdempotent guards the shutdown path.
func TestReadinessRegistry_StopIsIdempotent(t *testing.T) {
	t.Parallel()

	checker := health.NewChecker("test", observability.NopLogger())
	app := &application{
		healthChecker: checker,
		vaultClient: &readinessVaultClient{
			enabled: true,
			status:  &vault.HealthStatus{Initialized: true},
		},
	}

	registry := registerReadinessChecks(app, observability.NopLogger())
	require.NotNil(t, registry)

	done := make(chan struct{})
	go func() {
		registry.stop()
		registry.stop() // second stop must be a no-op
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("registry.stop() hung")
	}
}

// TestCachedReadinessCheck_ServesSnapshot verifies the check function reads
// the cached snapshot (no per-request probe).
func TestCachedReadinessCheck_ServesSnapshot(t *testing.T) {
	t.Parallel()

	probeCount := 0
	c := newCachedReadinessCheck(context.Background(), "probe", observability.NopLogger(),
		func(context.Context) health.Check {
			probeCount++
			return health.Check{Status: health.StatusHealthy}
		})

	for i := 0; i < 50; i++ {
		assert.Equal(t, health.StatusHealthy, c.Check().Status)
	}
	assert.Equal(t, 1, probeCount,
		"Check() must serve the cached snapshot, not re-evaluate the probe per request")
}

// TestCachedReadinessCheck_NotEvaluatedYetDegrades covers the defensive
// branch: before the first evaluation stores a snapshot, Check reports
// degraded rather than blocking readiness on unknown state.
func TestCachedReadinessCheck_NotEvaluatedYetDegrades(t *testing.T) {
	t.Parallel()

	c := &cachedReadinessCheck{name: "unevaluated", logger: observability.NopLogger()}

	check := c.Check()

	assert.Equal(t, health.StatusDegraded, check.Status)
	assert.Equal(t, "check not evaluated yet", check.Message)
}

// TestReadinessRegistry_TickerRefresh_ObservesStateTransition covers the
// periodic refresh path: a dependency flipping healthy → sealed after the
// initial snapshot must be re-observed by Check() without a restart.
func TestReadinessRegistry_TickerRefresh_ObservesStateTransition(t *testing.T) {
	t.Parallel()

	var sealed atomic.Bool
	check := newCachedReadinessCheck(context.Background(), readinessCheckVault,
		observability.NopLogger(),
		func(context.Context) health.Check {
			if sealed.Load() {
				return health.Check{Status: health.StatusUnhealthy, Message: "vault is sealed"}
			}
			return health.Check{Status: health.StatusHealthy}
		})
	require.Equal(t, health.StatusHealthy, check.Check().Status,
		"initial synchronous snapshot must be healthy")

	registry := &readinessRegistry{
		checks:          []*cachedReadinessCheck{check},
		refreshInterval: 5 * time.Millisecond,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}
	go registry.run(context.Background())
	defer registry.stop()

	sealed.Store(true)

	require.Eventually(t, func() bool {
		return check.Check().Status == health.StatusUnhealthy
	}, 10*time.Second, 5*time.Millisecond,
		"background ticker must re-evaluate the probe and surface the sealed state")
	assert.Equal(t, "vault is sealed", check.Check().Message)
}
