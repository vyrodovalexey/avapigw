package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

func TestNew(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)

	assert.NotNil(t, p)
	assert.NotNil(t, p.router)
	assert.NotNil(t, p.director)
	assert.NotNil(t, p.streamHandler)
	assert.NotNil(t, p.connPool)
	assert.NotNil(t, p.logger)
	assert.Equal(t, 30*time.Second, p.defaultTimeout)
}

func TestNew_WithAllOptions(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := NewRouterDirector(r, pool)
	reg := prometheus.NewRegistry()
	authMetrics := auth.NewMetricsWithRegisterer("test_new_all_opts", reg)
	mockVC := &mockVaultClientForProxy{enabled: true}

	p := New(r,
		WithProxyLogger(logger),
		WithConnectionPool(pool),
		WithDirector(director),
		WithDefaultTimeout(60*time.Second),
		WithMetricsRegistry(reg),
		WithAuthMetrics(authMetrics),
		WithProxyVaultClient(mockVC),
	)
	defer p.Close()

	assert.NotNil(t, p)
	assert.Equal(t, pool, p.connPool)
	assert.Equal(t, director, p.director)
	assert.Equal(t, 60*time.Second, p.defaultTimeout)
	assert.Equal(t, reg, p.metricsRegistry)
	assert.Equal(t, authMetrics, p.authMetrics)
	assert.Equal(t, mockVC, p.vaultClient)
}

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	logger := observability.NopLogger()
	director := NewRouterDirector(r, pool)

	p := New(r,
		WithProxyLogger(logger),
		WithConnectionPool(pool),
		WithDirector(director),
		WithDefaultTimeout(60*time.Second),
	)

	assert.NotNil(t, p)
	assert.Equal(t, pool, p.connPool)
	assert.Equal(t, director, p.director)
	assert.Equal(t, 60*time.Second, p.defaultTimeout)
}

func TestWithProxyLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	p := &Proxy{}

	opt := WithProxyLogger(logger)
	opt(p)

	assert.NotNil(t, p.logger)
}

func TestWithConnectionPool(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	p := &Proxy{}

	opt := WithConnectionPool(pool)
	opt(p)

	assert.Equal(t, pool, p.connPool)
}

func TestWithDirector(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)
	p := &Proxy{}

	opt := WithDirector(director)
	opt(p)

	assert.Equal(t, director, p.director)
}

func TestWithDefaultTimeout(t *testing.T) {
	t.Parallel()

	p := &Proxy{}

	opt := WithDefaultTimeout(60 * time.Second)
	opt(p)

	assert.Equal(t, 60*time.Second, p.defaultTimeout)
}

func TestProxy_StreamHandler(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)
	defer p.Close()

	handler := p.StreamHandler()
	assert.NotNil(t, handler)
}

func TestProxy_Close(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)

	err := p.Close()
	assert.NoError(t, err)
}

func TestProxy_Close_NilPool(t *testing.T) {
	t.Parallel()

	p := &Proxy{}

	err := p.Close()
	assert.NoError(t, err)
}

func TestProxy_Router(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)
	defer p.Close()

	assert.Equal(t, r, p.Router())
}

func TestProxy_ConnectionPool(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	p := New(r, WithConnectionPool(pool))

	assert.Equal(t, pool, p.ConnectionPool())
}

func TestProxy_Director(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	director := NewRouterDirector(r, pool)
	p := New(r, WithDirector(director))
	defer p.Close()

	assert.Equal(t, director, p.Director())
}

func TestProxy_ApplyTimeout_NoDeadline(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r, WithDefaultTimeout(5*time.Second))
	defer p.Close()

	ctx := context.Background()
	newCtx, cancel, matched := p.applyTimeout(ctx, "/test.Service/Method")
	// No route configured, so matched should be false
	assert.False(t, matched)
	assert.Nil(t, cancel)
	// Context should be unchanged when route is not matched
	_, hasDeadline := newCtx.Deadline()
	assert.False(t, hasDeadline)
}

func TestProxy_ApplyTimeout_ExistingDeadline(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r, WithDefaultTimeout(5*time.Second))
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	newCtx, newCancel, matched := p.applyTimeout(ctx, "/test.Service/Method")
	assert.True(t, matched)
	assert.Nil(t, newCancel)
	assert.Equal(t, ctx, newCtx)
}

func TestProxy_ApplyTimeout_RouteTimeout(t *testing.T) {
	t.Parallel()

	r := router.New()
	err := r.AddRoute(config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.Service"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Timeout: config.Duration(10 * time.Second),
	})
	require.NoError(t, err)

	p := New(r, WithDefaultTimeout(5*time.Second))
	defer p.Close()

	ctx := context.Background()
	newCtx, cancel, matched := p.applyTimeout(ctx, "/test.Service/Method")
	assert.True(t, matched)
	require.NotNil(t, cancel)
	defer cancel()

	deadline, ok := newCtx.Deadline()
	assert.True(t, ok)
	// Should use route timeout (10s) instead of default (5s)
	assert.True(t, deadline.After(time.Now().Add(9*time.Second)))
}

func TestProxy_HandleStream_NoMethodInContext(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)
	defer p.Close()

	// Context without method
	ctx := context.Background()
	stream := &proxyTestServerStream{ctx: ctx}

	err := p.handleStream(nil, stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get method from context")
}

func TestProxy_HandleStream_WithMethod(t *testing.T) {
	t.Parallel()

	r := router.New()
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

	p := New(r)
	defer p.Close()

	// Context with method using ServerTransportStream
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&proxyTestServerTransportStream{method: "/test.Service/Method"},
	)
	stream := &proxyTestServerStream{ctx: ctx}

	// This will fail at the director level since we don't have a real backend
	// but it tests that handleStream properly extracts the method
	err = p.handleStream(nil, stream)
	// Error is expected since we can't connect to backend
	assert.Error(t, err)
}

func TestProxy_HandleStream_WithTimeout(t *testing.T) {
	t.Parallel()

	r := router.New()
	err := r.AddRoute(config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Timeout: config.Duration(100 * time.Millisecond),
	})
	require.NoError(t, err)

	p := New(r, WithDefaultTimeout(5*time.Second))
	defer p.Close()

	// Context with method
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&proxyTestServerTransportStream{method: "/test.Service/Method"},
	)
	stream := &proxyTestServerStream{ctx: ctx}

	// This will fail but tests the timeout path
	err = p.handleStream(nil, stream)
	assert.Error(t, err)
}

// proxyTestServerStream implements grpc.ServerStream for testing
type proxyTestServerStream struct {
	ctx context.Context
}

func (m *proxyTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *proxyTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *proxyTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *proxyTestServerStream) Context() context.Context       { return m.ctx }
func (m *proxyTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *proxyTestServerStream) RecvMsg(_ interface{}) error    { return nil }

// proxyTestServerTransportStream implements grpc.ServerTransportStream for testing
type proxyTestServerTransportStream struct {
	method string
}

func (m *proxyTestServerTransportStream) Method() string {
	return m.method
}

func (m *proxyTestServerTransportStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *proxyTestServerTransportStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *proxyTestServerTransportStream) SetTrailer(md metadata.MD) error {
	return nil
}

// --- ClearAuthCache tests ---

func TestProxy_ClearAuthCache_DelegatesToDirector(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Create a RouterDirector (which implements ClearAuthCache)
	director := NewRouterDirector(r, pool,
		WithDirectorLogger(observability.NopLogger()),
	)

	// Pre-populate the director's auth cache
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "x-api-key",
		},
	}
	_, err := director.getOrCreateAuthenticator("test-route", authCfg)
	require.NoError(t, err)

	// Verify cache has an entry
	director.authCacheMu.RLock()
	assert.Len(t, director.authCache, 1)
	director.authCacheMu.RUnlock()

	// Create proxy with the RouterDirector
	p := New(r,
		WithDirector(director),
		WithConnectionPool(pool),
		WithProxyLogger(observability.NopLogger()),
	)
	defer p.Close()

	// Call ClearAuthCache on the proxy — should delegate to director
	p.ClearAuthCache()

	// Verify the director's cache was cleared
	director.authCacheMu.RLock()
	assert.Len(t, director.authCache, 0, "director auth cache should be empty after proxy.ClearAuthCache()")
	director.authCacheMu.RUnlock()
}

func TestProxy_ClearAuthCache_StaticDirector_NoPanic(t *testing.T) {
	t.Parallel()

	r := router.New()
	pool := NewConnectionPool()
	defer pool.Close()

	// Create a StaticDirector (doesn't implement ClearAuthCache)
	staticDirector := NewStaticDirector("localhost:50051", pool, observability.NopLogger())

	// Create proxy with the StaticDirector
	p := New(r,
		WithDirector(staticDirector),
		WithConnectionPool(pool),
		WithProxyLogger(observability.NopLogger()),
	)
	defer p.Close()

	// ClearAuthCache should not panic when director doesn't implement the interface
	assert.NotPanics(t, func() {
		p.ClearAuthCache()
	})
}

func TestProxy_ClearAuthCache_NilDirector_NoPanic(t *testing.T) {
	t.Parallel()

	// Create a proxy with a nil director field (edge case)
	p := &Proxy{
		logger: observability.NopLogger(),
	}

	// ClearAuthCache should not panic when director is nil
	assert.NotPanics(t, func() {
		p.ClearAuthCache()
	})
}

// --- WithBackendRegistry tests ---

func TestWithBackendRegistry_SetsRegistry(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	p := &Proxy{}

	// We can't easily create a real backend.Registry without importing backend,
	// but we can test the option sets the field. Use nil to verify the option works.
	opt := WithBackendRegistry(nil)
	opt(p)

	assert.Nil(t, p.backendRegistry)

	// Now test with a non-nil value by using the proxy constructor
	r := router.New()
	proxy := New(r, WithProxyLogger(logger))
	defer proxy.Close()

	// backendRegistry should be nil by default
	assert.Nil(t, proxy.backendRegistry)
}

func TestWithBackendRegistry_NilRegistry(t *testing.T) {
	t.Parallel()

	p := &Proxy{}

	opt := WithBackendRegistry(nil)
	opt(p)

	assert.Nil(t, p.backendRegistry)
}

func TestNew_WithBackendRegistry_PassesToDirector(t *testing.T) {
	t.Parallel()

	r := router.New()

	// Create proxy with nil backend registry — director should still be created
	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithBackendRegistry(nil),
	)
	defer p.Close()

	assert.NotNil(t, p)
	assert.NotNil(t, p.director)
	assert.Nil(t, p.backendRegistry)
}

// --- CleanupStaleConnections tests ---

func TestProxy_CleanupStaleConnections_NilPool(t *testing.T) {
	t.Parallel()

	p := &Proxy{
		connPool: nil,
		logger:   observability.NopLogger(),
	}

	// Should be a no-op, not panic
	assert.NotPanics(t, func() {
		p.CleanupStaleConnections(map[string]bool{"target1:50051": true})
	})
}

func TestProxy_CleanupStaleConnections_EmptyValidTargets(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(WithPoolLogger(observability.NopLogger()))
	defer pool.Close()

	r := router.New()
	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithConnectionPool(pool),
	)

	// No connections in pool, empty valid targets — should be no-op
	p.CleanupStaleConnections(map[string]bool{})

	assert.Equal(t, 0, pool.Size())
}

func TestProxy_CleanupStaleConnections_AllTargetsValid(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(WithPoolLogger(observability.NopLogger()))
	defer pool.Close()

	r := router.New()
	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithConnectionPool(pool),
	)

	// Get connections to create entries in the pool
	// Note: These will fail to connect but the pool tracks them
	ctx := context.Background()
	_, _ = pool.Get(ctx, "localhost:50051")
	_, _ = pool.Get(ctx, "localhost:50052")

	targets := pool.Targets()

	// Build valid targets map from all current targets
	validTargets := make(map[string]bool)
	for _, t := range targets {
		validTargets[t] = true
	}

	// All targets are valid — none should be closed
	initialSize := pool.Size()
	p.CleanupStaleConnections(validTargets)

	assert.Equal(t, initialSize, pool.Size())
}

func TestProxy_CleanupStaleConnections_SomeStaleTargets(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(WithPoolLogger(observability.NopLogger()))
	defer pool.Close()

	r := router.New()
	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithConnectionPool(pool),
	)

	// Create connections
	ctx := context.Background()
	_, _ = pool.Get(ctx, "localhost:50051")
	_, _ = pool.Get(ctx, "localhost:50052")
	_, _ = pool.Get(ctx, "localhost:50053")

	initialSize := pool.Size()
	require.Greater(t, initialSize, 0)

	// Only localhost:50051 is valid — others should be cleaned up
	validTargets := map[string]bool{
		"localhost:50051": true,
	}

	p.CleanupStaleConnections(validTargets)

	// The stale connections should have been removed
	// Only localhost:50051 should remain
	remainingTargets := pool.Targets()
	for _, target := range remainingTargets {
		assert.True(t, validTargets[target], "remaining target %s should be in valid targets", target)
	}
}

// --- mockVaultClientForProxy implements vault.Client for proxy tests ---

type mockVaultClientForProxy struct {
	enabled bool
}

func (m *mockVaultClientForProxy) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClientForProxy) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForProxy) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForProxy) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForProxy) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClientForProxy) KV() vault.KVClient           { return nil }
func (m *mockVaultClientForProxy) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForProxy) Close() error                 { return nil }

// --- WithMetricsRegistry tests ---

func TestWithMetricsRegistry(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	p := &Proxy{}

	opt := WithMetricsRegistry(reg)
	opt(p)

	assert.Equal(t, reg, p.metricsRegistry)
}

func TestWithMetricsRegistry_Nil(t *testing.T) {
	t.Parallel()

	p := &Proxy{}

	opt := WithMetricsRegistry(nil)
	opt(p)

	assert.Nil(t, p.metricsRegistry)
}

// --- WithAuthMetrics tests ---

func TestWithAuthMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := auth.NewMetricsWithRegisterer("test_proxy_auth", reg)
	p := &Proxy{}

	opt := WithAuthMetrics(metrics)
	opt(p)

	assert.Equal(t, metrics, p.authMetrics)
}

func TestWithAuthMetrics_Nil(t *testing.T) {
	t.Parallel()

	p := &Proxy{}

	opt := WithAuthMetrics(nil)
	opt(p)

	assert.Nil(t, p.authMetrics)
}

// --- WithProxyVaultClient tests ---

func TestWithProxyVaultClient(t *testing.T) {
	t.Parallel()

	mockClient := &mockVaultClientForProxy{enabled: true}
	p := &Proxy{}

	opt := WithProxyVaultClient(mockClient)
	opt(p)

	assert.Equal(t, mockClient, p.vaultClient)
}

func TestWithProxyVaultClient_Nil(t *testing.T) {
	t.Parallel()

	p := &Proxy{}

	opt := WithProxyVaultClient(nil)
	opt(p)

	assert.Nil(t, p.vaultClient)
}

// --- New with auth/vault/metrics options (director creation paths) ---

func TestNew_WithAuthMetrics_PassesToDirector(t *testing.T) {
	t.Parallel()

	r := router.New()
	reg := prometheus.NewRegistry()
	metrics := auth.NewMetricsWithRegisterer("test_new_auth_metrics", reg)

	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithAuthMetrics(metrics),
	)
	defer p.Close()

	assert.NotNil(t, p)
	assert.NotNil(t, p.director)
	assert.Equal(t, metrics, p.authMetrics)
}

func TestNew_WithVaultClient_PassesToDirector(t *testing.T) {
	t.Parallel()

	r := router.New()
	mockClient := &mockVaultClientForProxy{enabled: true}

	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithProxyVaultClient(mockClient),
	)
	defer p.Close()

	assert.NotNil(t, p)
	assert.NotNil(t, p.director)
	assert.Equal(t, mockClient, p.vaultClient)
}

func TestNew_WithAllDirectorOptions_NoExplicitDirector(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	reg := prometheus.NewRegistry()
	authMetrics := auth.NewMetricsWithRegisterer("test_new_all_dir_opts", reg)
	mockVC := &mockVaultClientForProxy{enabled: true}
	backendReg := backend.NewRegistry(logger)

	// Create proxy without explicit director but with all director options
	// This exercises the director creation path with all optional branches
	p := New(r,
		WithProxyLogger(logger),
		WithAuthMetrics(authMetrics),
		WithProxyVaultClient(mockVC),
		WithBackendRegistry(backendReg),
	)
	defer p.Close()

	assert.NotNil(t, p)
	assert.NotNil(t, p.director)
	assert.Equal(t, authMetrics, p.authMetrics)
	assert.Equal(t, mockVC, p.vaultClient)
	assert.Equal(t, backendReg, p.backendRegistry)
}

// --- StreamHandler inner function test ---

func TestProxy_StreamHandler_InnerFunction_NoMethod(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)
	defer p.Close()

	handler := p.StreamHandler()
	require.NotNil(t, handler)

	// Call the inner function (the actual grpc.StreamHandler)
	// with a context that has no method — should return error
	ctx := context.Background()
	stream := &proxyTestServerStream{ctx: ctx}

	err := handler(nil, stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get method from context")
}

func TestProxy_StreamHandler_InnerFunction_NoRoute(t *testing.T) {
	t.Parallel()

	r := router.New()
	p := New(r)
	defer p.Close()

	handler := p.StreamHandler()
	require.NotNil(t, handler)

	// Call with a method that has no matching route
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&proxyTestServerTransportStream{method: "/nonexistent.Service/Method"},
	)
	stream := &proxyTestServerStream{ctx: ctx}

	err := handler(nil, stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no route for method")
}

func TestProxy_StreamHandler_InnerFunction_WithRoute(t *testing.T) {
	t.Parallel()

	r := router.New()
	err := r.AddRoute(config.GRPCRoute{
		Name: "handler-test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "handler."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
	})
	require.NoError(t, err)

	p := New(r)
	defer p.Close()

	handler := p.StreamHandler()
	require.NotNil(t, handler)

	// Call with a method that has a matching route
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&proxyTestServerTransportStream{method: "/handler.Service/Method"},
	)
	stream := &proxyTestServerStream{ctx: ctx}

	// Will fail at backend connection but exercises the inner function path
	err = handler(nil, stream)
	assert.Error(t, err)
}

// --- HandleStream with deadline exceeded ---

func TestProxy_HandleStream_DeadlineExceeded(t *testing.T) {
	t.Parallel()

	r := router.New()
	err := r.AddRoute(config.GRPCRoute{
		Name: "deadline-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "deadline."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Timeout: config.Duration(1 * time.Millisecond),
	})
	require.NoError(t, err)

	p := New(r, WithDefaultTimeout(1*time.Millisecond))
	defer p.Close()

	// Create a context that will expire immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // Ensure deadline is exceeded

	ctx = grpc.NewContextWithServerTransportStream(
		ctx,
		&proxyTestServerTransportStream{method: "/deadline.Service/Method"},
	)
	stream := &proxyTestServerStream{ctx: ctx}

	err = p.handleStream(nil, stream)
	// Error is expected — either deadline exceeded or connection error
	assert.Error(t, err)
}
