package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
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
