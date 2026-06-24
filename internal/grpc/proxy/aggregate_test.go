package proxy

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fakeGRPCAggregateHandler records invocations and returns a configurable error.
type fakeGRPCAggregateHandler struct {
	called  atomic.Int32
	gotCfg  *config.AggregateConfig
	gotPool *ConnectionPool
	err     error
}

func (f *fakeGRPCAggregateHandler) HandleAggregate(
	_ interface{},
	_ grpc.ServerStream,
	cfg *config.AggregateConfig,
	pool *ConnectionPool,
) error {
	f.called.Add(1)
	f.gotCfg = cfg
	f.gotPool = pool
	return f.err
}

// aggregateGRPCRoute builds a gRPC route declaring an (optionally enabled)
// aggregate config with a single target.
func aggregateGRPCRoute(enabled bool) config.GRPCRoute {
	return config.GRPCRoute{
		Name: "agg-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "agg."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "localhost", Port: 50051}},
		},
		Aggregate: &config.AggregateConfig{
			Enabled: enabled,
			Targets: []config.AggregateTarget{
				{Name: "t1", Destination: config.Destination{Host: "localhost", Port: 9090}},
			},
		},
	}
}

func newAggregateProxy(t *testing.T, h GRPCAggregateHandler, route config.GRPCRoute) *Proxy {
	t.Helper()
	r := router.New()
	require.NoError(t, r.AddRoute(route))
	p := New(r,
		WithProxyLogger(observability.NopLogger()),
		WithAggregateHandler(h),
	)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func aggregateContext(method string) context.Context {
	return grpc.NewContextWithServerTransportStream(
		context.Background(),
		&proxyTestServerTransportStream{method: method},
	)
}

// (a) A gRPC unary route with aggregate.enabled invokes the aggregate handler.
func TestProxy_HandleStream_AggregateEnabled_InvokesHandler(t *testing.T) {
	t.Parallel()

	h := &fakeGRPCAggregateHandler{}
	p := newAggregateProxy(t, h, aggregateGRPCRoute(true))

	stream := &proxyTestServerStream{ctx: aggregateContext("/agg.Service/Method")}
	err := p.handleStream(nil, stream)

	require.NoError(t, err)
	assert.Equal(t, int32(1), h.called.Load(), "aggregate handler must be invoked")
	require.NotNil(t, h.gotCfg)
	assert.True(t, h.gotCfg.IsEnabled())
	assert.Equal(t, p.ConnectionPool(), h.gotPool, "proxy must pass its own pool")
}

// When aggregate is disabled, the handler must NOT be invoked and normal
// single-destination proxying proceeds (which fails at backend connection).
func TestProxy_HandleStream_AggregateDisabled_SkipsHandler(t *testing.T) {
	t.Parallel()

	h := &fakeGRPCAggregateHandler{}
	p := newAggregateProxy(t, h, aggregateGRPCRoute(false))

	stream := &proxyTestServerStream{ctx: aggregateContext("/agg.Service/Method")}
	_ = p.handleStream(nil, stream)

	assert.Equal(t, int32(0), h.called.Load(), "aggregate handler must not be invoked when disabled")
}

// When no aggregate handler is injected, aggregate-enabled routes fall through to
// normal proxying with no panic (no regression).
func TestProxy_HandleStream_AggregateEnabled_NoHandler_NoPanic(t *testing.T) {
	t.Parallel()

	r := router.New()
	require.NoError(t, r.AddRoute(aggregateGRPCRoute(true)))
	p := New(r, WithProxyLogger(observability.NopLogger()))
	defer p.Close()

	stream := &proxyTestServerStream{ctx: aggregateContext("/agg.Service/Method")}
	assert.NotPanics(t, func() {
		_ = p.handleStream(nil, stream)
	})
}

// The handler's terminal error is propagated to the caller.
func TestProxy_HandleStream_AggregateHandler_ErrorPropagates(t *testing.T) {
	t.Parallel()

	h := &fakeGRPCAggregateHandler{err: context.DeadlineExceeded}
	p := newAggregateProxy(t, h, aggregateGRPCRoute(true))

	stream := &proxyTestServerStream{ctx: aggregateContext("/agg.Service/Method")}
	err := p.handleStream(nil, stream)

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, int32(1), h.called.Load())
}

func TestWithAggregateHandler_SetsField(t *testing.T) {
	t.Parallel()

	h := &fakeGRPCAggregateHandler{}
	p := &Proxy{}
	WithAggregateHandler(h)(p)
	assert.Equal(t, h, p.aggregateHandler)
}
