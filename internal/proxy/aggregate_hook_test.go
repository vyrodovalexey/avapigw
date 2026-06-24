package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// fakeAggregateHandler records invocations and returns a configurable error.
type fakeAggregateHandler struct {
	called bool
	cfg    *config.AggregateConfig
	err    error
}

func (f *fakeAggregateHandler) ServeAggregate(w http.ResponseWriter, _ *http.Request, cfg *config.AggregateConfig) error {
	f.called = true
	f.cfg = cfg
	if f.err != nil {
		return f.err
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"aggregated":true}`))
	return nil
}

func newAggProxy(t *testing.T, h AggregateHandler) *ReverseProxy {
	t.Helper()
	r := router.New()
	registry := backend.NewRegistry(observability.NopLogger())
	opts := []ProxyOption{WithProxyLogger(observability.NopLogger())}
	if h != nil {
		opts = append(opts, WithAggregateHandler(h))
	}
	return NewReverseProxy(r, registry, opts...)
}

func aggRoute(enabled bool) *router.CompiledRoute {
	cfg := config.Route{Name: "agg-route"}
	if enabled {
		cfg.Aggregate = &config.AggregateConfig{
			Enabled: true,
			Targets: []config.AggregateTarget{
				{Name: "a", Destination: config.Destination{Host: "h", Port: 80}},
			},
		}
	}
	return &router.CompiledRoute{Name: "agg-route", Config: cfg}
}

func TestWithAggregateHandler(t *testing.T) {
	h := &fakeAggregateHandler{}
	p := newAggProxy(t, h)
	assert.Equal(t, h, p.aggregateHandler)
}

func TestHandleAggregate_NoHandler(t *testing.T) {
	p := newAggProxy(t, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handled := p.handleAggregate(rr, req, aggRoute(true))
	assert.False(t, handled, "no handler injected -> not handled")
}

func TestHandleAggregate_Disabled(t *testing.T) {
	h := &fakeAggregateHandler{}
	p := newAggProxy(t, h)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handled := p.handleAggregate(rr, req, aggRoute(false))
	assert.False(t, handled)
	assert.False(t, h.called)
}

func TestHandleAggregate_Success(t *testing.T) {
	h := &fakeAggregateHandler{}
	p := newAggProxy(t, h)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handled := p.handleAggregate(rr, req, aggRoute(true))
	require.True(t, handled)
	assert.True(t, h.called)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"aggregated":true}`, rr.Body.String())
}

func TestHandleAggregate_ErrorInvokesErrorHandler(t *testing.T) {
	h := &fakeAggregateHandler{err: errors.New("fanout failed")}
	p := newAggProxy(t, h)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handled := p.handleAggregate(rr, req, aggRoute(true))
	require.True(t, handled, "error still counts as handled")
	assert.True(t, h.called)
	// Default error handler writes a non-200 status.
	assert.NotEqual(t, http.StatusOK, rr.Code)
}
