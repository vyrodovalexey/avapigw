package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpcache "github.com/vyrodovalexey/avapigw/internal/mcp/cache"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// ============================================================================
// resolveBackend error paths
// ============================================================================

func TestMCPHandler_ResolveBackend_NilRegistry(t *testing.T) {
	t.Parallel()

	h, err := NewMCPHandler(
		WithMCPHandlerHub(&fakeHub{resp: okListResponse(t)}),
		WithMCPHandlerConfig(
			[]config.MCPRoute{{Name: "r", Upstreams: []string{testUpstreamName}}},
			map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
			&config.MCPConfig{},
		),
		WithMCPHandlerServerInfo(mustServerInfo()),
	)
	require.NoError(t, err)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestMCPHandler_ResolveBackend_Missing(t *testing.T) {
	t.Parallel()

	// registry has no backend for the configured upstream name.
	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{}}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{resp: okListResponse(t)}),
		WithMCPHandlerConfig(
			[]config.MCPRoute{{Name: "r", Upstreams: []string{testUpstreamName}}},
			map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
			&config.MCPConfig{},
		),
		WithMCPHandlerServerInfo(mustServerInfo()),
	)
	require.NoError(t, err)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// ============================================================================
// route middleware application
// ============================================================================

// passthroughMiddleware records that it was applied and wraps the handler
// verbatim.
type passthroughMiddleware struct {
	applied bool
	name    string
}

func (m *passthroughMiddleware) ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler {
	m.applied = true
	if route != nil {
		m.name = route.Name
	}
	return handler
}

func TestMCPHandler_RouteMiddlewareApplied(t *testing.T) {
	t.Parallel()

	mw := &passthroughMiddleware{}
	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{resp: okListResponse(t)}),
		WithMCPHandlerConfig(
			[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}},
			map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
			&config.MCPConfig{},
		),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerRouteMiddleware(mw),
	)
	require.NoError(t, err)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, mw.applied, "route middleware must be applied")
	assert.Equal(t, mcpChainScope+"catch-all", mw.name)
}

// ============================================================================
// Real HTTP hub round-trip through an httptest upstream
// ============================================================================

func TestMCPHandler_RealHubRoundTrip(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackendFor(t, testUpstreamName, upstream.URL),
	}}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(mcpproxy.NewHTTPHubClient()),
		WithMCPHandlerConfig(
			[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}},
			map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
			&config.MCPConfig{},
		),
		WithMCPHandlerServerInfo(mustServerInfo()),
	)
	require.NoError(t, err)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	assert.Nil(t, resp.Error)
}

// ============================================================================
// aggregated cache hit path
// ============================================================================

func TestMCPHandler_Aggregated_CacheHit(t *testing.T) {
	t.Parallel()

	agg := &fakeAggregator{result: &discovery.DiscoverResult{
		Items:      []json.RawMessage{json.RawMessage(`{"name":"mcp-backend.weather"}`)},
		TTLMs:      60000,
		CacheScope: "public",
	}}
	cache, err := mcpcache.New(newMemBackend(), mcpcache.Config{})
	require.NoError(t, err)

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerConfig(
			[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}},
			map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
			&config.MCPConfig{},
		),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerAggregator(agg),
		WithMCPHandlerCache(cache),
	)
	require.NoError(t, err)

	do := func() *httptest.ResponseRecorder {
		body := mcpBody{method: protocol.MethodToolsList}.build(t)
		r := newMCPRequest(t, body, protocol.MethodToolsList, "")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	rec1 := do()
	require.Equal(t, http.StatusOK, rec1.Code)
	// second call is served from the aggregated cache (writeAggregatedEntry).
	rec2 := do()
	require.Equal(t, http.StatusOK, rec2.Code)
	assert.JSONEq(t, rec1.Body.String(), rec2.Body.String())
}

// ============================================================================
// StreamUpstream (subscription streamer adapter)
// ============================================================================

func TestMCPUpstreamStreamer_StreamUpstream(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{}
	h := newTestHandler(t, hub).handler
	streamer := h.NewUpstreamStreamer()

	req := &jsonrpc.Request{JSONRPC: jsonrpc.Version, Method: protocol.MethodSubscriptionsListen}
	err := streamer.StreamUpstream(context.Background(), testUpstreamName, req,
		func(_ mcpproxy.SSEEvent) error { return nil })
	assert.NoError(t, err)
}

func TestMCPUpstreamStreamer_UnknownUpstream(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	streamer := h.NewUpstreamStreamer()

	req := &jsonrpc.Request{JSONRPC: jsonrpc.Version, Method: protocol.MethodSubscriptionsListen}
	err := streamer.StreamUpstream(context.Background(), "missing", req,
		func(_ mcpproxy.SSEEvent) error { return nil })
	assert.ErrorIs(t, err, errUnknownUpstream)
}

// compile-time: fakeHub satisfies the proxy HubClient interface.
var _ mcpproxy.HubClient = (*fakeHub)(nil)
