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
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// fakeAggregator is a test double for discovery.Aggregator.
type fakeAggregator struct {
	result *discovery.DiscoverResult
	err    error
}

func (a *fakeAggregator) Discover(
	_ context.Context, _ []string, _ []string,
) (*discovery.DiscoverResult, error) {
	return a.answer(protocol.MethodServerDiscover)
}

func (a *fakeAggregator) ListTools(
	_ context.Context, _ []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	return a.answer(protocol.MethodToolsList)
}

func (a *fakeAggregator) ListPrompts(
	_ context.Context, _ []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	return a.answer(protocol.MethodPromptsList)
}

func (a *fakeAggregator) ListResources(
	_ context.Context, _ []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	return a.answer(protocol.MethodResourcesList)
}

func (a *fakeAggregator) ListResourceTemplates(
	_ context.Context, _ []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	return a.answer(protocol.MethodResourceTemplatesList)
}

func (a *fakeAggregator) answer(method string) (*discovery.DiscoverResult, error) {
	if a.err != nil {
		return nil, a.err
	}
	res := *a.result
	res.Method = method
	return &res, nil
}

// newAggregatedHandler builds a handler whose aggregator is the given fake.
func newAggregatedHandler(t *testing.T, agg discovery.Aggregator) *MCPHandler {
	t.Helper()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	routes := []config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerAggregator(agg),
	)
	require.NoError(t, err)
	return h
}

func TestMCPHandler_Aggregated_ToolsList(t *testing.T) {
	t.Parallel()

	agg := &fakeAggregator{result: &discovery.DiscoverResult{
		Items:      []json.RawMessage{json.RawMessage(`{"name":"mcp-backend.weather"}`)},
		TTLMs:      1000,
		CacheScope: "public",
	}}
	h := newAggregatedHandler(t, agg)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.Nil(t, resp.Error)
	var result map[string]any
	require.NoError(t, json.Unmarshal(resp.Result, &result))
	tools, ok := result["tools"].([]any)
	require.True(t, ok)
	assert.Len(t, tools, 1)
}

func TestMCPHandler_Aggregated_ServerDiscover(t *testing.T) {
	t.Parallel()

	agg := &fakeAggregator{result: &discovery.DiscoverResult{
		SupportedVersions: []string{protocol.LatestVersion},
		Instructions:      "hello",
		CacheScope:        "public",
	}}
	h := newAggregatedHandler(t, agg)

	body := mcpBody{method: protocol.MethodServerDiscover}.build(t)
	r := newMCPRequest(t, body, protocol.MethodServerDiscover, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.Nil(t, resp.Error)
	var result map[string]any
	require.NoError(t, json.Unmarshal(resp.Result, &result))
	assert.Equal(t, "hello", result["instructions"])
}

func TestMCPHandler_Aggregated_Error(t *testing.T) {
	t.Parallel()

	agg := &fakeAggregator{err: assertErr("aggregate failed")}
	h := newAggregatedHandler(t, agg)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.InternalError, resp.Error.Code)
}

// ============================================================================
// G-1: MCPUpstreamResolver hot reload
// ============================================================================

// nonServiceBackend is a backend.Backend that is NOT a *backend.ServiceBackend,
// used to exercise the Resolve type-assertion failure path.
type nonServiceBackend struct{}

func (nonServiceBackend) Name() string                    { return "non-service" }
func (nonServiceBackend) GetHost() (*backend.Host, error) { return nil, nil }
func (nonServiceBackend) ReleaseHost(_ *backend.Host)     {}
func (nonServiceBackend) Status() backend.Status          { return backend.StatusHealthy }
func (nonServiceBackend) Start(_ context.Context) error   { return nil }
func (nonServiceBackend) Stop(_ context.Context) error    { return nil }

// countingAggregator is a discovery.Aggregator that returns N distinct tool
// items where N is the number of upstreams it is asked to aggregate, and counts
// its invocations. It lets G-2 tests distinguish two routes' aggregates.
type countingAggregator struct {
	calls int
}

func (a *countingAggregator) items(upstreams []string) *discovery.DiscoverResult {
	a.calls++
	items := make([]json.RawMessage, 0, len(upstreams))
	for _, up := range upstreams {
		items = append(items, json.RawMessage(`{"name":"`+up+`.tool"}`))
	}
	return &discovery.DiscoverResult{Items: items, TTLMs: 1000, CacheScope: "public"}
}

func (a *countingAggregator) Discover(
	_ context.Context, upstreams []string, _ []string,
) (*discovery.DiscoverResult, error) {
	res := a.items(upstreams)
	res.Method = protocol.MethodServerDiscover
	return res, nil
}

func (a *countingAggregator) ListTools(
	_ context.Context, upstreams []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	res := a.items(upstreams)
	res.Method = protocol.MethodToolsList
	return res, nil
}

func (a *countingAggregator) ListPrompts(
	_ context.Context, upstreams []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	res := a.items(upstreams)
	res.Method = protocol.MethodPromptsList
	return res, nil
}

func (a *countingAggregator) ListResources(
	_ context.Context, upstreams []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	res := a.items(upstreams)
	res.Method = protocol.MethodResourcesList
	return res, nil
}

func (a *countingAggregator) ListResourceTemplates(
	_ context.Context, upstreams []string, _ string, _ []string,
) (*discovery.DiscoverResult, error) {
	res := a.items(upstreams)
	res.Method = protocol.MethodResourceTemplatesList
	return res, nil
}

// TestMCPUpstreamResolver_UpdateHotReload proves G-1: a newly-added upstream is
// visible to Resolve after Update (was a stale boot snapshot before), and Update
// on a nil receiver is a no-op.
func TestMCPUpstreamResolver_UpdateHotReload(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		"a": newServiceBackend(t, "a"),
		"b": newServiceBackend(t, "b"),
	}}
	resolver := NewMCPUpstreamResolver(reg, map[string]config.MCPBackend{
		"a": {Name: "a"},
	})

	// Before Update: "b" is not in the resolver's map (stale snapshot).
	_, _, ok := resolver.Resolve("b")
	assert.False(t, ok, "b must be invisible before hot reload")

	// Hot reload adds "b".
	resolver.Update(map[string]config.MCPBackend{
		"a": {Name: "a"},
		"b": {Name: "b"},
	})

	sb, cfg, ok := resolver.Resolve("b")
	require.True(t, ok, "b must be visible after hot reload (G-1)")
	assert.NotNil(t, sb)
	assert.Equal(t, "b", cfg.Name)

	// Update on a nil receiver must not panic.
	var nilResolver *MCPUpstreamResolver
	assert.NotPanics(t, func() { nilResolver.Update(map[string]config.MCPBackend{"x": {Name: "x"}}) })
}

// TestMCPUpstreamResolver_Resolve_NotServiceBackend covers the Resolve type
// assertion failure: a non-*ServiceBackend registry entry yields ok=false.
func TestMCPUpstreamResolver_Resolve_NotServiceBackend(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		"a": nonServiceBackend{},
	}}
	resolver := NewMCPUpstreamResolver(reg, map[string]config.MCPBackend{"a": {Name: "a"}})

	_, _, ok := resolver.Resolve("a")
	assert.False(t, ok, "a non-ServiceBackend must not resolve")
}

// TestMCPUpstreamResolver_Resolve_NilRegistry covers the nil-registry guard.
func TestMCPUpstreamResolver_Resolve_NilRegistry(t *testing.T) {
	t.Parallel()

	resolver := NewMCPUpstreamResolver(nil, map[string]config.MCPBackend{"a": {Name: "a"}})
	_, _, ok := resolver.Resolve("a")
	assert.False(t, ok)
}

// TestMCPUpstreamResolver_Resolve_BackendMissing covers the registry.Get miss
// path (upstream in config map but not in the registry).
func TestMCPUpstreamResolver_Resolve_BackendMissing(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{}}
	resolver := NewMCPUpstreamResolver(reg, map[string]config.MCPBackend{"a": {Name: "a"}})
	_, _, ok := resolver.Resolve("a")
	assert.False(t, ok)
}

// TestUpdateConfig_RefreshesResolver proves the G-1 integration: a handler wired
// with WithMCPHandlerUpstreamResolver refreshes the resolver on UpdateConfig so
// a newly-added upstream becomes resolvable.
func TestUpdateConfig_RefreshesResolver(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
		"added":          newServiceBackend(t, "added"),
	}}
	resolver := NewMCPUpstreamResolver(reg, map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName},
	})
	routes := []config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerUpstreamResolver(resolver),
	)
	require.NoError(t, err)

	// "added" is not resolvable yet.
	_, _, ok := resolver.Resolve("added")
	require.False(t, ok)

	// Hot reload adds "added".
	h.UpdateConfig(
		[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName, "added"}}},
		map[string]config.MCPBackend{
			testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
			"added":          {Name: "added", NamespacePrefix: "added"},
		},
		&config.MCPConfig{},
	)

	sb, cfg, ok := resolver.Resolve("added")
	require.True(t, ok, "UpdateConfig must refresh the resolver (G-1)")
	assert.NotNil(t, sb)
	assert.Equal(t, "added", cfg.Name)
}

// ============================================================================
// G-2: upstreamSetDigest / aggregated cache key isolation
// ============================================================================

// TestUpstreamSetDigest covers the digest contract: empty->"", order-independent,
// and set-identifying.
func TestUpstreamSetDigest(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", upstreamSetDigest(nil))
	assert.Equal(t, "", upstreamSetDigest([]string{}))
	assert.Equal(t, "a", upstreamSetDigest([]string{"a"}))

	// Order-independent: same set, different order -> same digest.
	assert.Equal(t, upstreamSetDigest([]string{"a", "b"}), upstreamSetDigest([]string{"b", "a"}))

	// Different sets -> different digests.
	assert.NotEqual(t, upstreamSetDigest([]string{"a", "b", "c"}), upstreamSetDigest([]string{"a"}))
}

// TestServeAggregated_DifferentUpstreamSetsNoCrossServe proves G-2: two routes
// with different upstream sets, same method/cursor/anonymous auth, do NOT share
// the cached aggregate (their KeyParts.Params digests differ), so a route never
// serves primitives outside its configured upstream set.
func TestServeAggregated_DifferentUpstreamSetsNoCrossServe(t *testing.T) {
	t.Parallel()

	cache, err := mcpcache.New(newMemBackend(), mcpcache.Config{})
	require.NoError(t, err)

	// Aggregator returns a distinct item set per call so we can tell the two
	// routes' aggregates apart. It is keyed by the upstream count it receives.
	agg := &countingAggregator{}

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		"a": newServiceBackend(t, "a"),
		"b": newServiceBackend(t, "b"),
		"c": newServiceBackend(t, "c"),
	}}
	routeR1 := config.MCPRoute{Name: "r1", Upstreams: []string{"a", "b", "c"}}
	routeR2 := config.MCPRoute{Name: "r2", Upstreams: []string{"a"}}
	upstreams := map[string]config.MCPBackend{
		"a": {Name: "a", NamespacePrefix: "a"},
		"b": {Name: "b", NamespacePrefix: "b"},
		"c": {Name: "c", NamespacePrefix: "c"},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerConfig([]config.MCPRoute{routeR1, routeR2}, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerAggregator(agg),
		WithMCPHandlerCache(cache),
	)
	require.NoError(t, err)

	serve := func(route *config.MCPRoute) map[string]any {
		mr := newSelectReq(protocol.MethodToolsList, "")
		r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsList}.build(t),
			protocol.MethodToolsList, "")
		rec := httptest.NewRecorder()
		h.serveAggregated(rec, r, mr, route)
		require.Equal(t, http.StatusOK, rec.Code)
		resp := decodeRPCResponse(t, rec.Body.Bytes())
		require.Nil(t, resp.Error)
		var result map[string]any
		require.NoError(t, json.Unmarshal(resp.Result, &result))
		return result
	}

	// Populate R1's 3-upstream aggregate.
	r1res := serve(&routeR1)
	// Serve R2: it must NOT get R1's cached aggregate (different set digest).
	r2res := serve(&routeR2)

	r1tools, _ := r1res["tools"].([]any)
	r2tools, _ := r2res["tools"].([]any)
	assert.Len(t, r1tools, 3, "R1 aggregate fans out over 3 upstreams")
	assert.Len(t, r2tools, 1, "R2 must serve its own 1-upstream aggregate, not R1's cached 3")
	assert.Equal(t, 2, agg.calls, "both routes must hit the aggregator (no cross-serve)")
}

func TestMCPHandler_Aggregated_CursorRestart(t *testing.T) {
	t.Parallel()

	agg := &fakeAggregator{err: discovery.ErrCursorRestart}
	h := newAggregatedHandler(t, agg)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.InvalidParams, resp.Error.Code)
}
