package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// newSelectHandler builds an MCPHandler over the given routes/upstreams with a
// backend registry populated for every named upstream, so pickWeightedUpstream /
// selectUpstream can be driven directly against a realistic map.
func newSelectHandler(
	t *testing.T, routes []config.MCPRoute, upstreams map[string]config.MCPBackend,
) *MCPHandler {
	t.Helper()

	backends := make(map[string]backend.Backend, len(upstreams))
	for name := range upstreams {
		backends[name] = newServiceBackend(t, name)
	}
	reg := &fakeBackendRegistry{backends: backends}

	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
	)
	require.NoError(t, err)
	return h
}

// newSelectReq builds an mcpReq for the given method/primitive name.
func newSelectReq(method, name string) *mcpReq {
	params := map[string]any{}
	if name != "" {
		params["name"] = name
	}
	rawParams, _ := json.Marshal(params)
	return &mcpReq{
		req:    &jsonrpc.Request{ID: json.RawMessage(`1`), Method: method, Params: rawParams},
		params: params,
		start:  time.Now(),
	}
}

// ----------------------------------------------------------------------------
// pickWeightedUpstream
// ----------------------------------------------------------------------------

func TestPickWeightedUpstream_NilRoute(t *testing.T) {
	t.Parallel()

	h := newSelectHandler(t, nil, map[string]config.MCPBackend{
		"a": {Name: "a"},
	})
	_, _, picked := h.pickWeightedUpstream(nil, h.upstreams)
	assert.False(t, picked, "nil route must not pick")
}

// TestPickWeightedUpstream_DanglingFirstNameSkipped covers G-4: a first upstream
// absent from the live map is filtered out so a healthy sibling is still chosen.
func TestPickWeightedUpstream_DanglingFirstNameSkipped(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r", WeightedUpstreams: []config.MCPUpstreamRef{
		{Name: "missing", Weight: 100}, {Name: "live", Weight: 0},
	}}
	upstreams := map[string]config.MCPBackend{"live": {Name: "live"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	id, up, picked := h.pickWeightedUpstream(route, upstreams)
	require.True(t, picked, "a healthy sibling must be selected when the first is dangling")
	assert.Equal(t, "live", id)
	assert.Equal(t, "live", up.Name)
}

// TestPickWeightedUpstream_OnlyDanglingNotPicked covers G-4 fallback: when every
// referenced upstream is absent from the map, nothing is picked.
func TestPickWeightedUpstream_OnlyDanglingNotPicked(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r", Upstreams: []string{"gone-1", "gone-2"}}
	upstreams := map[string]config.MCPBackend{"other": {Name: "other"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	_, _, picked := h.pickWeightedUpstream(route, upstreams)
	assert.False(t, picked, "all-dangling refs must not pick")
}

// TestPickWeightedUpstream_MultiCandidateRecordsMetric asserts the selection
// counter fires (and the Debug path runs) when more than one live candidate
// exists.
func TestPickWeightedUpstream_MultiCandidateRecordsMetric(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "canary-route", WeightedUpstreams: []config.MCPUpstreamRef{
		{Name: "a", Weight: 50}, {Name: "b", Weight: 50},
	}}
	upstreams := map[string]config.MCPBackend{"a": {Name: "a"}, "b": {Name: "b"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	before := testutil.ToFloat64(mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(
		"canary-route", "a")) +
		testutil.ToFloat64(mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(
			"canary-route", "b"))

	id, _, picked := h.pickWeightedUpstream(route, upstreams)
	require.True(t, picked)
	assert.Contains(t, []string{"a", "b"}, id)

	after := testutil.ToFloat64(mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(
		"canary-route", "a")) +
		testutil.ToFloat64(mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(
			"canary-route", "b"))
	assert.Equal(t, before+1, after, "a multi-candidate selection must record the metric once")
}

// TestPickWeightedUpstream_SingleCandidateNoMetric asserts the counter does NOT
// fire for a single live candidate (len==1 fast path).
func TestPickWeightedUpstream_SingleCandidateNoMetric(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "single-route", Upstreams: []string{"a"}}
	upstreams := map[string]config.MCPBackend{"a": {Name: "a"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	before := testutil.ToFloat64(mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(
		"single-route", "a"))
	id, _, picked := h.pickWeightedUpstream(route, upstreams)
	require.True(t, picked)
	assert.Equal(t, "a", id)
	after := testutil.ToFloat64(mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(
		"single-route", "a"))
	assert.Equal(t, before, after, "single-candidate selection must not record the metric")
}

// ----------------------------------------------------------------------------
// selectUpstream
// ----------------------------------------------------------------------------

// TestSelectUpstream_EmptyCandidates404 asserts the not-found tail: a route whose
// refs are all absent from the map yields a MethodNotFound JSON-RPC error.
func TestSelectUpstream_EmptyCandidates404(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r", Upstreams: []string{"absent"}}
	upstreams := map[string]config.MCPBackend{"present": {Name: "present"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	mr := newSelectReq(protocol.MethodToolsCall, "")
	rec := httptest.NewRecorder()
	id, _, ok := h.selectUpstream(rec, mr, route)
	assert.False(t, ok)
	assert.Empty(t, id)

	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.MethodNotFound, resp.Error.Code)
}

// TestSelectUpstream_NamespacedOwnerPinBypassesWeighting proves a namespaced
// primitive resolves to its owning upstream regardless of the route's weights.
func TestSelectUpstream_NamespacedOwnerPinBypassesWeighting(t *testing.T) {
	t.Parallel()

	// Route weights strongly toward "a", but the namespaced primitive is owned
	// by "b" (prefix "b" de-namespaces to upstream "b").
	route := &config.MCPRoute{Name: "r", WeightedUpstreams: []config.MCPUpstreamRef{
		{Name: "a", Weight: 100}, {Name: "b", Weight: 0},
	}}
	upstreams := map[string]config.MCPBackend{
		"a": {Name: "a", NamespacePrefix: "a"},
		"b": {Name: "b", NamespacePrefix: "b"},
	}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	mr := newSelectReq(protocol.MethodToolsCall, "b.weather")
	rec := httptest.NewRecorder()
	id, up, ok := h.selectUpstream(rec, mr, route)
	require.True(t, ok)
	assert.Equal(t, "b", id, "namespaced primitive must pin to owner regardless of weights")
	assert.Equal(t, "b", up.Name)
}

// TestSelectUpstream_NamespacedOwnerMissingFallsThroughToWeighted proves that
// when a de-namespaced owner is not in the live map, selection falls through to
// weighted selection over the route candidates.
func TestSelectUpstream_NamespacedOwnerMissingFallsThroughToWeighted(t *testing.T) {
	t.Parallel()

	// "ghost" de-namespaces (prefix registered) but is not in the live map, so
	// the owner-pin branch's exists==false path is taken and weighting picks the
	// sole live upstream "a".
	route := &config.MCPRoute{Name: "r", Upstreams: []string{"a", "ghost"}}
	upstreams := map[string]config.MCPBackend{
		"a":     {Name: "a", NamespacePrefix: "a"},
		"ghost": {Name: "ghost", NamespacePrefix: "ghost"},
	}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	// Now drop "ghost" from the live map (leave the prefix registered) so
	// Denamespace succeeds but the owner id is absent.
	h.mu.Lock()
	h.upstreams = map[string]config.MCPBackend{"a": {Name: "a", NamespacePrefix: "a"}}
	h.mu.Unlock()

	mr := newSelectReq(protocol.MethodToolsCall, "ghost.tool")
	rec := httptest.NewRecorder()
	id, _, ok := h.selectUpstream(rec, mr, route)
	require.True(t, ok, "must fall through to weighted selection when owner is absent")
	assert.Equal(t, "a", id)
}

// ----------------------------------------------------------------------------
// resolveDryRunUpstream / dryRunCandidates
// ----------------------------------------------------------------------------

// TestResolveDryRunUpstream_Weighted asserts a non-namespaced dry-run resolves
// to one of the live weighted candidates.
func TestResolveDryRunUpstream_Weighted(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r", WeightedUpstreams: []config.MCPUpstreamRef{
		{Name: "a", Weight: 50}, {Name: "b", Weight: 50},
	}}
	upstreams := map[string]config.MCPBackend{"a": {Name: "a"}, "b": {Name: "b"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	got := h.resolveDryRunUpstream("", route)
	assert.Contains(t, []string{"a", "b"}, got)
}

// TestResolveDryRunUpstream_NoCandidates asserts the empty return when no live
// candidate exists.
func TestResolveDryRunUpstream_NoCandidates(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r", Upstreams: []string{"absent"}}
	upstreams := map[string]config.MCPBackend{"present": {Name: "present"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	assert.Empty(t, h.resolveDryRunUpstream("", route))
}

// TestResolveDryRunUpstream_NamespacedName asserts the namespaced primitive
// resolves to its owner id via the mapper.
func TestResolveDryRunUpstream_NamespacedName(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r", Upstreams: []string{"a"}}
	upstreams := map[string]config.MCPBackend{"a": {Name: "a", NamespacePrefix: "a"}}
	h := newSelectHandler(t, []config.MCPRoute{*route}, upstreams)

	assert.Equal(t, "a", h.resolveDryRunUpstream("a.weather", route))
}

func TestDryRunCandidates_NilRoute(t *testing.T) {
	t.Parallel()

	assert.Nil(t, dryRunCandidates(nil))
}

// TestDryRunCandidates_Weighted asserts the full candidate list (name+weight) is
// reported for shadow mode.
func TestDryRunCandidates_Weighted(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{WeightedUpstreams: []config.MCPUpstreamRef{
		{Name: "a", Weight: 70}, {Name: "b", Weight: 30},
	}}
	got := dryRunCandidates(route)
	require.Len(t, got, 2)
	assert.Equal(t, "a", got[0]["name"])
	assert.Equal(t, 70, got[0]["weight"])
	assert.Equal(t, "b", got[1]["name"])
	assert.Equal(t, 30, got[1]["weight"])
}
