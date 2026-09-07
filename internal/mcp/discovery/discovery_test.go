package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/mcp/security"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fakeHub is a scripted hubCaller keyed on (upstreamID inferred from path is
// not available, so key on method + a per-upstream response registry).
type fakeHub struct {
	// responses maps method -> per-call responses, indexed by call order per
	// method. Because the aggregator iterates upstreams in order, we instead
	// key by a counter via the resolver's upstream identity captured through
	// a side channel: we use responder(method) returning the next response.
	responder func(method string) (*jsonrpc.Response, error)
}

func (f *fakeHub) Call(
	_ context.Context, _ *backend.ServiceBackend, _ string, req *jsonrpc.Request, _ http.Header,
) (*jsonrpc.Response, error) {
	return f.responder(req.Method)
}

// fakeResolver returns config for known upstreams. It records which upstream
// the aggregator is currently resolving so the fakeHub can answer per-upstream.
type fakeResolver struct {
	known   map[string]config.MCPBackend
	current *string
}

func (r *fakeResolver) Resolve(id string) (*backend.ServiceBackend, config.MCPBackend, bool) {
	cfg, ok := r.known[id]
	if !ok {
		return nil, config.MCPBackend{}, false
	}
	if r.current != nil {
		*r.current = id
	}
	return nil, cfg, true
}

func newMapper(t *testing.T, upstreams ...string) namespace.Mapper {
	t.Helper()
	m, err := namespace.NewDefaultMapper("_")
	require.NoError(t, err)
	for _, u := range upstreams {
		require.NoError(t, m.Register(u, u))
	}
	return m
}

func toolResp(names ...string) *jsonrpc.Response {
	items := make([]string, 0, len(names))
	for _, n := range names {
		items = append(items, `{"name":"`+n+`","inputSchema":{"type":"object"}}`)
	}
	result := `{"tools":[` + join(items) + `]}`
	return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(result)}
}

func join(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// buildAgg wires a DefaultAggregator with per-upstream scripted responses.
func buildAgg(
	t *testing.T,
	upstreamCfgs map[string]config.MCPBackend,
	responses map[string]*jsonrpc.Response,
	errs map[string]error,
	opts ...AggregatorOption,
) *DefaultAggregator {
	t.Helper()
	var current string
	res := &fakeResolver{known: upstreamCfgs, current: &current}
	hub := &fakeHub{responder: func(method string) (*jsonrpc.Response, error) {
		if err, ok := errs[current]; ok {
			return nil, err
		}
		return responses[current], nil
	}}
	names := make([]string, 0, len(upstreamCfgs))
	for id := range upstreamCfgs {
		names = append(names, id)
	}
	mapper := newMapper(t, names...)
	codec, err := NewCursorCodec(newSealer(t))
	require.NoError(t, err)
	agg, err := NewDefaultAggregator(hub, res, mapper, codec, opts...)
	require.NoError(t, err)
	return agg
}

func TestNewDefaultAggregatorNilHub(t *testing.T) {
	t.Parallel()
	_, err := NewDefaultAggregator(nil, nil, nil, nil)
	assert.ErrorIs(t, err, ErrNilHub)
}

func TestListToolsDeterministicOrdering(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{
		"up1": {Name: "up1"},
		"up2": {Name: "up2"},
	}
	responses := map[string]*jsonrpc.Response{
		"up1": toolResp("zeta", "alpha"),
		"up2": toolResp("beta"),
	}
	agg := buildAgg(t, cfgs, responses, nil)

	r1, err := agg.ListTools(context.Background(), []string{"up1", "up2"}, "", nil)
	require.NoError(t, err)
	// Different upstream order must produce identical ordering.
	r2, err := agg.ListTools(context.Background(), []string{"up2", "up1"}, "", nil)
	require.NoError(t, err)

	names1 := itemNames(t, r1.Items)
	names2 := itemNames(t, r2.Items)
	assert.Equal(t, names1, names2, "ordering must be replica/order-stable")
	// Sorted by namespaced name.
	assert.Equal(t, []string{"up1_alpha", "up1_zeta", "up2_beta"}, names1)
	assert.False(t, r1.Degraded)
}

func TestListToolsDegraded(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}, "up2": {Name: "up2"}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("alpha")}
	errs := map[string]error{"up2": errors.New("upstream down")}
	agg := buildAgg(t, cfgs, responses, errs)

	r, err := agg.ListTools(context.Background(), []string{"up1", "up2"}, "", nil)
	require.NoError(t, err)
	assert.True(t, r.Degraded, "one failed upstream marks the result degraded")
	assert.Equal(t, degradedTTLMs, r.TTLMs, "degraded shortens the TTL")
	assert.Equal(t, []string{"up1_alpha"}, itemNames(t, r.Items))
}

func TestListToolsUnknownUpstreamDegraded(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("alpha")}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1", "ghost"}, "", nil)
	require.NoError(t, err)
	assert.True(t, r.Degraded)
}

func TestListToolsScopesMarkPrivate(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("alpha")}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", []string{"mcp:tools:read"})
	require.NoError(t, err)
	assert.Equal(t, cacheScopePrivate, r.CacheScope)
}

func TestListToolsRejectsBadXMcpHeaderKeepsOthers(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	// good tool + tool with an invalid x-mcp-header (number type).
	result := `{"tools":[` +
		`{"name":"good","inputSchema":{"type":"object","properties":{"r":{"type":"string","x-mcp-header":"X-R"}}}},` +
		`{"name":"bad","inputSchema":{"type":"object","properties":{"n":{"type":"number","x-mcp-header":"X-N"}}}}` +
		`]}`
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(result)},
	}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"up1_good"}, itemNames(t, r.Items), "bad tool dropped, good kept")
}

func TestListToolsPolicyDeny(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1", Deny: []string{"secret"}}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("secret", "public")}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"up1_public"}, itemNames(t, r.Items))
}

func TestListToolsAllowList(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1", Allow: []string{"keep"}}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("keep", "drop")}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"up1_keep"}, itemNames(t, r.Items))
}

func TestListToolsUpstreamRPCError(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Error: &jsonrpc.Error{Code: -32000, Message: "boom"}},
	}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.True(t, r.Degraded, "an upstream JSON-RPC error degrades the result")
}

func TestPaginationCursorRoundTrip(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[{"name":"a","inputSchema":{}}],"nextCursor":"c2"}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	require.NotEmpty(t, r.NextCursor, "nextCursor sealed when upstream has more pages")

	// Decoding the issued cursor for a different method must restart.
	r2, err := agg.ListPrompts(context.Background(), []string{"up1"}, r.NextCursor, nil)
	assert.Nil(t, r2)
	assert.ErrorIs(t, err, ErrCursorRestart)
}

func TestListWithBadCursor(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("a")}
	agg := buildAgg(t, cfgs, responses, nil)

	_, err := agg.ListTools(context.Background(), []string{"up1"}, "garbage-token", nil)
	assert.ErrorIs(t, err, ErrCursorRestart)
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	result := `{"capabilities":{"tools":{}},"instructions":"hello","tools":[{"name":"a","inputSchema":{"type":"object"}}]}`
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(result)},
	}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.Discover(context.Background(), []string{"up1"}, nil)
	require.NoError(t, err)
	assert.Equal(t, protocol.HubSupportedVersions, r.SupportedVersions)
	assert.Equal(t, "hello", r.Instructions)
	assert.Contains(t, r.Capabilities, "tools")
	assert.Equal(t, []string{"up1_a"}, itemNames(t, r.Items))
}

func TestDiscoverPrincipalScopesPrivate(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.Discover(context.Background(), []string{"up1"}, []string{"mcp:tools"})
	require.NoError(t, err)
	assert.Equal(t, cacheScopePrivate, r.CacheScope)
}

func TestDiscoverDegradedUnknown(t *testing.T) {
	t.Parallel()
	agg := buildAgg(t, map[string]config.MCPBackend{}, nil, nil)
	r, err := agg.Discover(context.Background(), []string{"ghost"}, nil)
	require.NoError(t, err)
	assert.True(t, r.Degraded)
}

func TestCacheHintsMinTTLAndPrivate(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}, "up2": {Name: "up2"}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[{"name":"a","inputSchema":{}}],"ttlMs":30000,"cacheScope":"private"}`)},
		"up2": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[{"name":"b","inputSchema":{}}],"ttlMs":10000}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)

	r, err := agg.ListTools(context.Background(), []string{"up1", "up2"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(10000), r.TTLMs, "TTL is the minimum across contributors")
	assert.Equal(t, cacheScopePrivate, r.CacheScope, "private if any contributor is private")
}

func TestListResourcesNamespacesURIs(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"resources":[{"uri":"file:///a","name":"A"}]}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.ListResources(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	require.Len(t, r.Items, 1)
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(r.Items[0], &obj))
	// The uri field is re-namespaced.
	var uri string
	require.NoError(t, json.Unmarshal(obj["uri"], &uri))
	assert.Equal(t, "up1_file:///a", uri)
}

func TestListResourceTemplates(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"resourceTemplates":[{"uriTemplate":"file:///{x}","name":"T"}]}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.ListResourceTemplates(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Len(t, r.Items, 1)
}

func TestAggregatorOptions(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("a")}
	agg := buildAgg(t, cfgs, responses, nil,
		WithAggregatorLogger(observability.NopLogger()),
		WithAggregatorLogger(nil),  // ignored
		WithAggregatorMetrics(nil), // ignored
		WithAggregatorPageLimit(50),
		WithAggregatorPageLimit(0), // ignored
		WithAggregatorTrustPolicy("flag"),
	)
	assert.Equal(t, 50, agg.pageLimit)
	assert.Equal(t, "flag", agg.effectiveTrustPolicy())

	// buildRequest includes cursor + limit when set.
	req, err := agg.buildRequest(protocol.MethodToolsList, "cursor-x", protocol.LatestVersion)
	require.NoError(t, err)
	var params map[string]any
	require.NoError(t, json.Unmarshal(req.Params, &params))
	assert.Equal(t, "cursor-x", params["cursor"])
	assert.EqualValues(t, 50, params["limit"])
}

// TestBuildRequestInjectsUpstreamMeta asserts the forwarded discovery/list
// request carries the fresh per-request _meta mandated by HUB-124: the
// negotiated protocol version, the hub's brokerable clientCapabilities and the
// hub's own clientInfo.
func TestBuildRequestInjectsUpstreamMeta(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("a")}
	agg := buildAgg(t, cfgs, responses, nil,
		WithAggregatorClientInfo(meta.Info{Name: "avapigw-mcp-hub", Version: "9.9.9"}),
		WithAggregatorBrokerableCapabilities(map[string]bool{"tools": true, "resources": true}),
	)

	req, err := agg.buildRequest(protocol.MethodToolsList, "", protocol.LatestVersion)
	require.NoError(t, err)

	var params map[string]any
	require.NoError(t, json.Unmarshal(req.Params, &params))
	metaObj, ok := params["_meta"].(map[string]any)
	require.True(t, ok, "params._meta must be present and be an object")

	assert.Equal(t, protocol.LatestVersion, metaObj[protocol.MetaProtocolVersion],
		"protocolVersion must equal the negotiated upstream version")

	caps, ok := metaObj[protocol.MetaClientCapabilities].(map[string]any)
	require.True(t, ok, "clientCapabilities must be present and be an object")
	assert.Contains(t, caps, "tools")
	assert.Contains(t, caps, "resources")

	info, ok := metaObj[protocol.MetaClientInfo].(map[string]any)
	require.True(t, ok, "clientInfo must be present and be an object")
	assert.Equal(t, "avapigw-mcp-hub", info["name"])
	assert.Equal(t, "9.9.9", info["version"])
}

// TestNegotiatedVersionPinned asserts the pinned upstream version wins over the
// hub's latest version, and that both the _meta protocolVersion and the
// MCP-Protocol-Version header carry it (HUB-122/124).
func TestNegotiatedVersionPinned(t *testing.T) {
	t.Parallel()
	const pinned = "2025-06-18"
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1", PinnedVersion: pinned}}
	responses := map[string]*jsonrpc.Response{"up1": toolResp("a")}

	var gotHeader, gotBodyVersion string
	res := &fakeResolver{known: cfgs}
	hub := &fakeHub{responder: func(string) (*jsonrpc.Response, error) { return responses["up1"], nil }}
	// Wrap the hub to capture the header and body it is called with.
	capturing := &capturingHub{inner: hub, header: &gotHeader, bodyVersion: &gotBodyVersion}
	mapper := newMapper(t, "up1")
	codec, err := NewCursorCodec(newSealer(t))
	require.NoError(t, err)
	agg, err := NewDefaultAggregator(capturing, res, mapper, codec,
		WithAggregatorClientInfo(meta.Info{Name: "hub"}),
		WithAggregatorBrokerableCapabilities(map[string]bool{"tools": true}),
	)
	require.NoError(t, err)

	_, err = agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, pinned, gotHeader, "MCP-Protocol-Version header carries the pinned version")
	assert.Equal(t, pinned, gotBodyVersion, "body _meta protocolVersion carries the pinned version")
}

// capturingHub records the MCP-Protocol-Version header and the body _meta
// protocolVersion of the forwarded request, then delegates to inner.
type capturingHub struct {
	inner       hubCaller
	header      *string
	bodyVersion *string
}

func (c *capturingHub) Call(
	ctx context.Context, sb *backend.ServiceBackend, path string, req *jsonrpc.Request, hdrs http.Header,
) (*jsonrpc.Response, error) {
	*c.header = hdrs.Get(headers.HeaderMcpProtocolVersion)
	var params map[string]any
	if err := json.Unmarshal(req.Params, &params); err == nil {
		if m, ok := params["_meta"].(map[string]any); ok {
			if v, ok := m[protocol.MetaProtocolVersion].(string); ok {
				*c.bodyVersion = v
			}
		}
	}
	return c.inner.Call(ctx, sb, path, req, hdrs)
}

func TestEffectiveTrustPolicyDefault(t *testing.T) {
	t.Parallel()
	agg := buildAgg(t, map[string]config.MCPBackend{"up1": {Name: "up1"}},
		map[string]*jsonrpc.Response{"up1": toolResp("a")}, nil)
	assert.Equal(t, config.MCPTrustPolicyStrip, agg.effectiveTrustPolicy())
}

func TestDriftExcludes(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	// Same tool name, definition changes across two calls.
	drift := security.NewDriftStore(true) // reapproval mode -> exclude on change
	agg := buildAgg(t, cfgs, map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[{"name":"a","inputSchema":{"v":1}}]}`)},
	}, nil, WithAggregatorDriftStore(drift))

	// First observation: not a change, tool included.
	r1, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Len(t, r1.Items, 1)

	// Second observation with a different definition -> drift -> excluded.
	agg2 := agg
	agg2.hub = &fakeHub{responder: func(string) (*jsonrpc.Response, error) {
		return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[{"name":"a","inputSchema":{"v":2}}]}`)}, nil
	}}
	r2, err := agg2.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Empty(t, r2.Items, "changed tool excluded pending re-approval")
}

func TestSchemaLimitsRejectNetworkRef(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	// inputSchema with a network $ref should be rejected.
	result := `{"tools":[{"name":"bad","inputSchema":{"$ref":"https://evil/x"}},{"name":"ok","inputSchema":{"type":"object"}}]}`
	agg := buildAgg(t, cfgs, map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(result)},
	}, nil, WithAggregatorSchemaLimits(security.SchemaLimits{MaxDepth: 10, MaxNodes: 100}))

	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"up1_ok"}, itemNames(t, r.Items), "unsafe-schema tool dropped")
}

func TestTrustPolicyFlagAppliedToUntrusted(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1", TrustLevel: config.MCPTrustUntrusted}}
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[{"name":"a","description":"do X","inputSchema":{"type":"object"}}]}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil, WithAggregatorTrustPolicy(config.MCPTrustPolicyFlag))
	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	require.Len(t, r.Items, 1)
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(r.Items[0], &obj))
	assert.Contains(t, obj, "description")
}

func TestMergeItemsMalformedIgnored(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	// tools is not an array -> mergeItems returns without panicking.
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":"not-an-array"}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Empty(t, r.Items)
}

func TestMergeItemNonObjectSkipped(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	// A non-object item within the array is skipped.
	responses := map[string]*jsonrpc.Response{
		"up1": {JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"tools":[42,{"name":"ok","inputSchema":{}}]}`)},
	}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"up1_ok"}, itemNames(t, r.Items))
}

func TestNilResultIgnored(t *testing.T) {
	t.Parallel()
	cfgs := map[string]config.MCPBackend{"up1": {Name: "up1"}}
	responses := map[string]*jsonrpc.Response{"up1": {JSONRPC: jsonrpc.Version}}
	agg := buildAgg(t, cfgs, responses, nil)
	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.Empty(t, r.Items)
}

func TestDecodeResultObjectAndHelpers(t *testing.T) {
	t.Parallel()
	assert.Nil(t, decodeResultObject(nil))
	assert.Nil(t, decodeResultObject(json.RawMessage(`[1,2]`)))
	assert.NotNil(t, decodeResultObject(json.RawMessage(`{"a":1}`)))

	obj := map[string]json.RawMessage{"a": json.RawMessage(`"str"`), "b": json.RawMessage(`123`)}
	assert.Equal(t, "str", decodeStringField(obj, "a"))
	assert.Equal(t, "", decodeStringField(obj, "b"))    // not a string
	assert.Equal(t, "", decodeStringField(obj, "miss")) // absent

	assert.Equal(t, "", firstNameField(map[string]json.RawMessage{}))
	assert.Equal(t, "n", firstNameField(map[string]json.RawMessage{"name": json.RawMessage(`"n"`)}))
}

func TestResolveNilResolver(t *testing.T) {
	t.Parallel()
	codec, err := NewCursorCodec(newSealer(t))
	require.NoError(t, err)
	mapper := newMapper(t, "up1")
	hub := &fakeHub{responder: func(string) (*jsonrpc.Response, error) { return toolResp("a"), nil }}
	agg, err := NewDefaultAggregator(hub, nil, mapper, codec)
	require.NoError(t, err)
	// Nil resolver -> every upstream is unavailable -> degraded.
	r, err := agg.ListTools(context.Background(), []string{"up1"}, "", nil)
	require.NoError(t, err)
	assert.True(t, r.Degraded)
}

func TestPolicyAllows(t *testing.T) {
	t.Parallel()
	assert.True(t, policyAllows(config.MCPBackend{}, "x"))
	assert.False(t, policyAllows(config.MCPBackend{Deny: []string{"x"}}, "x"))
	assert.True(t, policyAllows(config.MCPBackend{Allow: []string{"x"}}, "x"))
	assert.False(t, policyAllows(config.MCPBackend{Allow: []string{"y"}}, "x"))
}

// ── helpers ─────────────────────────────────────────────────────────────

func itemNames(t *testing.T, items []json.RawMessage) []string {
	t.Helper()
	var out []string
	for _, it := range items {
		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(it, &obj))
		out = append(out, firstNameField(obj))
	}
	return out
}
