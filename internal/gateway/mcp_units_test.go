package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// mcpLimiter
// ============================================================================

func TestMCPLimiter_Streams(t *testing.T) {
	t.Parallel()

	l := newMCPLimiter(2, 0)
	assert.True(t, l.acquireStream("alice"))
	assert.True(t, l.acquireStream("alice"))
	assert.False(t, l.acquireStream("alice"), "third stream exceeds limit")

	l.releaseStream("alice")
	assert.True(t, l.acquireStream("alice"))
}

func TestMCPLimiter_StreamsDisabled(t *testing.T) {
	t.Parallel()

	l := newMCPLimiter(0, 0)
	for i := 0; i < 100; i++ {
		assert.True(t, l.acquireStream("p"))
	}
	l.releaseStream("p") // no-op path
}

func TestMCPLimiter_NilReceiver(t *testing.T) {
	t.Parallel()

	var l *mcpLimiter
	assert.True(t, l.acquireStream("p"))
	assert.True(t, l.tryAcquireUpstream())
	l.releaseStream("p")
	l.releaseUpstream()
}

func TestMCPLimiter_Upstream(t *testing.T) {
	t.Parallel()

	l := newMCPLimiter(0, 1)
	assert.True(t, l.tryAcquireUpstream())
	assert.False(t, l.tryAcquireUpstream(), "pool of 1 exhausted")
	l.releaseUpstream()
	assert.True(t, l.tryAcquireUpstream())
}

func TestEnforceResultLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		result    json.RawMessage
		maxBlocks int
		maxSize   int64
		wantErr   error
	}{
		{name: "within limits", result: json.RawMessage(`{"content":[1,2]}`), maxBlocks: 5, maxSize: 100, wantErr: nil},
		{name: "too large", result: json.RawMessage(`{"content":[1]}`), maxBlocks: 5, maxSize: 2, wantErr: errResponseTooLarge},
		{
			name:      "too many blocks",
			result:    json.RawMessage(`{"content":[1,2,3]}`),
			maxBlocks: 2,
			maxSize:   0,
			wantErr:   errTooManyContentBlocks,
		},
		{name: "zero bounds disable", result: json.RawMessage(`{"content":[1,2,3]}`), maxBlocks: 0, maxSize: 0, wantErr: nil},
		{name: "non-content object", result: json.RawMessage(`{"x":1}`), maxBlocks: 1, maxSize: 0, wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := enforceResultLimits(tt.result, tt.maxBlocks, tt.maxSize)
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestResultLimitError_Error(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "mcp: response exceeds max size", errResponseTooLarge.Error())
}

// ============================================================================
// audit classifiers / helpers
// ============================================================================

func TestAuditActionForDecision(t *testing.T) {
	t.Parallel()

	assert.Equal(t, audit.ActionDeny, auditActionForDecision("deny"))
	assert.Equal(t, audit.ActionAccess, auditActionForDecision("allow"))
}

func TestAuditOutcomeForDecision(t *testing.T) {
	t.Parallel()

	assert.Equal(t, audit.OutcomeDenied, auditOutcomeForDecision("deny"))
	assert.Equal(t, audit.OutcomeError, auditOutcomeForDecision("error"))
	assert.Equal(t, audit.OutcomeSuccess, auditOutcomeForDecision("allow"))
}

func TestRouteName(t *testing.T) {
	t.Parallel()

	assert.Empty(t, routeName(nil))
	assert.Equal(t, "r", routeName(&config.MCPRoute{Name: "r"}))
}

func TestAuditDecisionFor(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "allow", auditDecisionFor(nil))
	assert.Equal(t, "allow", auditDecisionFor(&jsonrpc.Response{}))
	assert.Equal(t, "error", auditDecisionFor(&jsonrpc.Response{Error: &jsonrpc.Error{Code: -1}}))
}

func TestBrokeredSpanOutcome(t *testing.T) {
	t.Parallel()

	rt, oc := brokeredSpanOutcome(&jsonrpc.Response{})
	assert.Equal(t, protocol.ResultComplete, rt)
	assert.NotEmpty(t, oc)

	rt2, _ := brokeredSpanOutcome(&jsonrpc.Response{Error: &jsonrpc.Error{Code: -1}})
	assert.Equal(t, resultTypeUnknown, rt2)
}

// ============================================================================
// authz helpers
// ============================================================================

func TestRouteRequiresAuthz(t *testing.T) {
	t.Parallel()

	assert.False(t, routeRequiresAuthz(nil))
	assert.False(t, routeRequiresAuthz(&config.MCPRoute{Name: "r"}))
	assert.True(t, routeRequiresAuthz(&config.MCPRoute{Authentication: &config.AuthenticationConfig{}}))
	assert.True(t, routeRequiresAuthz(&config.MCPRoute{Authorization: &config.AuthorizationConfig{}}))
	assert.True(t, routeRequiresAuthz(&config.MCPRoute{ScopeMap: map[string][]string{"a": {"b"}}}))
}

func TestPrincipalScopes(t *testing.T) {
	t.Parallel()

	assert.Nil(t, principalScopes(nil))
	assert.Equal(t, []string{"a"}, principalScopes(&mcpauthz.Principal{Scopes: []string{"a"}}))
}

func TestAuthContextKey(t *testing.T) {
	t.Parallel()

	assert.Empty(t, authContextKey(nil))
	assert.NotEmpty(t, authContextKey(&mcpauthz.Principal{Subject: "s", Scopes: []string{"a"}}))
}

func TestAuthDescriptionAndClass(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "a bearer token is required", authDescription(mcpauthz.ErrNoToken))
	assert.Equal(t, "token audience is not this resource", authDescription(mcpauthz.ErrAudienceMismatch))
	assert.Equal(t, "the access token is invalid", authDescription(assertErr("x")))

	// Distinct classes for the sentinel errors vs. a generic error.
	noToken := authFailureClass(mcpauthz.ErrNoToken)
	audience := authFailureClass(mcpauthz.ErrAudienceMismatch)
	generic := authFailureClass(assertErr("x"))
	assert.NotEmpty(t, noToken)
	assert.NotEqual(t, noToken, generic)
	assert.NotEqual(t, audience, generic)
}

func TestRouteScopeResolver(t *testing.T) {
	t.Parallel()

	// nil route yields a resolver with no requirements.
	r := routeScopeResolver(nil)
	assert.Empty(t, r.Required("tools/call", "x"))

	r2 := routeScopeResolver(&config.MCPRoute{ScopeMap: map[string][]string{"tools/call": {"read"}}})
	assert.Equal(t, []string{"read"}, r2.Required("tools/call", ""))
}

// ============================================================================
// context helpers
// ============================================================================

func TestMCPRouteContext(t *testing.T) {
	t.Parallel()

	route := &config.MCPRoute{Name: "r"}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	r = withMCPRouteContext(r, route)
	assert.Equal(t, route, mcpRouteFromContext(r))

	// absent
	r2 := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	assert.Nil(t, mcpRouteFromContext(r2))
}

func TestMCPPrincipalContext(t *testing.T) {
	t.Parallel()

	// nil principal leaves the request unchanged.
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	assert.Same(t, r, withMCPPrincipal(r, nil))
	assert.Nil(t, mcpPrincipalFromContext(r))

	p := &mcpauthz.Principal{Subject: "alice"}
	r2 := withMCPPrincipal(r, p)
	assert.Equal(t, p, mcpPrincipalFromContext(r2))
}

// ============================================================================
// discovery pure helpers
// ============================================================================

func TestItemKeyForMethod(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "tools", itemKeyForMethod(protocol.MethodToolsList))
	assert.Equal(t, "prompts", itemKeyForMethod(protocol.MethodPromptsList))
	assert.Equal(t, "resources", itemKeyForMethod(protocol.MethodResourcesList))
	assert.Equal(t, "resourceTemplates", itemKeyForMethod(protocol.MethodResourceTemplatesList))
	assert.Equal(t, "items", itemKeyForMethod("unknown"))
}

func TestRouteUpstreams(t *testing.T) {
	t.Parallel()

	assert.Nil(t, routeUpstreams(nil))
	assert.Equal(t, []string{"a", "b"}, routeUpstreams(&config.MCPRoute{Upstreams: []string{"a", "b"}}))
}

func TestStringParam(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "v", stringParam(map[string]any{"k": "v"}, "k"))
	assert.Empty(t, stringParam(map[string]any{"k": 1}, "k"))
	assert.Empty(t, stringParam(map[string]any{}, "k"))
}

func TestItemName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "n", itemName(json.RawMessage(`{"name":"n"}`)))
	assert.Equal(t, "u", itemName(json.RawMessage(`{"uri":"u"}`)))
	assert.Equal(t, "t", itemName(json.RawMessage(`{"uriTemplate":"t"}`)))
	assert.Empty(t, itemName(json.RawMessage(`{"other":1}`)))
	assert.Empty(t, itemName(json.RawMessage(`not json`)))
}

func TestIsAggregatedMethod(t *testing.T) {
	t.Parallel()

	assert.True(t, isAggregatedMethod(protocol.MethodToolsList))
	assert.True(t, isAggregatedMethod(protocol.MethodServerDiscover))
	assert.False(t, isAggregatedMethod(protocol.MethodToolsCall))
}

func TestIsCursorRestart(t *testing.T) {
	t.Parallel()

	assert.True(t, isCursorRestart(discovery.ErrCursorRestart))
	assert.False(t, isCursorRestart(assertErr("x")))
}

// ============================================================================
// cache pure helpers
// ============================================================================

func TestReadTTLMs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, int64(0), readTTLMs(json.RawMessage(`not json`)))
	assert.Equal(t, int64(0), readTTLMs(json.RawMessage(`{}`)))
	assert.Equal(t, int64(1000), readTTLMs(json.RawMessage(`{"ttlMs":1000}`)))
	assert.Equal(t, int64(0), readTTLMs(json.RawMessage(`{"ttlMs":-5}`)))
}

func TestReadCacheScope(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "private", readCacheScope(json.RawMessage(`{"cacheScope":"private"}`), false))
	assert.Equal(t, "public", readCacheScope(json.RawMessage(`{}`), false))
	assert.Equal(t, "private", readCacheScope(json.RawMessage(`{}`), true))
}

func TestReadKeyParts(t *testing.T) {
	t.Parallel()

	parts := readKeyParts("up1", map[string]any{"uri": "file://x"})
	assert.Equal(t, "up1", parts.Upstream)
	assert.Equal(t, protocol.MethodResourcesRead, parts.Method)
	assert.Equal(t, "file://x", parts.Params)
}

func TestMCPCacheAuthContextKey(t *testing.T) {
	t.Parallel()

	assert.Equal(t, mcpcacheAuthContextKey("s", nil), mcpcacheAuthContextKey("s", nil))
}

// ============================================================================
// era helpers
// ============================================================================

func TestDefaultLegacyInteropVersion(t *testing.T) {
	t.Parallel()

	assert.NotEmpty(t, defaultLegacyInteropVersion())
}

func TestHandler_UpstreamEraInfo(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	info, ok := h.UpstreamEraInfo(testUpstreamName)
	require.True(t, ok)
	assert.Equal(t, testUpstreamName, info.ID)

	_, ok = h.UpstreamEraInfo("missing")
	assert.False(t, ok)
}

func TestHandler_ResolveBackend_Era(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	sb, path, ok := h.ResolveBackend(testUpstreamName)
	require.True(t, ok)
	assert.NotNil(t, sb)
	assert.Equal(t, config.DefaultMCPUpstreamPath, path)

	_, _, ok = h.ResolveBackend("missing")
	assert.False(t, ok)
}

func TestHandler_InitParams(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	p := h.InitParams(testUpstreamName)
	assert.NotEmpty(t, p.ProtocolVersion)
}

func TestHandler_ServerRequestHandler_NilBridge(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	assert.Nil(t, h.ServerRequestHandler(testUpstreamName))
}

// ============================================================================
// subscription helpers
// ============================================================================

func TestSubscriptionPrincipalKey(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	r.RemoteAddr = "10.0.0.1:1234"
	assert.Equal(t, "10.0.0.1:1234", subscriptionPrincipalKey(r))

	r2 := withMCPPrincipal(r, &mcpauthz.Principal{Subject: "alice"})
	assert.Equal(t, "alice", subscriptionPrincipalKey(r2))
}

// ============================================================================
// SSE writer
// ============================================================================

func TestWantsSSE(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	assert.False(t, wantsSSE(r))
	r.Header.Set("Accept", "text/event-stream")
	assert.True(t, wantsSSE(r))
}

func TestSSEResponseWriter(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw, err := newSSEResponseWriter(rec)
	require.NoError(t, err)

	require.NoError(t, sw.WriteEvent("message", []byte("line1\nline2")))
	require.NoError(t, sw.WriteComment("keepalive"))
	require.NoError(t, sw.Flush())

	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	body := rec.Body.String()
	assert.Contains(t, body, "event: message")
	assert.Contains(t, body, "data: line1")
	assert.Contains(t, body, "data: line2")
	assert.Contains(t, body, ": keepalive")
}

// ============================================================================
// health checker
// ============================================================================

func TestMCPHealthChecker_Disabled(t *testing.T) {
	t.Parallel()

	resolver := NewMCPUpstreamResolver(nil, nil)
	hc := NewMCPHealthChecker(&fakeHub{}, resolver, []string{"up1"}, 0, observability.NopLogger())
	hc.Start(context.Background()) // no-op when interval <= 0
	// Unprobed upstream is optimistically healthy.
	assert.True(t, hc.IsHealthy("up1"))
	hc.Stop()
	hc.Stop() // idempotent
}

func TestMCPHealthChecker_NilReceiver(t *testing.T) {
	t.Parallel()

	var hc *MCPHealthChecker
	assert.NotPanics(t, func() { hc.Start(context.Background()); hc.Stop() })
}

func TestMCPHealthChecker_ProbeHealthy(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	resolver := NewMCPUpstreamResolver(reg, map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName},
	})
	hub := &fakeHub{resp: okListResponse(t)}
	hc := NewMCPHealthChecker(hub, resolver, []string{testUpstreamName}, 0, observability.NopLogger())

	hc.probeAll(context.Background())
	assert.True(t, hc.IsHealthy(testUpstreamName))
}

func TestMCPHealthChecker_ProbeUnhealthy(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	resolver := NewMCPUpstreamResolver(reg, map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName},
	})
	hub := &fakeHub{err: assertErr("probe failed")}
	hc := NewMCPHealthChecker(hub, resolver, []string{testUpstreamName}, 0, observability.NopLogger())

	hc.probeAll(context.Background())
	assert.False(t, hc.IsHealthy(testUpstreamName))
}

func TestMCPHealthChecker_ProbeUnresolvable(t *testing.T) {
	t.Parallel()

	resolver := NewMCPUpstreamResolver(nil, nil)
	hc := NewMCPHealthChecker(&fakeHub{}, resolver, []string{"missing"}, 0, observability.NopLogger())

	hc.probeAll(context.Background())
	assert.False(t, hc.IsHealthy("missing"))
}

func TestHandler_AttachHealthChecker(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	resolver := NewMCPUpstreamResolver(nil, nil)
	// interval 0 => Start is a no-op, so this is deterministic.
	hc := NewMCPHealthChecker(&fakeHub{}, resolver, []string{"up"}, 0, observability.NopLogger())
	h.AttachHealthChecker(context.Background(), hc)
	assert.NotPanics(t, h.Close)
}

func TestMCPUpstreamResolver_Resolve(t *testing.T) {
	t.Parallel()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName},
	}
	resolver := NewMCPUpstreamResolver(reg, upstreams)

	sb, cfg, ok := resolver.Resolve(testUpstreamName)
	require.True(t, ok)
	assert.NotNil(t, sb)
	assert.Equal(t, testUpstreamName, cfg.Name)

	_, _, ok = resolver.Resolve("missing")
	assert.False(t, ok)
}

// ============================================================================
// handler lifecycle
// ============================================================================

func TestHandler_UpdateConfigAndClose(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	h.UpdateConfig(
		[]config.MCPRoute{{Name: "new", Upstreams: []string{"other"}}},
		map[string]config.MCPBackend{"other": {Name: "other", NamespacePrefix: "other"}},
		&config.MCPConfig{Path: "/mcp2"},
	)
	// Close with no subscription manager / health checker is a no-op.
	assert.NotPanics(t, h.Close)
}

func TestHandler_AttachHealthChecker_Nil(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	assert.NotPanics(t, func() { h.AttachHealthChecker(context.Background(), nil) })
}

func TestHandler_SetHub(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	replacement := &fakeHub{resp: okListResponse(t)}
	h.SetHub(replacement)
	// nil is ignored.
	h.SetHub(nil)
	assert.Same(t, replacement, h.hub)
}

func TestHandler_NewUpstreamStreamer(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	assert.NotNil(t, h.NewUpstreamStreamer())
}
