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
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// assertErr is a tiny error helper for injecting upstream failures.
func assertErr(msg string) error { return &simpleErr{msg} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

// fakeAuditLogger records the events passed to LogEvent and satisfies the full
// audit.Logger interface.
type fakeAuditLogger struct {
	events []*audit.Event
}

func (l *fakeAuditLogger) LogEvent(_ context.Context, event *audit.Event) {
	l.events = append(l.events, event)
}

func (l *fakeAuditLogger) LogAuthentication(
	_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject,
) {
}

func (l *fakeAuditLogger) LogAuthorization(
	_ context.Context, _ audit.Outcome, _ *audit.Subject, _ *audit.Resource,
) {
}

func (l *fakeAuditLogger) LogSecurity(
	_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject, _ map[string]interface{},
) {
}

func (l *fakeAuditLogger) Close() error { return nil }

func TestMCPHandler_ToolsCall_Audited(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okCallResponse(t)}
	auditLog := &fakeAuditLogger{}

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	routes := []config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(hub),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerAuditLogger(auditLog),
	)
	require.NoError(t, err)

	nsName := testNamespacePrefix + "." + "weather"
	body := mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, auditLog.events, 1, "a tools/call must emit exactly one audit event")
	assert.Equal(t, "mcp_tool", auditLog.events[0].Resource.Type)
}

// ============================================================================
// Happy-path tools/list round-trip
// ============================================================================

func TestMCPHandler_ToolsList_HappyPath(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	harness := newTestHandler(t, hub)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	harness.handler.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	assert.Nil(t, resp.Error)

	// The hub was actually called at the upstream path.
	assert.Equal(t, 1, hub.callCount)
	assert.Equal(t, config.DefaultMCPUpstreamPath, hub.calledPath)
	// Upstream Mcp-Method header was re-derived.
	assert.Equal(t, protocol.MethodToolsList, hub.calledHeaders.Get(headers.HeaderMcpMethod))
}

// ============================================================================
// Happy-path tools/call round-trip with namespacing + serverInfo injection
// ============================================================================

func TestMCPHandler_ToolsCall_HappyPath(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okCallResponse(t)}
	harness := newTestHandler(t, hub)

	// namespaced tool name: "<prefix>.<original>" == "mcp-backend.weather"
	nsName := testNamespacePrefix + "." + "weather"
	body := mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)

	rec := httptest.NewRecorder()
	harness.handler.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.Nil(t, resp.Error)

	// Upstream request de-namespaced the tool name to "weather".
	require.Equal(t, 1, hub.callCount)
	var upParams map[string]any
	require.NoError(t, json.Unmarshal(hub.calledReq.Params, &upParams))
	assert.Equal(t, "weather", upParams["name"])
	// Upstream Mcp-Name header carries the de-namespaced name.
	assert.Equal(t, "weather", hub.calledHeaders.Get(headers.HeaderMcpName))

	// serverInfo was injected into the result's _meta.
	var result map[string]any
	require.NoError(t, json.Unmarshal(resp.Result, &result))
	meta, ok := result["_meta"].(map[string]any)
	require.True(t, ok, "result should carry _meta with serverInfo")
	assert.Contains(t, meta, protocol.MetaServerInfo)
}

// ============================================================================
// Upstream error is surfaced as a bad-gateway JSON-RPC error
// ============================================================================

func TestMCPHandler_UpstreamError(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{err: assertErr("boom")}
	harness := newTestHandler(t, hub)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	harness.handler.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.InternalError, resp.Error.Code)
}

// ============================================================================
// Upstream-connection limiter saturation (HUB-405)
// ============================================================================

func TestMCPHandler_UpstreamPoolExhausted(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	harness := newTestHandler(t, hub, WithMCPHandlerLimits(0, 1))
	// Pre-acquire the single upstream slot so the request sees an exhausted
	// pool.
	require.True(t, harness.handler.limiter.tryAcquireUpstream())

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	harness.handler.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, 0, hub.callCount)
}

// ============================================================================
// Dry-run mode returns a synthetic result without calling upstream (HUB-507)
// ============================================================================

func TestMCPHandler_DryRun_Global(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	harness := newTestHandler(t, hub, WithMCPHandlerDryRun(true))

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	harness.handler.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 0, hub.callCount, "dry-run must not call upstream")

	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.Nil(t, resp.Error)
	result := decodeDryRunResult(t, resp.Result)
	assert.Equal(t, true, result["dryRun"])
	assert.Equal(t, protocol.MethodToolsList, result["method"])
}

// decodeDryRunResult decodes the dry-run synthetic result. serveDryRun encodes
// the body as a []byte passed to jsonrpc.NewResponse, which JSON-encodes it as a
// base64 string, so the result is first decoded to raw bytes then to a map.
func decodeDryRunResult(t *testing.T, result json.RawMessage) map[string]any {
	t.Helper()
	var inner []byte
	require.NoError(t, json.Unmarshal(result, &inner))
	var m map[string]any
	require.NoError(t, json.Unmarshal(inner, &m))
	return m
}

func TestMCPHandler_DryRun_PerRequestHeader(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	harness := newTestHandler(t, hub) // global dry-run off

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	r.Header.Set("Mcp-Dry-Run", "true")

	rec := httptest.NewRecorder()
	harness.handler.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 0, hub.callCount)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	result := decodeDryRunResult(t, resp.Result)
	assert.Equal(t, true, result["dryRun"])
}

// ============================================================================
// Authorization enforcement (HUB-305/306/307)
// ============================================================================

// newAuthorizedHandler builds a handler with an enabled authorizer that
// accepts the token "good" (subject "alice", scopes ["read"]) with an audience
// matching the canonical URI.
func newAuthorizedHandler(
	t *testing.T, hub *fakeHub, route config.MCPRoute,
) *MCPHandler {
	t.Helper()

	validator := &fakeTokenValidator{info: &oidc.TokenInfo{
		Subject:  "alice",
		Scopes:   []string{"read"},
		Audience: []string{"https://hub.example.com"},
	}}
	authorizer := mcpauthz.NewAuthorizer(validator, mcpauthz.Config{
		CanonicalURI:        "https://hub.example.com",
		ResourceMetadataURL: "https://hub.example.com/.well-known/oauth-protected-resource",
	})

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(hub),
		WithMCPHandlerConfig([]config.MCPRoute{route}, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerAuthorizer(authorizer),
	)
	require.NoError(t, err)
	return h
}

func TestMCPHandler_Authz_MissingToken(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	route := config.MCPRoute{
		Name:           "secured",
		Upstreams:      []string{testUpstreamName},
		Authentication: &config.AuthenticationConfig{Enabled: true},
	}
	h := newAuthorizedHandler(t, hub, route)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	// No Authorization header.

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, hub.callCount)
}

func TestMCPHandler_Authz_InsufficientScope(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	route := config.MCPRoute{
		Name:      "secured",
		Upstreams: []string{testUpstreamName},
		ScopeMap:  map[string][]string{protocol.MethodToolsList: {"admin"}},
	}
	h := newAuthorizedHandler(t, hub, route)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	r.Header.Set("Authorization", "Bearer good")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, hub.callCount)
}

func TestMCPHandler_Authz_Allowed(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	route := config.MCPRoute{
		Name:      "secured",
		Upstreams: []string{testUpstreamName},
		ScopeMap:  map[string][]string{protocol.MethodToolsList: {"read"}},
	}
	h := newAuthorizedHandler(t, hub, route)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	r.Header.Set("Authorization", "Bearer good")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, hub.callCount)
}

func TestMCPHandler_Authz_PassThroughWhenNotConfigured(t *testing.T) {
	t.Parallel()

	// Route declares no Authentication/Authorization/ScopeMap => authz is
	// skipped even though an authorizer is wired.
	hub := &fakeHub{resp: okListResponse(t)}
	route := config.MCPRoute{Name: "open", Upstreams: []string{testUpstreamName}}
	h := newAuthorizedHandler(t, hub, route)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	// No Authorization header, but route does not require authz.

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, hub.callCount)
}
