package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmrtr "github.com/vyrodovalexey/avapigw/internal/mcp/mrtr"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// newMRTRSealer builds a deterministic AEAD sealer for MRTR tests.
func newMRTRSealer(t *testing.T) *envelope.AEADSealer {
	t.Helper()
	key := make([]byte, envelope.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	sealer, err := envelope.NewAEADSealer(key)
	require.NoError(t, err)
	return sealer
}

// newMRTRCoordinator builds a real MRTR coordinator over a deterministic AEAD
// sealer.
func newMRTRCoordinator(t *testing.T) *mcpmrtr.Coordinator {
	t.Helper()
	coord, err := mcpmrtr.NewCoordinator(newMRTRSealer(t), mcpmrtr.Config{})
	require.NoError(t, err)
	return coord
}

// buildWithCaps builds an MCP request body like build but declaring the given
// client capabilities in _meta so the MRTR capability discipline is satisfied
// (HUB-206).
func (b mcpBody) buildWithCaps(t *testing.T, caps ...string) []byte {
	t.Helper()
	raw := b.build(t)
	var req map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &req))
	var params map[string]any
	require.NoError(t, json.Unmarshal(req["params"], &params))
	metaObj, _ := params["_meta"].(map[string]any)
	if metaObj == nil {
		metaObj = map[string]any{}
	}
	capMap := map[string]any{}
	for _, c := range caps {
		capMap[c] = map[string]any{}
	}
	metaObj[protocol.MetaClientCapabilities] = capMap
	params["_meta"] = metaObj
	newParams, err := json.Marshal(params)
	require.NoError(t, err)
	req["params"] = newParams
	out, err := json.Marshal(req)
	require.NoError(t, err)
	return out
}

// newMRTRHandler builds a handler with the MRTR coordinator wired.
func newMRTRHandler(t *testing.T, hub *fakeHub) *MCPHandler {
	t.Helper()
	return newMRTRHandlerWithCoord(t, hub, newMRTRCoordinator(t))
}

// newMRTRHandlerWithCoord builds a handler with an explicit MRTR coordinator so
// tests can bound MaxRounds/Budget for the round-limit path (HUB-208).
func newMRTRHandlerWithCoord(t *testing.T, hub *fakeHub, coord *mcpmrtr.Coordinator) *MCPHandler {
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
		WithMCPHandlerHub(hub),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerMRTRCoordinator(coord),
	)
	require.NoError(t, err)
	return h
}

// inputRequiredResponse builds a canned tools/call input_required result asking
// for a sampling input (HUB-201/206).
func inputRequiredResponse(t *testing.T) *jsonrpc.Response {
	t.Helper()
	resp, err := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]any{
		mcpmrtr.FieldResultType:    protocol.ResultInputRequired,
		mcpmrtr.FieldRequestState:  "upstream-state",
		mcpmrtr.FieldInputRequests: map[string]any{"r1": map[string]any{"type": mcpmrtr.CapSampling}},
	})
	require.NoError(t, err)
	return resp
}

// mrtrRetryToken drives one input_required round and extracts the hub's sealed
// requestState token from the downstream result so a retry can be issued.
func mrtrRetryToken(t *testing.T, h *MCPHandler, nsName string) string {
	t.Helper()
	body := mcpBody{
		method: protocol.MethodToolsCall, name: nsName,
		extra: map[string]any{"q": "hi"},
	}.buildWithCaps(t, mcpmrtr.CapSampling)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.Nil(t, resp.Error)
	var res map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp.Result, &res))
	var token string
	require.NoError(t, json.Unmarshal(res[mcpmrtr.FieldRequestState], &token))
	require.NotEmpty(t, token)
	return token
}

// elicitationInputRequiredResponse builds a tools/call input_required result
// asking for an elicitation input the client did not declare (HUB-206).
func elicitationInputRequiredResponse(t *testing.T) *jsonrpc.Response {
	t.Helper()
	resp, err := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]any{
		mcpmrtr.FieldResultType:    protocol.ResultInputRequired,
		mcpmrtr.FieldRequestState:  "upstream-state",
		mcpmrtr.FieldInputRequests: map[string]any{"r1": map[string]any{"type": mcpmrtr.CapElicitation}},
	})
	require.NoError(t, err)
	return resp
}

// TestMCPHandler_MRTR_MissingCapability proves that when the upstream returns an
// inputRequests entry of a type the downstream client did NOT declare, the hub
// fails with -32021 (MissingRequiredClientCapability) and never forwards the
// input request (HUB-206). The client here declares only sampling.
func TestMCPHandler_MRTR_MissingCapability(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: elicitationInputRequiredResponse(t)}
	h := newMRTRHandler(t, hub)

	nsName := testNamespacePrefix + "." + "weather"
	body := mcpBody{
		method: protocol.MethodToolsCall, name: nsName,
		extra: map[string]any{"q": "hi"},
	}.buildWithCaps(t, mcpmrtr.CapSampling) // no elicitation
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.MissingRequiredClientCapability, resp.Error.Code)
	// It is an error, not a forwarded input_required result: no result body
	// and thus no requestState/inputRequests reaches the client (HUB-206).
	assert.Nil(t, resp.Result)
	assert.NotContains(t, string(rec.Body.Bytes()), mcpmrtr.FieldInputRequests)
	assert.NotContains(t, string(rec.Body.Bytes()), "input_required")
	// The -32021 data lists the missing capability so the client can react.
	require.NotNil(t, resp.Error.Data)
	assert.Contains(t, string(resp.Error.Data), mcpmrtr.CapElicitation)
}

// TestMCPHandler_MRTR_SSEProgressRelay proves that an SSE-typed upstream
// tools/call response with interleaved notifications/progress is relayed
// downstream on the response stream, followed by the terminal result (HUB-244).
func TestMCPHandler_MRTR_SSEProgressRelay(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\","+
				"\"params\":{\"progressToken\":\"t1\",\"progress\":0.5}}\n\n")
		_, _ = io.WriteString(w,
			"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n")
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
		WithMCPHandlerMRTRCoordinator(newMRTRCoordinator(t)),
	)
	require.NoError(t, err)

	nsName := testNamespacePrefix + "." + "weather"
	body := mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)
	r.Header.Set("Accept", "text/event-stream") // client wants a stream

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	out := rec.Body.String()
	// Progress relayed on the response stream, then the terminal result.
	assert.Contains(t, out, "notifications/progress")
	assert.Contains(t, out, `"content":[]`)
	// Progress must precede the terminal result on the wire (HUB-244).
	assert.Less(t, strings.Index(out, "notifications/progress"),
		strings.Index(out, `"content"`))
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

// TestMCPHandler_MRTR_RoundLimit proves the maximum round count is enforced
// SERVER-SIDE from the sealed envelope round, not any client-supplied hint
// (HUB-208). With MaxRounds=1 the first input_required seals round 1; the retry
// would seal round 2 and is rejected.
func TestMCPHandler_MRTR_RoundLimit(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: inputRequiredResponse(t)}
	coord, err := mcpmrtr.NewCoordinator(newMRTRSealer(t), mcpmrtr.Config{MaxRounds: 1})
	require.NoError(t, err)
	h := newMRTRHandlerWithCoord(t, hub, coord)

	nsName := testNamespacePrefix + "." + "weather"
	token := mrtrRetryToken(t, h, nsName)

	// Retry: upstream would return input_required again, sealing round 2 > 1.
	retryBody := mcpBody{
		method: protocol.MethodToolsCall, name: nsName,
		extra: map[string]any{
			"q":                         "hi",
			mcpmrtr.FieldRequestState:   token,
			mcpmrtr.FieldInputResponses: map[string]any{"r1": map[string]any{"answer": "ok"}},
		},
	}.buildWithCaps(t, mcpmrtr.CapSampling)
	r := newMCPRequest(t, retryBody, protocol.MethodToolsCall, nsName)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.InvalidParams, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "round")
}

// A tools/call that returns a normal (non-input_required) result flows through
// the coordinator's complete path (HUB-201..209) and is written downstream as a
// normal brokered response.
func TestMCPHandler_MRTR_CompletePath(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okCallResponse(t)}
	h := newMRTRHandler(t, hub)

	nsName := testNamespacePrefix + "." + "weather"
	body := mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	assert.Nil(t, resp.Error)
	assert.Equal(t, 1, hub.callCount)
}

func TestMCPHandler_MRTR_UpstreamError(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{err: assertErr("boom")}
	h := newMRTRHandler(t, hub)

	nsName := testNamespacePrefix + "." + "weather"
	body := mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestMCPHandler_MRTR_InvalidRetryState(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okCallResponse(t)}
	h := newMRTRHandler(t, hub)

	nsName := testNamespacePrefix + "." + "weather"
	// A retry request carries requestState; a bogus token fails verification.
	body := mcpBody{
		method: protocol.MethodToolsCall,
		name:   nsName,
		extra: map[string]any{
			mcpmrtr.FieldRequestState:   "bogus-token",
			mcpmrtr.FieldInputResponses: map[string]any{"answer": "42"},
		},
	}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsCall, nsName)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 0, hub.callCount, "retry must be verified before any upstream call")
}

// ============================================================================
// writeMRTRResult / writeTerminalOnRelay direct-path tests (HUB-244)
// ============================================================================

// mustMCPReq parses r's body into a *mcpReq for direct method-under-test calls.
func mustMCPReq(t *testing.T, r *http.Request) *mcpReq {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var req jsonrpc.Request
	require.NoError(t, json.Unmarshal(body, &req))
	params, err := decodeParams(req.Params)
	require.NoError(t, err)
	return &mcpReq{req: &req, params: params}
}

// okTerminalResponse returns a small successful JSON-RPC response.
func okTerminalResponse(t *testing.T) *jsonrpc.Response {
	t.Helper()
	resp, err := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]any{"content": []any{}})
	require.NoError(t, err)
	return resp
}

// requestWithOpenRelay returns a request carrying a progress relay that has
// already opened its downstream SSE stream over rec.
func requestWithOpenRelay(t *testing.T, rec http.ResponseWriter) *http.Request {
	t.Helper()
	r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
		protocol.MethodToolsCall, "x")
	r.Header.Set("Accept", "text/event-stream")
	r = withProgressRelayContext(r, rec)
	relay := progressRelayFromContext(r)
	require.NotNil(t, relay)
	require.NoError(t, relay.writeProgress([]byte(`{"progress":0.5}`)))
	return r
}

// 6.1 writeMRTRResult relay-active path: terminal written on the relay stream.
func TestMCPHandler_WriteMRTRResult_RelayActive(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})
	rec := httptest.NewRecorder()
	r := requestWithOpenRelay(t, rec)

	h.writeMRTRResult(rec, r, okTerminalResponse(t))

	body := rec.Body.String()
	// One progress event + one terminal event on the same stream.
	assert.Contains(t, body, `"content"`)
	assert.Equal(t, 2, countOccurrences(body, "event: message"))
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

// 6.2 writeMRTRResult SSE path (no relay): fresh SSE writer, one message event.
func TestMCPHandler_WriteMRTRResult_SSENoRelay(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})
	rec := httptest.NewRecorder()
	// SSE requested but NO relay attached to the context.
	r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
		protocol.MethodToolsCall, "x")
	r.Header.Set("Accept", "text/event-stream")

	h.writeMRTRResult(rec, r, okTerminalResponse(t))

	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, 1, countOccurrences(rec.Body.String(), "event: message"))
}

// 6.3 writeMRTRResult plain-JSON fallback: no relay, no SSE Accept → 200 JSON.
func TestMCPHandler_WriteMRTRResult_PlainJSON(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})
	rec := httptest.NewRecorder()
	r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
		protocol.MethodToolsCall, "x")

	h.writeMRTRResult(rec, r, okTerminalResponse(t))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	assert.NotContains(t, rec.Body.String(), "event: message")
}

// 6.4 writeTerminalOnRelay error arms.
func TestMCPHandler_WriteTerminalOnRelay_Arms(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})

	t.Run("no relay → false", func(t *testing.T) {
		t.Parallel()
		r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
			protocol.MethodToolsCall, "x")
		assert.False(t, h.writeTerminalOnRelay(r, okTerminalResponse(t)))
	})

	t.Run("inactive relay → false", func(t *testing.T) {
		t.Parallel()
		// Relay attached but never opened (no progress event) → inactive.
		r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
			protocol.MethodToolsCall, "x")
		r.Header.Set("Accept", "text/event-stream")
		r = withProgressRelayContext(r, httptest.NewRecorder())
		assert.False(t, h.writeTerminalOnRelay(r, okTerminalResponse(t)))
	})

	t.Run("encode failure → false", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		r := requestWithOpenRelay(t, rec)
		// A Response whose Result is invalid JSON fails jsonrpc.Encode.
		bad := &jsonrpc.Response{JSONRPC: "2.0", ID: json.RawMessage(`1`),
			Result: json.RawMessage([]byte{0xff, 0xfe})}
		assert.False(t, h.writeTerminalOnRelay(r, bad))
	})

	t.Run("write terminal on failed stream → still true", func(t *testing.T) {
		t.Parallel()
		// Open the relay, then break the underlying stream so writeTerminal
		// errors but the function still reports it handled the terminal.
		fw := &failingAfterOpenWriter{header: make(http.Header)}
		r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
			protocol.MethodToolsCall, "x")
		r.Header.Set("Accept", "text/event-stream")
		r = withProgressRelayContext(r, fw)
		relay := progressRelayFromContext(r)
		require.NoError(t, relay.writeProgress([]byte(`{"progress":0.5}`)))
		fw.fail = true // subsequent writes error
		assert.True(t, h.writeTerminalOnRelay(r, okTerminalResponse(t)))
	})
}

// 6.6 writeMRTRComplete relay-active with success and error responses.
func TestMCPHandler_WriteMRTRComplete_RelayActive(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})

	t.Run("success rewrites result on relay", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		r := requestWithOpenRelay(t, rec)
		h.writeMRTRComplete(rec, r, mustMCPReq(t, r), okTerminalResponse(t), testUpstreamName, "")
		assert.Equal(t, 2, countOccurrences(rec.Body.String(), "event: message"))
	})

	t.Run("error response terminal on relay", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		r := requestWithOpenRelay(t, rec)
		errResp := jsonrpc.NewErrorResponse(json.RawMessage(`1`),
			&jsonrpc.Error{Code: protocol.InternalError, Message: "boom"})
		h.writeMRTRComplete(rec, r, mustMCPReq(t, r), errResp, testUpstreamName, "")
		assert.Contains(t, rec.Body.String(), "boom")
	})
}

// 6.7 completeMRTR inspect-error: an upstream result that Inspect rejects →
// BadGateway JSON-RPC error.
func TestMCPHandler_CompleteMRTR_InspectError(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})
	nsName := testNamespacePrefix + "." + "weather"
	r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t),
		protocol.MethodToolsCall, nsName)
	mr := mustMCPReq(t, r)

	// A result that is a JSON array cannot decode into the input_required
	// struct, so coordinator.Inspect returns an error.
	badResp := &jsonrpc.Response{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Result: json.RawMessage(`[1,2,3]`)}

	rec := httptest.NewRecorder()
	cc := h.buildCallContext(r, mr, testUpstreamName,
		config.MCPBackend{Name: testUpstreamName, NamespacePrefix: testNamespacePrefix})
	h.completeMRTR(rec, r, mr, cc, testUpstreamName, badResp, mrtrProgress{})

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.InternalError, resp.Error.Code)
}

// 6.8 buildMRTRUpstreamRequest: retry injects upstreamState; initial strips
// inputResponses; params-not-object → unmarshal error.
func TestMCPHandler_BuildMRTRUpstreamRequest(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})

	t.Run("retry injects upstream state", func(t *testing.T) {
		t.Parallel()
		nsName := testNamespacePrefix + "." + "weather"
		mr := mustMCPReq(t, newMCPRequest(t,
			mcpBody{method: protocol.MethodToolsCall, name: nsName,
				extra: map[string]any{mcpmrtr.FieldInputResponses: map[string]any{"r1": "ok"}}}.build(t),
			protocol.MethodToolsCall, nsName))

		got, err := h.buildMRTRUpstreamRequest(mr, testProtocolVersion,
			json.RawMessage(`{"orig":"state"}`))
		require.NoError(t, err)
		assert.Contains(t, string(got.Params), mcpmrtr.FieldRequestState)
	})

	t.Run("initial call strips inputResponses", func(t *testing.T) {
		t.Parallel()
		nsName := testNamespacePrefix + "." + "weather"
		mr := mustMCPReq(t, newMCPRequest(t,
			mcpBody{method: protocol.MethodToolsCall, name: nsName,
				extra: map[string]any{mcpmrtr.FieldInputResponses: map[string]any{"r1": "ok"}}}.build(t),
			protocol.MethodToolsCall, nsName))

		got, err := h.buildMRTRUpstreamRequest(mr, testProtocolVersion, nil)
		require.NoError(t, err)
		assert.NotContains(t, string(got.Params), mcpmrtr.FieldInputResponses)
	})
}

// 6.5 withProgressRelay: a nil relay returns ctx unchanged; a present relay
// returns a derived ctx carrying the sink.
func TestMCPHandler_WithProgressRelay(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})

	t.Run("nil relay returns ctx unchanged", func(t *testing.T) {
		t.Parallel()
		r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: "x"}.build(t),
			protocol.MethodToolsCall, "x")
		ctx := r.Context()
		got := h.withProgressRelay(ctx, r, testUpstreamName)
		assert.Equal(t, ctx, got)
	})

	t.Run("present relay derives a new ctx", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		r := requestWithOpenRelay(t, rec)
		got := h.withProgressRelay(r.Context(), r, testUpstreamName)
		assert.NotEqual(t, r.Context(), got)
	})
}

// TestMCPHandler_BuildCallContext_WithPrincipal covers the principal-present
// arm of buildCallContext.
func TestMCPHandler_BuildCallContext_WithPrincipal(t *testing.T) {
	t.Parallel()

	h := newMRTRHandler(t, &fakeHub{resp: okCallResponse(t)})
	nsName := testNamespacePrefix + "." + "weather"
	r := newMCPRequest(t, mcpBody{method: protocol.MethodToolsCall, name: nsName}.build(t),
		protocol.MethodToolsCall, nsName)
	r = withMCPPrincipal(r, &mcpauthz.Principal{Subject: "alice"})
	mr := mustMCPReq(t, r)

	cc := h.buildCallContext(r, mr, testUpstreamName,
		config.MCPBackend{Name: testUpstreamName, NamespacePrefix: testNamespacePrefix})
	assert.Equal(t, "alice", cc.Principal)
}

// failingAfterOpenWriter is a flushable writer whose Write fails once fail is
// set, letting a relay open successfully then error on the terminal write.
type failingAfterOpenWriter struct {
	header http.Header
	fail   bool
}

func (w *failingAfterOpenWriter) Header() http.Header { return w.header }
func (w *failingAfterOpenWriter) Write(b []byte) (int, error) {
	if w.fail {
		return 0, assertErr("write failed")
	}
	return len(b), nil
}
func (w *failingAfterOpenWriter) WriteHeader(int) {}
func (w *failingAfterOpenWriter) Flush()          {}
