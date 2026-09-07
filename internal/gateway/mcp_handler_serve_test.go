package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// ============================================================================
// Transport method rules (HUB-103)
// ============================================================================

func TestMCPHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(method, "/mcp", http.NoBody)
			h.ServeHTTP(rec, r)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
			assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
		})
	}
}

// ============================================================================
// Origin allowlist (HUB-106)
// ============================================================================

func TestMCPHandler_OriginForbidden(t *testing.T) {
	t.Parallel()

	cfg := &config.MCPConfig{AllowedOrigins: []string{"https://allowed.example.com"}}
	h := newTestHandler(t, &fakeHub{}).handler
	h.UpdateConfig(
		[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}},
		map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
		cfg,
	)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	r.Header.Set("Origin", "https://evil.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMCPHandler_OriginAllowed(t *testing.T) {
	t.Parallel()

	cfg := &config.MCPConfig{AllowedOrigins: []string{"*"}}
	hub := &fakeHub{resp: okListResponse(t)}
	h := newTestHandler(t, hub).handler
	h.UpdateConfig(
		[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}},
		map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
		cfg,
	)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")
	r.Header.Set("Origin", "https://anything.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// Body size limit (HUB-405)
// ============================================================================

func TestMCPHandler_BodyTooLarge(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{}
	h := newTestHandler(t, hub).handler
	h.UpdateConfig(
		[]config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}},
		map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
		&config.MCPConfig{MaxBodySize: 16},
	)

	body := mcpBody{method: protocol.MethodToolsList, extra: map[string]any{
		"filler": strings.Repeat("x", 1024),
	}}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	// MaxBytesReader failure surfaces as a parse error (400) with a JSON-RPC
	// InvalidRequest body.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// Batch / multiple JSON-RPC rejection (HUB-102)
// ============================================================================

func TestMCPHandler_BatchRejected(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	batch := []byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(batch))
	r.Header.Set(headers.HeaderMcpMethod, protocol.MethodToolsList)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.InvalidRequest, resp.Error.Code)
}

// ============================================================================
// _meta discipline (HUB-121/123)
// ============================================================================

func TestMCPHandler_MissingMeta(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	tests := []struct {
		name string
		body mcpBody
	}{
		{name: "no meta", body: mcpBody{method: protocol.MethodToolsList, omitMeta: true}},
		{name: "no version", body: mcpBody{method: protocol.MethodToolsList, omitVersion: true}},
		{name: "no caps", body: mcpBody{method: protocol.MethodToolsList, omitCaps: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := tt.body.build(t)
			r := newMCPRequest(t, body, protocol.MethodToolsList, "")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			resp := decodeRPCResponse(t, rec.Body.Bytes())
			require.NotNil(t, resp.Error)
			assert.Equal(t, protocol.InvalidParams, resp.Error.Code)
		})
	}
}

func TestMCPHandler_UnsupportedVersion(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	body := mcpBody{method: protocol.MethodToolsList, version: "1999-01-01"}.build(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set(headers.HeaderMcpMethod, protocol.MethodToolsList)
	// Do NOT set a conflicting MCP-Protocol-Version header (leave empty so the
	// header-agreement check passes and version support is evaluated).

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.UnsupportedProtocolVersion, resp.Error.Code)
	// data carries supported + requested.
	var data map[string]any
	require.NoError(t, json.Unmarshal(resp.Error.Data, &data))
	assert.Equal(t, "1999-01-01", data["requested"])
	assert.Contains(t, data, "supported")
}

// ============================================================================
// Header/meta agreement (HUB-122)
// ============================================================================

func TestMCPHandler_ProtocolVersionHeaderMismatch(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set(headers.HeaderMcpMethod, protocol.MethodToolsList)
	r.Header.Set(headers.HeaderMcpProtocolVersion, "2020-01-01") // conflicts with _meta

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.HeaderMismatch, resp.Error.Code)
}

// TestMCPHandler_MissingProtocolVersionHeader proves that a request WITHOUT the
// MCP-Protocol-Version header is rejected with -32020 / HTTP 400 (HUB-122): the
// header is required, not optional.
func TestMCPHandler_MissingProtocolVersionHeader(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	// _meta carries a supported version so validateMeta passes; the header is
	// deliberately omitted so validateHeaders must reject it.
	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set(headers.HeaderMcpMethod, protocol.MethodToolsList)
	// No MCP-Protocol-Version header set.

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.HeaderMismatch, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "required")
}

// ============================================================================
// Mirrored header validation (HUB-141..143)
// ============================================================================

func TestMCPHandler_MissingMcpMethodHeader(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set(headers.HeaderMcpProtocolVersion, testProtocolVersion)
	// No Mcp-Method header.

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.HeaderMismatch, resp.Error.Code)
}

func TestMCPHandler_MissingMcpNameHeader(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	// tools/call requires Mcp-Name.
	body := mcpBody{method: protocol.MethodToolsCall, name: "svc.weather"}.build(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set(headers.HeaderMcpProtocolVersion, testProtocolVersion)
	r.Header.Set(headers.HeaderMcpMethod, protocol.MethodToolsCall)
	// No Mcp-Name header.

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.HeaderMismatch, resp.Error.Code)
}

// ============================================================================
// Route not found
// ============================================================================

func TestMCPHandler_NoMatchingRoute(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{}
	h := newTestHandler(t, hub).handler
	// Replace catch-all with a route that only matches prompts/get.
	h.UpdateConfig(
		[]config.MCPRoute{{
			Name:      "prompts",
			Upstreams: []string{testUpstreamName},
			Match:     []config.MCPRouteMatch{{Method: protocol.MethodPromptsGet}},
		}},
		map[string]config.MCPBackend{testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix}},
		&config.MCPConfig{},
	)

	body := mcpBody{method: protocol.MethodToolsList}.build(t)
	r := newMCPRequest(t, body, protocol.MethodToolsList, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	resp := decodeRPCResponse(t, rec.Body.Bytes())
	require.NotNil(t, resp.Error)
	assert.Equal(t, protocol.MethodNotFound, resp.Error.Code)
}
