//go:build functional
// +build functional

package functional

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// fakeMCPUpstream is an in-process MCP upstream used by the functional tests.
// Unlike the docker mock it accepts the vendor-prefixed _meta the hub emits and
// returns canned discover/list/call responses so the gateway MCP pipeline can be
// exercised end-to-end without any external ENV.
type fakeMCPUpstream struct {
	server *httptest.Server

	// recorded state for assertions.
	lastAuthorization atomic.Value // string
	lastToolName      atomic.Value // string (de-namespaced name seen upstream)
	lastMethod        atomic.Value // string
	lastMcpMethodHdr  atomic.Value // string (mirrored Mcp-Method header)
	lastMcpNameHdr    atomic.Value // string (mirrored Mcp-Name header, de-namespaced)
	callCount         atomic.Int64
}

func newFakeMCPUpstream(t *testing.T) *fakeMCPUpstream {
	t.Helper()
	f := &fakeMCPUpstream{}
	f.lastAuthorization.Store("")
	f.lastToolName.Store("")
	f.lastMethod.Store("")
	f.lastMcpMethodHdr.Store("")
	f.lastMcpNameHdr.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		// GET/DELETE => 405 (mirrors the real mock transport rule).
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		f.callCount.Add(1)
		f.lastAuthorization.Store(r.Header.Get("Authorization"))
		f.lastMcpMethodHdr.Store(r.Header.Get(helpers.MCPHeaderMethod))
		f.lastMcpNameHdr.Store(r.Header.Get(helpers.MCPHeaderName))

		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		f.lastMethod.Store(req.Method)
		f.lastToolName.Store(req.Params.Name)

		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case helpers.MCPMethodToolsList:
			writeJSON(w, req.ID, map[string]any{
				"tools": []any{
					map[string]any{"name": "echo", "description": "echoes"},
					map[string]any{"name": "sleep", "description": "sleeps"},
				},
			})
		case helpers.MCPMethodServerDiscover:
			writeJSON(w, req.ID, map[string]any{
				"tools": []any{
					map[string]any{"name": "echo", "description": "echoes"},
				},
			})
		case helpers.MCPMethodToolsCall:
			writeJSON(w, req.ID, map[string]any{
				"content": []any{
					map[string]any{"type": "text", "text": "pong:" + req.Params.Name},
				},
			})
		default:
			writeJSON(w, req.ID, map[string]any{"ok": true})
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func writeJSON(w http.ResponseWriter, id json.RawMessage, result map[string]any) {
	raw, _ := json.Marshal(result)
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  json.RawMessage(raw),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeMCPUpstream) URL() string { return f.server.URL + "/mcp" }

// startFunctionalMCPGateway builds and starts an in-process MCP gateway pointed
// at the fake upstream(s) with an OS-assigned port.
func startFunctionalMCPGateway(
	t *testing.T, opts helpers.MCPGatewayConfigOptions, gwOpts ...helpers.MCPGatewayOption,
) *helpers.MCPGatewayInstance {
	t.Helper()
	port, err := helpers.GetFreeTCPPort()
	require.NoError(t, err)
	opts.Port = port

	cfg := helpers.BuildMCPGatewayConfig(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	gi, err := helpers.StartMCPGateway(ctx, cfg, gwOpts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })
	return gi
}

// TestFunctional_MCP_TransportRules exercises the gateway-enforced MCP transport
// rules (HUB-103/106/121..123) which are applied BEFORE any upstream call.
func TestFunctional_MCP_TransportRules(t *testing.T) {
	up := newFakeMCPUpstream(t)
	be, err := helpers.MCPBackendFromURL("svc", up.URL())
	require.NoError(t, err)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		Backends:       []config.MCPBackend{be},
		AllowedOrigins: []string{"https://allowed.example.com"},
	})

	client := helpers.HTTPClient()

	t.Run("GET on the MCP path returns 405", func(t *testing.T) {
		resp, err := client.Get(gi.BaseURL + gi.MCPPath)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		assert.Equal(t, http.MethodPost, resp.Header.Get("Allow"))
	})

	t.Run("disallowed Origin returns 403", func(t *testing.T) {
		body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList}.MustBuild()
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsList,
			Origin: "https://evil.example.com",
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("allowed Origin is accepted", func(t *testing.T) {
		body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList}.MustBuild()
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsList,
			Origin: "https://allowed.example.com",
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("missing _meta returns -32602 (InvalidParams)", func(t *testing.T) {
		body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList, OmitMeta: true}.MustBuild()
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsList,
		})
		require.NoError(t, err)
		rpc, err := helpers.DecodeMCPResponse(resp)
		require.NoError(t, err)
		require.NotNil(t, rpc.Error)
		assert.Equal(t, helpers.MCPErrInvalidParams, rpc.Error.Code)
	})

	t.Run("MCP-Protocol-Version header != _meta version returns -32020", func(t *testing.T) {
		body := helpers.MCPRequestBody{
			Method:  helpers.MCPMethodToolsList,
			Version: helpers.MCPProtocolVersion,
		}.MustBuild()
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method:          helpers.MCPMethodToolsList,
			ProtocolVersion: "2099-01-01", // mismatched header vs body _meta
		})
		require.NoError(t, err)
		rpc, err := helpers.DecodeMCPResponse(resp)
		require.NoError(t, err)
		require.NotNil(t, rpc.Error)
		assert.Equal(t, helpers.MCPErrHeaderMismatch, rpc.Error.Code)
	})

	t.Run("unsupported protocol version returns -32022", func(t *testing.T) {
		body := helpers.MCPRequestBody{
			Method:  helpers.MCPMethodToolsList,
			Version: "1999-01-01",
		}.MustBuild()
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method:          helpers.MCPMethodToolsList,
			ProtocolVersion: "1999-01-01", // header matches body so version check fires
		})
		require.NoError(t, err)
		rpc, err := helpers.DecodeMCPResponse(resp)
		require.NoError(t, err)
		require.NotNil(t, rpc.Error)
		assert.Equal(t, helpers.MCPErrUnsupportedProtocolVersion, rpc.Error.Code)
	})

	t.Run("missing Mcp-Method header returns -32020", func(t *testing.T) {
		body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList}.MustBuild()
		// Omit the Mcp-Method header entirely.
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{})
		require.NoError(t, err)
		rpc, err := helpers.DecodeMCPResponse(resp)
		require.NoError(t, err)
		require.NotNil(t, rpc.Error)
		assert.Equal(t, helpers.MCPErrHeaderMismatch, rpc.Error.Code)
	})

	t.Run("missing Mcp-Name for tools/call returns -32020", func(t *testing.T) {
		body := helpers.MCPRequestBody{
			Method:    helpers.MCPMethodToolsCall,
			Name:      "svc.echo",
			Arguments: map[string]any{"message": "hi"},
		}.MustBuild()
		// Set Mcp-Method but omit Mcp-Name (required for tools/call).
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsCall,
		})
		require.NoError(t, err)
		rpc, err := helpers.DecodeMCPResponse(resp)
		require.NoError(t, err)
		require.NotNil(t, rpc.Error)
		assert.Equal(t, helpers.MCPErrHeaderMismatch, rpc.Error.Code)
	})
}

// TestFunctional_MCP_ToolsCall_Namespacing verifies the happy-path tools/call
// round-trip: the downstream tool name is namespaced (svc.echo), and the fake
// upstream receives the de-namespaced name (echo). Also asserts no-token
// passthrough (the downstream Authorization is never forwarded upstream).
func TestFunctional_MCP_ToolsCall_Namespacing(t *testing.T) {
	up := newFakeMCPUpstream(t)
	be, err := helpers.MCPBackendFromURL("svc", up.URL())
	require.NoError(t, err)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		Backends: []config.MCPBackend{be},
	})

	const namespacedTool = "svc.echo"
	body := helpers.MCPRequestBody{
		Method:    helpers.MCPMethodToolsCall,
		Name:      namespacedTool,
		Arguments: map[string]any{"message": "ping"},
	}.MustBuild()

	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method:        helpers.MCPMethodToolsCall,
		Name:          namespacedTool,
		Authorization: "Bearer downstream-secret-token",
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "tools/call must succeed")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// De-namespacing: the upstream must observe the bare tool name "echo".
	assert.Equal(t, "echo", up.lastToolName.Load().(string),
		"upstream must receive the de-namespaced tool name")
	assert.Equal(t, helpers.MCPMethodToolsCall, up.lastMethod.Load().(string))

	// No-token-passthrough: the downstream Authorization is never forwarded.
	assert.Empty(t, up.lastAuthorization.Load().(string),
		"downstream Authorization must NOT be forwarded upstream (HUB-303/304)")

	// serverInfo injection: the hub injects its own serverInfo into the result.
	assert.Contains(t, string(rpc.Result), "serverInfo",
		"hub serverInfo must be injected into the result (_meta.serverInfo)")
}

// TestFunctional_MCP_HeaderMirroring verifies the hub mirrors the derived MCP
// headers onto the upstream request after de-namespacing (HUB-141/143): the
// upstream must observe Mcp-Method equal to the JSON-RPC method and Mcp-Name
// equal to the DE-NAMESPACED primitive name (svc.echo -> echo), even though the
// downstream request carried the namespaced name.
func TestFunctional_MCP_HeaderMirroring(t *testing.T) {
	up := newFakeMCPUpstream(t)
	be, err := helpers.MCPBackendFromURL("svc", up.URL())
	require.NoError(t, err)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		Backends: []config.MCPBackend{be},
	})

	const namespacedTool = "svc.echo"
	body := helpers.MCPRequestBody{
		Method:    helpers.MCPMethodToolsCall,
		Name:      namespacedTool,
		Arguments: map[string]any{"message": "mirror"},
	}.MustBuild()

	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsCall,
		Name:   namespacedTool,
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "tools/call must succeed")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The upstream must see the mirrored Mcp-Method header verbatim.
	assert.Equal(t, helpers.MCPMethodToolsCall, up.lastMcpMethodHdr.Load().(string),
		"upstream must receive the mirrored Mcp-Method header")

	// The upstream must see the DE-NAMESPACED name in the mirrored Mcp-Name
	// header (svc.echo downstream -> echo upstream), matching the rewritten body.
	assert.Equal(t, "echo", up.lastMcpNameHdr.Load().(string),
		"upstream must receive the de-namespaced Mcp-Name header (HUB-143)")
}

// TestFunctional_MCP_ToolsList_Aggregation verifies tools/list aggregation with
// namespacing: each upstream tool is exposed as "<prefix>.<tool>", in
// deterministic order, and serverInfo is injected.
func TestFunctional_MCP_ToolsList_Aggregation(t *testing.T) {
	up1 := newFakeMCPUpstream(t)
	up2 := newFakeMCPUpstream(t)
	be1, err := helpers.MCPBackendFromURL("alpha", up1.URL())
	require.NoError(t, err)
	be2, err := helpers.MCPBackendFromURL("beta", up2.URL())
	require.NoError(t, err)

	gi := startFunctionalMCPGateway(t,
		helpers.MCPGatewayConfigOptions{Backends: []config.MCPBackend{be1, be2}},
		helpers.WithMCPAggregator(),
	)

	body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList}.MustBuild()
	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsList,
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "tools/list must succeed")

	names, err := rpc.ToolNames()
	require.NoError(t, err)

	// Both upstreams expose echo+sleep -> namespaced with their prefix.
	assert.Contains(t, names, "alpha.echo")
	assert.Contains(t, names, "alpha.sleep")
	assert.Contains(t, names, "beta.echo")
	assert.Contains(t, names, "beta.sleep")

	// Deterministic order: re-issuing the request yields the same order.
	resp2, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsList,
	})
	require.NoError(t, err)
	rpc2, err := helpers.DecodeMCPResponse(resp2)
	require.NoError(t, err)
	names2, err := rpc2.ToolNames()
	require.NoError(t, err)
	assert.Equal(t, names, names2, "aggregated tools/list order must be deterministic")
}

// TestFunctional_MCP_Degraded verifies degraded operation: one upstream points
// at a dead port, the other is healthy, and tools/list still serves the healthy
// upstream's tools.
func TestFunctional_MCP_Degraded(t *testing.T) {
	up := newFakeMCPUpstream(t)
	healthy, err := helpers.MCPBackendFromURL("healthy", up.URL())
	require.NoError(t, err)
	dead := helpers.MCPBackendToDeadPort("dead", 1) // port 1: no listener

	gi := startFunctionalMCPGateway(t,
		helpers.MCPGatewayConfigOptions{Backends: []config.MCPBackend{healthy, dead}},
		helpers.WithMCPAggregator(),
	)

	body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList}.MustBuild()
	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsList,
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "degraded tools/list must still succeed")

	names, err := rpc.ToolNames()
	require.NoError(t, err)
	assert.Contains(t, names, "healthy.echo",
		"the healthy upstream's tools must still be served when one upstream is down")
	for _, n := range names {
		assert.False(t, strings.HasPrefix(n, "dead."),
			"the dead upstream must contribute no tools")
	}
}

// TestFunctional_MCP_NoTokenPassthrough asserts the downstream Authorization
// header is never forwarded to the upstream across methods.
func TestFunctional_MCP_NoTokenPassthrough(t *testing.T) {
	up := newFakeMCPUpstream(t)
	be, err := helpers.MCPBackendFromURL("svc", up.URL())
	require.NoError(t, err)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		Backends: []config.MCPBackend{be},
	})

	body := helpers.MCPRequestBody{
		Method:    helpers.MCPMethodToolsCall,
		Name:      "svc.echo",
		Arguments: map[string]any{"message": "x"},
	}.MustBuild()
	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method:        helpers.MCPMethodToolsCall,
		Name:          "svc.echo",
		Authorization: "Bearer super-secret",
	})
	require.NoError(t, err)
	_, err = helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)

	assert.Empty(t, up.lastAuthorization.Load().(string),
		"upstream must never see the downstream bearer token")
}

// TestFunctional_MCP_DryRun verifies shadow mode (HUB-507): the request is
// resolved WITHOUT invoking the upstream and a synthetic result is returned.
func TestFunctional_MCP_DryRun(t *testing.T) {
	up := newFakeMCPUpstream(t)
	be, err := helpers.MCPBackendFromURL("svc", up.URL())
	require.NoError(t, err)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		Backends: []config.MCPBackend{be},
		DryRun:   true,
	})

	body := helpers.MCPRequestBody{
		Method:    helpers.MCPMethodToolsCall,
		Name:      "svc.echo",
		Arguments: map[string]any{"message": "x"},
	}.MustBuild()
	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsCall,
		Name:   "svc.echo",
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "dry-run must resolve without an upstream error")

	assert.Equal(t, int64(0), up.callCount.Load(),
		"dry-run must NOT invoke the upstream")
}

// TestFunctional_MCP_ConfigLoadValidate verifies MCPRoute/MCPBackend config
// loads and validates through the shared validator.
func TestFunctional_MCP_ConfigLoadValidate(t *testing.T) {
	up := newFakeMCPUpstream(t)
	be, err := helpers.MCPBackendFromURL("svc", up.URL())
	require.NoError(t, err)

	cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
		Port:     18099,
		Backends: []config.MCPBackend{be},
	})

	// Validate through the production validator (mirrors config.LoadConfig).
	v := config.NewValidator()
	err = v.Validate(cfg)
	require.NoError(t, err, "MCP config must pass validation")

	require.Len(t, cfg.Spec.MCPRoutes, 1)
	require.Len(t, cfg.Spec.MCPBackends, 1)
	assert.Equal(t, "svc", cfg.Spec.MCPBackends[0].Name)
	assert.Equal(t, []string{"svc"}, cfg.Spec.MCPRoutes[0].Upstreams)
}
