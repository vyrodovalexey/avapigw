package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// ----------------------------------------------------------------------------
// Fake hub client
// ----------------------------------------------------------------------------

// fakeHub is a test double for mcpproxy.HubClient. It records the last Call and
// returns a canned response (or error).
type fakeHub struct {
	resp *jsonrpc.Response
	err  error

	// captured inputs from the last Call.
	calledPath    string
	calledReq     *jsonrpc.Request
	calledHeaders http.Header
	callCount     int
}

func (f *fakeHub) Call(
	_ context.Context,
	_ *backend.ServiceBackend,
	upstreamPath string,
	req *jsonrpc.Request,
	upstreamHeaders http.Header,
) (*jsonrpc.Response, error) {
	f.callCount++
	f.calledPath = upstreamPath
	f.calledReq = req
	f.calledHeaders = upstreamHeaders
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeHub) Stream(
	_ context.Context,
	_ *backend.ServiceBackend,
	_ string,
	_ *jsonrpc.Request,
	_ http.Header,
	_ mcpproxy.SSEEventHandler,
) error {
	return nil
}

// ----------------------------------------------------------------------------
// Fake backend registry
// ----------------------------------------------------------------------------

// fakeBackendRegistry resolves upstream names to real *backend.ServiceBackend
// values so resolveBackend's type assertion succeeds.
type fakeBackendRegistry struct {
	backends map[string]backend.Backend
}

func (r *fakeBackendRegistry) Get(name string) (backend.Backend, bool) {
	b, ok := r.backends[name]
	return b, ok
}

// newServiceBackend builds a real ServiceBackend pointed at a dummy address.
// The fake hub ignores the backend, so the address is never dialed.
func newServiceBackend(t *testing.T, name string) *backend.ServiceBackend {
	t.Helper()
	sb, err := backend.NewBackend(config.Backend{
		Name:  name,
		Hosts: []config.BackendHost{{Address: "127.0.0.1", Port: 9}},
	})
	require.NoError(t, err)
	return sb
}

// newServiceBackendFor builds a real ServiceBackend pointed at an httptest
// server URL so the real HTTP hub client can reach it.
func newServiceBackendFor(t *testing.T, name, serverURL string) *backend.ServiceBackend {
	t.Helper()
	u, err := url.Parse(serverURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	sb, err := backend.NewBackend(config.Backend{
		Name:  name,
		Hosts: []config.BackendHost{{Address: u.Hostname(), Port: port}},
	})
	require.NoError(t, err)
	return sb
}

// ----------------------------------------------------------------------------
// Fake token validator
// ----------------------------------------------------------------------------

// fakeTokenValidator returns a canned TokenInfo/err based on the presented
// token so authz paths can be exercised deterministically.
type fakeTokenValidator struct {
	info *oidc.TokenInfo
	err  error
}

// errInvalidTestToken is returned by the fake validator for empty tokens.
var errInvalidTestToken = errors.New("invalid test token")

func (v *fakeTokenValidator) Validate(_ context.Context, token string) (*oidc.TokenInfo, error) {
	if v.err != nil {
		return nil, v.err
	}
	if token == "" {
		return nil, errInvalidTestToken
	}
	return v.info, nil
}

// ----------------------------------------------------------------------------
// Request building
// ----------------------------------------------------------------------------

const testProtocolVersion = protocol.LatestVersion

// mcpBody is a convenience builder for a JSON-RPC request body carrying the
// required _meta (protocolVersion + clientCapabilities).
type mcpBody struct {
	method string
	name   string // primitive name (params.name); empty omits it
	extra  map[string]any
	// omitMeta / omitVersion / omitCaps control the _meta discipline for
	// negative tests.
	omitMeta    bool
	omitVersion bool
	omitCaps    bool
	version     string // override protocol version in _meta
}

func (b mcpBody) build(t *testing.T) []byte {
	t.Helper()
	params := map[string]any{}
	if b.name != "" {
		params["name"] = b.name
	}
	for k, v := range b.extra {
		params[k] = v
	}
	if !b.omitMeta {
		meta := map[string]any{}
		version := b.version
		if version == "" {
			version = testProtocolVersion
		}
		if !b.omitVersion {
			meta[protocol.MetaProtocolVersion] = version
		}
		if !b.omitCaps {
			meta[protocol.MetaClientCapabilities] = map[string]any{}
		}
		params["_meta"] = meta
	}
	rawParams, err := json.Marshal(params)
	require.NoError(t, err)
	req := map[string]any{
		"jsonrpc": jsonrpc.Version,
		"id":      1,
		"method":  b.method,
		"params":  json.RawMessage(rawParams),
	}
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	return raw
}

// newMCPRequest constructs a POST request to /mcp with the mirrored headers set
// for the given method/name and a valid protocol version header.
func newMCPRequest(t *testing.T, body []byte, method, name string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(headers.HeaderMcpProtocolVersion, testProtocolVersion)
	if method != "" {
		r.Header.Set(headers.HeaderMcpMethod, method)
	}
	if name != "" {
		r.Header.Set(headers.HeaderMcpName, name)
	}
	return r
}

// decodeRPCResponse decodes a recorded JSON-RPC response body.
func decodeRPCResponse(t *testing.T, body []byte) *jsonrpc.Response {
	t.Helper()
	var resp jsonrpc.Response
	require.NoError(t, json.Unmarshal(body, &resp))
	return &resp
}

// testUpstreamName is the single upstream backend name used across handler
// tests.
const testUpstreamName = "mcp-backend"

// testNamespacePrefix is the namespace prefix (== upstream name by default), so
// a namespaced tool "mcp-backend.weather" de-namespaces to upstream
// "mcp-backend" and original "weather".
const testNamespacePrefix = testUpstreamName

// handlerHarness bundles a handler and its injected fakes for assertions.
type handlerHarness struct {
	handler *MCPHandler
	hub     *fakeHub
}

// newTestHandler builds an MCPHandler with a single upstream backed by the
// provided fake hub, plus a catch-all route. Extra options are appended so
// individual tests can enable authz/dry-run/limits.
func newTestHandler(t *testing.T, hub *fakeHub, extra ...MCPHandlerOption) *handlerHarness {
	t.Helper()

	routes := []config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {
			Name:            testUpstreamName,
			NamespacePrefix: testNamespacePrefix,
			Hosts:           []config.BackendHost{{Address: "127.0.0.1", Port: 9}},
		},
	}
	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}

	opts := []MCPHandlerOption{
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(hub),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
	}
	opts = append(opts, extra...)

	h, err := NewMCPHandler(opts...)
	require.NoError(t, err)
	return &handlerHarness{handler: h, hub: hub}
}

// mustServerInfo returns the hub serverInfo injected into results.
func mustServerInfo() meta.Info {
	return meta.Info{Name: "avapigw-hub", Version: "test"}
}

// okListResponse builds a canned successful tools/list JSON-RPC response.
func okListResponse(t *testing.T) *jsonrpc.Response {
	t.Helper()
	resp, err := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]any{"tools": []any{}})
	require.NoError(t, err)
	return resp
}

// okCallResponse builds a canned successful tools/call JSON-RPC response with a
// single text content block.
func okCallResponse(t *testing.T) *jsonrpc.Response {
	t.Helper()
	resp, err := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "sunny"}},
	})
	require.NoError(t, err)
	return resp
}
