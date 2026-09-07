package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
)

// newBackendFor constructs a ServiceBackend targeting the given httptest
// server URL (plain HTTP).
func newBackendFor(t *testing.T, serverURL string) *backend.ServiceBackend {
	t.Helper()
	u, err := url.Parse(serverURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	sb, err := backend.NewBackend(config.Backend{
		Name:  "up1",
		Hosts: []config.BackendHost{{Address: u.Hostname(), Port: port}},
	})
	require.NoError(t, err)
	return sb
}

func testRequest() *jsonrpc.Request {
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
		Params:  json.RawMessage(`{}`),
	}
}

func TestCallNilArgs(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient()
	_, err := c.Call(context.Background(), nil, "/mcp", testRequest(), nil)
	assert.ErrorIs(t, err, ErrNilUpstream)

	sb := newBackendFor(t, "http://127.0.0.1:1")
	_, err = c.Call(context.Background(), sb, "/mcp", nil, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestCallSuccessAndHeaders(t *testing.T) {
	t.Parallel()
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)

	upstreamHeaders := http.Header{}
	upstreamHeaders.Set("Mcp-Session-Id", "sess-1")
	// Downstream credentials that MUST be stripped (HUB-303).
	upstreamHeaders.Set("Authorization", "Bearer downstream-token")
	upstreamHeaders.Set("Cookie", "sid=abc")
	upstreamHeaders.Set("Proxy-Authorization", "Basic xyz")

	resp, err := c.Call(context.Background(), sb, "/mcp", testRequest(), upstreamHeaders)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.JSONEq(t, `{"tools":[]}`, string(resp.Result))

	// Content negotiation headers.
	assert.Equal(t, contentTypeJSON, gotHeaders.Get("Content-Type"))
	assert.Equal(t, acceptTypes, gotHeaders.Get("Accept"))
	// Re-derived Mcp-* header forwarded.
	assert.Equal(t, "sess-1", gotHeaders.Get("Mcp-Session-Id"))
	// Downstream credentials stripped.
	assert.Empty(t, gotHeaders.Get("Authorization"))
	assert.Empty(t, gotHeaders.Get("Cookie"))
	assert.Empty(t, gotHeaders.Get("Proxy-Authorization"))
	// Body is the marshaled request.
	assert.Contains(t, string(gotBody), `"method":"tools/list"`)
}

func TestCallUpstreamErrorStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)
	_, err := c.Call(context.Background(), sb, "/mcp", testRequest(), nil)
	require.Error(t, err)
	var ue *UpstreamError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, http.StatusBadGateway, ue.StatusCode)
	assert.Contains(t, ue.Error(), "502")
}

func TestCallResponseTooLarge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 200)))
	}))
	defer srv.Close()

	c := NewHTTPHubClient(WithHubClientMaxResponseSize(100))
	sb := newBackendFor(t, srv.URL)
	_, err := c.Call(context.Background(), sb, "/mcp", testRequest(), nil)
	assert.ErrorIs(t, err, ErrResponseTooLarge)
}

func TestCallDecodeError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)
	_, err := c.Call(context.Background(), sb, "/mcp", testRequest(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode upstream response")
}

func TestCallTransportError(t *testing.T) {
	t.Parallel()
	// Point at a closed port so Do() fails.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	sb := newBackendFor(t, srv.URL)
	srv.Close() // close so the connection fails

	c := NewHTTPHubClient()
	_, err := c.Call(context.Background(), sb, "/mcp", testRequest(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream request failed")
}

// TestCallSSEResponseWithProgress proves Call parses an SSE-typed tools/call
// upstream response, relays notifications/progress to the context-scoped sink,
// and returns the terminal JSON-RPC response (HUB-244). Previously Call decoded
// only JSON and failed on an SSE body, dropping progress notifications.
func TestCallSSEResponseWithProgress(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Two progress notifications, then the terminal result.
		_, _ = io.WriteString(w,
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\","+
				"\"params\":{\"progressToken\":\"t1\",\"progress\":0.5}}\n\n")
		_, _ = io.WriteString(w,
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\","+
				"\"params\":{\"progressToken\":\"t1\",\"progress\":1.0}}\n\n")
		_, _ = io.WriteString(w,
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n")
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)

	var progress [][]byte
	ctx := WithProgressSink(context.Background(), func(raw []byte) {
		progress = append(progress, append([]byte(nil), raw...))
	})

	resp, err := c.Call(ctx, sb, "/mcp", testRequest(), nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.JSONEq(t, `{"content":[]}`, string(resp.Result))
	require.Len(t, progress, 2, "both progress notifications relayed")
	assert.Contains(t, string(progress[0]), "notifications/progress")
}

// TestCallSSENoTerminal proves an SSE stream that ends without a terminal
// response yields an error rather than a silent nil result.
func TestCallSSENoTerminal(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)
	_, err := c.Call(context.Background(), sb, "/mcp", testRequest(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal response")
}

// TestCallSSEErrorStatus proves a non-2xx SSE-typed response is surfaced as an
// UpstreamError.
func TestCallSSEErrorStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "data: boom\n\n")
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)
	_, err := c.Call(context.Background(), sb, "/mcp", testRequest(), nil)
	var ue *UpstreamError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, http.StatusBadGateway, ue.StatusCode)
}

func TestNewHTTPHubClientOptions(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient(
		WithHubClientLogger(nil),
		WithHubClientMaxResponseSize(0), // ignored (non-positive)
		WithHubClientMaxResponseSize(500),
		WithHubClientMaxSSEEventSize(0), // ignored
		WithHubClientMaxSSEEventSize(400),
	)
	assert.Equal(t, int64(500), c.maxResponseSize)
	assert.Equal(t, int64(400), c.maxSSEEventSize)
}

func TestIsDownstreamCredentialHeader(t *testing.T) {
	t.Parallel()
	assert.True(t, isDownstreamCredentialHeader("Authorization"))
	assert.True(t, isDownstreamCredentialHeader("authorization"))
	assert.True(t, isDownstreamCredentialHeader("Cookie"))
	assert.True(t, isDownstreamCredentialHeader("Proxy-Authorization"))
	assert.False(t, isDownstreamCredentialHeader("Mcp-Session-Id"))
}

func TestStripDownstreamCredentials(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("Authorization", "Bearer x")
	h.Set("Cookie", "a=b")
	h.Set("Proxy-Authorization", "y")
	h.Set("Keep", "me")
	stripDownstreamCredentials(h)
	assert.Empty(t, h.Get("Authorization"))
	assert.Empty(t, h.Get("Cookie"))
	assert.Empty(t, h.Get("Proxy-Authorization"))
	assert.Equal(t, "me", h.Get("Keep"))
}

// TestClassifySSEEvent covers the classification of SSE event payloads:
// notification, response(result/error), non-JSON, malformed, and neither.
func TestClassifySSEEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      string
		wantResp  bool
		wantNotif bool
	}{
		{name: "notification", data: `{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`, wantNotif: true},
		{name: "response result", data: `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`, wantResp: true},
		{name: "response error", data: `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, wantResp: true},
		{name: "non-JSON ignored", data: `not-json`},
		{name: "neither result nor error", data: `{"jsonrpc":"2.0","id":1}`},
		{name: "empty object", data: `{}`},
		{name: "malformed notification", data: `{"method":123}`},
		{name: "malformed response", data: `{"result":true,"id":123,"error":[}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp, notif := classifySSEEvent([]byte(tt.data))
			if tt.wantResp {
				assert.NotNil(t, resp)
			} else {
				assert.Nil(t, resp)
			}
			if tt.wantNotif {
				assert.NotNil(t, notif)
			} else {
				assert.Nil(t, notif)
			}
		})
	}
}
