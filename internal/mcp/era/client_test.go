package era

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// testBackend builds a ServiceBackend named "u1" (address is irrelevant for the
// era-aware client tests: legacy paths route through the pool's fakeTransport).
func testBackend(t *testing.T, name string) *backend.ServiceBackend {
	t.Helper()
	u, _ := url.Parse("http://127.0.0.1:1")
	port, _ := strconv.Atoi(u.Port())
	sb, err := backend.NewBackend(config.Backend{
		Name:  name,
		Hosts: []config.BackendHost{{Address: u.Hostname(), Port: port}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func legacyInfo(id string) *fakeInfo {
	return &fakeInfo{info: UpstreamEraInfo{ID: id, Origin: id, ConfiguredEra: "legacy"}, ok: true}
}

func modernInfo(id string) *fakeInfo {
	return &fakeInfo{info: UpstreamEraInfo{ID: id, Origin: id, ConfiguredEra: "modern"}, ok: true}
}

func newLegacyPool(t *testing.T, tp LegacyTransport, handler ServerRequestFunc) *SessionPool {
	t.Helper()
	p, err := NewSessionPool(tp, &fakeFactory{handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewEraAwareHubClientNilArgs(t *testing.T) {
	t.Parallel()
	det := NewDeterminer(nil, nil)
	pool := newLegacyPool(t, okInitTransport(), nil)
	info := modernInfo("u1")
	prober := &stubProber{}

	if _, err := NewEraAwareHubClient(nil, det, pool, prober, info); err == nil {
		t.Fatal("want nil inner error")
	}
	if _, err := NewEraAwareHubClient(&fakeInner{}, nil, pool, prober, info); err == nil {
		t.Fatal("want nil determiner error")
	}
	if _, err := NewEraAwareHubClient(&fakeInner{}, det, nil, prober, info); err == nil {
		t.Fatal("want nil pool error")
	}
	if _, err := NewEraAwareHubClient(&fakeInner{}, det, pool, prober, nil); err == nil {
		t.Fatal("want nil info error")
	}
}

func TestCallNilUpstream(t *testing.T) {
	t.Parallel()
	c := mustClient(t, &fakeInner{}, okInitTransport(), modernInfo("u1"), nil)
	if _, err := c.Call(context.Background(), nil, "/mcp", &jsonrpc.Request{}, nil); !errors.Is(err, mcpproxy.ErrNilUpstream) {
		t.Fatalf("want ErrNilUpstream, got %v", err)
	}
}

func TestCallModernDelegates(t *testing.T) {
	t.Parallel()
	inner := &fakeInner{callResp: &jsonrpc.Response{JSONRPC: jsonrpc.Version}}
	c := mustClient(t, inner, okInitTransport(), modernInfo("u1"), nil)
	sb := testBackend(t, "u1")
	if _, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{}, nil); err != nil {
		t.Fatal(err)
	}
	if inner.callCount != 1 {
		t.Fatalf("inner.Call count = %d want 1", inner.callCount)
	}
}

func TestCallUnknownUpstreamDefaultsModern(t *testing.T) {
	t.Parallel()
	inner := &fakeInner{callResp: &jsonrpc.Response{JSONRPC: jsonrpc.Version}}
	c := mustClient(t, inner, okInitTransport(), &fakeInfo{ok: false}, nil)
	sb := testBackend(t, "u1")
	if _, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{}, nil); err != nil {
		t.Fatal(err)
	}
	if inner.callCount != 1 {
		t.Fatalf("unknown upstream should delegate modern, got %d", inner.callCount)
	}
}

func TestCallDeterminerErrorDefaultsModern(t *testing.T) {
	t.Parallel()
	inner := &fakeInner{callResp: &jsonrpc.Response{JSONRPC: jsonrpc.Version}}
	// Unpinned info + prober error → resolveEra defaults modern.
	info := &fakeInfo{info: UpstreamEraInfo{ID: "u1", Origin: "u1"}, ok: true}
	det := NewDeterminer(NewEraCache(), nil)
	pool := newLegacyPool(t, okInitTransport(), nil)
	c, err := NewEraAwareHubClient(inner, det, pool, &stubProber{err: errors.New("probe boom")}, info)
	if err != nil {
		t.Fatal(err)
	}
	sb := testBackend(t, "u1")
	if _, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{}, nil); err != nil {
		t.Fatal(err)
	}
	if inner.callCount != 1 {
		t.Fatalf("determiner error should delegate modern, got %d", inner.callCount)
	}
}

func TestCallLegacyNoBridge(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"x":1}`)}, "", nil
		},
	}
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), nil)
	sb := testBackend(t, "u1")
	resp, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "tools/list"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(resp.Result, &obj)
	if _, ok := obj[resultTypeField]; !ok {
		t.Fatal("expected modern resultType injected")
	}
}

func TestCallLegacyAcquireError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return nil, "", errors.New("init boom")
		},
	}
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), nil)
	sb := testBackend(t, "u1")
	if _, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "m"}, nil); err == nil {
		t.Fatal("expected acquire error")
	}
}

func TestCallLegacyPostRequestErrorNoBridge(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return nil, "", errors.New("post boom")
		},
	}
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), nil)
	sb := testBackend(t, "u1")
	if _, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "m"}, nil); err == nil {
		t.Fatal("expected post error")
	}
}

func TestCallLegacyCorrelatedDirectResponse(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"x":1}`)}, "", nil
		},
	}
	bridge, _ := NewServerInitiatedBridge(realSealer(), nil)
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), bridge)
	sb := testBackend(t, "u1")
	resp, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "tools/list"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(resp.Result, &obj)
	if _, ok := obj[resultTypeField]; !ok {
		t.Fatal("expected modern resultType")
	}
}

func TestCallLegacyCorrelatedPostError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return nil, "", errors.New("post boom")
		},
	}
	bridge, _ := NewServerInitiatedBridge(realSealer(), nil)
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), bridge)
	sb := testBackend(t, "u1")
	if _, err := c.Call(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "m"}, nil); err == nil {
		t.Fatal("expected post error")
	}
}

func TestCallLegacyCorrelatedServerInitiated(t *testing.T) {
	t.Parallel()
	bridge, _ := NewServerInitiatedBridge(realSealer(), nil)
	// PostRequest returns nil resp; a server-initiated request is delivered via
	// HandleServerRequest concurrently to resolve the pending call.
	tp := &fakeTransport{
		postRequestFn: func(ctx context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			// Deliver a server-initiated request to the bridge.
			_ = bridge.HandleServerRequest(ctx, "u1",
				&jsonrpc.Request{ID: json.RawMessage("9"), Method: LegacyMethodSamplingCreate})
			return nil, "", nil
		},
	}
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), bridge)
	sb := testBackend(t, "u1")
	req := &jsonrpc.Request{ID: json.RawMessage("1"), Method: "tools/list"}
	resp, err := c.Call(context.Background(), sb, "/mcp", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.ID) != "1" {
		t.Fatalf("id = %q want request id", string(resp.ID))
	}
	var body map[string]json.RawMessage
	_ = json.Unmarshal(resp.Result, &body)
	if _, ok := body["resultType"]; !ok {
		t.Fatal("expected input_required result")
	}
}

func TestOutcomeToResponse(t *testing.T) {
	t.Parallel()
	req := &jsonrpc.Request{ID: json.RawMessage("7")}
	// Response arm.
	out, err := outcomeToResponse(req, PendingOutcome{Response: &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"x":1}`)}})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(out.Result, &obj)
	if _, ok := obj[resultTypeField]; !ok {
		t.Fatal("expected translated modern result")
	}
	// InputRequired arm.
	out2, err := outcomeToResponse(req, PendingOutcome{InputRequired: json.RawMessage(`{"resultType":"input_required"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if string(out2.ID) != "7" {
		t.Fatalf("id = %q", string(out2.ID))
	}
}

func TestStreamNilUpstream(t *testing.T) {
	t.Parallel()
	c := mustClient(t, &fakeInner{}, okInitTransport(), modernInfo("u1"), nil)
	err := c.Stream(context.Background(), nil, "/mcp", &jsonrpc.Request{}, nil, func(mcpproxy.SSEEvent) error { return nil })
	if !errors.Is(err, mcpproxy.ErrNilUpstream) {
		t.Fatalf("want ErrNilUpstream, got %v", err)
	}
}

func TestStreamModernDelegates(t *testing.T) {
	t.Parallel()
	inner := &fakeInner{}
	c := mustClient(t, inner, okInitTransport(), modernInfo("u1"), nil)
	sb := testBackend(t, "u1")
	if err := c.Stream(context.Background(), sb, "/mcp", &jsonrpc.Request{}, nil, func(mcpproxy.SSEEvent) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if inner.streamCount != 1 {
		t.Fatalf("inner.Stream count = %d want 1", inner.streamCount)
	}
}

func TestStreamLegacy(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"x":1}`)}, "", nil
		},
	}
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), nil)
	sb := testBackend(t, "u1")
	var events []mcpproxy.SSEEvent
	err := c.Stream(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "tools/list"}, nil,
		func(ev mcpproxy.SSEEvent) error { events = append(events, ev); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Event != eventNameMessage {
		t.Fatalf("expected 1 message event, got %+v", events)
	}
}

func TestStreamLegacyCallError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return nil, "", errors.New("init boom")
		},
	}
	called := false
	c := mustClient(t, &fakeInner{}, tp, legacyInfo("u1"), nil)
	sb := testBackend(t, "u1")
	err := c.Stream(context.Background(), sb, "/mcp", &jsonrpc.Request{Method: "m"}, nil,
		func(mcpproxy.SSEEvent) error { called = true; return nil })
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("handler must not be called on error")
	}
}

func TestOrigin(t *testing.T) {
	t.Parallel()
	if Origin("u1") != "u1" {
		t.Fatal("Origin should return upstream id unchanged")
	}
}

func mustClient(t *testing.T, inner mcpproxy.HubClient, tp LegacyTransport, info UpstreamInfoProvider, bridge *ServerInitiatedBridge) *EraAwareHubClient {
	t.Helper()
	det := NewDeterminer(NewEraCache(), nil)
	pool := newLegacyPool(t, tp, nil)
	opts := []ClientOption{WithClientLogger(nil), WithClientLogger(observability.NopLogger())}
	if bridge != nil {
		opts = append(opts, WithClientBridge(bridge))
	}
	c, err := NewEraAwareHubClient(inner, det, pool, &stubProber{era: EraLegacy}, info, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
