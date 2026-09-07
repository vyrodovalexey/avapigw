package era

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func newSession(tp LegacyTransport, disp *EventDispatcher) *LegacySession {
	return &LegacySession{
		upstreamID: "u1",
		transport:  tp,
		initParams: InitializeParams{ProtocolVersion: "2025-06-18"},
		metrics:    mcpmetrics.GetMetrics(),
		logger:     observability.NopLogger(),
		dispatcher: disp,
	}
}

func TestSessionInitializeHappyNoDispatcher(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
		},
	}
	s := newSession(tp, nil)
	if err := s.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.SessionID() != "sid-1" {
		t.Fatalf("session id = %q", s.SessionID())
	}
	_, note, stream := tp.calls()
	if note != 1 {
		t.Fatalf("expected 1 notification, got %d", note)
	}
	if stream != 0 {
		t.Fatal("no pump should run without dispatcher")
	}
	if tp.lastNote.Method != MethodInitialized {
		t.Fatalf("expected initialized notification, got %q", tp.lastNote.Method)
	}
}

func TestSessionInitializeWithDispatcherStartsPump(t *testing.T) {
	t.Parallel()
	streamStarted := make(chan struct{})
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
		},
		openServerStreamFn: func(ctx context.Context, _, _, _ string, _ mcpproxy.SSEEventHandler) error {
			close(streamStarted)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	disp := newEventDispatcher("u1", observability.NopLogger(), nil)
	s := newSession(tp, disp)
	if err := s.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-streamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not start")
	}
	s.close() // must cancel and join the pump
}

func TestBuildInitializeRequest(t *testing.T) {
	t.Parallel()
	p := InitializeParams{
		ProtocolVersion:  "2025-06-18",
		ClientInfoJSON:   []byte(`{"name":"hub"}`),
		CapabilitiesJSON: []byte(`{"x":1}`),
	}
	req, err := buildInitializeRequest(p)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != MethodInitialize || string(req.ID) != "1" {
		t.Fatalf("req = %+v", req)
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(req.Params, &params)
	if _, ok := params["clientInfo"]; !ok {
		t.Fatal("missing clientInfo")
	}
	if _, ok := params["capabilities"]; !ok {
		t.Fatal("missing capabilities")
	}

	// Empty client info / capabilities → keys omitted.
	req2, _ := buildInitializeRequest(InitializeParams{ProtocolVersion: "v"})
	var params2 map[string]json.RawMessage
	_ = json.Unmarshal(req2.Params, &params2)
	if _, ok := params2["clientInfo"]; ok {
		t.Fatal("clientInfo should be omitted")
	}
	if _, ok := params2["capabilities"]; ok {
		t.Fatal("capabilities should be omitted")
	}
}

func TestSessionInitializePostRequestError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return nil, "", errors.New("post boom")
		},
	}
	s := newSession(tp, nil)
	if err := s.initialize(context.Background()); err == nil || !contains(err.Error(), "legacy initialize") {
		t.Fatalf("want legacy initialize error, got %v", err)
	}
}

func TestSessionInitializeUpstreamError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Error: &jsonrpc.Error{Code: -1, Message: "no"}}, "", nil
		},
	}
	s := newSession(tp, nil)
	if err := s.initialize(context.Background()); err == nil || !contains(err.Error(), "legacy initialize rejected") {
		t.Fatalf("want rejected error, got %v", err)
	}
}

func TestSessionInitializeNotificationError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
		},
		postNotificationFn: func(context.Context, string, *jsonrpc.Request, string) error {
			return errors.New("note boom")
		},
	}
	s := newSession(tp, nil)
	if err := s.initialize(context.Background()); err == nil || !contains(err.Error(), "initialized notification") {
		t.Fatalf("want notification error, got %v", err)
	}
}

func TestSessionPostRequestHappy(t *testing.T) {
	t.Parallel()
	var seenSID string
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, sid string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			seenSID = sid
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{}`)}, "", nil
		},
	}
	s := newSession(tp, nil)
	_ = s.initialize(context.Background())
	resp, err := s.PostRequest(context.Background(), &jsonrpc.Request{Method: "tools/list"})
	if err != nil || resp == nil {
		t.Fatalf("PostRequest = %v,%v", resp, err)
	}
	if seenSID != "sid-1" {
		t.Fatalf("transport did not see current sid, got %q", seenSID)
	}
}

func TestPostOnceSessionIDRotation(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-new", nil
		},
	}
	s := newSession(tp, nil)
	s.setSessionID("sid-old")
	_, err := s.PostRequest(context.Background(), &jsonrpc.Request{Method: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if s.SessionID() != "sid-new" {
		t.Fatalf("sid not rotated: %q", s.SessionID())
	}
}

func TestPostRequestNonSessionLossError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return nil, "", errors.New("other error")
		},
	}
	s := newSession(tp, nil)
	if _, err := s.PostRequest(context.Background(), &jsonrpc.Request{Method: "m"}); err == nil {
		t.Fatal("expected error")
	}
	post, _, _ := tp.calls()
	if post != 1 {
		t.Fatalf("expected 1 post attempt (no retry), got %d", post)
	}
}

func TestPostRequestSessionLossRecovery(t *testing.T) {
	t.Parallel()
	attempts := 0
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			attempts++
			if attempts == 1 {
				return nil, "", ErrSessionLost
			}
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{}`)}, "", nil
		},
	}
	s := newSession(tp, nil)
	resp, err := s.PostRequest(context.Background(), &jsonrpc.Request{Method: "tools/list"})
	if err != nil || resp == nil {
		t.Fatalf("recovery failed: %v,%v", resp, err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 non-init post attempts, got %d", attempts)
	}
}

func TestPostRequestReinitFails(t *testing.T) {
	t.Parallel()
	initCount := 0
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				initCount++
				if initCount == 2 {
					return nil, "", errors.New("reinit boom")
				}
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return nil, "", ErrSessionLost
		},
	}
	s := newSession(tp, nil)
	_ = s.initialize(context.Background())
	_, err := s.PostRequest(context.Background(), &jsonrpc.Request{Method: "m"})
	if err == nil || !contains(err.Error(), "reinitialize after session loss") {
		t.Fatalf("want reinit error, got %v", err)
	}
}

func TestPostRequestRetryStillErrors(t *testing.T) {
	t.Parallel()
	posts := 0
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			posts++
			if posts == 1 {
				return nil, "", ErrSessionLost
			}
			return nil, "", errors.New("still broken")
		},
	}
	s := newSession(tp, nil)
	_, err := s.PostRequest(context.Background(), &jsonrpc.Request{Method: "m"})
	if err == nil || contains(err.Error(), "reinitialize") {
		t.Fatalf("want the retry error, got %v", err)
	}
}

func TestSessionPostNotification(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{}
	s := newSession(tp, nil)
	if err := s.PostNotification(context.Background(), &jsonrpc.Request{Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	_, note, _ := tp.calls()
	if note != 1 {
		t.Fatalf("expected 1 notification, got %d", note)
	}
}

func TestSessionDispatcher(t *testing.T) {
	t.Parallel()
	disp := newEventDispatcher("u1", observability.NopLogger(), nil)
	s := newSession(&fakeTransport{}, disp)
	if s.Dispatcher() != disp {
		t.Fatal("Dispatcher() mismatch")
	}
	s2 := newSession(&fakeTransport{}, nil)
	if s2.Dispatcher() != nil {
		t.Fatal("expected nil dispatcher")
	}
}

func TestSessionStopPumpNoPump(t *testing.T) {
	t.Parallel()
	s := newSession(&fakeTransport{}, nil)
	s.stopPump() // no panic
}

func TestSessionCloseIdempotent(t *testing.T) {
	t.Parallel()
	s := newSession(&fakeTransport{}, nil)
	s.close()
	s.close() // second returns immediately
}

func TestRunPumpLogsOnUnexpectedEnd(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		openServerStreamFn: func(context.Context, string, string, string, mcpproxy.SSEEventHandler) error {
			return errors.New("stream ended")
		},
	}
	disp := newEventDispatcher("u1", observability.NopLogger(), nil)
	s := newSession(tp, disp)
	done := make(chan struct{})
	go s.runPump(context.Background(), "sid", done)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runPump did not finish")
	}
}

func TestBuildInitializedNotification(t *testing.T) {
	t.Parallel()
	n := buildInitializedNotification()
	if n.Method != MethodInitialized || len(n.ID) != 0 {
		t.Fatalf("bad notification: %+v", n)
	}
}

func TestMustJSONString(t *testing.T) {
	t.Parallel()
	if string(mustJSONString("hi")) != `"hi"` {
		t.Fatalf("mustJSONString = %q", mustJSONString("hi"))
	}
}

func TestApplySessionHeader(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	applySessionHeader(h, "sid-1")
	if h.Get(HeaderMcpSessionID) != "sid-1" {
		t.Fatal("session header not set")
	}
	h2 := http.Header{}
	applySessionHeader(h2, "")
	if h2.Get(HeaderMcpSessionID) != "" {
		t.Fatal("empty session should not set header")
	}
}
