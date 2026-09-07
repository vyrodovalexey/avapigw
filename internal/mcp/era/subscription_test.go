package era

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

func TestNewLegacySubscriptionAdapterNilPool(t *testing.T) {
	t.Parallel()
	if _, err := NewLegacySubscriptionAdapter(nil); err == nil {
		t.Fatal("want nil pool error")
	}
}

func TestResourceSubscriptionURIs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  *jsonrpc.Request
		want []string
	}{
		{"nil req", nil, nil},
		{"empty params", &jsonrpc.Request{}, nil},
		{"invalid json", &jsonrpc.Request{Params: json.RawMessage("{bad")}, nil},
		{"valid", &jsonrpc.Request{Params: json.RawMessage(`{"resourceSubscriptions":["a","b"]}`)}, []string{"a", "b"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resourceSubscriptionURIs(tt.req)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v want %v", got, tt.want)
				}
			}
		})
	}
}

func TestBuildResourceSubscribe(t *testing.T) {
	t.Parallel()
	req, err := buildResourceSubscribe(MethodResourcesSubscribe, "res://x")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != MethodResourcesSubscribe || string(req.ID) != `"sub"` {
		t.Fatalf("bad request: %+v", req)
	}
	var params map[string]string
	_ = json.Unmarshal(req.Params, &params)
	if params["uri"] != "res://x" {
		t.Fatalf("uri = %q", params["uri"])
	}
}

func TestSubscribeAllSuccess(t *testing.T) {
	t.Parallel()
	tp := okInitTransport()
	p := newLegacyPool(t, tp, nil)
	sess, _ := p.Acquire(context.Background(), "u1")
	a := &LegacySubscriptionAdapter{pool: p}
	if err := a.subscribeAll(context.Background(), sess, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	post, _, _ := tp.calls()
	// 1 init + 2 subscribes.
	if post != 3 {
		t.Fatalf("expected 3 posts, got %d", post)
	}
	p.Close()
}

func TestSubscribeAllError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, req *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if req.Method == MethodInitialize {
				return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
			}
			return nil, "", errors.New("subscribe boom")
		},
	}
	p := newLegacyPool(t, tp, nil)
	sess, _ := p.Acquire(context.Background(), "u1")
	a := &LegacySubscriptionAdapter{pool: p}
	if err := a.subscribeAll(context.Background(), sess, []string{"a"}); err == nil || !contains(err.Error(), "legacy resources/subscribe") {
		t.Fatalf("want subscribe error, got %v", err)
	}
	p.Close()
}

func TestStreamUpstreamAcquireError(t *testing.T) {
	t.Parallel()
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return nil, "", errors.New("init boom")
		},
	}
	p := newLegacyPool(t, tp, nil)
	a, _ := NewLegacySubscriptionAdapter(p)
	err := a.StreamUpstream(context.Background(), "u1", &jsonrpc.Request{}, func(mcpproxy.SSEEvent) error { return nil })
	if err == nil || !contains(err.Error(), "acquire legacy session") {
		t.Fatalf("want acquire error, got %v", err)
	}
	p.Close()
}

func TestStreamUpstreamHappy(t *testing.T) {
	t.Parallel()
	tp := okInitTransport()
	p := newLegacyPool(t, tp, nil)
	a, _ := NewLegacySubscriptionAdapter(p)

	// Acquire once so the shared session/dispatcher exists.
	sess, _ := p.Acquire(context.Background(), "u1")
	dispatcher := sess.Dispatcher()
	if dispatcher == nil {
		t.Fatal("expected dispatcher on session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	received := make(chan mcpproxy.SSEEvent, 1)
	req := &jsonrpc.Request{Params: json.RawMessage(`{"resourceSubscriptions":["res://a"]}`)}
	done := make(chan error, 1)
	go func() {
		done <- a.StreamUpstream(ctx, "u1", req, func(ev mcpproxy.SSEEvent) error {
			received <- ev
			return nil
		})
	}()

	// Wait for the relay to be registered, then push a notification.
	waitFor(t, func() bool {
		dispatcher.mu.RLock()
		defer dispatcher.mu.RUnlock()
		return len(dispatcher.relays) > 0
	})
	if err := dispatcher.handle(mcpproxy.SSEEvent{Data: []byte(`{"method":"notifications/resources/updated"}`)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not receive notification")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StreamUpstream returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamUpstream did not return after cancel")
	}
	// Relay unregistered on teardown.
	dispatcher.mu.RLock()
	n := len(dispatcher.relays)
	dispatcher.mu.RUnlock()
	if n != 0 {
		t.Fatalf("relay not unregistered, %d remain", n)
	}
	p.Close()
}

// TestStreamUpstreamNilDispatcher covers the no-dispatcher branch of
// StreamUpstream (§5.3). The public pool always installs a dispatcher, so we
// construct a session with a nil dispatcher directly (in-package white-box) and
// register it in the pool so Acquire returns it without re-initializing.
func TestStreamUpstreamNilDispatcher(t *testing.T) {
	t.Parallel()
	p := newLegacyPool(t, okInitTransport(), nil)
	sess := newSession(&fakeTransport{}, nil) // dispatcher == nil
	p.mu.Lock()
	p.sessions["u1"] = sess
	p.mu.Unlock()

	a, _ := NewLegacySubscriptionAdapter(p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- a.StreamUpstream(ctx, "u1", &jsonrpc.Request{}, func(mcpproxy.SSEEvent) error { return nil })
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StreamUpstream (nil dispatcher) returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamUpstream (nil dispatcher) did not return after cancel")
	}
	p.Close()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
