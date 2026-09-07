package era

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func newTestDispatcher(sr func(ctx context.Context, upstreamID string, req *jsonrpc.Request) error) *EventDispatcher {
	return newEventDispatcher("u1", observability.NopLogger(), sr)
}

func TestRegisterUnregisterRelay(t *testing.T) {
	t.Parallel()
	d := newTestDispatcher(nil)
	var mu sync.Mutex
	var got1, got2 int
	t1 := d.registerRelay(func(mcpproxy.SSEEvent) error { mu.Lock(); got1++; mu.Unlock(); return nil })
	t2 := d.registerRelay(func(mcpproxy.SSEEvent) error { mu.Lock(); got2++; mu.Unlock(); return nil })
	if t1 == t2 {
		t.Fatalf("expected distinct tokens, got %d and %d", t1, t2)
	}
	d.unregisterRelay(t1)
	// A notification now only reaches the remaining relay.
	ev := mcpproxy.SSEEvent{Data: []byte(`{"method":"notifications/resources/updated"}`)}
	if err := d.handle(ev); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got1 != 0 {
		t.Fatalf("unregistered relay was called %d times", got1)
	}
	if got2 != 1 {
		t.Fatalf("remaining relay called %d times want 1", got2)
	}
}

func TestHandleUnparseable(t *testing.T) {
	t.Parallel()
	d := newTestDispatcher(nil)
	if err := d.handle(mcpproxy.SSEEvent{Data: []byte("{bad")}); err != nil {
		t.Fatalf("unparseable event should be dropped with nil err, got %v", err)
	}
}

func TestHandleServerInitiatedRequestRouted(t *testing.T) {
	t.Parallel()
	var captured *jsonrpc.Request
	d := newTestDispatcher(func(_ context.Context, _ string, req *jsonrpc.Request) error {
		captured = req
		return nil
	})
	ev := mcpproxy.SSEEvent{Data: []byte(`{"id":1,"method":"sampling/createMessage","params":{"a":1}}`)}
	if err := d.handle(ev); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("server request not routed")
	}
	if captured.Method != "sampling/createMessage" {
		t.Fatalf("method = %q", captured.Method)
	}
	if string(captured.ID) != "1" {
		t.Fatalf("id = %q", string(captured.ID))
	}
	if string(captured.Params) != `{"a":1}` {
		t.Fatalf("params = %q", string(captured.Params))
	}
}

func TestHandleServerRequestNilHandler(t *testing.T) {
	t.Parallel()
	d := newTestDispatcher(nil)
	ev := mcpproxy.SSEEvent{Data: []byte(`{"id":1,"method":"sampling/createMessage"}`)}
	if err := d.handle(ev); err != nil {
		t.Fatalf("nil handler should drop, got %v", err)
	}
}

func TestHandleSuppressedMethod(t *testing.T) {
	t.Parallel()
	d := newTestDispatcher(nil)
	called := false
	d.registerRelay(func(mcpproxy.SSEEvent) error { called = true; return nil })
	ev := mcpproxy.SSEEvent{Data: []byte(`{"method":"ping"}`)}
	if err := d.handle(ev); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("suppressed method should not fan out")
	}
}

func TestHandleNotificationFanOut(t *testing.T) {
	t.Parallel()
	d := newTestDispatcher(nil)
	var mu sync.Mutex
	count := 0
	d.registerRelay(func(mcpproxy.SSEEvent) error { mu.Lock(); count++; mu.Unlock(); return nil })
	d.registerRelay(func(mcpproxy.SSEEvent) error { mu.Lock(); count++; mu.Unlock(); return nil })
	ev := mcpproxy.SSEEvent{Data: []byte(`{"method":"notifications/resources/updated"}`)}
	if err := d.handle(ev); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Fatalf("fan-out reached %d relays want 2", count)
	}
}

func TestFanOutRelayErrorTolerated(t *testing.T) {
	t.Parallel()
	d := newTestDispatcher(nil)
	second := false
	d.registerRelay(func(mcpproxy.SSEEvent) error { return errors.New("relay boom") })
	d.registerRelay(func(mcpproxy.SSEEvent) error { second = true; return nil })
	ev := mcpproxy.SSEEvent{Data: []byte(`{"method":"notifications/resources/updated"}`)}
	if err := d.handle(ev); err != nil {
		t.Fatalf("relay error must be tolerated, got %v", err)
	}
	if !second {
		t.Fatal("second relay should still be invoked despite first error")
	}
}

func TestIsServerInitiatedRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		msg  *eventMessage
		want bool
	}{
		{"has id + known method", &eventMessage{ID: json.RawMessage("1"), Method: "sampling/createMessage"}, true},
		{"no id", &eventMessage{Method: "sampling/createMessage"}, false},
		{"has id + unknown method", &eventMessage{ID: json.RawMessage("1"), Method: "tools/list"}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isServerInitiatedRequest(tt.msg); got != tt.want {
				t.Fatalf("isServerInitiatedRequest=%v want %v", got, tt.want)
			}
		})
	}
}

func TestParseEventMessage(t *testing.T) {
	t.Parallel()
	msg, err := parseEventMessage([]byte(`{"method":"m","id":5}`))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Method != "m" {
		t.Fatalf("method = %q", msg.Method)
	}
	if _, err := parseEventMessage([]byte("{bad")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
