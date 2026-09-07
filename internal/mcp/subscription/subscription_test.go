package subscription

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// ── test doubles ────────────────────────────────────────────────────────

type capturedEvent struct {
	event string
	data  []byte
}

// fakeWriter is a thread-safe SSEWriter capturing events and comments.
type fakeWriter struct {
	mu       sync.Mutex
	events   []capturedEvent
	comments []string
	writeErr error
}

func (w *fakeWriter) WriteEvent(event string, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	w.events = append(w.events, capturedEvent{event: event, data: append([]byte(nil), data...)})
	return nil
}

func (w *fakeWriter) WriteComment(c string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	w.comments = append(w.comments, c)
	return nil
}

func (w *fakeWriter) Flush() error { return nil }

func (w *fakeWriter) snapshot() ([]capturedEvent, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]capturedEvent(nil), w.events...), append([]string(nil), w.comments...)
}

// fakeStreamer feeds scripted events to the handler and blocks until ctx done.
type fakeStreamer struct {
	// feed sends events; if nil, the streamer just blocks until ctx done.
	feed func(ctx context.Context, upstreamID string, handler mcpproxy.SSEEventHandler)
	// endImmediately makes StreamUpstream return right away (upstream teardown).
	endImmediately bool
}

func (s *fakeStreamer) StreamUpstream(
	ctx context.Context, upstreamID string, _ *jsonrpc.Request, handler mcpproxy.SSEEventHandler,
) error {
	if s.feed != nil {
		s.feed(ctx, upstreamID, handler)
	}
	if s.endImmediately {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

type recordingInvalidator struct {
	mu    sync.Mutex
	calls [][3]string
}

func (r *recordingInvalidator) InvalidateCache(_ context.Context, upstream, kind, uri string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, [3]string{upstream, kind, uri})
}

func (r *recordingInvalidator) snapshot() [][3]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][3]string(nil), r.calls...)
}

func newTestMapper(t *testing.T, upstreams ...string) namespace.Mapper {
	t.Helper()
	m, err := namespace.NewDefaultMapper("_")
	require.NoError(t, err)
	for _, u := range upstreams {
		require.NoError(t, m.Register(u, u))
	}
	return m
}

// ── ParseFilter ─────────────────────────────────────────────────────────

func TestParseFilter(t *testing.T) {
	t.Parallel()
	params := map[string]any{
		"toolsListChanged":      true,
		"promptsListChanged":    false,
		"resourcesListChanged":  true,
		"resourceSubscriptions": []any{"up1_res://a", "", 42, "up1_res://b"},
		"unknown":               "ignored",
	}
	f := ParseFilter(params)
	assert.True(t, f.ToolsListChanged)
	assert.False(t, f.PromptsListChanged)
	assert.True(t, f.ResourcesListChanged)
	assert.Equal(t, []string{"up1_res://a", "up1_res://b"}, f.ResourceSubscriptions)
}

func TestParseFilterEmpty(t *testing.T) {
	t.Parallel()
	f := ParseFilter(map[string]any{})
	assert.False(t, f.ToolsListChanged)
	assert.Empty(t, f.ResourceSubscriptions)
}

// ── NewManager ──────────────────────────────────────────────────────────

func TestNewManagerValidation(t *testing.T) {
	t.Parallel()
	_, err := NewManager(nil, newTestMapper(t), Config{})
	assert.Error(t, err)
	_, err = NewManager(&fakeStreamer{}, nil, Config{})
	assert.Error(t, err)

	m, err := NewManager(&fakeStreamer{}, newTestMapper(t), Config{})
	require.NoError(t, err)
	assert.Equal(t, DefaultKeepAlive, m.cfg.KeepAlive)
	assert.Equal(t, DefaultDebounce, m.cfg.Debounce)
}

// ── acknowledged / complete builders ────────────────────────────────────

func TestBuildAcknowledged(t *testing.T) {
	t.Parallel()
	f := Filter{ToolsListChanged: true, ResourceSubscriptions: []string{"up1_res://a"}}
	raw, err := buildAcknowledged(json.RawMessage(`"sub-1"`), f)
	require.NoError(t, err)

	var msg map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &msg))
	var method string
	require.NoError(t, json.Unmarshal(msg["method"], &method))
	assert.Equal(t, MethodAcknowledged, method)

	var params map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msg["params"], &params))
	var filter map[string]any
	require.NoError(t, json.Unmarshal(params["filter"], &filter))
	assert.Equal(t, true, filter["toolsListChanged"])
	assert.Equal(t, false, filter["promptsListChanged"])
	assert.Contains(t, filter, "resourceSubscriptions")
}

func TestBuildComplete(t *testing.T) {
	t.Parallel()
	raw, err := buildComplete(json.RawMessage(`7`), json.RawMessage(`"sub-1"`))
	require.NoError(t, err)
	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &resp))
	assert.JSONEq(t, `7`, string(resp["id"]))
	var result map[string]any
	require.NoError(t, json.Unmarshal(resp["result"], &result))
	assert.Equal(t, "complete", result["resultType"])
}

func TestRawOrNull(t *testing.T) {
	t.Parallel()
	assert.JSONEq(t, `null`, string(rawOrNull(nil)))
	assert.JSONEq(t, `"x"`, string(rawOrNull(json.RawMessage(`"x"`))))
}

func TestMustMarshal(t *testing.T) {
	t.Parallel()
	assert.JSONEq(t, `{"a":1}`, string(mustMarshal(map[string]any{"a": 1})))
	// Unmarshalable value -> empty object fallback.
	assert.JSONEq(t, `{}`, string(mustMarshal(make(chan int))))
}

// ── Listen: ack first, then graceful complete on shutdown ───────────────

func TestListenAckThenShutdownComplete(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	streamer := &fakeStreamer{} // blocks until ctx done
	m, err := NewManager(streamer, newTestMapper(t, "up1"),
		Config{KeepAlive: time.Hour, Debounce: time.Hour})
	require.NoError(t, err)

	p := ListenParams{
		SubscriptionID: json.RawMessage(`"sub-1"`),
		RequestID:      json.RawMessage(`10`),
		Filter:         Filter{ToolsListChanged: true},
		Upstreams:      []string{"up1"},
	}

	done := make(chan error, 1)
	go func() { done <- m.Listen(context.Background(), w, p) }()

	// Wait for the acknowledged message.
	require.Eventually(t, func() bool {
		ev, _ := w.snapshot()
		return len(ev) >= 1
	}, 2*time.Second, 5*time.Millisecond)

	ev, _ := w.snapshot()
	assert.Equal(t, eventMessage, ev[0].event)
	assert.Contains(t, string(ev[0].data), MethodAcknowledged)

	// Graceful shutdown -> complete result then close.
	m.Shutdown()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Listen did not return after Shutdown (goroutine leak)")
	}

	ev, _ = w.snapshot()
	require.GreaterOrEqual(t, len(ev), 2)
	assert.Contains(t, string(ev[len(ev)-1].data), "complete")
}

func TestListenClientDisconnectNoComplete(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"),
		Config{KeepAlive: time.Hour, Debounce: time.Hour})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	p := ListenParams{SubscriptionID: json.RawMessage(`"s"`), RequestID: json.RawMessage(`1`), Upstreams: []string{"up1"}}

	done := make(chan error, 1)
	go func() { done <- m.Listen(ctx, w, p) }()

	require.Eventually(t, func() bool {
		ev, _ := w.snapshot()
		return len(ev) >= 1
	}, 2*time.Second, 5*time.Millisecond)

	cancel() // client disconnect (HUB-241): no complete emitted

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Listen did not return on client disconnect")
	}
	ev, _ := w.snapshot()
	for _, e := range ev {
		assert.NotContains(t, string(e.data), `"resultType":"complete"`)
	}
}

func TestListenUpstreamTeardownComplete(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	// Upstream ends immediately -> treated as graceful teardown -> complete.
	m, err := NewManager(&fakeStreamer{endImmediately: true}, newTestMapper(t, "up1"),
		Config{KeepAlive: time.Hour, Debounce: time.Hour})
	require.NoError(t, err)

	p := ListenParams{SubscriptionID: json.RawMessage(`"s"`), RequestID: json.RawMessage(`1`), Upstreams: []string{"up1"}}
	done := make(chan error, 1)
	go func() { done <- m.Listen(context.Background(), w, p) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Listen did not return on upstream teardown")
	}
	ev, _ := w.snapshot()
	require.NotEmpty(t, ev)
	assert.Contains(t, string(ev[len(ev)-1].data), "complete")
}

func TestListenAckWriteError(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{writeErr: assertErr("write down")}
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"), Config{})
	require.NoError(t, err)
	p := ListenParams{SubscriptionID: json.RawMessage(`"s"`), Upstreams: []string{"up1"}}
	err = m.Listen(context.Background(), w, p)
	require.Error(t, err)
}

func TestRegisterAfterShutdownRejected(t *testing.T) {
	t.Parallel()
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"), Config{})
	require.NoError(t, err)
	m.Shutdown()
	err = m.Listen(context.Background(), &fakeWriter{}, ListenParams{Upstreams: []string{"up1"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutting down")
}

func TestShutdownIdempotent(t *testing.T) {
	t.Parallel()
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"), Config{})
	require.NoError(t, err)
	m.Shutdown()
	m.Shutdown() // second call is a no-op
}

func TestManagerInvalidateNoHook(t *testing.T) {
	t.Parallel()
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"), Config{})
	require.NoError(t, err)
	// No invalidator configured -> no panic.
	m.invalidate(context.Background(), "up1", "tools", "")
}

func TestOptionsWithNil(t *testing.T) {
	t.Parallel()
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"), Config{},
		WithMetrics(nil), WithLogger(nil), WithInvalidator(nil))
	require.NoError(t, err)
	require.NotNil(t, m)
}

// assertErr is a tiny error helper.
type assertErr string

func (e assertErr) Error() string { return string(e) }
