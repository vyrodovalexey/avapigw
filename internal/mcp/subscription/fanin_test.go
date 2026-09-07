package subscription

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// newSub builds a subscription wired to a fakeWriter for fan-in tests.
func newSub(t *testing.T, w *fakeWriter, inv CacheInvalidator, debounce time.Duration, p ListenParams) *subscription {
	t.Helper()
	opts := []Option{}
	if inv != nil {
		opts = append(opts, WithInvalidator(inv))
	}
	m, err := NewManager(&fakeStreamer{}, newTestMapper(t, "up1"), Config{Debounce: debounce}, opts...)
	require.NoError(t, err)
	return newSubscription(m, w, p)
}

func evt(data string) mcpproxy.SSEEvent {
	return mcpproxy.SSEEvent{Event: "message", Data: []byte(data)}
}

func TestHandleUpstreamEventDropsRequestScoped(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})

	// progress and message are request-scoped and must not flow (HUB-227).
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1",
		evt(`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`)))
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1",
		evt(`{"jsonrpc":"2.0","method":"notifications/message","params":{}}`)))

	ev, _ := w.snapshot()
	assert.Empty(t, ev, "request-scoped notifications dropped")
}

func TestHandleUpstreamEventNonNotificationIgnored(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})
	// A response (no method) is not a notification.
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1",
		evt(`{"jsonrpc":"2.0","id":1,"result":{}}`)))
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(`not-json`)))
	ev, _ := w.snapshot()
	assert.Empty(t, ev)
}

func TestHandleUpstreamEventRewritesURIAndSubscriptionID(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"sub-77"`)})

	data := `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"res://a","_meta":{"io.modelcontextprotocol/subscriptionId":"upstream-id"}}}`
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(data)))

	ev, _ := w.snapshot()
	require.Len(t, ev, 1)
	var out map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(ev[0].data, &out))
	var params map[string]any
	require.NoError(t, json.Unmarshal(out["params"], &params))
	// URI re-namespaced to hub-visible form.
	assert.Equal(t, "up1_res://a", params["uri"])
	// subscriptionId rewritten to the downstream value.
	meta := params["_meta"].(map[string]any)
	assert.Equal(t, "sub-77", meta[protocol.MetaSubscriptionID])
}

func TestHandleUpstreamEventStampsSubscriptionIDWhenNoMeta(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"sub-1"`)})
	data := `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"res://x"}}`
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(data)))
	ev, _ := w.snapshot()
	require.Len(t, ev, 1)
	var out map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(ev[0].data, &out))
	var params map[string]any
	require.NoError(t, json.Unmarshal(out["params"], &params))
	meta := params["_meta"].(map[string]any)
	assert.Equal(t, "sub-1", meta[protocol.MetaSubscriptionID])
}

func TestCoalesceListChanged(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})

	lc := `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(lc)))
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(lc)))

	ev, _ := w.snapshot()
	assert.Len(t, ev, 1, "identical list_changed within debounce coalesced")
}

func TestCoalesceDistinctResourcesNotCoalesced(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})

	u1 := `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"res://a"}}`
	u2 := `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"res://b"}}`
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(u1)))
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(u2)))

	ev, _ := w.snapshot()
	assert.Len(t, ev, 2, "distinct resources/updated never coalesced")
}

func TestCoalesceOutsideDebounceWindow(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	// Debounce of 1ms: two events spaced apart are both forwarded.
	sub := newSub(t, w, nil, time.Millisecond, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})

	lc := `{"jsonrpc":"2.0","method":"notifications/prompts/list_changed","params":{}}`
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(lc)))
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(lc)))

	ev, _ := w.snapshot()
	assert.Len(t, ev, 2)
}

func TestFireInvalidation(t *testing.T) {
	t.Parallel()
	inv := &recordingInvalidator{}
	w := &fakeWriter{}
	sub := newSub(t, w, inv, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})

	cases := []struct {
		method string
		want   [3]string
	}{
		{MethodToolsListChanged, [3]string{"up1", kindTools, ""}},
		{MethodPromptsListChanged, [3]string{"up1", kindPrompts, ""}},
		{MethodResourcesListChanged, [3]string{"up1", kindResources, ""}},
	}
	for _, tc := range cases {
		data := `{"jsonrpc":"2.0","method":"` + tc.method + `","params":{}}`
		require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1", evt(data)))
	}
	// resources/updated with uri.
	require.NoError(t, sub.handleUpstreamEvent(context.Background(), "up1",
		evt(`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"res://z"}}`)))

	calls := inv.snapshot()
	require.Len(t, calls, 4)
	assert.Equal(t, [3]string{"up1", kindResources, "res://z"}, calls[3])
}

func TestHandleUpstreamEventStopsWhenDone(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})
	sub.stop() // close done

	err := sub.handleUpstreamEvent(context.Background(), "up1",
		evt(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestHandleUpstreamEventWriteError(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{writeErr: assertErr("boom")}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})
	err := sub.handleUpstreamEvent(context.Background(), "up1",
		evt(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`))
	require.Error(t, err)
}

func TestParseNotification(t *testing.T) {
	t.Parallel()
	n, ok := parseNotification([]byte(`{"method":"m","params":{"a":1}}`))
	require.True(t, ok)
	assert.Equal(t, "m", n.Method)

	_, ok = parseNotification([]byte(`{"id":1}`))
	assert.False(t, ok)
	_, ok = parseNotification([]byte(`bad`))
	assert.False(t, ok)
}

func TestDecodeParams(t *testing.T) {
	t.Parallel()
	assert.Empty(t, decodeParams(nil))
	assert.Equal(t, map[string]any{"a": float64(1)}, decodeParams(json.RawMessage(`{"a":1}`)))
}

func TestIsRequestScopedAndListChanged(t *testing.T) {
	t.Parallel()
	assert.True(t, isRequestScoped("notifications/progress"))
	assert.True(t, isRequestScoped("notifications/message"))
	assert.False(t, isRequestScoped("notifications/tools/list_changed"))

	assert.True(t, isListChanged(MethodToolsListChanged))
	assert.True(t, isListChanged(MethodResourcesListChanged))
	assert.False(t, isListChanged(MethodResourcesUpdated))
}

func TestRawSubscriptionID(t *testing.T) {
	t.Parallel()
	assert.Nil(t, rawSubscriptionID(nil))
	assert.Equal(t, "x", rawSubscriptionID(json.RawMessage(`"x"`)))
	assert.EqualValues(t, 5, rawSubscriptionID(json.RawMessage(`5`)))
	// Invalid JSON falls back to the raw string.
	assert.Equal(t, "raw", rawSubscriptionID(json.RawMessage(`raw`)))
}

func TestBuildUpstreamRequestDenamespacesURIs(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{
		SubscriptionID: json.RawMessage(`"s"`),
		Filter: Filter{
			ToolsListChanged:      true,
			ResourceSubscriptions: []string{"up1_res://a", "unknown_uri"},
		},
		UpstreamMeta: json.RawMessage(`{"k":"v"}`),
	})
	req := sub.buildUpstreamRequest()
	var params map[string]any
	require.NoError(t, json.Unmarshal(req.Params, &params))
	// Only the resolvable URI is de-namespaced and kept.
	subs := params["resourceSubscriptions"].([]any)
	assert.Equal(t, []any{"res://a"}, subs)
	assert.Contains(t, params, "_meta")
}

func TestDenamespaceURIsEmpty(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	sub := newSub(t, w, nil, time.Hour, ListenParams{SubscriptionID: json.RawMessage(`"s"`)})
	assert.Empty(t, sub.denamespaceURIs())
}
