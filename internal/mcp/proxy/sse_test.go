package proxy

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
)

func TestStreamNilArgs(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient()
	err := c.Stream(context.Background(), nil, "/mcp", testRequest(), nil, func(SSEEvent) error { return nil })
	assert.ErrorIs(t, err, ErrNilUpstream)

	sb := newBackendFor(t, "http://127.0.0.1:1")
	err = c.Stream(context.Background(), sb, "/mcp", nil, nil, func(SSEEvent) error { return nil })
	assert.ErrorIs(t, err, ErrNilRequest)

	err = c.Stream(context.Background(), sb, "/mcp", testRequest(), nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil SSE handler")
}

func TestStreamSSERelay(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: message\ndata: {\"a\":1}\n\n" +
			": keep-alive\n\n" +
			"event: notice\ndata: hello\ndata: world\n\n"))
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)

	var mu sync.Mutex
	var events []SSEEvent
	err := c.Stream(context.Background(), sb, "/mcp", testRequest(), nil, func(ev SSEEvent) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, ev)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "message", events[0].Event)
	assert.Equal(t, `{"a":1}`, string(events[0].Data))
	assert.Equal(t, "notice", events[1].Event)
	assert.Equal(t, "hello\nworld", string(events[1].Data))
}

func TestStreamSingleJSONFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)

	var events []SSEEvent
	err := c.Stream(context.Background(), sb, "/mcp", testRequest(), nil, func(ev SSEEvent) error {
		events = append(events, ev)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventNameMessage, events[0].Event)
	assert.Contains(t, string(events[0].Data), `"result"`)
}

func TestStreamErrorStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)
	err := c.Stream(context.Background(), sb, "/mcp", testRequest(), nil, func(SSEEvent) error { return nil })
	var ue *UpstreamError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, http.StatusServiceUnavailable, ue.StatusCode)
}

func TestStreamCtxCancelStops(t *testing.T) {
	t.Parallel()
	// Server streams slowly; cancel the context and assert the relay stops.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("event: message\ndata: {\"n\":1}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
		<-release // block until the test releases us
	}))
	defer srv.Close()
	defer close(release)

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	firstSeen := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- c.Stream(ctx, sb, "/mcp", testRequest(), nil, func(ev SSEEvent) error {
			select {
			case firstSeen <- struct{}{}:
			default:
			}
			return nil
		})
	}()

	select {
	case <-firstSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("first event not delivered")
	}
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled), "stream should end on ctx cancel, got %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not stop after ctx cancel (goroutine leak)")
	}
}

func TestStreamHandlerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: message\ndata: {\"a\":1}\n\n"))
	}))
	defer srv.Close()

	c := NewHTTPHubClient()
	sb := newBackendFor(t, srv.URL)
	handlerErr := errors.New("handler boom")
	err := c.Stream(context.Background(), sb, "/mcp", testRequest(), nil, func(SSEEvent) error {
		return handlerErr
	})
	assert.ErrorIs(t, err, handlerErr)
}

func TestIsSSEResponse(t *testing.T) {
	t.Parallel()
	sse := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}}}
	assert.True(t, isSSEResponse(sse))
	json := &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}}
	assert.False(t, isSSEResponse(json))
}

func TestRelaySSEDirect(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient()
	body := "event: a\ndata: one\n\nid: 5\nretry: 100\ndata: two\n\n"
	var events []SSEEvent
	err := c.relaySSE(context.Background(), bytes.NewReader([]byte(body)), func(ev SSEEvent) error {
		events = append(events, ev)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "a", events[0].Event)
	assert.Equal(t, "one", string(events[0].Data))
	// id/retry/unknown fields ignored; default event name "message".
	assert.Equal(t, eventNameMessage, events[1].Event)
	assert.Equal(t, "two", string(events[1].Data))
}

func TestRelaySSECommentOnlyIgnored(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient()
	var events []SSEEvent
	err := c.relaySSE(context.Background(), bytes.NewReader([]byte(": just a comment\n\n")), func(ev SSEEvent) error {
		events = append(events, ev)
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, events, "comment-only frames produce no events")
}

func TestRelaySSEEventTooLarge(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient(WithHubClientMaxSSEEventSize(10))
	big := "data: " + string(bytes.Repeat([]byte("x"), 100)) + "\n\n"
	err := c.relaySSE(context.Background(), bytes.NewReader([]byte(big)), func(SSEEvent) error { return nil })
	assert.ErrorIs(t, err, ErrSSEEventTooLarge)
}

func TestRelaySSECanceledContext(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.relaySSE(ctx, bytes.NewReader([]byte("data: x\n\ndata: y\n\n")), func(SSEEvent) error { return nil })
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestAppendSSEFieldDataAccumulationLimit(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	var name string
	// First data line fits.
	require.NoError(t, appendSSEField([]byte("data: hello"), &name, &buf, 100))
	// A second line that would exceed maxEvent triggers the size error.
	err := appendSSEField([]byte("data: "+string(bytes.Repeat([]byte("y"), 200))), &name, &buf, 100)
	assert.ErrorIs(t, err, ErrSSEEventTooLarge)
}

func TestDispatchEventEmptyDataResetsName(t *testing.T) {
	t.Parallel()
	c := NewHTTPHubClient()
	var buf bytes.Buffer
	name := "leftover"
	called := false
	require.NoError(t, c.dispatchEvent(&name, &buf, func(SSEEvent) error { called = true; return nil }))
	assert.False(t, called, "no data means no dispatch")
	assert.Equal(t, "", name, "event name reset after empty dispatch")
}

func TestRelaySingleJSONTooLarge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("z"), 100))
	}))
	defer srv.Close()

	c := NewHTTPHubClient(WithHubClientMaxResponseSize(10))
	sb := newBackendFor(t, srv.URL)
	err := c.Stream(context.Background(), sb, "/mcp", testRequest(), nil, func(SSEEvent) error { return nil })
	assert.ErrorIs(t, err, ErrResponseTooLarge)
}

func TestUpstreamErrorMessage(t *testing.T) {
	t.Parallel()
	e := &UpstreamError{StatusCode: 418, Body: "teapot"}
	assert.Contains(t, e.Error(), "418")
}

// compile-time: testRequest yields a valid encodable request.
var _ = jsonrpc.Version
