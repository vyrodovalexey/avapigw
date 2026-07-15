package proxy

// Regression tests for the GraphQL subscription relay (WP1).
//
// The original relayDirection set a 500ms read deadline and retried after
// timeouts. gorilla/websocket read errors are sticky, so the first expired
// deadline turned the relay into a busy-loop that panicked inside the library
// (after 1000 repeated reads on the failed connection) in a detached goroutine,
// crashing the whole process. These tests lock in the close-on-ctx.Done
// behavior: idle subscriptions stay alive, any relay error terminates the
// direction exactly once, and panics in relay goroutines are contained.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

const (
	// relayTestBackend is the backend name used across relay tests.
	relayTestBackend = "relay-backend"
	// relayTestConnID is the connection ID used in direct relay unit tests.
	relayTestConnID = "relay-test-conn"
	// panicRecoveredErrType is the metric error type recorded on panic recovery.
	panicRecoveredErrType = "panic_recovered"
	// relayTestTimeout bounds waits on relay termination in tests.
	relayTestTimeout = 3 * time.Second
)

// wsTestUpgrader accepts any origin for relay test backends.
var wsTestUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool { return true },
}

// syncMetricsRecorder is a goroutine-safe MetricsRecorder. Relay tests need it
// because cleanup and panic recovery record metrics from detached goroutines.
type syncMetricsRecorder struct {
	mu       sync.Mutex
	requests []mockRequest
	errors   []mockError
}

func (m *syncMetricsRecorder) RecordRequest(backend, operation string, statusCode int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, mockRequest{backend, operation, statusCode, duration})
}

func (m *syncMetricsRecorder) RecordError(backend, operation, errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, mockError{backend, operation, errorType})
}

// requestCount returns the number of recorded requests (cleanup invocations).
func (m *syncMetricsRecorder) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

// errorCountByType returns the number of recorded errors of the given type.
func (m *syncMetricsRecorder) errorCountByType(errorType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, e := range m.errors {
		if e.errorType == errorType {
			count++
		}
	}
	return count
}

// newWSPair returns a connected WebSocket server/client pair backed by an
// httptest server. All resources are released via t.Cleanup.
func newWSPair(t *testing.T) (serverConn, clientConn *websocket.Conn) {
	t.Helper()

	connCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := wsTestUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		connCh <- c
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	select {
	case serverConn = <-connCh:
	case <-time.After(relayTestTimeout):
		t.Fatal("timed out waiting for server-side WebSocket connection")
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	return serverConn, client
}

// subscriptionTestStack wires a WebSocket backend handler through the
// SubscriptionProxy and exposes a connected client plus the proxy internals.
type subscriptionTestStack struct {
	sp      *SubscriptionProxy
	metrics *syncMetricsRecorder
	client  *websocket.Conn
}

// newSubscriptionTestStack builds backend -> Proxy -> SubscriptionProxy ->
// HTTP test server -> dialed WebSocket client, and waits until the
// subscription connection is registered.
func newSubscriptionTestStack(t *testing.T, backendHandler http.HandlerFunc) *subscriptionTestStack {
	t.Helper()

	backendServer := httptest.NewServer(backendHandler)
	t.Cleanup(backendServer.Close)

	addr, port := parseHostPort(backendServer.Listener.Addr().String())

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  relayTestBackend,
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	metrics := &syncMetricsRecorder{}
	sp := NewSubscriptionProxy(p,
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = sp.HandleSubscription(r.Context(), w, r, relayTestBackend)
	}))
	t.Cleanup(proxyServer.Close)

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http")
	client, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.Eventually(t, func() bool {
		return sp.ActiveConnections() == 1
	}, 2*time.Second, 10*time.Millisecond, "expected 1 active subscription connection")

	return &subscriptionTestStack{sp: sp, metrics: metrics, client: client}
}

// echoBackendHandler returns a WebSocket handler that echoes every message.
func echoBackendHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsTestUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			msgType, msg, readErr := conn.ReadMessage()
			if readErr != nil {
				return
			}
			if writeErr := conn.WriteMessage(msgType, msg); writeErr != nil {
				return
			}
		}
	}
}

// silentBackendHandler returns a WebSocket handler that never sends anything,
// keeping both relay directions parked in blocking reads.
func silentBackendHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsTestUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				return
			}
		}
	}
}

// requireEcho sends a text message and asserts it is echoed back within the
// test timeout.
func requireEcho(t *testing.T, conn *websocket.Conn, payload string) {
	t.Helper()
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(payload)))
	requireReadMessage(t, conn, payload)
}

// requireReadMessage asserts the next message on conn equals want.
func requireReadMessage(t *testing.T, conn *websocket.Conn, want string) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(relayTestTimeout)))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, want, string(msg))
}

// ============================================================================
// (a) Idle subscription regression: >1.2s idle must not spin, panic, or drop
// the connection, and a later message must still be delivered.
// ============================================================================

func TestSubscriptionProxy_IdleSubscription_StaysAlive(t *testing.T) {
	t.Parallel()

	stack := newSubscriptionTestStack(t, echoBackendHandler())

	// Verify the relay works before going idle.
	requireEcho(t, stack.client, "before-idle")

	// Idle for longer than the old 500ms read deadline. With the old code this
	// made the sticky timeout error busy-loop and panic inside
	// gorilla/websocket, crashing the test binary.
	time.Sleep(1300 * time.Millisecond)

	// The subscription must still be registered — no cleanup, no panic.
	assert.Equal(t, 1, stack.sp.ActiveConnections(), "idle subscription must stay alive")
	assert.Zero(t, stack.metrics.requestCount(), "no cleanup may run while the subscription is idle")
	assert.Zero(t, stack.metrics.errorCountByType(panicRecoveredErrType), "no panic may occur while idle")

	// A message published after the idle period must still be delivered.
	requireEcho(t, stack.client, "after-idle")

	// Normal teardown still cleans up exactly once.
	require.NoError(t, stack.client.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")))
	require.Eventually(t, func() bool {
		return stack.sp.ActiveConnections() == 0
	}, relayTestTimeout, 10*time.Millisecond, "connection must be cleaned up after close")
}

// ============================================================================
// (b) Backend closes mid-stream: relay terminates, cleanup runs exactly once.
// ============================================================================

func TestSubscriptionProxy_BackendClosesMidStream_SingleCleanup(t *testing.T) {
	t.Parallel()

	// Backend echoes the first message, then closes abruptly mid-stream.
	backendHandler := func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsTestUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		msgType, msg, readErr := conn.ReadMessage()
		if readErr != nil {
			return
		}
		_ = conn.WriteMessage(msgType, msg)
	}

	stack := newSubscriptionTestStack(t, backendHandler)

	requireEcho(t, stack.client, "first")

	// Backend closed after the echo: the relay must terminate and clean up.
	require.Eventually(t, func() bool {
		return stack.sp.ActiveConnections() == 0
	}, relayTestTimeout, 10*time.Millisecond, "connection must be cleaned up after backend close")

	require.Eventually(t, func() bool {
		return stack.metrics.requestCount() == 1
	}, relayTestTimeout, 10*time.Millisecond, "cleanup must record the subscription")

	// The client side must be torn down as well.
	require.NoError(t, stack.client.SetReadDeadline(time.Now().Add(relayTestTimeout)))
	_, _, err := stack.client.ReadMessage()
	require.Error(t, err, "client connection must be closed after backend close")

	// Give the teardown time to prove cleanup does not run a second time.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, stack.metrics.requestCount(), "cleanup must run exactly once")
	assert.Zero(t, stack.metrics.errorCountByType(panicRecoveredErrType), "teardown must not panic")
}

// ============================================================================
// (c) Context cancellation: both connections closed, both directions return,
// no double-close panics, cleanup runs exactly once.
// ============================================================================

func TestSubscriptionProxy_ContextCancel_ClosesBothDirections(t *testing.T) {
	t.Parallel()

	stack := newSubscriptionTestStack(t, silentBackendHandler())

	// Close cancels every subscription context and closes both connections.
	stack.sp.Close()
	assert.Equal(t, 0, stack.sp.ActiveConnections())

	// The client connection must be closed promptly by the ctx watcher.
	require.NoError(t, stack.client.SetReadDeadline(time.Now().Add(relayTestTimeout)))
	_, _, err := stack.client.ReadMessage()
	require.Error(t, err, "client connection must be closed after context cancellation")

	// Both relay directions must have returned and cleanup must run exactly
	// once, despite the connections being closed from multiple paths.
	require.Eventually(t, func() bool {
		return stack.metrics.requestCount() == 1
	}, relayTestTimeout, 10*time.Millisecond, "cleanup must run after cancellation")

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, stack.metrics.requestCount(), "cleanup must run exactly once")
	assert.Zero(t, stack.metrics.errorCountByType(panicRecoveredErrType), "double close must not panic")
}

// TestRelayMessages_ContextCancel_BothConnectionsClosed drives relayMessages
// directly and asserts that canceling the context closes both proxy-side
// connections and unblocks both relay directions.
func TestRelayMessages_ContextCancel_BothConnectionsClosed(t *testing.T) {
	t.Parallel()

	clientSide, clientRemote := newWSPair(t)
	backendSide, backendRemote := newWSPair(t)

	metrics := &syncMetricsRecorder{}
	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	ctx, cancel := context.WithCancel(t.Context())
	conn := &subscriptionConn{
		clientConn:  clientSide,
		backendConn: backendSide,
		backendName: relayTestBackend,
		createdAt:   time.Now(),
		cancel:      cancel,
	}
	sp.connMu.Lock()
	sp.connections[relayTestConnID] = conn
	sp.connMu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sp.relayMessages(ctx, relayTestConnID, conn)
	}()

	// Verify the relay is live in both directions before canceling.
	require.NoError(t, clientRemote.WriteMessage(websocket.TextMessage, []byte("c2b")))
	requireReadMessage(t, backendRemote, "c2b")
	require.NoError(t, backendRemote.WriteMessage(websocket.TextMessage, []byte("b2c")))
	requireReadMessage(t, clientRemote, "b2c")

	cancel()

	// The backend->client direction (relayMessages itself) must return.
	select {
	case <-done:
	case <-time.After(relayTestTimeout):
		t.Fatal("relayMessages did not return after context cancellation")
	}

	// Both proxy-side connections must be closed: the remote peers see errors.
	require.NoError(t, clientRemote.SetReadDeadline(time.Now().Add(relayTestTimeout)))
	_, _, err := clientRemote.ReadMessage()
	require.Error(t, err, "client connection must be closed on cancel")

	require.NoError(t, backendRemote.SetReadDeadline(time.Now().Add(relayTestTimeout)))
	_, _, err = backendRemote.ReadMessage()
	require.Error(t, err, "backend connection must be closed on cancel")

	assert.Equal(t, 0, sp.ActiveConnections())
	require.Eventually(t, func() bool {
		return metrics.requestCount() == 1
	}, relayTestTimeout, 10*time.Millisecond, "cleanup must run exactly once")
	assert.Zero(t, metrics.errorCountByType(panicRecoveredErrType), "cancellation must not panic")
}

// ============================================================================
// relayDirection unit tests: any error terminates the direction (no retry).
// ============================================================================

func TestRelayDirection_ReturnsOnPeerClose_NoSpin(t *testing.T) {
	t.Parallel()

	srcSide, srcRemote := newWSPair(t)
	dstSide, _ := newWSPair(t)

	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()))

	done := make(chan struct{})
	go func() {
		defer close(done)
		sp.relayDirection(relayTestConnID, relayTestBackend, srcSide, dstSide, "src", "dst")
	}()

	// Closing the remote peer fails the blocking read; the relay must return
	// on the first (sticky) error instead of retrying it.
	require.NoError(t, srcRemote.Close())

	select {
	case <-done:
	case <-time.After(relayTestTimeout):
		t.Fatal("relayDirection did not return after peer close (busy-loop regression)")
	}
}

func TestRelayDirection_WriteError_Terminates(t *testing.T) {
	t.Parallel()

	srcSide, srcRemote := newWSPair(t)
	dstSide, _ := newWSPair(t)

	// Force writes to dst to fail.
	require.NoError(t, dstSide.Close())

	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()))

	done := make(chan struct{})
	go func() {
		defer close(done)
		sp.relayDirection(relayTestConnID, relayTestBackend, srcSide, dstSide, "src", "dst")
	}()

	require.NoError(t, srcRemote.WriteMessage(websocket.TextMessage, []byte("payload")))

	select {
	case <-done:
	case <-time.After(relayTestTimeout):
		t.Fatal("relayDirection did not return after write error")
	}
}

// ============================================================================
// Panic containment: recoverRelayPanic must swallow panics, log, and record
// the panic_recovered metric so a relay panic can never crash the process.
// ============================================================================

func TestRecoverRelayPanic_ContainsPanicAndRecordsMetric(t *testing.T) {
	t.Parallel()

	metrics := &syncMetricsRecorder{}
	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	require.NotPanics(t, func() {
		defer sp.recoverRelayPanic(relayTestConnID, relayTestBackend, "test_stage")
		panic("injected relay panic")
	})

	assert.Equal(t, 1, metrics.errorCountByType(panicRecoveredErrType))
}

func TestRecoverRelayPanic_NoPanic_NoMetric(t *testing.T) {
	t.Parallel()

	metrics := &syncMetricsRecorder{}
	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	func() {
		defer sp.recoverRelayPanic(relayTestConnID, relayTestBackend, "test_stage")
	}()

	assert.Zero(t, metrics.errorCountByType(panicRecoveredErrType))
	assert.Zero(t, metrics.requestCount())
}

func TestRecoverRelayPanic_NilMetrics_DoesNotCrash(t *testing.T) {
	t.Parallel()

	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()))

	require.NotPanics(t, func() {
		defer sp.recoverRelayPanic(relayTestConnID, relayTestBackend, "test_stage")
		panic("injected relay panic without metrics")
	})
}

// TestRecoverRelayPanic_InDetachedGoroutine proves the wiring works where it
// matters: a panic in a detached goroutine is only survivable when recovered
// inside that same goroutine.
func TestRecoverRelayPanic_InDetachedGoroutine(t *testing.T) {
	t.Parallel()

	metrics := &syncMetricsRecorder{}
	sp := NewSubscriptionProxy(New(WithLogger(observability.NopLogger())),
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer sp.recoverRelayPanic(relayTestConnID, relayTestBackend, "detached")
		panic("panic in detached relay goroutine")
	}()

	select {
	case <-done:
	case <-time.After(relayTestTimeout):
		t.Fatal("detached goroutine did not finish")
	}
	assert.Equal(t, 1, metrics.errorCountByType(panicRecoveredErrType))
}
