// Package proxy provides tests for the WebSocket origin allowlist policy
// (CSWSH protection) and the relay message-counter integrity under -race.
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================================
// Test helpers
// ============================================================================

// countingLogger counts Warn calls per message for warn-once assertions.
type countingLogger struct {
	mu    sync.Mutex
	warns map[string]int
}

func newCountingLogger() *countingLogger {
	return &countingLogger{warns: make(map[string]int)}
}

func (l *countingLogger) warnCount(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.warns[msg]
}

func (l *countingLogger) Debug(string, ...observability.Field) { /* no-op: not asserted */ }
func (l *countingLogger) Info(string, ...observability.Field)  { /* no-op: not asserted */ }
func (l *countingLogger) Warn(msg string, _ ...observability.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns[msg]++
}
func (l *countingLogger) Error(string, ...observability.Field) { /* no-op: not asserted */ }
func (l *countingLogger) Fatal(string, ...observability.Field) { /* no-op: not asserted */ }
func (l *countingLogger) With(...observability.Field) observability.Logger {
	return l
}
func (l *countingLogger) WithContext(context.Context) observability.Logger {
	return l
}
func (l *countingLogger) Sync() error { return nil }

// startWSEchoBackend starts a WebSocket echo backend for proxy tests and
// returns its URL plus a counter of requests that reached the backend.
func startWSEchoBackend(t *testing.T) (*url.URL, *atomic.Int64) {
	t.Helper()

	hits := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		up := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
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
	}))
	t.Cleanup(server.Close)

	backendURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	return backendURL, hits
}

// startWSProxy starts a proxy server that relays to backendURL using the
// given origin policy and returns its ws:// URL.
func startWSProxy(t *testing.T, backendURL *url.URL, policy *wsOriginPolicy) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger(), originPolicy: policy}
		_, _, _ = wp.proxyWebSocket(w, r, backendURL, nil)
	}))
	t.Cleanup(server.Close)

	return "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
}

// dialWS dials a WebSocket URL with an optional Origin header.
func dialWS(wsURL, origin string) (*websocket.Conn, *http.Response, error) {
	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	return dialer.Dial(wsURL, header)
}

// requireEcho sends a message and asserts it is echoed back.
func requireEcho(t *testing.T, conn *websocket.Conn, payload string) {
	t.Helper()

	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(payload)))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, payload, string(msg))
}

// ============================================================================
// wsOriginPolicy unit tests
// ============================================================================

func TestWSOriginPolicy_Allow(t *testing.T) {
	t.Parallel()

	allowlist := &config.WebSocketConfig{AllowedOrigins: []string{
		"https://app.example.com",
		"push.example.com",
		"wss://stream.example.com",
	}}

	tests := []struct {
		name    string
		cfg     *config.WebSocketConfig
		origin  string
		reqHost string
		want    bool
	}{
		{
			name: "nil config permissive allows any origin",
			cfg:  nil, origin: "https://evil.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name: "empty allowlist permissive allows any origin",
			cfg:  &config.WebSocketConfig{}, origin: "https://evil.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name:   "wildcard entry allows any origin",
			cfg:    &config.WebSocketConfig{AllowedOrigins: []string{config.WSOriginWildcard}},
			origin: "https://evil.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name: "no origin header always allowed",
			cfg:  allowlist, origin: "", reqHost: "gw.example.com", want: true,
		},
		{
			name: "exact scheme+host entry allowed",
			cfg:  allowlist, origin: "https://app.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name: "scheme mismatch against scheme entry rejected",
			cfg:  allowlist, origin: "http://app.example.com", reqHost: "gw.example.com", want: false,
		},
		{
			name: "host-only entry matches https",
			cfg:  allowlist, origin: "https://push.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name: "host-only entry matches http",
			cfg:  allowlist, origin: "http://push.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name: "wss entry normalized matches https origin",
			cfg:  allowlist, origin: "https://stream.example.com", reqHost: "gw.example.com", want: true,
		},
		{
			name: "unlisted origin rejected",
			cfg:  allowlist, origin: "https://evil.example.com", reqHost: "gw.example.com", want: false,
		},
		{
			name: "same-origin allowed when list non-empty",
			cfg:  allowlist, origin: "https://gw.example.com:8443", reqHost: "gw.example.com:8443", want: true,
		},
		{
			name: "same-origin case-insensitive",
			cfg:  allowlist, origin: "https://GW.Example.COM", reqHost: "gw.example.com", want: true,
		},
		{
			name: "origin case normalized against allowlist",
			cfg:  allowlist, origin: "HTTPS://APP.EXAMPLE.COM", reqHost: "gw.example.com", want: true,
		},
		{
			name: "malformed origin rejected fail-closed",
			cfg:  allowlist, origin: "http://[::1", reqHost: "gw.example.com", want: false,
		},
		{
			name: "origin with path rejected fail-closed",
			cfg:  allowlist, origin: "https://app.example.com/page", reqHost: "gw.example.com", want: false,
		},
		{
			name: "port mismatch rejected",
			cfg:  allowlist, origin: "https://app.example.com:8443", reqHost: "gw.example.com", want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := newWSOriginPolicy(tt.cfg, observability.NopLogger())
			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			req.Host = tt.reqHost
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			assert.Equal(t, tt.want, policy.allow(req))
		})
	}
}

func TestNewWSOriginPolicy_PermissiveWarnsOnce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *config.WebSocketConfig
		wantWarns int
	}{
		{name: "nil config warns once", cfg: nil, wantWarns: 1},
		{name: "empty allowlist warns once", cfg: &config.WebSocketConfig{}, wantWarns: 1},
		{
			name:      "explicit wildcard does not warn",
			cfg:       &config.WebSocketConfig{AllowedOrigins: []string{config.WSOriginWildcard}},
			wantWarns: 0,
		},
		{
			name:      "allowlist does not warn",
			cfg:       &config.WebSocketConfig{AllowedOrigins: []string{"https://app.example.com"}},
			wantWarns: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := newCountingLogger()
			policy := newWSOriginPolicy(tt.cfg, logger)
			require.NotNil(t, policy)

			// The warning is tied to construction (startup), not to
			// request evaluation: evaluate several requests and verify
			// the count does not grow.
			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			req.Header.Set("Origin", "https://any.example.com")
			for i := 0; i < 3; i++ {
				policy.allow(req)
			}

			assert.Equal(t, tt.wantWarns, logger.warnCount(wsPermissiveOriginWarning))
		})
	}
}

func TestNewWSOriginPolicy_InvalidEntrySkippedFailClosed(t *testing.T) {
	t.Parallel()

	logger := newCountingLogger()
	policy := newWSOriginPolicy(&config.WebSocketConfig{
		AllowedOrigins: []string{"https://ok.example.com", "https://bad.example.com/path"},
	}, logger)

	// The malformed entry is ignored (fail-closed), not treated as allow-all.
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Host = "gw.example.com"
	req.Header.Set("Origin", "https://bad.example.com")
	assert.False(t, policy.allow(req))

	req.Header.Set("Origin", "https://ok.example.com")
	assert.True(t, policy.allow(req))

	assert.Equal(t, 1, logger.warnCount("ignoring invalid websocket allowed origin"))
}

func TestWebsocketProxy_CheckOrigin_NilPolicyPermissive(t *testing.T) {
	t.Parallel()

	wp := &websocketProxy{logger: observability.NopLogger()}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://anything.example.com")
	assert.True(t, wp.checkOrigin(req))
}

// ============================================================================
// Handshake integration tests (allowlist enforcement end to end)
// ============================================================================

func TestProxyWebSocket_AllowedOriginConnects(t *testing.T) {
	t.Parallel()

	backendURL, _ := startWSEchoBackend(t)
	policy := newWSOriginPolicy(&config.WebSocketConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}, observability.NopLogger())
	wsURL := startWSProxy(t, backendURL, policy)

	conn, resp, err := dialWS(wsURL, "https://app.example.com")
	require.NoError(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	requireEcho(t, conn, "allowed origin message")
}

func TestProxyWebSocket_DisallowedOriginRejected403(t *testing.T) {
	t.Parallel()

	backendURL, backendHits := startWSEchoBackend(t)
	policy := newWSOriginPolicy(&config.WebSocketConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}, observability.NopLogger())
	wsURL := startWSProxy(t, backendURL, policy)

	conn, resp, err := dialWS(wsURL, "https://evil.example.com")
	require.Error(t, err)
	require.Nil(t, conn)
	require.NotNil(t, resp)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// The origin gate runs before the backend dial, so the rejected
	// handshake must never consume backend resources.
	assert.Zero(t, backendHits.Load())
}

func TestProxyWebSocket_EmptyConfigPermissiveCrossOrigin(t *testing.T) {
	t.Parallel()

	backendURL, _ := startWSEchoBackend(t)
	logger := newCountingLogger()
	policy := newWSOriginPolicy(&config.WebSocketConfig{}, logger)
	wsURL := startWSProxy(t, backendURL, policy)

	// Cross-origin connects under the permissive default.
	conn, resp, err := dialWS(wsURL, "https://some-other-site.example.com")
	require.NoError(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	requireEcho(t, conn, "permissive default message")

	// The permissive warning was emitted once at policy construction.
	assert.Equal(t, 1, logger.warnCount(wsPermissiveOriginWarning))
}

func TestProxyWebSocket_WildcardAllowsAllOrigins(t *testing.T) {
	t.Parallel()

	backendURL, _ := startWSEchoBackend(t)
	logger := newCountingLogger()
	policy := newWSOriginPolicy(&config.WebSocketConfig{
		AllowedOrigins: []string{config.WSOriginWildcard},
	}, logger)
	wsURL := startWSProxy(t, backendURL, policy)

	for _, origin := range []string{
		"https://first.example.com",
		"http://second.example.org:8080",
	} {
		conn, resp, err := dialWS(wsURL, origin)
		require.NoError(t, err, "origin %s should connect via wildcard", origin)
		if resp != nil {
			resp.Body.Close()
		}
		requireEcho(t, conn, "wildcard "+origin)
		conn.Close()
	}

	// Explicit wildcard is a deliberate choice: no permissive warning.
	assert.Equal(t, 0, logger.warnCount(wsPermissiveOriginWarning))
}

func TestProxyWebSocket_SameOriginAllowedWithNonEmptyList(t *testing.T) {
	t.Parallel()

	backendURL, _ := startWSEchoBackend(t)
	policy := newWSOriginPolicy(&config.WebSocketConfig{
		AllowedOrigins: []string{"https://unrelated.example.com"},
	}, observability.NopLogger())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger(), originPolicy: policy}
		_, _, _ = wp.proxyWebSocket(w, r, backendURL, nil)
	}))
	t.Cleanup(server.Close)

	// Use the proxy server's own host as the Origin host (same-origin).
	proxyHost := strings.TrimPrefix(server.URL, "http://")
	wsURL := "ws://" + proxyHost + "/ws"

	conn, resp, err := dialWS(wsURL, "http://"+proxyHost)
	require.NoError(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	requireEcho(t, conn, "same-origin message")
}

func TestProxyWebSocket_RejectionReturnsSentinelError(t *testing.T) {
	t.Parallel()

	backendURL, _ := startWSEchoBackend(t)
	policy := newWSOriginPolicy(&config.WebSocketConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}, observability.NopLogger())

	wp := &websocketProxy{logger: observability.NopLogger(), originPolicy: policy}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()

	sent, received, err := wp.proxyWebSocket(rec, req, backendURL, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWSOriginNotAllowed)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, sent)
	assert.Zero(t, received)

	// Metric label classification for the rejection.
	assert.Equal(t, wsErrorTypeOriginRejected, wsErrorType(err))
}

func TestWSErrorType_GenericError(t *testing.T) {
	t.Parallel()

	assert.Equal(t, wsErrorTypeProxy, wsErrorType(assert.AnError))
}

// ============================================================================
// ReverseProxy option wiring
// ============================================================================

func TestNewReverseProxy_WebSocketConfigWiring(t *testing.T) {
	t.Parallel()

	t.Run("default is permissive and warns once", func(t *testing.T) {
		t.Parallel()

		logger := newCountingLogger()
		p := newTestProxyWithLogger(t, logger)

		require.NotNil(t, p.wsOriginPolicy)
		assert.True(t, p.wsOriginPolicy.allowAll)
		assert.Equal(t, 1, logger.warnCount(wsPermissiveOriginWarning))
	})

	t.Run("allowlist config produces enforcing policy", func(t *testing.T) {
		t.Parallel()

		logger := newCountingLogger()
		p := newTestProxyWithLogger(t, logger,
			WithWebSocketConfig(&config.WebSocketConfig{
				AllowedOrigins: []string{"https://app.example.com"},
			}),
		)

		require.NotNil(t, p.wsOriginPolicy)
		assert.False(t, p.wsOriginPolicy.allowAll)
		assert.Equal(t, 0, logger.warnCount(wsPermissiveOriginWarning))

		req := httptest.NewRequest(http.MethodGet, "/ws", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		assert.False(t, p.wsOriginPolicy.allow(req))
	})
}

// newTestProxyWithLogger builds a ReverseProxy with the given logger and
// extra options for wiring tests.
func newTestProxyWithLogger(t *testing.T, logger observability.Logger, opts ...ProxyOption) *ReverseProxy {
	t.Helper()

	allOpts := append([]ProxyOption{WithProxyLogger(logger)}, opts...)
	return NewReverseProxy(router.New(), nil, allOpts...)
}

// ============================================================================
// WP5 — relay counter integrity under -race
// ============================================================================

// TestRelay_ConcurrentCountersUnderRace exercises both relay directions
// concurrently and asserts the returned counters are exact. Run with
// -race, this is the WP5 acceptance signal for the atomic counters.
func TestRelay_ConcurrentCountersUnderRace(t *testing.T) {
	t.Parallel()

	const messages = 50

	backendURL, _ := startWSEchoBackend(t)

	countsCh := make(chan [2]int64, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger()}
		sent, received, _ := wp.proxyWebSocket(w, r, backendURL, nil)
		countsCh <- [2]int64{sent, received}
	}))
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, resp, err := dialWS(wsURL, "")
	require.NoError(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	// Writer goroutine spams messages while the main goroutine reads the
	// echoes, keeping both relay directions active concurrently.
	writeErrCh := make(chan error, 1)
	go func() {
		for i := 0; i < messages; i++ {
			if writeErr := conn.WriteMessage(
				websocket.TextMessage, []byte("race-message"),
			); writeErr != nil {
				writeErrCh <- writeErr
				return
			}
		}
		writeErrCh <- nil
	}()

	for i := 0; i < messages; i++ {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, msg, readErr := conn.ReadMessage()
		require.NoError(t, readErr)
		assert.Equal(t, "race-message", string(msg))
	}
	require.NoError(t, <-writeErrCh)

	// Close the client; relay joins both goroutines before returning.
	require.NoError(t, conn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	))
	_ = conn.Close()

	select {
	case counts := <-countsCh:
		// Every echoed message passed through both directions before the
		// client observed it, so the joined counters must be exact.
		assert.Equal(t, int64(messages), counts[0], "messages sent to client")
		assert.Equal(t, int64(messages), counts[1], "messages received from client")
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return counts after client close")
	}
}
