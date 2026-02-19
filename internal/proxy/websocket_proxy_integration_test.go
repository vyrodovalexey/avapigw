// Package proxy provides integration tests for WebSocket proxying.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// proxyWebSocket integration test — exercises relay, proxyWebSocket, and
// the full bidirectional message path.
// ============================================================================

func TestProxyWebSocket_FullRelay(t *testing.T) {
	t.Parallel()

	// 1. Create a backend WebSocket server that echoes messages
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("backend upgrade error: %v", err)
			return
		}
		defer conn.Close()

		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Echo the message back
			if err := conn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	// 2. Create a proxy server that uses websocketProxy
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger()}
		_, _, _ = wp.proxyWebSocket(w, r, backendURL, nil)
	}))
	defer proxyServer.Close()

	// 3. Connect to the proxy as a WebSocket client
	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/ws"
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// 4. Send a message and verify echo
	testMsg := "hello from test"
	err = conn.WriteMessage(websocket.TextMessage, []byte(testMsg))
	require.NoError(t, err)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, websocket.TextMessage, msgType)
	assert.Equal(t, testMsg, string(msg))

	// 5. Send another message to exercise the relay loop further
	testMsg2 := "second message"
	err = conn.WriteMessage(websocket.TextMessage, []byte(testMsg2))
	require.NoError(t, err)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err = conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, websocket.TextMessage, msgType)
	assert.Equal(t, testMsg2, string(msg))

	// 6. Close the connection gracefully
	err = conn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	)
	require.NoError(t, err)
}

func TestProxyWebSocket_BackendClose(t *testing.T) {
	t.Parallel()

	// Backend that closes immediately after one message
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Read one message then close
		_, _, _ = conn.ReadMessage()
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
		conn.Close()
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger()}
		_, _, _ = wp.proxyWebSocket(w, r, backendURL, nil)
	}))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/ws"
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send a message
	err = conn.WriteMessage(websocket.TextMessage, []byte("hello"))
	require.NoError(t, err)

	// Backend will close, so we should get a close message
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	// Should get a close error since backend closed
	assert.Error(t, err)
}

func TestProxyWebSocket_WithTLSTransport(t *testing.T) {
	t.Parallel()

	// Backend WebSocket server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	// Use a custom transport (non-TLS, but exercises the transport code path)
	transport := &http.Transport{}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger()}
		_, _, _ = wp.proxyWebSocket(w, r, backendURL, transport)
	}))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/ws"
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	err = conn.WriteMessage(websocket.TextMessage, []byte("test"))
	require.NoError(t, err)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, "test", string(msg))

	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// ============================================================================
// proxyWebSocket — dial error with unreachable backend
// ============================================================================

func TestProxyWebSocket_DialError(t *testing.T) {
	t.Parallel()

	// Use a URL that will fail to connect
	backendURL, err := url.Parse("http://127.0.0.1:1") // port 1 is unlikely to be open
	require.NoError(t, err)

	// Create a proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &websocketProxy{logger: observability.NopLogger()}
		_, _, proxyErr := wp.proxyWebSocket(w, r, backendURL, nil)
		if proxyErr != nil {
			// Error is expected
			return
		}
	}))
	defer proxyServer.Close()

	// Try to connect — the proxy should return an error response
	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/ws"
	dialer := websocket.Dialer{}
	_, resp, err := dialer.Dial(wsURL, nil)
	assert.Error(t, err)
	if resp != nil {
		resp.Body.Close()
	}
}
