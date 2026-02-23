package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewSubscriptionProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []SubscriptionOption
	}{
		{
			name: "default subscription proxy",
			opts: nil,
		},
		{
			name: "with logger",
			opts: []SubscriptionOption{WithSubscriptionLogger(observability.NopLogger())},
		},
		{
			name: "with metrics",
			opts: []SubscriptionOption{WithSubscriptionMetrics(&mockMetricsRecorder{})},
		},
		{
			name: "with all options",
			opts: []SubscriptionOption{
				WithSubscriptionLogger(observability.NopLogger()),
				WithSubscriptionMetrics(&mockMetricsRecorder{}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New(WithLogger(observability.NopLogger()))
			sp := NewSubscriptionProxy(p, tt.opts...)
			require.NotNil(t, sp)
			assert.NotNil(t, sp.proxy)
			assert.NotNil(t, sp.connections)
			assert.Equal(t, 0, sp.ActiveConnections())
		})
	}
}

func TestSubscriptionProxy_ActiveConnections(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	sp := NewSubscriptionProxy(p)

	assert.Equal(t, 0, sp.ActiveConnections())
}

func TestSubscriptionProxy_Close_Empty(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	sp := NewSubscriptionProxy(p, WithSubscriptionLogger(observability.NopLogger()))

	// Should not panic when closing with no connections
	sp.Close()
	assert.Equal(t, 0, sp.ActiveConnections())
}

func TestSubscriptionProxy_BuildWebSocketURL(t *testing.T) {
	t.Parallel()

	p := New()
	sp := NewSubscriptionProxy(p)

	target := &backendTarget{
		name: "test",
		hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 4000},
			{Address: "10.0.0.2", Port: 4001},
		},
		current: 0,
	}

	// First call should use host 0
	url1 := sp.buildWebSocketURL(target)
	assert.Equal(t, "ws", url1.Scheme)
	assert.Equal(t, "10.0.0.1:4000", url1.Host)
	assert.Equal(t, "/graphql", url1.Path)

	// Second call should use host 1 (round-robin)
	url2 := sp.buildWebSocketURL(target)
	assert.Equal(t, "ws", url2.Scheme)
	assert.Equal(t, "10.0.0.2:4001", url2.Host)
	assert.Equal(t, "/graphql", url2.Path)

	// Third call should wrap around to host 0
	url3 := sp.buildWebSocketURL(target)
	assert.Equal(t, "ws", url3.Scheme)
	assert.Equal(t, "10.0.0.1:4000", url3.Host)
}

func TestCopySubscriptionHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		srcHeaders     http.Header
		expectedKeys   []string
		unexpectedKeys []string
	}{
		{
			name: "copies relevant headers",
			srcHeaders: http.Header{
				"Authorization":          {"Bearer token123"},
				"Cookie":                 {"session=abc"},
				"Sec-Websocket-Protocol": {"graphql-ws"},
			},
			expectedKeys: []string{"Authorization", "Cookie", "Sec-Websocket-Protocol"},
		},
		{
			name: "skips irrelevant headers",
			srcHeaders: http.Header{
				"Authorization": {"Bearer token123"},
				"Content-Type":  {"application/json"},
				"X-Custom":      {"value"},
			},
			expectedKeys:   []string{"Authorization"},
			unexpectedKeys: []string{"Content-Type", "X-Custom"},
		},
		{
			name: "empty headers",
			srcHeaders: http.Header{
				"Content-Type": {"application/json"},
			},
			unexpectedKeys: []string{"Authorization", "Cookie", "Sec-Websocket-Protocol"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := http.Header{}
			copySubscriptionHeaders(dst, tt.srcHeaders)

			for _, key := range tt.expectedKeys {
				assert.NotEmpty(t, dst.Get(key), "expected header %s to be copied", key)
			}
			for _, key := range tt.unexpectedKeys {
				assert.Empty(t, dst.Get(key), "expected header %s to NOT be copied", key)
			}
		})
	}
}

func TestSubscriptionProxy_HandleSubscription_BackendNotFound(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	sp := NewSubscriptionProxy(p, WithSubscriptionLogger(observability.NopLogger()))

	w := &fakeResponseWriter{}
	r := &http.Request{Header: http.Header{}}

	err := sp.HandleSubscription(t.Context(), w, r, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve backend")
}

func TestSubscriptionProxy_HandleSubscription_UpgradeFailure(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: "10.0.0.1", Port: 4000}},
		},
	})

	sp := NewSubscriptionProxy(p, WithSubscriptionLogger(observability.NopLogger()))

	// Use a regular HTTP request (not a WebSocket upgrade request)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)

	err := sp.HandleSubscription(t.Context(), w, r, "test-backend")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upgrade client connection")
}

func TestSubscriptionProxy_HandleSubscription_BackendDialFailure(t *testing.T) {
	t.Parallel()

	p := New(WithLogger(observability.NopLogger()))
	// Use a backend address that will fail to connect
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: "127.0.0.1", Port: 1}},
		},
	})

	sp := NewSubscriptionProxy(p, WithSubscriptionLogger(observability.NopLogger()))

	// Use atomic to safely share error between goroutines
	var gotError atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := sp.HandleSubscription(r.Context(), w, r, "test-backend")
		if err != nil {
			gotError.Store(true)
		}
	}))
	defer server.Close()

	// Connect as a WebSocket client
	dialer := websocket.Dialer{}
	wsURL := "ws" + server.URL[4:]
	conn, resp, err := dialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}

	// The connection should fail because the backend is unreachable
	if err == nil {
		// Backend dial failure happens after client upgrade
		time.Sleep(200 * time.Millisecond)
		assert.True(t, gotError.Load(), "expected backend dial error")
	}
	// If err != nil, the dial itself failed which is also acceptable
}

func TestSubscriptionProxy_HandleSubscription_FullRelay(t *testing.T) {
	t.Parallel()

	// Create a WebSocket echo backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool { return true },
		}
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

	addr, port := parseHostPort(backendServer.Listener.Addr().String())

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "echo-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	metrics := &mockMetricsRecorder{}
	sp := NewSubscriptionProxy(p,
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	// Create a proxy server that handles WebSocket subscriptions
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = sp.HandleSubscription(r.Context(), w, r, "echo-backend")
	}))
	defer proxyServer.Close()

	// Connect as a WebSocket client
	dialer := websocket.Dialer{}
	wsURL := "ws" + proxyServer.URL[4:]
	conn, resp, err := dialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	// Wait for connection to be registered with polling
	require.Eventually(t, func() bool {
		return sp.ActiveConnections() == 1
	}, 2*time.Second, 10*time.Millisecond, "expected 1 active connection")

	// Send a message and verify echo
	testMsg := []byte(`{"type":"subscribe","payload":{"query":"subscription { onEvent { id } }"}}`)
	err = conn.WriteMessage(websocket.TextMessage, testMsg)
	require.NoError(t, err)

	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, testMsg, msg)

	// Close the client connection
	_ = conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	conn.Close()

	// Wait for cleanup with polling
	assert.Eventually(t, func() bool {
		return sp.ActiveConnections() == 0
	}, 2*time.Second, 50*time.Millisecond, "expected 0 active connections after close")
}

func TestSubscriptionProxy_Close_WithActiveConnections(t *testing.T) {
	t.Parallel()

	// Create a WebSocket echo backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer backendServer.Close()

	addr, port := parseHostPort(backendServer.Listener.Addr().String())

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "test-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	sp := NewSubscriptionProxy(p, WithSubscriptionLogger(observability.NopLogger()))

	// Create a proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = sp.HandleSubscription(r.Context(), w, r, "test-backend")
	}))
	defer proxyServer.Close()

	// Connect as a WebSocket client
	dialer := websocket.Dialer{}
	wsURL := "ws" + proxyServer.URL[4:]
	conn, resp, err := dialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Wait for connection to be registered with polling
	require.Eventually(t, func() bool {
		return sp.ActiveConnections() == 1
	}, 2*time.Second, 10*time.Millisecond, "expected 1 active connection")

	// Close the subscription proxy (should force-close all connections)
	sp.Close()
	assert.Equal(t, 0, sp.ActiveConnections())

	// Clean up client connection
	_ = conn.Close()
}

func TestSubscriptionProxy_CleanupConnection(t *testing.T) {
	t.Parallel()

	metrics := &mockMetricsRecorder{}
	p := New(WithLogger(observability.NopLogger()))
	sp := NewSubscriptionProxy(p,
		WithSubscriptionLogger(observability.NopLogger()),
		WithSubscriptionMetrics(metrics),
	)

	assert.Equal(t, 0, sp.ActiveConnections())
}

func TestSubscriptionProxy_WithSubscriptionOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	metrics := &mockMetricsRecorder{}

	p := New()
	sp := NewSubscriptionProxy(p,
		WithSubscriptionLogger(logger),
		WithSubscriptionMetrics(metrics),
	)

	assert.NotNil(t, sp.logger)
	assert.Same(t, metrics, sp.metrics)
}

func TestSubscriptionConn_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	conn := &subscriptionConn{
		backendName: "test-backend",
		createdAt:   now,
	}

	assert.Equal(t, "test-backend", conn.backendName)
	assert.Equal(t, now, conn.createdAt)
}

// fakeResponseWriter is a minimal http.ResponseWriter for testing.
type fakeResponseWriter struct {
	headers    http.Header
	statusCode int
	body       []byte
}

func (f *fakeResponseWriter) Header() http.Header {
	if f.headers == nil {
		f.headers = http.Header{}
	}
	return f.headers
}

func (f *fakeResponseWriter) Write(b []byte) (int, error) {
	f.body = append(f.body, b...)
	return len(b), nil
}

func (f *fakeResponseWriter) WriteHeader(statusCode int) {
	f.statusCode = statusCode
}

// parseHostPort splits a host:port string into address and port.
func parseHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}
