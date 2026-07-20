// Subprotocol negotiation tests: the gateway upgrader must negotiate the
// graphql-ws subprotocols (RFC 6455 section 4.2.2) and echo the selected
// protocol in the 101 response's Sec-WebSocket-Protocol header. Strict
// graphql-ws clients reject handshakes without the echo. Clients offering
// no subprotocol keep the historical no-echo behavior.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// subprotocolTestBackend is a WebSocket echo backend that records the
// subprotocols requested on the backend leg of the relay.
type subprotocolTestBackend struct {
	*httptest.Server

	mu        sync.Mutex
	requested []string
}

// RequestedProtocols returns the subprotocols observed on the last
// backend-leg handshake.
func (b *subprotocolTestBackend) RequestedProtocols() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.requested...)
}

// newSubprotocolTestBackend starts an echo backend that accepts any of the
// gateway-supported subprotocols.
func newSubprotocolTestBackend(t *testing.T) *subprotocolTestBackend {
	t.Helper()

	backend := &subprotocolTestBackend{}
	upgrader := websocket.Upgrader{
		Subprotocols: supportedSubprotocols(),
		CheckOrigin:  func(*http.Request) bool { return true },
	}

	backend.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend.mu.Lock()
		backend.requested = websocket.Subprotocols(r)
		backend.mu.Unlock()

		conn, err := upgrader.Upgrade(w, r, nil)
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
	t.Cleanup(backend.Server.Close)

	return backend
}

// newSubprotocolProxyServer wires a subscription proxy in front of the
// backend and serves it on an httptest server.
func newSubprotocolProxyServer(t *testing.T, backend *subprotocolTestBackend) *httptest.Server {
	t.Helper()

	addr, port := parseHostPort(backend.Listener.Addr().String())

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "subprotocol-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	sp := NewSubscriptionProxy(p, WithSubscriptionLogger(observability.NopLogger()))
	t.Cleanup(sp.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = sp.HandleSubscription(r.Context(), w, r, "subprotocol-backend")
	}))
	t.Cleanup(srv.Close)

	return srv
}

// TestSupportedSubprotocols pins the negotiation order: the modern
// graphql-transport-ws protocol first, the legacy graphql-ws second.
func TestSupportedSubprotocols(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		[]string{SubprotocolGraphQLTransportWS, SubprotocolGraphQLWS},
		supportedSubprotocols(),
	)
}

// TestSubscriptionProxy_SubprotocolNegotiation is the negotiation matrix
// for the client-side upgrade: offered protocols vs the echoed selection.
func TestSubscriptionProxy_SubprotocolNegotiation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// offered is the client's Sec-WebSocket-Protocol list in
		// preference order (nil = header absent).
		offered []string
		// wantEcho is the subprotocol the gateway must echo in the 101
		// response ("" = no Sec-WebSocket-Protocol echo).
		wantEcho string
	}{
		{
			name:     "graphql-transport-ws offered and echoed",
			offered:  []string{SubprotocolGraphQLTransportWS},
			wantEcho: SubprotocolGraphQLTransportWS,
		},
		{
			name:     "legacy graphql-ws offered and echoed",
			offered:  []string{SubprotocolGraphQLWS},
			wantEcho: SubprotocolGraphQLWS,
		},
		{
			name:     "client preference order wins with modern first",
			offered:  []string{SubprotocolGraphQLTransportWS, SubprotocolGraphQLWS},
			wantEcho: SubprotocolGraphQLTransportWS,
		},
		{
			name:     "client preference order wins with legacy first",
			offered:  []string{SubprotocolGraphQLWS, SubprotocolGraphQLTransportWS},
			wantEcho: SubprotocolGraphQLWS,
		},
		{
			name:     "unknown protocol among offers selects the known one",
			offered:  []string{"custom-proto", SubprotocolGraphQLTransportWS},
			wantEcho: SubprotocolGraphQLTransportWS,
		},
		{
			name:     "no offered protocols keeps the no-echo behavior",
			offered:  nil,
			wantEcho: "",
		},
		{
			name:     "only unknown protocols offered yields no echo",
			offered:  []string{"custom-proto"},
			wantEcho: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := newSubprotocolTestBackend(t)
			srv := newSubprotocolProxyServer(t, backend)

			dialer := websocket.Dialer{Subprotocols: tt.offered}
			wsURL := "ws" + srv.URL[len("http"):]

			conn, resp, err := dialer.Dial(wsURL, nil)
			require.NoError(t, err, "upgrade through the gateway must succeed")
			defer conn.Close()
			require.NotNil(t, resp)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
			assert.Equal(t, tt.wantEcho,
				resp.Header.Get("Sec-Websocket-Protocol"),
				"101 response subprotocol echo mismatch")
			assert.Equal(t, tt.wantEcho, conn.Subprotocol(),
				"negotiated subprotocol on the client connection mismatch")

			// The relay must function regardless of the negotiation
			// outcome (protocol-agnostic frame forwarding).
			payload := []byte(`{"type":"connection_init"}`)
			require.NoError(t, conn.WriteMessage(websocket.TextMessage, payload))
			_, echoed, readErr := conn.ReadMessage()
			require.NoError(t, readErr)
			assert.Equal(t, payload, echoed, "relay must forward frames")

			// The client's offered protocols must still be forwarded on
			// the backend dial (existing behavior preserved).
			if len(tt.offered) > 0 {
				assert.Equal(t, tt.offered, backend.RequestedProtocols(),
					"backend leg must receive the client-offered subprotocols")
			} else {
				assert.Empty(t, backend.RequestedProtocols(),
					"backend leg must not invent subprotocols")
			}
		})
	}
}

// TestSubscriptionProxy_SubprotocolNegotiation_WithAllowedOrigins verifies
// negotiation still applies when the origin allowlist rebuilt the upgrader
// with a custom CheckOrigin.
func TestSubscriptionProxy_SubprotocolNegotiation_WithAllowedOrigins(t *testing.T) {
	t.Parallel()

	backend := newSubprotocolTestBackend(t)
	addr, port := parseHostPort(backend.Listener.Addr().String())

	p := New(WithLogger(observability.NopLogger()))
	p.UpdateBackends([]config.GraphQLBackend{
		{
			Name:  "subprotocol-backend",
			Hosts: []config.BackendHost{{Address: addr, Port: port}},
		},
	})

	sp := NewSubscriptionProxy(p,
		WithSubscriptionLogger(observability.NopLogger()),
		WithAllowedOrigins([]string{"https://app.example.com"}),
	)
	t.Cleanup(sp.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = sp.HandleSubscription(r.Context(), w, r, "subprotocol-backend")
	}))
	t.Cleanup(srv.Close)

	dialer := websocket.Dialer{Subprotocols: []string{SubprotocolGraphQLTransportWS}}
	header := http.Header{"Origin": []string{"https://app.example.com"}}

	conn, resp, err := dialer.Dial("ws"+srv.URL[len("http"):], header)
	require.NoError(t, err)
	defer conn.Close()
	require.NotNil(t, resp)
	defer resp.Body.Close()

	assert.Equal(t, SubprotocolGraphQLTransportWS, conn.Subprotocol(),
		"origin-restricted upgrader must still negotiate the subprotocol")
}
