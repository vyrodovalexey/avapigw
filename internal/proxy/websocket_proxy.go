// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// websocketProxy handles WebSocket proxying at the message level,
// enabling per-message metrics tracking.
type websocketProxy struct {
	logger observability.Logger
}

// upgrader upgrades HTTP connections to WebSocket.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Origin is validated by CORS middleware
	},
}

// proxyWebSocket upgrades the client connection, dials the backend,
// and relays messages bidirectionally while counting them.
// Returns the number of messages sent to client and received from client.
func (wp *websocketProxy) proxyWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	target *url.URL,
	transport http.RoundTripper,
) (sent int64, received int64, err error) {
	// Build backend WebSocket URL
	backendURL := wp.buildBackendWSURL(target, r)

	// Configure dialer with TLS settings from transport
	dialer := websocket.Dialer{}
	if transport != nil {
		if t, ok := transport.(*http.Transport); ok && t.TLSClientConfig != nil {
			dialer.TLSClientConfig = t.TLSClientConfig.Clone()
		}
	}

	// Forward request headers to backend (excluding hop-by-hop)
	requestHeader := wp.buildRequestHeaders(r)

	// Dial backend
	backendConn, resp, dialErr := dialer.DialContext(r.Context(), backendURL, requestHeader)
	if dialErr != nil {
		wp.handleDialError(w, resp, dialErr)
		return 0, 0, fmt.Errorf("failed to dial backend WebSocket: %w", dialErr)
	}
	defer backendConn.Close()

	// Upgrade client connection
	responseHeader := wp.buildResponseHeaders(resp)
	clientConn, upgradeErr := upgrader.Upgrade(w, r, responseHeader)
	if upgradeErr != nil {
		return 0, 0, fmt.Errorf("failed to upgrade client connection: %w", upgradeErr)
	}
	defer clientConn.Close()

	// Relay messages bidirectionally
	sent, received = wp.relay(clientConn, backendConn)
	return sent, received, nil
}

// handleDialError forwards the backend's error response to the client
// or returns a generic Bad Gateway if no response is available.
func (wp *websocketProxy) handleDialError(
	w http.ResponseWriter,
	resp *http.Response,
	dialErr error,
) {
	if resp != nil {
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
	} else {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	wp.logger.Debug("websocket backend dial failed",
		observability.Error(dialErr),
	)
}

// relay copies messages between client and backend connections.
// Returns counts of messages sent to client and received from client.
func (wp *websocketProxy) relay(
	clientConn, backendConn *websocket.Conn,
) (sent int64, received int64) {
	errCh := make(chan error, 2)
	var sentCount, receivedCount int64

	// Backend -> Client (messages "sent" to client)
	go func() {
		for {
			msgType, msg, readErr := backendConn.ReadMessage()
			if readErr != nil {
				// Send close message to client
				_ = clientConn.WriteMessage(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				)
				errCh <- readErr
				return
			}
			sentCount++
			if writeErr := clientConn.WriteMessage(msgType, msg); writeErr != nil {
				errCh <- writeErr
				return
			}
		}
	}()

	// Client -> Backend (messages "received" from client)
	go func() {
		for {
			msgType, msg, readErr := clientConn.ReadMessage()
			if readErr != nil {
				// Send close message to backend
				_ = backendConn.WriteMessage(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				)
				errCh <- readErr
				return
			}
			receivedCount++
			if writeErr := backendConn.WriteMessage(msgType, msg); writeErr != nil {
				errCh <- writeErr
				return
			}
		}
	}()

	// Wait for one direction to finish
	<-errCh

	return sentCount, receivedCount
}

// buildBackendWSURL constructs the WebSocket URL for the backend.
func (wp *websocketProxy) buildBackendWSURL(target *url.URL, r *http.Request) string {
	scheme := "ws"
	if target.Scheme == schemeHTTPS {
		scheme = "wss"
	}

	backendURL := scheme + "://" + target.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		backendURL += "?" + r.URL.RawQuery
	}

	return backendURL
}

// buildRequestHeaders builds headers to forward to the backend,
// excluding WebSocket and hop-by-hop headers that gorilla handles.
func (wp *websocketProxy) buildRequestHeaders(r *http.Request) http.Header {
	header := http.Header{}
	for k, vv := range r.Header {
		// Skip WebSocket and hop-by-hop headers (gorilla handles these)
		switch strings.ToLower(k) {
		case "upgrade", "connection", "sec-websocket-key",
			"sec-websocket-version", "sec-websocket-extensions",
			"sec-websocket-protocol":
			continue
		}
		for _, v := range vv {
			header.Add(k, v)
		}
	}
	return header
}

// buildResponseHeaders extracts headers from the backend response to forward to client,
// excluding WebSocket protocol headers that gorilla manages.
func (wp *websocketProxy) buildResponseHeaders(resp *http.Response) http.Header {
	if resp == nil {
		return nil
	}
	header := http.Header{}
	for k, vv := range resp.Header {
		switch strings.ToLower(k) {
		case "upgrade", "connection", "sec-websocket-accept":
			continue
		}
		for _, v := range vv {
			header.Add(k, v)
		}
	}
	return header
}

// Compile-time check: ensure *http.Transport satisfies http.RoundTripper
// so the TLS config extraction cast is valid.
var _ http.RoundTripper = (*http.Transport)(nil)

// Compile-time check: ensure *tls.Config has Clone method (used above).
var _ = (*tls.Config).Clone
