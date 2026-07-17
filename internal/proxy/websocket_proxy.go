// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// websocketProxy handles WebSocket proxying at the message level,
// enabling per-message metrics tracking.
type websocketProxy struct {
	logger observability.Logger

	// originPolicy validates the Origin header during the upgrade
	// handshake. A nil policy preserves the historical permissive
	// behavior (used by directly constructed instances in tests).
	originPolicy *wsOriginPolicy
}

// checkOrigin reports whether the request's Origin header is allowed by
// the configured origin allowlist policy.
func (wp *websocketProxy) checkOrigin(r *http.Request) bool {
	if wp.originPolicy == nil {
		return true
	}
	return wp.originPolicy.allow(r)
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
	// Enforce the origin allowlist before any backend work so rejected
	// cross-origin handshakes never consume backend resources.
	if !wp.checkOrigin(r) {
		origin := r.Header.Get("Origin")
		wp.logger.Warn("websocket origin rejected",
			observability.String("origin", origin),
			observability.String("host", r.Host),
			observability.String("path", r.URL.Path),
		)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return 0, 0, fmt.Errorf("websocket origin %q rejected: %w", origin, ErrWSOriginNotAllowed)
	}

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

	// Upgrade client connection. CheckOrigin re-applies the origin policy
	// as defense in depth behind the pre-dial gate above.
	responseHeader := wp.buildResponseHeaders(resp)
	upgrader := websocket.Upgrader{CheckOrigin: wp.checkOrigin}
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
//
// The message counters are atomic because each direction increments its
// counter from a dedicated goroutine; both goroutines are joined before
// the final counts are loaded so the returned values are complete.
func (wp *websocketProxy) relay(
	clientConn, backendConn *websocket.Conn,
) (sent int64, received int64) {
	var (
		sentCount     atomic.Int64
		receivedCount atomic.Int64
		wg            sync.WaitGroup
	)
	// Buffered so both goroutines can report their terminal error
	// without blocking, even after the first one has been consumed.
	errCh := make(chan error, 2)

	wg.Add(2)

	// Backend -> Client (messages "sent" to client)
	go func() {
		defer wg.Done()
		wp.relayDirection(backendConn, clientConn, &sentCount, errCh)
	}()

	// Client -> Backend (messages "received" from client)
	go func() {
		defer wg.Done()
		wp.relayDirection(clientConn, backendConn, &receivedCount, errCh)
	}()

	// Wait for one direction to finish, then close both connections to
	// unblock the peer goroutine's blocking ReadMessage call.
	<-errCh
	_ = clientConn.Close()
	_ = backendConn.Close()

	// Join both goroutines so the counters are stable before loading them.
	wg.Wait()

	return sentCount.Load(), receivedCount.Load()
}

// relayDirection copies messages from src to dst until a read or write
// error occurs, incrementing counter for every message read from src.
// The terminal error is reported on errCh (buffered by the caller).
func (wp *websocketProxy) relayDirection(
	src, dst *websocket.Conn,
	counter *atomic.Int64,
	errCh chan<- error,
) {
	for {
		msgType, msg, readErr := src.ReadMessage()
		if readErr != nil {
			// Propagate the close handshake to the destination peer.
			_ = dst.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			)
			errCh <- readErr
			return
		}
		counter.Add(1)
		if writeErr := dst.WriteMessage(msgType, msg); writeErr != nil {
			errCh <- writeErr
			return
		}
	}
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
