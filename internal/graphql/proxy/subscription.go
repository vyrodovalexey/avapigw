// Package proxy provides a reverse proxy for GraphQL requests.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// subscriptionTracerName is the OpenTelemetry tracer name for subscription operations.
const subscriptionTracerName = "avapigw/graphql-subscription"

// SubscriptionProxy handles WebSocket-based GraphQL subscriptions.
type SubscriptionProxy struct {
	proxy    *Proxy
	upgrader websocket.Upgrader
	logger   observability.Logger
	metrics  MetricsRecorder

	// Active connections tracking
	connMu      sync.Mutex
	connections map[string]*subscriptionConn
}

// subscriptionConn tracks an active subscription connection.
type subscriptionConn struct {
	clientConn  *websocket.Conn
	backendConn *websocket.Conn
	backendName string
	createdAt   time.Time
	cancel      context.CancelFunc
}

// SubscriptionOption is a functional option for configuring the subscription proxy.
type SubscriptionOption func(*SubscriptionProxy)

// WithSubscriptionLogger sets the logger for the subscription proxy.
func WithSubscriptionLogger(logger observability.Logger) SubscriptionOption {
	return func(sp *SubscriptionProxy) {
		sp.logger = logger
	}
}

// WithSubscriptionMetrics sets the metrics recorder for the subscription proxy.
func WithSubscriptionMetrics(metrics MetricsRecorder) SubscriptionOption {
	return func(sp *SubscriptionProxy) {
		sp.metrics = metrics
	}
}

// NewSubscriptionProxy creates a new subscription proxy.
func NewSubscriptionProxy(proxy *Proxy, opts ...SubscriptionOption) *SubscriptionProxy {
	sp := &SubscriptionProxy{
		proxy: proxy,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(_ *http.Request) bool {
				// Origin checking should be done at the middleware level
				return true
			},
		},
		logger:      observability.NopLogger(),
		connections: make(map[string]*subscriptionConn),
	}

	for _, opt := range opts {
		opt(sp)
	}

	return sp
}

// HandleSubscription upgrades an HTTP connection to WebSocket and proxies
// GraphQL subscription messages between the client and backend.
func (sp *SubscriptionProxy) HandleSubscription(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	backendName string,
) error {
	tracer := otel.Tracer(subscriptionTracerName)
	ctx, span := tracer.Start(ctx, "graphql.subscription.handle",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("graphql.backend", backendName),
		),
	)
	defer span.End()

	// Resolve backend
	target, err := sp.proxy.resolveBackend(backendName)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to resolve backend for subscription: %w", err)
	}

	// Build backend WebSocket URL
	backendURL := sp.buildWebSocketURL(target)
	span.SetAttributes(attribute.String("ws.backend_url", backendURL.String()))

	// Upgrade client connection
	clientConn, err := sp.upgrader.Upgrade(w, r, nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to upgrade client connection: %w", err)
	}

	// Connect to backend WebSocket
	backendHeaders := http.Header{}
	copySubscriptionHeaders(backendHeaders, r.Header)

	backendConn, resp, err := websocket.DefaultDialer.DialContext(ctx, backendURL.String(), backendHeaders)
	if err != nil {
		_ = clientConn.Close()
		span.RecordError(err)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("failed to connect to backend WebSocket: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	// Create subscription context with cancellation.
	// Use context.Background() because the subscription lifecycle extends beyond
	// the HTTP request that initiated it. The request context (ctx) is canceled
	// when the HTTP handler returns, but the WebSocket relay must continue running.
	subCtx, cancel := context.WithCancel(context.Background())

	connID := fmt.Sprintf("%s-%d", backendName, time.Now().UnixNano())
	conn := &subscriptionConn{
		clientConn:  clientConn,
		backendConn: backendConn,
		backendName: backendName,
		createdAt:   time.Now(),
		cancel:      cancel,
	}

	sp.connMu.Lock()
	sp.connections[connID] = conn
	sp.connMu.Unlock()

	sp.logger.Info("GraphQL subscription established",
		observability.String("backend", backendName),
		observability.String("conn_id", connID),
	)

	// Start bidirectional message relay.
	// Using context.Background() above is intentional: the subscription
	// lifecycle extends beyond the HTTP request that initiated it.
	go sp.relayMessages(subCtx, connID, conn) //nolint:contextcheck // subscription outlives HTTP request

	return nil
}

// relayMessages relays WebSocket messages between client and backend.
func (sp *SubscriptionProxy) relayMessages(ctx context.Context, connID string, conn *subscriptionConn) {
	defer sp.cleanupConnection(connID, conn)

	// Relay client -> backend in a separate goroutine
	go func() {
		defer conn.cancel()
		sp.relayDirection(ctx, connID, conn.clientConn, conn.backendConn, "client", "backend")
	}()

	// Relay backend -> client in the current goroutine
	sp.relayDirection(ctx, connID, conn.backendConn, conn.clientConn, "backend", "client")
}

// relayDirection relays WebSocket messages from source to destination.
// It uses a short read deadline so that context cancellation is detected promptly.
func (sp *SubscriptionProxy) relayDirection(
	ctx context.Context, connID string,
	src, dst *websocket.Conn,
	srcName, dstName string,
) {
	const readDeadlineInterval = 500 * time.Millisecond

	for {
		if ctx.Err() != nil {
			return
		}

		// Set a short read deadline so we can periodically check context cancellation.
		_ = src.SetReadDeadline(time.Now().Add(readDeadlineInterval))

		msgType, msg, err := src.ReadMessage()
		if err != nil {
			// If the context was canceled, exit silently.
			if ctx.Err() != nil {
				return
			}
			// If it's a timeout, loop back to check context and retry.
			if websocket.IsUnexpectedCloseError(err) {
				sp.logger.Debug(srcName+" connection closed",
					observability.String("conn_id", connID),
					observability.Error(err),
				)
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			sp.logger.Debug(srcName+" read error",
				observability.String("conn_id", connID),
				observability.Error(err),
			)
			return
		}

		if err := dst.WriteMessage(msgType, msg); err != nil {
			sp.logger.Debug("failed to write to "+dstName,
				observability.String("conn_id", connID),
				observability.Error(err),
			)
			return
		}
	}
}

// cleanupConnection cleans up a subscription connection.
func (sp *SubscriptionProxy) cleanupConnection(connID string, conn *subscriptionConn) {
	conn.cancel()
	_ = conn.clientConn.Close()
	_ = conn.backendConn.Close()

	sp.connMu.Lock()
	delete(sp.connections, connID)
	sp.connMu.Unlock()

	duration := time.Since(conn.createdAt)
	sp.logger.Info("GraphQL subscription closed",
		observability.String("conn_id", connID),
		observability.String("backend", conn.backendName),
		observability.Duration("duration", duration),
	)

	if sp.metrics != nil {
		sp.metrics.RecordRequest(conn.backendName, "subscription", http.StatusOK, duration)
	}
}

// buildWebSocketURL builds a WebSocket URL from the backend target.
func (sp *SubscriptionProxy) buildWebSocketURL(target *backendTarget) *url.URL {
	sp.proxy.mu.Lock()
	idx := target.current % len(target.hosts)
	target.current++
	sp.proxy.mu.Unlock()

	host := target.hosts[idx]
	return &url.URL{
		Scheme: "ws",
		Host:   fmt.Sprintf("%s:%d", host.Address, host.Port),
		Path:   "/graphql",
	}
}

// copySubscriptionHeaders copies relevant headers for the backend WebSocket connection.
func copySubscriptionHeaders(dst, src http.Header) {
	// Copy authorization and custom headers
	relevantHeaders := []string{
		"Authorization",
		"Cookie",
		"Sec-WebSocket-Protocol",
	}
	for _, h := range relevantHeaders {
		if v := src.Get(h); v != "" {
			dst.Set(h, v)
		}
	}
}

// ActiveConnections returns the number of active subscription connections.
func (sp *SubscriptionProxy) ActiveConnections() int {
	sp.connMu.Lock()
	defer sp.connMu.Unlock()
	return len(sp.connections)
}

// Close closes all active subscription connections.
func (sp *SubscriptionProxy) Close() {
	sp.connMu.Lock()
	defer sp.connMu.Unlock()

	for connID, conn := range sp.connections {
		conn.cancel()
		_ = conn.clientConn.Close()
		_ = conn.backendConn.Close()
		sp.logger.Debug("subscription connection force-closed",
			observability.String("conn_id", connID),
		)
	}

	sp.connections = make(map[string]*subscriptionConn)
	sp.logger.Info("all subscription connections closed")
}
