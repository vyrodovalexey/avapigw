// Package proxy provides a reverse proxy for GraphQL requests.
package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// connectionCounter is a package-level atomic counter for generating unique connection IDs.
// Using an atomic counter instead of time.Now().UnixNano() prevents ID collisions
// on fast hardware or VMs with coarse time resolution.
var connectionCounter atomic.Int64

// subscriptionTracerName is the OpenTelemetry tracer name for subscription operations.
const subscriptionTracerName = "avapigw/graphql-subscription"

// SubscriptionProxy handles WebSocket-based GraphQL subscriptions.
type SubscriptionProxy struct {
	proxy    *Proxy
	upgrader websocket.Upgrader
	logger   observability.Logger
	metrics  MetricsRecorder

	// allowedOrigins restricts WebSocket connections to specific origins.
	// When empty, all origins are allowed (backward compatible).
	// Use "*" to explicitly allow all origins.
	allowedOrigins []string

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

// WithAllowedOrigins sets the allowed origins for WebSocket connections.
// When empty, all origins are allowed (backward compatible).
// Use "*" to explicitly allow all origins.
//
// Security note: leaving this unconfigured allows connections from any origin.
// In production, configure specific allowed origins to prevent cross-site
// WebSocket hijacking attacks.
func WithAllowedOrigins(origins []string) SubscriptionOption {
	return func(sp *SubscriptionProxy) {
		sp.allowedOrigins = origins
	}
}

// NewSubscriptionProxy creates a new subscription proxy.
func NewSubscriptionProxy(proxy *Proxy, opts ...SubscriptionOption) *SubscriptionProxy {
	sp := &SubscriptionProxy{
		proxy:       proxy,
		logger:      observability.NopLogger(),
		connections: make(map[string]*subscriptionConn),
	}

	// Apply options first so allowedOrigins is set before building the upgrader.
	for _, opt := range opts {
		opt(sp)
	}

	sp.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// When no origins are configured, allow all (backward compatible).
			if len(sp.allowedOrigins) == 0 {
				return true
			}
			origin := r.Header.Get("Origin")
			for _, allowed := range sp.allowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
			}
			return false
		},
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
	// The cancel function is stored in subscriptionConn.cancel and called in closeConnection().
	//nolint:gosec // G118: cancel stored in conn.cancel, called in closeConnection
	subCtx, cancel := context.WithCancel(context.Background())

	connID := fmt.Sprintf("%s-%d", backendName, connectionCounter.Add(1))
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
//
// It uses the close-on-ctx.Done pattern (mirroring internal/proxy/websocket_proxy.go):
// a single watcher goroutine closes both connections when the subscription context
// is canceled, which unblocks the blocking ReadMessage calls in both relay
// directions. gorilla/websocket read errors are sticky (a repeated read on a
// failed connection eventually panics inside the library), so the relay loops
// must never retry a failed read; closing the connections is the only reliable
// way to interrupt them.
func (sp *SubscriptionProxy) relayMessages(ctx context.Context, connID string, conn *subscriptionConn) {
	// Defense-in-depth: relayMessages runs in a detached goroutine, so an
	// uncaught panic here would crash the whole process. Registered BEFORE
	// cleanupConnection so cleanup still runs during panic unwinding (defers
	// execute in LIFO order) and the recover handler fires last.
	defer sp.recoverRelayPanic(connID, conn.backendName, "relay")
	defer sp.cleanupConnection(connID, conn)

	// Single watcher goroutine: on context cancellation, close both
	// connections to unblock the blocking reads in both relay directions.
	// It always terminates because cleanupConnection cancels the context.
	go func() {
		<-ctx.Done()
		_ = conn.clientConn.Close()
		_ = conn.backendConn.Close()
	}()

	// Relay client -> backend in a separate goroutine.
	go func() {
		defer sp.recoverRelayPanic(connID, conn.backendName, "client_to_backend")
		defer conn.cancel()
		sp.relayDirection(connID, conn.backendName, conn.clientConn, conn.backendConn, "client", "backend")
	}()

	// Relay backend -> client in the current goroutine.
	sp.relayDirection(connID, conn.backendName, conn.backendConn, conn.clientConn, "backend", "client")
}

// relayDirection relays WebSocket messages from src to dst until an error occurs.
//
// The loop blocks in src.ReadMessage; the ctx watcher in relayMessages closes
// both connections on cancellation to unblock it. gorilla/websocket read errors
// are sticky, so the loop terminates on ANY read or write error — it must never
// continue after a failed read (doing so busy-loops and eventually panics
// inside gorilla/websocket).
func (sp *SubscriptionProxy) relayDirection(
	connID, backendName string,
	src, dst *websocket.Conn,
	srcName, dstName string,
) {
	// Defense-in-depth: relayDirection runs in detached relay goroutines.
	defer sp.recoverRelayPanic(connID, backendName, srcName+"_to_"+dstName)

	for {
		msgType, msg, err := src.ReadMessage()
		if err != nil {
			// Sticky read error: terminate this direction. This also covers
			// context cancellation, because the watcher goroutine closes both
			// connections, which fails this blocking read.
			sp.logger.Debug(srcName+" read ended",
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

// recoverRelayPanic recovers from a panic in a subscription relay goroutine.
// Relay goroutines are detached from any HTTP request lifecycle (and from the
// gateway's HTTP recovery middleware), so without this handler a panic would
// crash the entire process. On recovery it logs the panic with a stack trace
// and records a "panic_recovered" error metric.
//
// It must be invoked directly via defer for recover() to take effect.
func (sp *SubscriptionProxy) recoverRelayPanic(connID, backendName, stage string) {
	r := recover()
	if r == nil {
		return
	}

	sp.logger.Error("panic recovered in subscription relay",
		observability.String("conn_id", connID),
		observability.String("backend", backendName),
		observability.String("stage", stage),
		observability.Any("panic", r),
		observability.String("stack", string(debug.Stack())),
	)

	if sp.metrics != nil {
		sp.metrics.RecordError(backendName, "subscription", "panic_recovered")
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
// Uses atomic counter for lock-free concurrent access.
func (sp *SubscriptionProxy) buildWebSocketURL(target *backendTarget) *url.URL {
	idx := int(target.current.Add(1)-1) % len(target.hosts)
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
