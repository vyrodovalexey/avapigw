package proxy

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Proxy is the main gRPC reverse proxy.
type Proxy struct {
	router          *router.Router
	director        Director
	streamHandler   *StreamHandler
	connPool        *ConnectionPool
	logger          observability.Logger
	defaultTimeout  time.Duration
	metricsRegistry *prometheus.Registry
}

// ProxyOption is a functional option for configuring the proxy.
type ProxyOption func(*Proxy)

// WithProxyLogger sets the logger for the proxy.
func WithProxyLogger(logger observability.Logger) ProxyOption {
	return func(p *Proxy) {
		p.logger = logger
	}
}

// WithConnectionPool sets the connection pool for the proxy.
func WithConnectionPool(pool *ConnectionPool) ProxyOption {
	return func(p *Proxy) {
		p.connPool = pool
	}
}

// WithDirector sets the director for the proxy.
func WithDirector(director Director) ProxyOption {
	return func(p *Proxy) {
		p.director = director
	}
}

// WithDefaultTimeout sets the default timeout for requests.
func WithDefaultTimeout(timeout time.Duration) ProxyOption {
	return func(p *Proxy) {
		p.defaultTimeout = timeout
	}
}

// WithMetricsRegistry sets the Prometheus registry for gRPC proxy
// metrics. When provided, all gRPC proxy metrics are registered with
// this registry instead of the default global registerer, ensuring
// they appear on the gateway's /metrics endpoint.
func WithMetricsRegistry(registry *prometheus.Registry) ProxyOption {
	return func(p *Proxy) {
		p.metricsRegistry = registry
	}
}

// New creates a new gRPC proxy.
func New(r *router.Router, opts ...ProxyOption) *Proxy {
	p := &Proxy{
		router:         r,
		logger:         observability.NopLogger(),
		defaultTimeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Initialize gRPC proxy metrics with the configured registry so
	// they appear on the gateway's /metrics endpoint. When
	// metricsRegistry is nil the metrics fall back to the default
	// global registerer (e.g. in tests).
	InitGRPCProxyMetrics(p.metricsRegistry)

	// Create connection pool if not provided
	if p.connPool == nil {
		p.connPool = NewConnectionPool(WithPoolLogger(p.logger))
	}

	// Create director if not provided
	if p.director == nil {
		p.director = NewRouterDirector(r, p.connPool, WithDirectorLogger(p.logger))
	}

	// Create stream handler
	p.streamHandler = NewStreamHandler(p.director, p.logger)

	return p
}

// StreamHandler returns the gRPC stream handler for unknown services.
// This is used with grpc.UnknownServiceHandler option.
func (p *Proxy) StreamHandler() grpc.StreamHandler {
	return func(srv interface{}, stream grpc.ServerStream) error {
		return p.handleStream(srv, stream)
	}
}

// handleStream handles incoming gRPC streams.
func (p *Proxy) handleStream(srv interface{}, stream grpc.ServerStream) error {
	ctx := stream.Context()

	// Get full method from context
	fullMethod, ok := grpc.Method(ctx)
	if !ok {
		p.logger.Error("failed to get method from context")
		return status.Error(codes.Internal, "failed to get method from context")
	}

	p.logger.Debug("handling gRPC request",
		observability.String("method", fullMethod),
	)

	// Apply route-level timeout if configured.
	// If the route does not match, return early with an Unimplemented
	// error instead of creating a timeout context for an unmatched route.
	ctx, cancel, matched := p.applyTimeout(ctx, fullMethod)
	if cancel != nil {
		defer cancel()
	}
	if !matched {
		p.logger.Warn("no matching route for gRPC request",
			observability.String("method", fullMethod),
		)
		return status.Errorf(codes.Unimplemented, "no route for method %s", fullMethod)
	}

	// Wrap stream with new context
	wrappedStream := WrapServerStream(stream, ctx)

	// Handle the stream
	err := p.streamHandler.HandleStream(srv, wrappedStream)
	if err != nil {
		p.logger.Debug("stream handling error",
			observability.String("method", fullMethod),
			observability.Error(err),
		)

		// Track timeout occurrences
		if ctx.Err() == context.DeadlineExceeded {
			metrics := getGRPCProxyMetrics()
			metrics.timeoutOccurrences.WithLabelValues(fullMethod).Inc()
		}
	}

	return err
}

// applyTimeout applies route-level or default timeout.
// It only creates a context with timeout when a route matches or the
// context does not already carry a deadline. For unmatched routes the
// caller should return an appropriate error instead of allocating a
// timeout that will never be used.
func (p *Proxy) applyTimeout(ctx context.Context, fullMethod string) (context.Context, context.CancelFunc, bool) {
	// Check if context already has a deadline
	if _, ok := ctx.Deadline(); ok {
		return ctx, nil, true
	}

	// Try to get route-specific timeout
	timeout := p.defaultTimeout

	// Get metadata for route matching — if the route does not match,
	// return early so the caller can reject the request without
	// creating a context with timeout for an unmatched route.
	result, err := p.router.Match(fullMethod, nil)
	if err != nil {
		p.logger.Debug("no matching route for timeout lookup",
			observability.String("method", fullMethod),
			observability.Error(err),
		)
		return ctx, nil, false
	}

	if result.Route.Config.Timeout.Duration() > 0 {
		timeout = result.Route.Config.Timeout.Duration()
	}

	newCtx, cancel := context.WithTimeout(ctx, timeout)
	return newCtx, cancel, true
}

// Close closes the proxy and releases resources.
func (p *Proxy) Close() error {
	if p.connPool != nil {
		return p.connPool.Close()
	}
	return nil
}

// Router returns the router.
func (p *Proxy) Router() *router.Router {
	return p.router
}

// ConnectionPool returns the connection pool.
func (p *Proxy) ConnectionPool() *ConnectionPool {
	return p.connPool
}

// Director returns the director.
func (p *Proxy) Director() Director {
	return p.director
}
