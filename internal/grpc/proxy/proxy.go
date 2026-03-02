package proxy

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Proxy is the main gRPC reverse proxy.
type Proxy struct {
	router             *router.Router
	director           Director
	streamHandler      *StreamHandler
	connPool           *ConnectionPool
	logger             observability.Logger
	defaultTimeout     time.Duration
	metricsRegistry    *prometheus.Registry
	authMetrics        *auth.Metrics
	vaultClient        vault.Client
	backendRegistry    *backend.Registry
	rateLimiterManager *RouteRateLimiterManager
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

// WithAuthMetrics sets the authentication metrics for the proxy.
// When provided, per-route authentication operations in the director
// emit Prometheus metrics for observability.
func WithAuthMetrics(metrics *auth.Metrics) ProxyOption {
	return func(p *Proxy) {
		p.authMetrics = metrics
	}
}

// WithProxyVaultClient sets the vault client for the proxy.
// When provided, per-route API key authentication in the director
// can use Vault as the key store.
func WithProxyVaultClient(client vault.Client) ProxyOption {
	return func(p *Proxy) {
		p.vaultClient = client
	}
}

// WithBackendRegistry sets the backend registry for the proxy's director.
// When set, the director resolves backend names to actual host addresses
// using the backend's load balancer instead of using the route destination
// host directly.
func WithBackendRegistry(registry *backend.Registry) ProxyOption {
	return func(p *Proxy) {
		p.backendRegistry = registry
	}
}

// WithRouteRateLimiter sets the per-route rate limiter manager for the proxy.
// When set, routes with RateLimit configuration will have rate limiting
// enforced before forwarding requests to backends.
func WithRouteRateLimiter(manager *RouteRateLimiterManager) ProxyOption {
	return func(p *Proxy) {
		p.rateLimiterManager = manager
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
	InitGRPCProxyVecMetrics()

	// Create connection pool if not provided
	if p.connPool == nil {
		p.connPool = NewConnectionPool(WithPoolLogger(p.logger))
	}

	// Create director if not provided
	if p.director == nil {
		directorOpts := []DirectorOption{WithDirectorLogger(p.logger)}
		if p.backendRegistry != nil {
			directorOpts = append(directorOpts, WithDirectorBackendRegistry(p.backendRegistry))
		}
		if p.authMetrics != nil {
			directorOpts = append(directorOpts, WithDirectorAuthMetrics(p.authMetrics))
		}
		if p.vaultClient != nil {
			directorOpts = append(directorOpts, WithDirectorVaultClient(p.vaultClient))
		}
		p.director = NewRouterDirector(r, p.connPool, directorOpts...)
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
	ctx, cancel, matchResult := p.applyTimeout(ctx, fullMethod)
	if cancel != nil {
		defer cancel()
	}
	if matchResult == nil {
		p.logger.Warn("no matching route for gRPC request",
			observability.String("method", fullMethod),
		)
		return status.Errorf(codes.Unimplemented, "no route for method %s", fullMethod)
	}

	// Apply per-route rate limiting if configured
	if p.rateLimiterManager != nil && matchResult.Route.Config.RateLimit != nil {
		routeName := matchResult.Route.Name
		rateLimitCfg := matchResult.Route.Config.RateLimit
		if err := p.rateLimiterManager.Check(ctx, routeName, rateLimitCfg); err != nil {
			p.logger.Debug("per-route rate limit exceeded",
				observability.String("method", fullMethod),
				observability.String("route", routeName),
			)
			return err
		}
	}

	// Wrap stream with new context
	wrappedStream := WrapServerStream(stream, ctx)

	// Handle the stream with route config for transforms
	err := p.streamHandler.HandleStream(srv, wrappedStream, &matchResult.Route.Config)
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

// applyTimeout applies route-level or default timeout and returns the match result.
// It only creates a context with timeout when a route matches or the
// context does not already carry a deadline. For unmatched routes the
// caller should return an appropriate error instead of allocating a
// timeout that will never be used.
// Returns nil match result when no route matches.
func (p *Proxy) applyTimeout(
	ctx context.Context, fullMethod string,
) (context.Context, context.CancelFunc, *router.MatchResult) {
	// Extract incoming metadata for route matching so that metadata-based
	// match conditions (e.g., x-test-scenario header) are evaluated correctly.
	md, _ := metadata.FromIncomingContext(ctx)

	// Get metadata for route matching — if the route does not match,
	// return early so the caller can reject the request without
	// creating a context with timeout for an unmatched route.
	result, err := p.router.Match(fullMethod, md)
	if err != nil {
		p.logger.Debug("no matching route for timeout lookup",
			observability.String("method", fullMethod),
			observability.Error(err),
		)
		return ctx, nil, nil
	}

	// Check if context already has a deadline
	if _, ok := ctx.Deadline(); ok {
		return ctx, nil, result
	}

	// Try to get route-specific timeout
	timeout := p.defaultTimeout
	if result.Route.Config.Timeout.Duration() > 0 {
		timeout = result.Route.Config.Timeout.Duration()
	}

	newCtx, cancel := context.WithTimeout(ctx, timeout)
	return newCtx, cancel, result
}

// ClearAuthCache clears the gRPC director's authenticator cache.
// This delegates to the RouterDirector's ClearAuthCache method when
// the director supports it. It is safe to call even when the director
// does not support cache clearing (e.g., StaticDirector).
func (p *Proxy) ClearAuthCache() {
	type authCacheClearer interface {
		ClearAuthCache()
	}
	if clearer, ok := p.director.(authCacheClearer); ok {
		clearer.ClearAuthCache()
	}
}

// ClearRateLimitCache clears the per-route rate limiter cache.
// This should be called when route rate limit configuration changes
// so that the next request rebuilds rate limiters from the updated config.
func (p *Proxy) ClearRateLimitCache() {
	if p.rateLimiterManager != nil {
		p.rateLimiterManager.Clear()
	}
}

// Close closes the proxy and releases resources.
func (p *Proxy) Close() error {
	// Clean up rate limiter resources
	if p.rateLimiterManager != nil {
		p.rateLimiterManager.Clear()
	}
	if p.connPool != nil {
		return p.connPool.Close()
	}
	return nil
}

// CleanupStaleConnections closes connections to targets that are no longer
// in the provided set of valid targets. This should be called after a
// backend reload to clean up connections to removed or changed backends.
func (p *Proxy) CleanupStaleConnections(validTargets map[string]bool) {
	if p.connPool == nil {
		return
	}
	for _, target := range p.connPool.Targets() {
		if !validTargets[target] {
			if err := p.connPool.CloseConn(target); err != nil {
				p.logger.Warn("failed to close stale gRPC connection",
					observability.String("target", target),
					observability.Error(err),
				)
			} else {
				p.logger.Info("closed stale gRPC connection after backend reload",
					observability.String("target", target),
				)
			}
		}
	}
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
