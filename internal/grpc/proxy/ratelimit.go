package proxy

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcmiddleware "github.com/vyrodovalexey/avapigw/internal/grpc/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// RouteRateLimiterManager manages per-route rate limiters for the gRPC proxy.
// Each route with rate limiting enabled gets its own GRPCRateLimiter instance,
// keyed by route name. The manager uses double-checked locking to ensure
// thread-safe lazy initialization of limiters.
type RouteRateLimiterManager struct {
	limiters map[string]*grpcmiddleware.GRPCRateLimiter
	mu       sync.RWMutex
	logger   observability.Logger
}

// RouteRateLimiterManagerOption is a functional option for configuring the manager.
type RouteRateLimiterManagerOption func(*RouteRateLimiterManager)

// WithRateLimiterManagerLogger sets the logger for the rate limiter manager.
func WithRateLimiterManagerLogger(logger observability.Logger) RouteRateLimiterManagerOption {
	return func(m *RouteRateLimiterManager) {
		m.logger = logger
	}
}

// NewRouteRateLimiterManager creates a new per-route rate limiter manager.
func NewRouteRateLimiterManager(opts ...RouteRateLimiterManagerOption) *RouteRateLimiterManager {
	m := &RouteRateLimiterManager{
		limiters: make(map[string]*grpcmiddleware.GRPCRateLimiter),
		logger:   observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Check verifies whether the request is allowed by the route's rate limiter.
// If the rate limit is exceeded, it returns a ResourceExhausted gRPC status error.
// If the route has no rate limit config or rate limiting is disabled, it returns nil.
func (m *RouteRateLimiterManager) Check(ctx context.Context, routeName string, cfg *config.RateLimitConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	limiter := m.getOrCreateLimiter(routeName, cfg)

	clientAddr := extractClientAddr(ctx)

	metrics := getGRPCProxyMetrics()

	if !limiter.Allow(clientAddr) {
		m.logger.Warn("per-route rate limit exceeded",
			observability.String("route", routeName),
			observability.String("client_addr", clientAddr),
		)
		metrics.rateLimitRejected.WithLabelValues(routeName).Inc()
		return status.Errorf(codes.ResourceExhausted, "rate limit exceeded for route %s", routeName)
	}

	metrics.rateLimitAllowed.WithLabelValues(routeName).Inc()
	return nil
}

// getOrCreateLimiter returns a cached rate limiter for the given route,
// creating one from the config on first access. Uses double-checked locking
// to avoid holding the write lock on the hot path.
func (m *RouteRateLimiterManager) getOrCreateLimiter(
	routeName string, cfg *config.RateLimitConfig,
) *grpcmiddleware.GRPCRateLimiter {
	// Fast path: check cache under read lock.
	m.mu.RLock()
	if cached, ok := m.limiters[routeName]; ok {
		m.mu.RUnlock()
		return cached
	}
	m.mu.RUnlock()

	// Slow path: create limiter under write lock with double-check.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock.
	if cached, ok := m.limiters[routeName]; ok {
		return cached
	}

	limiter := grpcmiddleware.NewGRPCRateLimiter(
		cfg.RequestsPerSecond,
		cfg.Burst,
		cfg.PerClient,
		grpcmiddleware.WithRateLimiterLogger(m.logger),
	)
	limiter.StartAutoCleanup()

	m.limiters[routeName] = limiter

	m.logger.Debug("created per-route rate limiter",
		observability.String("route", routeName),
		observability.Int("rps", cfg.RequestsPerSecond),
		observability.Int("burst", cfg.Burst),
		observability.Bool("perClient", cfg.PerClient),
	)

	return limiter
}

// Clear stops all rate limiters and clears the cache.
// This should be called when routes are reloaded.
func (m *RouteRateLimiterManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, limiter := range m.limiters {
		limiter.Stop()
		m.logger.Debug("stopped per-route rate limiter",
			observability.String("route", name),
		)
	}

	m.limiters = make(map[string]*grpcmiddleware.GRPCRateLimiter)
	m.logger.Debug("per-route rate limiter cache cleared")
}

// LimiterCount returns the number of active route rate limiters.
func (m *RouteRateLimiterManager) LimiterCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.limiters)
}

// extractClientAddr extracts the client address from the gRPC peer context.
func extractClientAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}
