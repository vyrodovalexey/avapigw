package main

import (
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// middlewareChainResult holds the result of building the middleware chain.
type middlewareChainResult struct {
	handler            http.Handler
	rateLimiter        *middleware.RateLimiter
	maxSessionsLimiter *middleware.MaxSessionsLimiter
}

// buildMiddlewareChain builds the middleware chain.
// The execution order (outermost executes first):
// Recovery -> RequestID -> Logging -> Tracing -> Audit -> Metrics ->
// CORS -> MaxSessions -> CircuitBreaker -> RateLimit -> [proxy]
//
// Tracing runs before Audit so that trace context (TraceID/SpanID)
// is available in the request context when audit events are created.
func buildMiddlewareChain(
	handler http.Handler,
	cfg *config.GatewayConfig,
	logger observability.Logger,
	metrics *observability.Metrics,
	tracer *observability.Tracer,
	auditLogger audit.Logger,
) middlewareChainResult {
	h := handler
	var rateLimiter *middleware.RateLimiter
	var maxSessionsLimiter *middleware.MaxSessionsLimiter

	if cfg.Spec.RateLimit != nil && cfg.Spec.RateLimit.Enabled {
		var rateLimitMiddleware func(http.Handler) http.Handler
		rateLimitMiddleware, rateLimiter = middleware.RateLimitFromConfig(
			cfg.Spec.RateLimit, logger,
			middleware.WithRateLimitHitCallback(func(route string) {
				metrics.RecordRateLimitHit(route)
			}),
		)
		h = rateLimitMiddleware(h)
	}

	if cfg.Spec.CircuitBreaker != nil && cfg.Spec.CircuitBreaker.Enabled {
		h = middleware.CircuitBreakerFromConfig(
			cfg.Spec.CircuitBreaker, logger,
			middleware.WithCircuitBreakerStateCallback(
				func(name string, state int) {
					metrics.SetCircuitBreakerState(name, state)
				},
			),
		)(h)
	}

	// Max sessions middleware should be applied early to limit concurrent requests
	if cfg.Spec.MaxSessions != nil && cfg.Spec.MaxSessions.Enabled {
		var maxSessionsMiddleware func(http.Handler) http.Handler
		maxSessionsMiddleware, maxSessionsLimiter = middleware.MaxSessionsFromConfig(cfg.Spec.MaxSessions, logger)
		h = maxSessionsMiddleware(h)
	}

	if cfg.Spec.CORS != nil {
		h = middleware.CORSFromConfig(cfg.Spec.CORS)(h)
	}

	h = observability.MetricsMiddleware(metrics)(h)
	h = middleware.Audit(auditLogger)(h)
	h = observability.TracingMiddleware(tracer)(h)
	h = middleware.Logging(logger)(h)
	h = middleware.RequestID()(h)
	h = middleware.Recovery(logger)(h)

	return middlewareChainResult{
		handler:            h,
		rateLimiter:        rateLimiter,
		maxSessionsLimiter: maxSessionsLimiter,
	}
}
