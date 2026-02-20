package main

import (
	"fmt"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/auth"
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
// CORS -> MaxSessions -> CircuitBreaker -> RateLimit -> Auth -> [proxy]
//
// Tracing runs before Audit so that trace context (TraceID/SpanID)
// is available in the request context when audit events are created.
// Returns an error if auth is explicitly enabled but fails to initialize.
func buildMiddlewareChain(
	handler http.Handler,
	cfg *config.GatewayConfig,
	logger observability.Logger,
	metrics *observability.Metrics,
	tracer *observability.Tracer,
	auditLogger audit.Logger,
	authCfg *config.AuthenticationConfig,
	authMetrics *auth.Metrics,
) (middlewareChainResult, error) {
	h := handler
	var rateLimiter *middleware.RateLimiter
	var maxSessionsLimiter *middleware.MaxSessionsLimiter

	// Body limit middleware wraps the handler closest to the proxy (innermost,
	// before auth) so oversized requests are rejected before authentication
	// processing. This prevents resource exhaustion from large payloads.
	if cfg.Spec.RequestLimits != nil && cfg.Spec.RequestLimits.MaxBodySize > 0 {
		h = middleware.BodyLimitFromRequestLimits(cfg.Spec.RequestLimits, logger)(h)
	}

	// Auth middleware wraps the handler closest to the proxy (innermost).
	// If auth is explicitly enabled but fails to initialize, return an error
	// so the gateway does not start without required authentication.
	if authCfg != nil && authCfg.Enabled {
		authMiddleware, err := buildAuthMiddleware(authCfg, authMetrics, logger)
		if err != nil {
			return middlewareChainResult{}, fmt.Errorf("auth middleware initialization failed: %w", err)
		}
		if authMiddleware != nil {
			h = authMiddleware(h)
		}
	}

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
	}, nil
}

// buildAuthMiddleware creates the authentication middleware from gateway config.
// Returns an error if auth is explicitly enabled but fails to initialize,
// preventing the gateway from starting without required authentication.
func buildAuthMiddleware(
	authCfg *config.AuthenticationConfig,
	authMetrics *auth.Metrics,
	logger observability.Logger,
) (func(http.Handler) http.Handler, error) {
	authConfig, err := auth.ConvertFromGatewayConfig(authCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert auth config: %w", err)
	}

	if authConfig == nil {
		return nil, nil
	}

	var opts []auth.AuthenticatorOption
	opts = append(opts, auth.WithAuthenticatorLogger(logger))
	if authMetrics != nil {
		opts = append(opts, auth.WithAuthenticatorMetrics(authMetrics))
	}

	authenticator, err := auth.NewAuthenticator(authConfig, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	logger.Info("authentication middleware enabled")
	return authenticator.HTTPMiddleware(), nil
}
