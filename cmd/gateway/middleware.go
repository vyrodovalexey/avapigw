package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// rateLimitInitTimeout bounds redis rate limiter initialization (Vault
// password reads plus the retried connectivity check). It mirrors the
// redis cache initialization bound.
const rateLimitInitTimeout = 45 * time.Second

// globalRateLimitScope is the redis bucket scope for the gateway-level
// rate limiter (route-level limiters use their route name as scope).
const globalRateLimitScope = "global"

// middlewareChainResult holds the result of building the middleware chain.
type middlewareChainResult struct {
	handler            http.Handler
	rateLimiter        middleware.RateLimiterHandle
	maxSessionsLimiter *middleware.MaxSessionsLimiter
}

// middlewareChainDeps carries optional dependencies for the middleware chain.
type middlewareChainDeps struct {
	// routeCORSSkip, when set, exempts requests whose matched route defines
	// a route-level CORS policy from the GLOBAL CORS middleware, so the
	// route policy takes precedence (including preflight OPTIONS).
	routeCORSSkip func(*http.Request) bool
}

// buildMiddlewareChain builds the middleware chain.
// The execution order (outermost executes first):
// Recovery -> RequestID -> Logging -> Tracing -> Audit -> Metrics ->
// CORS -> MaxSessions -> CircuitBreaker -> RateLimit -> Auth -> [proxy]
//
// Tracing runs before Audit so that trace context (TraceID/SpanID)
// is available in the request context when audit events are created.
// Returns an error if auth is explicitly enabled but fails to initialize,
// or if a required (fail-closed) redis rate limiter cannot be constructed.
func buildMiddlewareChain(
	handler http.Handler,
	cfg *config.GatewayConfig,
	logger observability.Logger,
	metrics *observability.Metrics,
	tracer *observability.Tracer,
	auditLogger audit.Logger,
	authCfg *config.AuthenticationConfig,
	authMetrics *auth.Metrics,
	vaultClient vault.Client,
	deps ...middlewareChainDeps,
) (middlewareChainResult, error) {
	h := handler
	var rateLimiter middleware.RateLimiterHandle
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
		// Bound redis limiter initialization (Vault reads + retried ping);
		// the in-memory store ignores the context.
		ctx, cancel := context.WithTimeout(context.Background(), rateLimitInitTimeout)
		defer cancel()

		rateLimitMiddleware, handle, rlErr := middleware.NewRateLimitMiddleware(
			ctx, cfg.Spec.RateLimit, globalRateLimitScope, logger,
			middleware.RateLimitDeps{
				VaultClient: vaultClient,
				HitCallback: func(route string) {
					metrics.RecordRateLimitHit(route)
				},
			},
		)
		if rlErr != nil {
			return middlewareChainResult{}, fmt.Errorf("rate limit middleware initialization failed: %w", rlErr)
		}
		rateLimiter = handle
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

	h = wrapGlobalCORS(h, cfg, deps)

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

// wrapGlobalCORS applies the global CORS middleware when configured.
// Route-level CORS policies take precedence over the global policy: the
// skipper (deps.routeCORSSkip) exempts matched routes that define their own
// cors block, so their route chain answers preflight and owns the
// Access-Control-* headers (see gateway.NewRouteCORSSkipper).
func wrapGlobalCORS(h http.Handler, cfg *config.GatewayConfig, deps []middlewareChainDeps) http.Handler {
	if cfg.Spec.CORS == nil {
		return h
	}
	var routeCORSSkip func(*http.Request) bool
	if len(deps) > 0 {
		routeCORSSkip = deps[0].routeCORSSkip
	}
	return middleware.CORSFromConfigWithSkipper(cfg.Spec.CORS, routeCORSSkip)(h)
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
