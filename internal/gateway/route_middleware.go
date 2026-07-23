// Package gateway provides the core API Gateway functionality.
package gateway

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/config"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/openapi"
	"github.com/vyrodovalexey/avapigw/internal/security"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// routeRateLimitInitTimeout bounds per-route redis rate limiter
// initialization (Vault password reads plus the retried connectivity
// check). Route middleware chains are built lazily on first use, so this
// bound caps the worst-case first-request latency for the route.
const routeRateLimitInitTimeout = 10 * time.Second

// Security middleware stage labels used in fail-closed logs and metrics.
const (
	stageAuthentication = "authentication"
	stageAuthorization  = "authorization"
)

// securityUnavailableBody is the JSON error body returned by the
// fail-closed fallback when a route's authentication or authorization
// middleware could not be constructed.
const securityUnavailableBody = `{"error":"security middleware unavailable"}`

// RouteMiddlewareOption is a functional option for configuring RouteMiddlewareManager.
type RouteMiddlewareOption func(*RouteMiddlewareManager)

// WithRouteMiddlewareCacheFactory sets the cache factory for per-route caching.
func WithRouteMiddlewareCacheFactory(cf *CacheFactory) RouteMiddlewareOption {
	return func(m *RouteMiddlewareManager) {
		m.cacheFactory = cf
	}
}

// WithRouteMiddlewareAuthMetrics sets the auth metrics for per-route authentication.
func WithRouteMiddlewareAuthMetrics(m *auth.Metrics) RouteMiddlewareOption {
	return func(mgr *RouteMiddlewareManager) {
		mgr.authMetrics = m
	}
}

// WithRouteMiddlewareAuthzMetrics sets the authz metrics for per-route authorization.
func WithRouteMiddlewareAuthzMetrics(m *authz.Metrics) RouteMiddlewareOption {
	return func(mgr *RouteMiddlewareManager) {
		mgr.authzMetrics = m
	}
}

// WithRouteMiddlewareVaultClient sets the vault client for per-route API key authentication.
func WithRouteMiddlewareVaultClient(client vault.Client) RouteMiddlewareOption {
	return func(m *RouteMiddlewareManager) {
		m.vaultClient = client
	}
}

// RouteMiddlewareManager manages route-specific middleware chains.
// It handles merging route-level configurations with global configurations
// and creates appropriate middleware handlers for each route.
type RouteMiddlewareManager struct {
	globalConfig    *config.GatewaySpec
	logger          observability.Logger
	middlewareCache map[string][]func(http.Handler) http.Handler
	mu              sync.RWMutex
	cacheFactory    *CacheFactory
	authMetrics     *auth.Metrics
	authzMetrics    *authz.Metrics
	vaultClient     vault.Client

	// routeRateLimiters tracks per-route rate limiter lifecycles so their
	// resources (cleanup goroutines, redis connections) are released when
	// middleware chains are rebuilt or the gateway shuts down.
	routeRateLimiters map[string]middleware.RateLimiterHandle
}

// NewRouteMiddlewareManager creates a new route middleware manager.
func NewRouteMiddlewareManager(
	globalConfig *config.GatewaySpec,
	logger observability.Logger,
	opts ...RouteMiddlewareOption,
) *RouteMiddlewareManager {
	if logger == nil {
		logger = observability.NopLogger()
	}

	m := &RouteMiddlewareManager{
		globalConfig:      globalConfig,
		logger:            logger,
		middlewareCache:   make(map[string][]func(http.Handler) http.Handler),
		routeRateLimiters: make(map[string]middleware.RateLimiterHandle),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// GetMiddleware returns the middleware chain for a specific route.
// The middleware chain is cached for performance using double-check
// locking to avoid redundant builds under concurrent access.
// Middleware order: Security headers -> CORS -> Body limit
func (m *RouteMiddlewareManager) GetMiddleware(route *config.Route) []func(http.Handler) http.Handler {
	if route == nil {
		return m.getGlobalMiddleware()
	}

	// Check cache first (read lock)
	m.mu.RLock()
	if cached, ok := m.middlewareCache[route.Name]; ok {
		m.mu.RUnlock()
		return cached
	}
	m.mu.RUnlock()

	// Build middleware chain (write lock with double-check)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := m.middlewareCache[route.Name]; ok {
		return cached
	}

	middlewares := m.buildMiddlewareChain(route)
	m.middlewareCache[route.Name] = middlewares
	return middlewares
}

// getGlobalMiddleware returns the global middleware chain when no route is specified.
// Uses double-check locking to avoid redundant builds under concurrent access.
func (m *RouteMiddlewareManager) getGlobalMiddleware() []func(http.Handler) http.Handler {
	const globalCacheKey = "__global__"

	// Check cache first (read lock)
	m.mu.RLock()
	if cached, ok := m.middlewareCache[globalCacheKey]; ok {
		m.mu.RUnlock()
		return cached
	}
	m.mu.RUnlock()

	// Build middleware chain (write lock with double-check)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := m.middlewareCache[globalCacheKey]; ok {
		return cached
	}

	middlewares := m.buildGlobalMiddlewareChain()
	m.middlewareCache[globalCacheKey] = middlewares
	return middlewares
}

// buildRouteAuthMiddleware creates an authentication middleware for the given route.
// Returns nil if authentication is not configured or not enabled.
//
// Configuration conversion or authenticator construction errors fail
// CLOSED: a route configured WITH authentication must never serve traffic
// unauthenticated, so a rejecting fallback middleware is installed instead
// (see securityFailClosedFallback).
func (m *RouteMiddlewareManager) buildRouteAuthMiddleware(route *config.Route) func(http.Handler) http.Handler {
	if route.Authentication == nil || !route.Authentication.Enabled {
		return nil
	}

	authConfig, err := auth.ConvertFromGatewayConfig(route.Authentication)
	if err != nil {
		return m.securityFailClosedFallback(route.Name, stageAuthentication, err)
	}
	if authConfig == nil {
		return nil
	}

	opts := []auth.AuthenticatorOption{auth.WithAuthenticatorLogger(m.logger)}
	if m.authMetrics != nil {
		opts = append(opts, auth.WithAuthenticatorMetrics(m.authMetrics))
	}
	if m.vaultClient != nil {
		opts = append(opts, auth.WithVaultClient(m.vaultClient))
	}

	authenticator, err := auth.NewAuthenticator(authConfig, opts...)
	if err != nil {
		return m.securityFailClosedFallback(route.Name, stageAuthentication, err)
	}

	m.logger.Debug("applied route-level authentication",
		observability.String("route", route.Name),
	)
	return authenticator.HTTPMiddleware()
}

// securityFailClosedFallback returns a middleware that rejects every request
// with 503 Service Unavailable. It is installed when a route's
// authentication or authorization middleware cannot be constructed: a route
// configured WITH a security control must never serve traffic without it,
// mirroring the fail-closed fallback of strict rate limiters below. The
// gateway keeps serving other routes; the affected route recovers on the
// next configuration reload that yields a constructible middleware.
func (m *RouteMiddlewareManager) securityFailClosedFallback(
	routeName, stage string, err error,
) func(http.Handler) http.Handler {
	m.logger.Error("failed to build route security middleware, failing closed",
		observability.String("route", routeName),
		observability.String("stage", stage),
		observability.Error(err),
	)

	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			routepkg.GetRouteMetrics().RecordAuthFailure(
				routeName, r.Method, stage, "construction_failed",
			)
			w.Header().Set(middleware.HeaderContentType, middleware.ContentTypeJSON)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, securityUnavailableBody)
		})
	}
}

// getOrCreateAuthzMetrics returns the shared authz metrics instance,
// creating it lazily on first use. This ensures all routes share a single
// metrics instance, preventing duplicate Prometheus registration panics.
// Must be called under m.mu write lock (which is the case when called
// from buildMiddlewareChain via GetMiddleware).
func (m *RouteMiddlewareManager) getOrCreateAuthzMetrics() *authz.Metrics {
	if m.authzMetrics == nil {
		m.authzMetrics = authz.NewMetrics("gateway")
	}
	return m.authzMetrics
}

// buildRouteAuthzMiddleware creates an authorization middleware for the given route.
// Returns nil if authorization is not configured or not enabled.
//
// Configuration conversion or authorizer construction errors fail CLOSED:
// a route configured WITH authorization must never serve traffic without
// policy enforcement, so a rejecting fallback middleware is installed
// instead (see securityFailClosedFallback).
func (m *RouteMiddlewareManager) buildRouteAuthzMiddleware(route *config.Route) func(http.Handler) http.Handler {
	if route.Authorization == nil || !route.Authorization.Enabled {
		return nil
	}

	authzConfig, err := authz.ConvertFromGatewayConfig(route.Authorization)
	if err != nil {
		return m.securityFailClosedFallback(route.Name, stageAuthorization, err)
	}
	if authzConfig == nil {
		return nil
	}

	metrics := m.getOrCreateAuthzMetrics()
	opts := []authz.AuthorizerOption{
		authz.WithAuthorizerLogger(m.logger),
		authz.WithAuthorizerMetrics(metrics),
	}
	// Vault client enables Vault-referenced Redis password resolution for
	// the redis-backed decision cache.
	if m.vaultClient != nil {
		opts = append(opts, authz.WithAuthorizerVaultClient(m.vaultClient))
	}

	authorizer, err := authz.New(authzConfig, opts...)
	if err != nil {
		return m.securityFailClosedFallback(route.Name, stageAuthorization, err)
	}

	httpAuthz := authz.NewHTTPAuthorizer(authorizer, authzConfig,
		authz.WithHTTPAuthorizerLogger(m.logger),
		authz.WithHTTPAuthorizerMetrics(metrics),
	)

	m.logger.Debug("applied route-level authorization",
		observability.String("route", route.Name),
	)
	return httpAuthz.HTTPMiddleware()
}

// buildRouteRateLimitMiddleware creates a rate limit middleware for the
// given route, honoring the configured store (in-memory or redis-backed
// distributed limiting). The limiter lifecycle handle is tracked so its
// resources are released on chain rebuilds and shutdown.
//
// Construction failures follow the limiter's failure policy: fail-open
// limiters degrade to no limiting (logged error), while fail-closed
// limiters reject all route traffic until the configuration is fixed —
// a strict limiter must never run unenforced.
// Must be called with m.mu held (via buildMiddlewareChain).
func (m *RouteMiddlewareManager) buildRouteRateLimitMiddleware(route *config.Route) func(http.Handler) http.Handler {
	if route.RateLimit == nil || !route.RateLimit.Enabled {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), routeRateLimitInitTimeout)
	defer cancel()

	mw, handle, err := middleware.NewRateLimitMiddleware(
		ctx, route.RateLimit, route.Name, m.logger,
		middleware.RateLimitDeps{VaultClient: m.vaultClient},
	)
	if err != nil {
		return m.rateLimitConstructionFallback(route, err)
	}

	if handle != nil {
		m.routeRateLimiters[route.Name] = handle
	}

	m.logger.Debug("applied route-level rate limit",
		observability.String("route", route.Name),
		observability.String("store", route.RateLimit.GetEffectiveStore()),
	)
	return mw
}

// rateLimitConstructionFallback resolves a rate limiter construction error
// according to the failure policy of the route's rate limit configuration.
func (m *RouteMiddlewareManager) rateLimitConstructionFallback(
	route *config.Route, err error,
) func(http.Handler) http.Handler {
	failOpen := route.RateLimit.Redis.GetEffectiveFailOpen()

	m.logger.Error("failed to create route rate limiter",
		observability.String("route", route.Name),
		observability.Bool("failOpen", failOpen),
		observability.Error(err),
	)

	if failOpen {
		// Fail open: skip rate limiting for this route until a config
		// reload provides a constructible limiter.
		return nil
	}

	// Fail closed: reject route traffic rather than running unlimited.
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(middleware.HeaderContentType, middleware.ContentTypeJSON)
			w.Header().Set(middleware.HeaderRetryAfter, "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, middleware.ErrRateLimitExceeded)
		})
	}
}

// buildRouteCacheMiddleware creates a cache middleware for the given route.
// Returns nil if caching is not configured, not enabled, or if an error occurs.
func (m *RouteMiddlewareManager) buildRouteCacheMiddleware(route *config.Route) func(http.Handler) http.Handler {
	if route.Cache == nil || !route.Cache.Enabled || m.cacheFactory == nil {
		return nil
	}

	c, err := m.cacheFactory.GetOrCreate(route.Name, route.Cache)
	if err != nil {
		m.logger.Error("failed to create cache for route, skipping cache middleware",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		return nil
	}

	m.logger.Debug("applied route-level cache",
		observability.String("route", route.Name),
	)
	return middleware.CacheFromConfig(c, route.Cache, m.logger)
}

// buildMiddlewareChain builds the middleware chain for a route.
func (m *RouteMiddlewareManager) buildMiddlewareChain(route *config.Route) []func(http.Handler) http.Handler {
	var middlewares []func(http.Handler) http.Handler

	// Identity and admission stage, in order:
	//   0. Authentication (must be first - closest to client)
	//   1. Authorization (after authentication - needs identity from context)
	//   1.5. Rate limiting (after auth so unauthenticated requests get 401
	//        before 429; before body/validation work to shed load early)
	admissionBuilders := []func(*config.Route) func(http.Handler) http.Handler{
		m.buildRouteAuthMiddleware,
		m.buildRouteAuthzMiddleware,
		m.buildRouteRateLimitMiddleware,
	}
	for _, builder := range admissionBuilders {
		if mw := builder(route); mw != nil {
			middlewares = append(middlewares, mw)
		}
	}

	// 2. Security headers (applied early)
	securityCfg := m.GetEffectiveSecurity(route)
	if securityCfg != nil && securityCfg.Enabled {
		securityMiddleware := security.SecurityHeadersFromConfig(securityCfg)
		if securityMiddleware != nil {
			middlewares = append(middlewares, securityMiddleware)
			m.logger.Debug("applied route-level security headers",
				observability.String("route", route.Name),
			)
		}
	}

	// 3. CORS (applied before request processing)
	corsCfg := m.GetEffectiveCORS(route)
	if corsCfg != nil {
		corsMiddleware := middleware.CORSFromConfig(corsCfg)
		middlewares = append(middlewares, corsMiddleware)
		m.logger.Debug("applied route-level CORS",
			observability.String("route", route.Name),
		)
	}

	// 4. Body limit (applied before reading body)
	requestLimits := m.GetEffectiveRequestLimits(route)
	if requestLimits != nil {
		bodyLimitMiddleware := middleware.BodyLimitFromRequestLimits(requestLimits, m.logger)
		middlewares = append(middlewares, bodyLimitMiddleware)
		m.logger.Debug("applied route-level body limit",
			observability.String("route", route.Name),
			observability.Int64("max_body_size", requestLimits.GetEffectiveMaxBodySize()),
		)
	}

	// 5. OpenAPI Validation (after body limit, before headers)
	if openapiMw := m.buildRouteOpenAPIValidationMiddleware(route); openapiMw != nil {
		middlewares = append(middlewares, openapiMw)
	}

	// 6. Headers manipulation
	if route.Headers != nil {
		headersMiddleware := middleware.HeadersFromConfig(route.Headers)
		middlewares = append(middlewares, headersMiddleware)
		m.logger.Debug("applied route-level headers",
			observability.String("route", route.Name),
		)
	}

	// 7. Cache (applied around the proxy handler)
	if cacheMw := m.buildRouteCacheMiddleware(route); cacheMw != nil {
		middlewares = append(middlewares, cacheMw)
	}

	// 8. Transform (request/response transformation)
	if route.Transform != nil && !route.Transform.IsEmpty() {
		transformMiddleware := middleware.TransformFromConfig(route.Transform, m.logger)
		middlewares = append(middlewares, transformMiddleware)
		m.logger.Debug("applied route-level transform",
			observability.String("route", route.Name),
		)
	}

	// 9. Encoding (content negotiation and metrics)
	if route.Encoding != nil && !route.Encoding.IsEmpty() {
		encodingMiddleware := middleware.EncodingFromConfig(route.Encoding, m.logger)
		middlewares = append(middlewares, encodingMiddleware)
		m.logger.Debug("applied route-level encoding",
			observability.String("route", route.Name),
		)
	}

	return middlewares
}

// buildGlobalMiddlewareChain builds the global middleware chain.
func (m *RouteMiddlewareManager) buildGlobalMiddlewareChain() []func(http.Handler) http.Handler {
	var middlewares []func(http.Handler) http.Handler

	if m.globalConfig == nil {
		return middlewares
	}

	// 1. Security headers
	if m.globalConfig.Security != nil && m.globalConfig.Security.Enabled {
		securityMiddleware := security.SecurityHeadersFromConfig(m.globalConfig.Security)
		if securityMiddleware != nil {
			middlewares = append(middlewares, securityMiddleware)
		}
	}

	// 2. CORS
	if m.globalConfig.CORS != nil {
		corsMiddleware := middleware.CORSFromConfig(m.globalConfig.CORS)
		middlewares = append(middlewares, corsMiddleware)
	}

	// 3. Body limit
	if m.globalConfig.RequestLimits != nil {
		bodyLimitMiddleware := middleware.BodyLimitFromRequestLimits(m.globalConfig.RequestLimits, m.logger)
		middlewares = append(middlewares, bodyLimitMiddleware)
	}

	return middlewares
}

// GetEffectiveRequestLimits returns the effective request limits for a route.
// Route config takes precedence over global config.
// If both are nil, returns default limits.
func (m *RouteMiddlewareManager) GetEffectiveRequestLimits(route *config.Route) *config.RequestLimitsConfig {
	// Route-level config takes precedence
	if route != nil && route.RequestLimits != nil {
		return route.RequestLimits
	}

	// Fall back to global config
	if m.globalConfig != nil && m.globalConfig.RequestLimits != nil {
		return m.globalConfig.RequestLimits
	}

	// Return default limits
	return config.DefaultRequestLimits()
}

// GetEffectiveCORS returns the effective CORS config for a route.
// Route config takes precedence over global config.
// If both are nil, returns nil (no CORS).
func (m *RouteMiddlewareManager) GetEffectiveCORS(route *config.Route) *config.CORSConfig {
	// Route-level config takes precedence
	if route != nil && route.CORS != nil {
		return route.CORS
	}

	// Fall back to global config
	if m.globalConfig != nil && m.globalConfig.CORS != nil {
		return m.globalConfig.CORS
	}

	return nil
}

// GetEffectiveSecurity returns the effective security config for a route.
// Route config takes precedence over global config.
// If both are nil, returns nil (no security headers).
func (m *RouteMiddlewareManager) GetEffectiveSecurity(route *config.Route) *config.SecurityConfig {
	// Route-level config takes precedence
	if route != nil && route.Security != nil {
		return route.Security
	}

	// Fall back to global config
	if m.globalConfig != nil && m.globalConfig.Security != nil {
		return m.globalConfig.Security
	}

	return nil
}

// buildRouteOpenAPIValidationMiddleware creates an OpenAPI validation middleware
// for the given route. Returns nil if OpenAPI validation is not configured or not enabled.
func (m *RouteMiddlewareManager) buildRouteOpenAPIValidationMiddleware(
	route *config.Route,
) func(http.Handler) http.Handler {
	cfg := m.GetEffectiveOpenAPIValidation(route)
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	mw := openapi.MiddlewareFromConfig(cfg, m.logger)

	m.logger.Debug("applied route-level OpenAPI validation",
		observability.String("route", route.Name),
	)
	return mw
}

// GetEffectiveOpenAPIValidation returns the effective OpenAPI validation config for a route.
// Route config takes precedence over global config.
// If both are nil, returns nil (no validation).
func (m *RouteMiddlewareManager) GetEffectiveOpenAPIValidation(route *config.Route) *config.OpenAPIValidationConfig {
	// Route-level config takes precedence.
	if route != nil && route.OpenAPIValidation != nil {
		return route.OpenAPIValidation
	}

	// Fall back to global config.
	if m.globalConfig != nil && m.globalConfig.OpenAPIValidation != nil {
		return m.globalConfig.OpenAPIValidation
	}

	return nil
}

// ClearCache clears the middleware cache.
// This should be called when configuration changes.
func (m *RouteMiddlewareManager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clearLocked()
}

// UpdateGlobalConfig updates the global configuration and clears the cache.
func (m *RouteMiddlewareManager) UpdateGlobalConfig(globalConfig *config.GatewaySpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalConfig = globalConfig
	m.clearLocked()
}

// Stop releases resources held by route middleware (rate limiter cleanup
// goroutines and redis connections). It should be called during shutdown.
func (m *RouteMiddlewareManager) Stop() {
	m.ClearCache()
}

// clearLocked resets the middleware cache and stops tracked rate limiters
// so rebuilt chains do not leak goroutines or redis connections.
// Must be called with m.mu held.
func (m *RouteMiddlewareManager) clearLocked() {
	m.middlewareCache = make(map[string][]func(http.Handler) http.Handler)

	for name, limiter := range m.routeRateLimiters {
		limiter.Stop()
		m.logger.Debug("stopped route rate limiter",
			observability.String("route", name),
		)
	}
	m.routeRateLimiters = make(map[string]middleware.RateLimiterHandle)
}

// ApplyMiddleware applies the middleware chain to a handler for a specific route.
func (m *RouteMiddlewareManager) ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler {
	middlewares := m.GetMiddleware(route)

	// Apply middlewares in reverse order so they execute in the correct order
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}
