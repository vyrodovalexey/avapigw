// Package gateway provides the core API Gateway functionality.
package gateway

import (
	"net/http"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/security"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

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
		globalConfig:    globalConfig,
		logger:          logger,
		middlewareCache: make(map[string][]func(http.Handler) http.Handler),
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
// Returns nil if authentication is not configured, not enabled, or if an error occurs
// during configuration conversion or authenticator creation.
func (m *RouteMiddlewareManager) buildRouteAuthMiddleware(route *config.Route) func(http.Handler) http.Handler {
	if route.Authentication == nil || !route.Authentication.Enabled {
		return nil
	}

	authConfig, err := auth.ConvertFromGatewayConfig(route.Authentication)
	if err != nil {
		m.logger.Error("failed to convert route auth config",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		return nil
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
		m.logger.Error("failed to create route authenticator",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		return nil
	}

	m.logger.Debug("applied route-level authentication",
		observability.String("route", route.Name),
	)
	return authenticator.HTTPMiddleware()
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
// Returns nil if authorization is not configured, not enabled, or if an error occurs
// during configuration conversion or authorizer creation.
func (m *RouteMiddlewareManager) buildRouteAuthzMiddleware(route *config.Route) func(http.Handler) http.Handler {
	if route.Authorization == nil || !route.Authorization.Enabled {
		return nil
	}

	authzConfig, err := authz.ConvertFromGatewayConfig(route.Authorization)
	if err != nil {
		m.logger.Error("failed to convert route authz config",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		return nil
	}
	if authzConfig == nil {
		return nil
	}

	metrics := m.getOrCreateAuthzMetrics()
	opts := []authz.AuthorizerOption{
		authz.WithAuthorizerLogger(m.logger),
		authz.WithAuthorizerMetrics(metrics),
	}

	authorizer, err := authz.New(authzConfig, opts...)
	if err != nil {
		m.logger.Error("failed to create route authorizer",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		return nil
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

	// 0. Authentication (must be first - closest to client)
	if authMw := m.buildRouteAuthMiddleware(route); authMw != nil {
		middlewares = append(middlewares, authMw)
	}

	// 1. Authorization (must be after authentication - needs identity from context)
	if authzMw := m.buildRouteAuthzMiddleware(route); authzMw != nil {
		middlewares = append(middlewares, authzMw)
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

	// 5. Headers manipulation
	if route.Headers != nil {
		headersMiddleware := middleware.HeadersFromConfig(route.Headers)
		middlewares = append(middlewares, headersMiddleware)
		m.logger.Debug("applied route-level headers",
			observability.String("route", route.Name),
		)
	}

	// 6. Cache (applied around the proxy handler)
	if cacheMw := m.buildRouteCacheMiddleware(route); cacheMw != nil {
		middlewares = append(middlewares, cacheMw)
	}

	// 7. Transform (request/response transformation)
	if route.Transform != nil && !route.Transform.IsEmpty() {
		transformMiddleware := middleware.TransformFromConfig(route.Transform, m.logger)
		middlewares = append(middlewares, transformMiddleware)
		m.logger.Debug("applied route-level transform",
			observability.String("route", route.Name),
		)
	}

	// 8. Encoding (content negotiation and metrics)
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

// ClearCache clears the middleware cache.
// This should be called when configuration changes.
func (m *RouteMiddlewareManager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.middlewareCache = make(map[string][]func(http.Handler) http.Handler)
}

// UpdateGlobalConfig updates the global configuration and clears the cache.
func (m *RouteMiddlewareManager) UpdateGlobalConfig(globalConfig *config.GatewaySpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalConfig = globalConfig
	m.middlewareCache = make(map[string][]func(http.Handler) http.Handler)
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
