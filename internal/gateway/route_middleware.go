// Package gateway provides the core API Gateway functionality.
package gateway

import (
	"net/http"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/security"
)

// RouteMiddlewareManager manages route-specific middleware chains.
// It handles merging route-level configurations with global configurations
// and creates appropriate middleware handlers for each route.
type RouteMiddlewareManager struct {
	globalConfig    *config.GatewaySpec
	logger          observability.Logger
	middlewareCache map[string][]func(http.Handler) http.Handler
	mu              sync.RWMutex
}

// NewRouteMiddlewareManager creates a new route middleware manager.
func NewRouteMiddlewareManager(globalConfig *config.GatewaySpec, logger observability.Logger) *RouteMiddlewareManager {
	if logger == nil {
		logger = observability.NopLogger()
	}

	return &RouteMiddlewareManager{
		globalConfig:    globalConfig,
		logger:          logger,
		middlewareCache: make(map[string][]func(http.Handler) http.Handler),
	}
}

// GetMiddleware returns the middleware chain for a specific route.
// The middleware chain is cached for performance.
// Middleware order: Security headers -> CORS -> Body limit
func (m *RouteMiddlewareManager) GetMiddleware(route *config.Route) []func(http.Handler) http.Handler {
	if route == nil {
		return m.getGlobalMiddleware()
	}

	// Check cache first
	m.mu.RLock()
	if cached, ok := m.middlewareCache[route.Name]; ok {
		m.mu.RUnlock()
		return cached
	}
	m.mu.RUnlock()

	// Build middleware chain
	middlewares := m.buildMiddlewareChain(route)

	// Cache the result
	m.mu.Lock()
	m.middlewareCache[route.Name] = middlewares
	m.mu.Unlock()

	return middlewares
}

// getGlobalMiddleware returns the global middleware chain when no route is specified.
func (m *RouteMiddlewareManager) getGlobalMiddleware() []func(http.Handler) http.Handler {
	const globalCacheKey = "__global__"

	m.mu.RLock()
	if cached, ok := m.middlewareCache[globalCacheKey]; ok {
		m.mu.RUnlock()
		return cached
	}
	m.mu.RUnlock()

	middlewares := m.buildGlobalMiddlewareChain()

	m.mu.Lock()
	m.middlewareCache[globalCacheKey] = middlewares
	m.mu.Unlock()

	return middlewares
}

// buildMiddlewareChain builds the middleware chain for a route.
func (m *RouteMiddlewareManager) buildMiddlewareChain(route *config.Route) []func(http.Handler) http.Handler {
	var middlewares []func(http.Handler) http.Handler

	// 1. Security headers (applied early)
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

	// 2. CORS (applied before request processing)
	corsCfg := m.GetEffectiveCORS(route)
	if corsCfg != nil {
		corsMiddleware := middleware.CORSFromConfig(corsCfg)
		middlewares = append(middlewares, corsMiddleware)
		m.logger.Debug("applied route-level CORS",
			observability.String("route", route.Name),
		)
	}

	// 3. Body limit (applied before reading body)
	requestLimits := m.GetEffectiveRequestLimits(route)
	if requestLimits != nil {
		bodyLimitMiddleware := middleware.BodyLimitFromRequestLimits(requestLimits, m.logger)
		middlewares = append(middlewares, bodyLimitMiddleware)
		m.logger.Debug("applied route-level body limit",
			observability.String("route", route.Name),
			observability.Int64("max_body_size", requestLimits.GetEffectiveMaxBodySize()),
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
