package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewRouteMiddlewareManager(t *testing.T) {
	t.Parallel()

	t.Run("creates manager with global config", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		assert.NotNil(t, manager)
		assert.Equal(t, globalConfig, manager.globalConfig)
	})

	t.Run("creates manager with nil config", func(t *testing.T) {
		t.Parallel()

		manager := NewRouteMiddlewareManager(nil, nil)

		assert.NotNil(t, manager)
		assert.Nil(t, manager.globalConfig)
	})

	t.Run("creates manager with logger", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()
		manager := NewRouteMiddlewareManager(nil, logger)

		assert.NotNil(t, manager)
		assert.NotNil(t, manager.logger)
	})
}

func TestRouteMiddlewareManager_GetEffectiveRequestLimits(t *testing.T) {
	t.Parallel()

	t.Run("returns route config when present", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		route := &config.Route{
			Name: "test-route",
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 2048,
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		result := manager.GetEffectiveRequestLimits(route)

		assert.Equal(t, int64(2048), result.MaxBodySize)
	})

	t.Run("returns global config when route config is nil", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		result := manager.GetEffectiveRequestLimits(route)

		assert.Equal(t, int64(1024), result.MaxBodySize)
	})

	t.Run("returns default config when both are nil", func(t *testing.T) {
		t.Parallel()

		manager := NewRouteMiddlewareManager(nil, nil)
		result := manager.GetEffectiveRequestLimits(nil)

		assert.NotNil(t, result)
		assert.Equal(t, int64(config.DefaultMaxBodySize), result.GetEffectiveMaxBodySize())
	})
}

func TestRouteMiddlewareManager_GetEffectiveCORS(t *testing.T) {
	t.Parallel()

	t.Run("returns route config when present", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://global.example.com"},
			},
		}

		route := &config.Route{
			Name: "test-route",
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://route.example.com"},
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		result := manager.GetEffectiveCORS(route)

		require.NotNil(t, result)
		assert.Equal(t, []string{"https://route.example.com"}, result.AllowOrigins)
	})

	t.Run("returns global config when route config is nil", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://global.example.com"},
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		result := manager.GetEffectiveCORS(route)

		require.NotNil(t, result)
		assert.Equal(t, []string{"https://global.example.com"}, result.AllowOrigins)
	})

	t.Run("returns nil when both are nil", func(t *testing.T) {
		t.Parallel()

		manager := NewRouteMiddlewareManager(nil, nil)
		result := manager.GetEffectiveCORS(nil)

		assert.Nil(t, result)
	})
}

func TestRouteMiddlewareManager_GetEffectiveSecurity(t *testing.T) {
	t.Parallel()

	t.Run("returns route config when present", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			Security: &config.SecurityConfig{
				Enabled:        true,
				ReferrerPolicy: "no-referrer",
			},
		}

		route := &config.Route{
			Name: "test-route",
			Security: &config.SecurityConfig{
				Enabled:        true,
				ReferrerPolicy: "strict-origin",
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		result := manager.GetEffectiveSecurity(route)

		require.NotNil(t, result)
		assert.Equal(t, "strict-origin", result.ReferrerPolicy)
	})

	t.Run("returns global config when route config is nil", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			Security: &config.SecurityConfig{
				Enabled:        true,
				ReferrerPolicy: "no-referrer",
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		result := manager.GetEffectiveSecurity(route)

		require.NotNil(t, result)
		assert.Equal(t, "no-referrer", result.ReferrerPolicy)
	})

	t.Run("returns nil when both are nil", func(t *testing.T) {
		t.Parallel()

		manager := NewRouteMiddlewareManager(nil, nil)
		result := manager.GetEffectiveSecurity(nil)

		assert.Nil(t, result)
	})
}

func TestRouteMiddlewareManager_GetMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("returns middleware chain for route", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"*"},
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		middlewares := manager.GetMiddleware(route)

		// Should have CORS and body limit middleware
		assert.GreaterOrEqual(t, len(middlewares), 1)
	})

	t.Run("caches middleware chain", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		// First call
		middlewares1 := manager.GetMiddleware(route)
		// Second call should return cached result
		middlewares2 := manager.GetMiddleware(route)

		assert.Equal(t, len(middlewares1), len(middlewares2))
	})

	t.Run("returns global middleware when route is nil", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)
		middlewares := manager.GetMiddleware(nil)

		assert.GreaterOrEqual(t, len(middlewares), 1)
	})
}

func TestRouteMiddlewareManager_ApplyMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("applies middleware chain to handler", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"*"},
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := manager.ApplyMiddleware(handler, route)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		// CORS middleware should add Access-Control-Allow-Origin header
		assert.Equal(t, "https://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestRouteMiddlewareManager_ClearCache(t *testing.T) {
	t.Parallel()

	t.Run("clears middleware cache", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		// Populate cache
		_ = manager.GetMiddleware(route)

		// Clear cache
		manager.ClearCache()

		// Cache should be empty
		manager.mu.RLock()
		cacheLen := len(manager.middlewareCache)
		manager.mu.RUnlock()

		assert.Equal(t, 0, cacheLen)
	})
}

func TestRouteMiddlewareManager_UpdateGlobalConfig(t *testing.T) {
	t.Parallel()

	t.Run("updates global config and clears cache", func(t *testing.T) {
		t.Parallel()

		oldConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 1024,
			},
		}

		newConfig := &config.GatewaySpec{
			RequestLimits: &config.RequestLimitsConfig{
				MaxBodySize: 2048,
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(oldConfig, nil)

		// Populate cache
		_ = manager.GetMiddleware(route)

		// Update config
		manager.UpdateGlobalConfig(newConfig)

		// Config should be updated
		assert.Equal(t, newConfig, manager.globalConfig)

		// Cache should be cleared
		manager.mu.RLock()
		cacheLen := len(manager.middlewareCache)
		manager.mu.RUnlock()

		assert.Equal(t, 0, cacheLen)
	})
}

func TestRouteMiddlewareManager_SecurityMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("applies security headers middleware", func(t *testing.T) {
		t.Parallel()

		globalConfig := &config.GatewaySpec{
			Security: &config.SecurityConfig{
				Enabled: true,
				Headers: &config.SecurityHeadersConfig{
					Enabled:             true,
					XFrameOptions:       "DENY",
					XContentTypeOptions: "nosniff",
				},
			},
		}

		route := &config.Route{
			Name: "test-route",
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := manager.ApplyMiddleware(handler, route)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		// Security headers should be set
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	})
}
