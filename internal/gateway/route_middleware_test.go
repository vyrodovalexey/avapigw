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

	t.Run("updates CORS for routes falling back to global", func(t *testing.T) {
		t.Parallel()

		// Arrange: create manager with old global CORS config
		oldConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://old.example.com"},
			},
		}

		route := &config.Route{
			Name: "no-cors-route",
			// No route-level CORS — falls back to global
		}

		manager := NewRouteMiddlewareManager(oldConfig, nil)

		// Act: verify old global CORS is returned
		result := manager.GetEffectiveCORS(route)
		require.NotNil(t, result)
		assert.Equal(t, []string{"https://old.example.com"}, result.AllowOrigins)

		// Act: update global config with new CORS
		newConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://new.example.com"},
			},
		}
		manager.UpdateGlobalConfig(newConfig)

		// Assert: new global CORS is returned
		result = manager.GetEffectiveCORS(route)
		require.NotNil(t, result)
		assert.Equal(t, []string{"https://new.example.com"}, result.AllowOrigins)
	})

	t.Run("preserves route-level CORS override after update", func(t *testing.T) {
		t.Parallel()

		// Arrange: create manager with global CORS config
		globalConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://global.example.com"},
			},
		}

		route := &config.Route{
			Name: "cors-override-route",
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://route.example.com"},
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		// Act: update global config with new CORS
		newConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://new-global.example.com"},
			},
		}
		manager.UpdateGlobalConfig(newConfig)

		// Assert: route-level CORS still takes precedence
		result := manager.GetEffectiveCORS(route)
		require.NotNil(t, result)
		assert.Equal(t, []string{"https://route.example.com"}, result.AllowOrigins)
	})

	t.Run("clears middleware cache and rebuilds with new CORS", func(t *testing.T) {
		t.Parallel()

		// Arrange: create manager with old global CORS
		oldConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://old.example.com"},
			},
		}

		route := &config.Route{
			Name: "cache-rebuild-route",
		}

		manager := NewRouteMiddlewareManager(oldConfig, nil)

		// Act: populate cache by calling GetMiddleware
		middlewares1 := manager.GetMiddleware(route)
		require.NotEmpty(t, middlewares1)

		// Verify cache is populated
		manager.mu.RLock()
		cacheLenBefore := len(manager.middlewareCache)
		manager.mu.RUnlock()
		assert.Greater(t, cacheLenBefore, 0)

		// Act: update global config with new CORS
		newConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://new.example.com"},
			},
		}
		manager.UpdateGlobalConfig(newConfig)

		// Assert: cache is cleared
		manager.mu.RLock()
		cacheLenAfter := len(manager.middlewareCache)
		manager.mu.RUnlock()
		assert.Equal(t, 0, cacheLenAfter)

		// Act: call GetMiddleware again — should rebuild with new CORS
		middlewares2 := manager.GetMiddleware(route)
		require.NotEmpty(t, middlewares2)

		// Assert: apply middleware and verify new CORS headers in response
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		wrapped := manager.ApplyMiddleware(handler, route)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://new.example.com")
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, "https://new.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS middleware applied correctly after hot reload", func(t *testing.T) {
		t.Parallel()

		// Arrange: create manager with old global CORS
		oldConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://old.example.com"},
			},
		}

		route := &config.Route{
			Name: "hot-reload-cors-route",
		}

		manager := NewRouteMiddlewareManager(oldConfig, nil)

		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Act: apply middleware and send request with old origin — should get CORS headers
		wrapped := manager.ApplyMiddleware(handler, route)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://old.example.com")
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, "https://old.example.com", rec.Header().Get("Access-Control-Allow-Origin"),
			"old origin should be allowed before hot reload")

		// Act: hot reload with new CORS config
		newConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://new.example.com"},
			},
		}
		manager.UpdateGlobalConfig(newConfig)

		// Act: apply middleware again and send request with new origin — should get CORS headers
		wrapped = manager.ApplyMiddleware(handler, route)
		req = httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://new.example.com")
		rec = httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, "https://new.example.com", rec.Header().Get("Access-Control-Allow-Origin"),
			"new origin should be allowed after hot reload")

		// Act: send request with old origin — should NOT get CORS headers
		req = httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://old.example.com")
		rec = httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"),
			"old origin should NOT be allowed after hot reload")
	})

	t.Run("route-level CORS takes precedence after multiple UpdateGlobalConfig calls", func(t *testing.T) {
		t.Parallel()

		// Arrange: create manager with global CORS
		globalConfig := &config.GatewaySpec{
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://global-v1.example.com"},
			},
		}

		route := &config.Route{
			Name: "multi-update-route",
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://route.example.com"},
			},
		}

		manager := NewRouteMiddlewareManager(globalConfig, nil)

		// Act & Assert: call UpdateGlobalConfig multiple times and verify route-level CORS
		for i, origin := range []string{
			"https://global-v2.example.com",
			"https://global-v3.example.com",
			"https://global-v4.example.com",
		} {
			newConfig := &config.GatewaySpec{
				CORS: &config.CORSConfig{
					AllowOrigins: []string{origin},
				},
			}
			manager.UpdateGlobalConfig(newConfig)

			result := manager.GetEffectiveCORS(route)
			require.NotNil(t, result, "iteration %d: effective CORS should not be nil", i)
			assert.Equal(t, []string{"https://route.example.com"}, result.AllowOrigins,
				"iteration %d: route-level CORS should take precedence", i)

			// Also verify via middleware that route-level CORS is applied
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			wrapped := manager.ApplyMiddleware(handler, route)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", "https://route.example.com")
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			assert.Equal(t, "https://route.example.com", rec.Header().Get("Access-Control-Allow-Origin"),
				"iteration %d: route-level origin should be allowed", i)
		}
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
