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

// TestRouteMiddlewareManager_GetGlobalMiddleware_NilConfig tests getGlobalMiddleware with nil config.
func TestRouteMiddlewareManager_GetGlobalMiddleware_NilConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	manager := NewRouteMiddlewareManager(nil, logger)

	// Should return empty middleware chain
	middlewares := manager.GetMiddleware(nil)
	assert.Empty(t, middlewares)
}

// TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_WithSecurity tests buildGlobalMiddlewareChain with security.
func TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_WithSecurity(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	globalCfg := &config.GatewaySpec{
		Security: &config.SecurityConfig{
			Enabled: true,
			Headers: &config.SecurityHeadersConfig{
				XContentTypeOptions: "nosniff",
				XFrameOptions:       "DENY",
			},
		},
	}

	manager := NewRouteMiddlewareManager(globalCfg, logger)
	middlewares := manager.GetMiddleware(nil)
	assert.NotEmpty(t, middlewares)
}

// TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_WithCORS tests buildGlobalMiddlewareChain with CORS.
func TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_WithCORS(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	globalCfg := &config.GatewaySpec{
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET", "POST"},
		},
	}

	manager := NewRouteMiddlewareManager(globalCfg, logger)
	middlewares := manager.GetMiddleware(nil)
	assert.NotEmpty(t, middlewares)
}

// TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_WithBodyLimit tests buildGlobalMiddlewareChain with body limit.
func TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_WithBodyLimit(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	globalCfg := &config.GatewaySpec{
		RequestLimits: &config.RequestLimitsConfig{
			MaxBodySize: 1024,
		},
	}

	manager := NewRouteMiddlewareManager(globalCfg, logger)
	middlewares := manager.GetMiddleware(nil)
	assert.NotEmpty(t, middlewares)
}

// TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_AllMiddleware tests with all middleware types.
func TestRouteMiddlewareManager_BuildGlobalMiddlewareChain_AllMiddleware(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	globalCfg := &config.GatewaySpec{
		Security: &config.SecurityConfig{
			Enabled: true,
			Headers: &config.SecurityHeadersConfig{
				XContentTypeOptions: "nosniff",
			},
		},
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
		},
		RequestLimits: &config.RequestLimitsConfig{
			MaxBodySize: 1024,
		},
	}

	manager := NewRouteMiddlewareManager(globalCfg, logger)
	middlewares := manager.GetMiddleware(nil)
	assert.Len(t, middlewares, 3) // security + CORS + body limit
}

// TestRouteMiddlewareManager_GetMiddleware_CachesResult tests that GetMiddleware caches results.
func TestRouteMiddlewareManager_GetMiddleware_CachesResult(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	globalCfg := &config.GatewaySpec{
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
		},
	}

	manager := NewRouteMiddlewareManager(globalCfg, logger)

	// First call
	mw1 := manager.GetMiddleware(nil)
	// Second call should return cached result
	mw2 := manager.GetMiddleware(nil)

	assert.Equal(t, len(mw1), len(mw2))
}

// TestListener_ConvertToTLSConfig_NilConfig_Coverage tests convertToTLSConfig with nil.
func TestListener_ConvertToTLSConfig_NilConfig_Coverage(t *testing.T) {
	t.Parallel()

	l := &Listener{
		logger: observability.NopLogger(),
	}

	result := l.convertToTLSConfig(nil)
	assert.Nil(t, result)
}

// TestNewListener_WithAllOptions tests NewListener with all options.
func TestNewListener_WithAllOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	l, err := NewListener(cfg, handler,
		WithListenerLogger(logger),
	)
	require.NoError(t, err)
	assert.NotNil(t, l)
	assert.Equal(t, "test-listener", l.Name())
	assert.Equal(t, 8080, l.Port())
	assert.False(t, l.IsRunning())
	assert.False(t, l.IsTLSEnabled())
	assert.Nil(t, l.GetTLSManager())
	assert.Nil(t, l.GetRouteTLSManager())
	assert.False(t, l.IsRouteTLSEnabled())
}

// TestListener_HSTSMiddleware tests the HSTS middleware.
func TestListener_HSTSMiddleware_Coverage(t *testing.T) {
	t.Parallel()

	l := &Listener{
		config: config.Listener{
			TLS: &config.ListenerTLSConfig{
				HSTS: &config.HSTSConfig{
					Enabled:           true,
					MaxAge:            31536000,
					IncludeSubDomains: true,
					Preload:           true,
				},
			},
		},
		logger: observability.NopLogger(),
	}

	handler := l.hstsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	assert.Contains(t, rec.Header().Get("Strict-Transport-Security"), "includeSubDomains")
	assert.Contains(t, rec.Header().Get("Strict-Transport-Security"), "preload")
}

// TestListener_HTTPSRedirectMiddleware_Coverage tests the HTTPS redirect middleware.
func TestListener_HTTPSRedirectMiddleware_Coverage(t *testing.T) {
	t.Parallel()

	l := &Listener{
		config: config.Listener{
			Port: 8443,
			Hosts: []string{
				"example.com",
			},
		},
		logger: observability.NopLogger(),
	}

	handler := l.httpsRedirectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test with HTTP request (should redirect)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
}
