//go:build functional
// +build functional

package functional

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestFunctional_RouteConfig_RequestLimits(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("route with custom RequestLimits smaller than global", func(t *testing.T) {
		t.Parallel()

		// Route-level limit: 1KB
		routeLimits := &config.RequestLimitsConfig{
			MaxBodySize:   1024, // 1KB
			MaxHeaderSize: 512,
		}

		handler := middleware.BodyLimitFromRequestLimits(routeLimits, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
			}),
		)

		// Request within limit should succeed
		smallBody := strings.Repeat("a", 500)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/small", strings.NewReader(smallBody))
		req.Header.Set("Content-Length", "500")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Request exceeding limit should fail
		largeBody := strings.Repeat("a", 2048)
		req = httptest.NewRequest(http.MethodPost, "/api/v1/small", strings.NewReader(largeBody))
		req.Header.Set("Content-Length", "2048")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("route with custom RequestLimits larger than global", func(t *testing.T) {
		t.Parallel()

		// Route-level limit: 50MB
		routeLimits := &config.RequestLimitsConfig{
			MaxBodySize:   50 * 1024 * 1024, // 50MB
			MaxHeaderSize: 2 * 1024 * 1024,  // 2MB
		}

		handler := middleware.BodyLimitFromRequestLimits(routeLimits, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// Request of 20MB should succeed (larger than default 10MB but within route limit)
		largeBody := bytes.Repeat([]byte("a"), 20*1024*1024)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/large", bytes.NewReader(largeBody))
		req.ContentLength = int64(len(largeBody))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("route inheriting global configuration", func(t *testing.T) {
		t.Parallel()

		// Use default limits (nil config)
		handler := middleware.BodyLimitFromRequestLimits(nil, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// Request within default limit should succeed
		smallBody := strings.Repeat("a", 1024)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/default", strings.NewReader(smallBody))
		req.Header.Set("Content-Length", "1024")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("multiple routes with different configurations", func(t *testing.T) {
		t.Parallel()

		// Small limit route
		smallLimits := &config.RequestLimitsConfig{MaxBodySize: 100}
		smallHandler := middleware.BodyLimitFromRequestLimits(smallLimits, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "small")
			}),
		)

		// Large limit route
		largeLimits := &config.RequestLimitsConfig{MaxBodySize: 10000}
		largeHandler := middleware.BodyLimitFromRequestLimits(largeLimits, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "large")
			}),
		)

		// Test small route with body exceeding its limit
		body := strings.Repeat("a", 500)
		req := httptest.NewRequest(http.MethodPost, "/small", strings.NewReader(body))
		req.Header.Set("Content-Length", "500")
		rec := httptest.NewRecorder()
		smallHandler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

		// Test large route with same body (should succeed)
		req = httptest.NewRequest(http.MethodPost, "/large", strings.NewReader(body))
		req.Header.Set("Content-Length", "500")
		rec = httptest.NewRecorder()
		largeHandler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFunctional_RouteConfig_CORS(t *testing.T) {
	t.Parallel()

	t.Run("route with custom CORS configuration", func(t *testing.T) {
		t.Parallel()

		corsConfig := &config.CORSConfig{
			AllowOrigins:     []string{"https://example.com", "https://app.example.com"},
			AllowMethods:     []string{"GET", "POST"},
			AllowHeaders:     []string{"Content-Type", "X-Custom-Header"},
			ExposeHeaders:    []string{"X-Response-ID"},
			MaxAge:           3600,
			AllowCredentials: true,
		}

		handler := middleware.CORSFromConfig(corsConfig)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// Preflight request from allowed origin
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/cors", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "POST")
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))

		// Request from disallowed origin
		req = httptest.NewRequest(http.MethodOptions, "/api/v1/cors", nil)
		req.Header.Set("Origin", "https://malicious.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Origin should not be in response
		assert.NotEqual(t, "https://malicious.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("route inheriting global CORS", func(t *testing.T) {
		t.Parallel()

		// Global CORS with wildcard
		globalCORS := &config.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
			AllowHeaders: []string{"Content-Type", "Authorization"},
		}

		handler := middleware.CORSFromConfig(globalCORS)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// Any origin should be allowed
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/default", nil)
		req.Header.Set("Origin", "https://any-origin.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "https://any-origin.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS preflight with route-specific origins", func(t *testing.T) {
		t.Parallel()

		corsConfig := &config.CORSConfig{
			AllowOrigins: []string{"https://specific.example.com"},
			AllowMethods: []string{"GET"},
		}

		handler := middleware.CORSFromConfig(corsConfig)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// Allowed origin
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/specific", nil)
		req.Header.Set("Origin", "https://specific.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "https://specific.example.com", rec.Header().Get("Access-Control-Allow-Origin"))

		// Disallowed origin
		req = httptest.NewRequest(http.MethodOptions, "/api/v1/specific", nil)
		req.Header.Set("Origin", "https://other.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestFunctional_RouteConfig_Security(t *testing.T) {
	t.Parallel()

	t.Run("route with custom Security headers", func(t *testing.T) {
		t.Parallel()

		securityHeaders := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
				"X-XSS-Protection":       "1; mode=block",
				"Referrer-Policy":        "strict-origin-when-cross-origin",
				"X-Custom-Security":      "enabled",
			},
		}

		handler := middleware.Headers(securityHeaders)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/secure", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", rec.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
		assert.Equal(t, "enabled", rec.Header().Get("X-Custom-Security"))
	})

	t.Run("route inheriting global security headers", func(t *testing.T) {
		t.Parallel()

		// Global security headers
		globalHeaders := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"X-Frame-Options":        "SAMEORIGIN",
				"X-Content-Type-Options": "nosniff",
			},
		}

		handler := middleware.Headers(globalHeaders)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/default", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "SAMEORIGIN", rec.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	})

	t.Run("security headers present in response", func(t *testing.T) {
		t.Parallel()

		securityHeaders := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"Content-Security-Policy":   "default-src 'self'",
			},
		}

		handler := middleware.Headers(securityHeaders)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "secure content")
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/secure", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "max-age=31536000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
		assert.Equal(t, "default-src 'self'", rec.Header().Get("Content-Security-Policy"))
	})
}

func TestFunctional_RouteConfig_Combined(t *testing.T) {
	t.Parallel()

	t.Run("route with all custom configurations", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		// Create middleware chain with all configurations
		requestLimits := &config.RequestLimitsConfig{
			MaxBodySize:   5 * 1024 * 1024, // 5MB
			MaxHeaderSize: 1024 * 1024,     // 1MB
		}

		corsConfig := &config.CORSConfig{
			AllowOrigins:     []string{"https://custom.example.com"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			AllowCredentials: false,
		}

		securityHeaders := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"X-Frame-Options":        "SAMEORIGIN",
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "no-referrer",
			},
		}

		// Build handler chain
		handler := middleware.BodyLimitFromRequestLimits(requestLimits, logger)(
			middleware.CORSFromConfig(corsConfig)(
				middleware.Headers(securityHeaders)(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						_, _ = io.WriteString(w, "success")
					}),
				),
			),
		)

		// Test CORS preflight
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/custom", nil)
		req.Header.Set("Origin", "https://custom.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://custom.example.com", rec.Header().Get("Access-Control-Allow-Origin"))

		// Test actual request with security headers
		req = httptest.NewRequest(http.MethodGet, "/api/v1/custom", nil)
		req.Header.Set("Origin", "https://custom.example.com")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "SAMEORIGIN", rec.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))

		// Test body limit
		largeBody := bytes.Repeat([]byte("a"), 6*1024*1024) // 6MB, exceeds 5MB limit
		req = httptest.NewRequest(http.MethodPost, "/api/v1/custom", bytes.NewReader(largeBody))
		req.ContentLength = int64(len(largeBody))
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
}

func TestFunctional_RouteConfig_RequestLimitsConfig(t *testing.T) {
	t.Parallel()

	t.Run("GetEffectiveMaxBodySize returns configured value", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RequestLimitsConfig{
			MaxBodySize: 20 * 1024 * 1024, // 20MB
		}
		assert.Equal(t, int64(20*1024*1024), cfg.GetEffectiveMaxBodySize())
	})

	t.Run("GetEffectiveMaxBodySize returns default for nil config", func(t *testing.T) {
		t.Parallel()

		var cfg *config.RequestLimitsConfig
		assert.Equal(t, int64(config.DefaultMaxBodySize), cfg.GetEffectiveMaxBodySize())
	})

	t.Run("GetEffectiveMaxBodySize returns default for zero value", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RequestLimitsConfig{
			MaxBodySize: 0,
		}
		assert.Equal(t, int64(config.DefaultMaxBodySize), cfg.GetEffectiveMaxBodySize())
	})

	t.Run("GetEffectiveMaxHeaderSize returns configured value", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RequestLimitsConfig{
			MaxHeaderSize: 2 * 1024 * 1024, // 2MB
		}
		assert.Equal(t, int64(2*1024*1024), cfg.GetEffectiveMaxHeaderSize())
	})

	t.Run("DefaultRequestLimits returns sensible defaults", func(t *testing.T) {
		t.Parallel()

		defaults := config.DefaultRequestLimits()
		require.NotNil(t, defaults)
		assert.Equal(t, int64(config.DefaultMaxBodySize), defaults.MaxBodySize)
		assert.Equal(t, int64(config.DefaultMaxHeaderSize), defaults.MaxHeaderSize)
	})
}
