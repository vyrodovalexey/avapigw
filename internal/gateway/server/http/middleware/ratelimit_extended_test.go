package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
)

// TestRateLimitMiddlewareWithCore tests the RateLimitMiddlewareWithCore function
func TestRateLimitMiddlewareWithCore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("allows request when under limit", func(t *testing.T) {
		limiter := &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{
					Allowed:    true,
					Limit:      100,
					Remaining:  99,
					ResetAfter: time.Minute,
				}, nil
			},
		}

		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Limiter:        limiter,
			IncludeHeaders: true,
		}

		router := gin.New()
		router.Use(RateLimitMiddlewareWithCore(coreConfig, ratelimit.IPKeyFunc))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "100", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "99", w.Header().Get("X-RateLimit-Remaining"))
	})

	t.Run("blocks request when over limit", func(t *testing.T) {
		limiter := &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{
					Allowed:    false,
					Limit:      100,
					Remaining:  0,
					ResetAfter: time.Minute,
					RetryAfter: 30 * time.Second,
				}, nil
			},
		}

		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Limiter:        limiter,
			IncludeHeaders: true,
		}

		router := gin.New()
		router.Use(RateLimitMiddlewareWithCore(coreConfig, ratelimit.IPKeyFunc))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "Rate limit exceeded")
		assert.Equal(t, "30", w.Header().Get("Retry-After"))
	})

	t.Run("skip path", func(t *testing.T) {
		limiter := &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{Allowed: false}, nil
			},
		}

		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger:    zap.NewNop(),
				SkipPaths: []string{"/skip"},
			},
			Limiter:        limiter,
			IncludeHeaders: true,
		}

		router := gin.New()
		router.Use(RateLimitMiddlewareWithCore(coreConfig, ratelimit.IPKeyFunc))
		router.GET("/skip", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/skip", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("nil key func uses default", func(t *testing.T) {
		var capturedKey string
		limiter := &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				capturedKey = key
				return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
			},
		}

		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Limiter:        limiter,
			IncludeHeaders: true,
		}

		router := gin.New()
		router.Use(RateLimitMiddlewareWithCore(coreConfig, nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "192.168.1.1", capturedKey)
	})

	t.Run("allows request on limiter error", func(t *testing.T) {
		limiter := &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return nil, assert.AnError
			},
		}

		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Limiter:        limiter,
			IncludeHeaders: true,
		}

		router := gin.New()
		router.Use(RateLimitMiddlewareWithCore(coreConfig, ratelimit.IPKeyFunc))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should allow request on error
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("without headers", func(t *testing.T) {
		limiter := &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{
					Allowed:   true,
					Limit:     100,
					Remaining: 99,
				}, nil
			},
		}

		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Limiter:        limiter,
			IncludeHeaders: false,
		}

		router := gin.New()
		router.Use(RateLimitMiddlewareWithCore(coreConfig, ratelimit.IPKeyFunc))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("X-RateLimit-Limit"))
	})
}

// TestSetRateLimitHeaders tests the setRateLimitHeaders function
func TestSetRateLimitHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	result := &core.RateLimitResult{
		Limit:      100,
		Remaining:  50,
		ResetAfter: time.Minute,
	}

	setRateLimitHeaders(c, result)

	assert.Equal(t, "100", w.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "50", w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
}

// TestHandleRateLimitExceeded tests the handleRateLimitExceeded function
func TestHandleRateLimitExceeded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("default error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		result := &core.RateLimitResult{
			Limit:      100,
			RetryAfter: 30 * time.Second,
		}

		rateLimitCore := core.NewRateLimitCore(core.RateLimitCoreConfig{
			IncludeHeaders: true,
		})

		handleRateLimitExceeded(c, result, rateLimitCore, "test-key", nil)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "Rate limit exceeded")
		assert.Equal(t, "30", w.Header().Get("Retry-After"))
	})

	t.Run("custom error handler", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		result := &core.RateLimitResult{
			Limit:      100,
			RetryAfter: 30 * time.Second,
		}

		rateLimitCore := core.NewRateLimitCore(core.RateLimitCoreConfig{
			IncludeHeaders: true,
		})

		customHandlerCalled := false
		customHandler := func(c *gin.Context) {
			customHandlerCalled = true
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "custom"})
		}

		handleRateLimitExceeded(c, result, rateLimitCore, "test-key", customHandler)

		assert.True(t, customHandlerCalled)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("without headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		result := &core.RateLimitResult{
			Limit:      100,
			RetryAfter: 30 * time.Second,
		}

		rateLimitCore := core.NewRateLimitCore(core.RateLimitCoreConfig{
			IncludeHeaders: false,
		})

		handleRateLimitExceeded(c, result, rateLimitCore, "test-key", nil)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Empty(t, w.Header().Get("Retry-After"))
	})
}

// TestRateLimitMiddleware_KeyFunctions tests various key functions
func TestRateLimitMiddleware_KeyFunctions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		keyFunc   ratelimit.KeyFunc
		setupReq  func(*http.Request)
		expectKey string
	}{
		{
			name:    "IP key function",
			keyFunc: ratelimit.IPKeyFunc,
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:12345"
			},
			expectKey: "10.0.0.1",
		},
		{
			name:    "per route key function",
			keyFunc: ratelimit.PerRouteKeyFunc("my-route", ratelimit.IPKeyFunc),
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:12345"
			},
			expectKey: "my-route:10.0.0.1",
		},
		{
			name:    "per endpoint key function",
			keyFunc: ratelimit.PerEndpointKeyFunc(ratelimit.IPKeyFunc),
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:12345"
			},
			expectKey: "GET:/test:10.0.0.1",
		},
		{
			name:    "API key function with header",
			keyFunc: ratelimit.APIKeyFunc("X-API-Key", "api_key"),
			setupReq: func(r *http.Request) {
				r.Header.Set("X-API-Key", "my-api-key")
			},
			expectKey: "my-api-key",
		},
		{
			name:    "API key function with query param",
			keyFunc: ratelimit.APIKeyFunc("X-API-Key", "api_key"),
			setupReq: func(r *http.Request) {
				// No header, will check query param
			},
			expectKey: "", // Will fall back to IP
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedKey string
			limiter := &MockLimiter{
				allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
					capturedKey = key
					return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
				},
			}

			router := gin.New()
			router.Use(RateLimitMiddleware(limiter, tt.keyFunc))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tt.expectKey != "" {
				assert.Contains(t, capturedKey, tt.expectKey)
			}
		})
	}
}

// TestRateLimitMiddlewareWithConfig_MultipleSkipPaths tests multiple skip paths
func TestRateLimitMiddlewareWithConfig_MultipleSkipPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := &MockLimiter{
		allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
			return &ratelimit.Result{Allowed: false}, nil
		},
	}

	config := RateLimitConfig{
		Limiter:   limiter,
		SkipPaths: []string{"/health", "/ready", "/metrics"},
	}

	router := gin.New()
	router.Use(RateLimitMiddlewareWithConfig(config))
	router.GET("/health", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.GET("/ready", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.GET("/metrics", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.GET("/api", func(c *gin.Context) { c.String(http.StatusOK, "OK") })

	paths := []struct {
		path           string
		expectedStatus int
	}{
		{"/health", http.StatusOK},
		{"/ready", http.StatusOK},
		{"/metrics", http.StatusOK},
		{"/api", http.StatusTooManyRequests},
	}

	for _, p := range paths {
		t.Run(p.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, p.expectedStatus, w.Code)
		})
	}
}
