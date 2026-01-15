package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// MockLimiter is a mock implementation of ratelimit.Limiter for testing
type MockLimiter struct {
	allowFunc func(ctx context.Context, key string) (*ratelimit.Result, error)
	limit     *ratelimit.Limit
}

func (m *MockLimiter) Allow(ctx context.Context, key string) (*ratelimit.Result, error) {
	if m.allowFunc != nil {
		return m.allowFunc(ctx, key)
	}
	return &ratelimit.Result{
		Allowed:    true,
		Limit:      100,
		Remaining:  99,
		ResetAfter: time.Minute,
		RetryAfter: 0,
	}, nil
}

func (m *MockLimiter) AllowN(ctx context.Context, key string, n int) (*ratelimit.Result, error) {
	return m.Allow(ctx, key)
}

func (m *MockLimiter) GetLimit(key string) *ratelimit.Limit {
	return m.limit
}

func (m *MockLimiter) Reset(ctx context.Context, key string) error {
	return nil
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	assert.NotNil(t, config.KeyFunc)
	assert.True(t, config.IncludeHeaders)
}

func TestRateLimitMiddleware(t *testing.T) {
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

		router := gin.New()
		router.Use(RateLimitMiddleware(limiter, ratelimit.IPKeyFunc))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "100", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "99", w.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
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

		router := gin.New()
		router.Use(RateLimitMiddleware(limiter, ratelimit.IPKeyFunc))
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
}

func TestRateLimitMiddlewareWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		config         RateLimitConfig
		path           string
		expectedStatus int
		expectHeaders  bool
	}{
		{
			name: "skip path",
			config: RateLimitConfig{
				Limiter: &MockLimiter{
					allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
						return &ratelimit.Result{Allowed: false}, nil
					},
				},
				SkipPaths:      []string{"/skip"},
				IncludeHeaders: true,
			},
			path:           "/skip",
			expectedStatus: http.StatusOK,
			expectHeaders:  false,
		},
		{
			name: "without headers",
			config: RateLimitConfig{
				Limiter: &MockLimiter{
					allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
						return &ratelimit.Result{
							Allowed:   true,
							Limit:     100,
							Remaining: 99,
						}, nil
					},
				},
				IncludeHeaders: false,
			},
			path:           "/test",
			expectedStatus: http.StatusOK,
			expectHeaders:  false,
		},
		{
			name: "with headers",
			config: RateLimitConfig{
				Limiter: &MockLimiter{
					allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
						return &ratelimit.Result{
							Allowed:    true,
							Limit:      100,
							Remaining:  99,
							ResetAfter: time.Minute,
						}, nil
					},
				},
				IncludeHeaders: true,
			},
			path:           "/test",
			expectedStatus: http.StatusOK,
			expectHeaders:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RateLimitMiddlewareWithConfig(tt.config))
			router.GET(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectHeaders {
				assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
			} else {
				assert.Empty(t, w.Header().Get("X-RateLimit-Limit"))
			}
		})
	}
}

func TestRateLimitMiddlewareWithConfig_NilLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimitConfig{
		Limiter: nil, // Will use NoopLimiter
	}

	router := gin.New()
	router.Use(RateLimitMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddlewareWithConfig_NilKeyFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimitConfig{
		Limiter: &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
			},
		},
		KeyFunc: nil, // Will use IPKeyFunc
	}

	router := gin.New()
	router.Use(RateLimitMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddlewareWithConfig_CustomErrorHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	customHandlerCalled := false

	config := RateLimitConfig{
		Limiter: &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{
					Allowed:    false,
					RetryAfter: time.Minute,
				}, nil
			},
		},
		ErrorHandler: func(c *gin.Context) {
			customHandlerCalled = true
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "custom rate limit error",
			})
		},
		IncludeHeaders: true,
	}

	router := gin.New()
	router.Use(RateLimitMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, customHandlerCalled)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "custom rate limit error")
}

func TestRateLimitMiddlewareWithConfig_LimiterError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	config := RateLimitConfig{
		Limiter: &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return nil, assert.AnError
			},
		},
		Logger: logger,
	}

	router := gin.New()
	router.Use(RateLimitMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should allow request on error
	assert.Equal(t, http.StatusOK, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

func TestRateLimitMiddlewareWithConfig_WithLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	config := RateLimitConfig{
		Limiter: &MockLimiter{
			allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
				return &ratelimit.Result{
					Allowed:    false,
					Limit:      100,
					RetryAfter: time.Minute,
				}, nil
			},
		},
		Logger:         logger,
		IncludeHeaders: true,
	}

	router := gin.New()
	router.Use(RateLimitMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

func TestPerRouteRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedKey string

	limiter := &MockLimiter{
		allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
			capturedKey = key
			return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
		},
	}

	router := gin.New()
	router.Use(PerRouteRateLimitMiddleware(limiter, "my-route"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, capturedKey, "my-route:")
}

func TestPerEndpointRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedKey string

	limiter := &MockLimiter{
		allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
			capturedKey = key
			return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
		},
	}

	router := gin.New()
	router.Use(PerEndpointRateLimitMiddleware(limiter))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, capturedKey, "GET:")
	assert.Contains(t, capturedKey, "/test:")
}

func TestAPIKeyRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedKey string

	limiter := &MockLimiter{
		allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
			capturedKey = key
			return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
		},
	}

	router := gin.New()
	router.Use(APIKeyRateLimitMiddleware(limiter, "X-API-Key", "api_key"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	t.Run("uses header API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", "my-api-key")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "my-api-key", capturedKey)
	})

	t.Run("uses query param API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?api_key=query-api-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "query-api-key", capturedKey)
	})

	t.Run("falls back to IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "10.0.0.1", capturedKey)
	})
}

func TestJWTRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedKey string

	limiter := &MockLimiter{
		allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
			capturedKey = key
			return &ratelimit.Result{Allowed: true, Limit: 100, Remaining: 99}, nil
		},
	}

	router := gin.New()
	router.Use(JWTRateLimitMiddleware(limiter, "sub"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Without JWT claims, should fall back to IP
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "10.0.0.1", capturedKey)
}

func TestRateLimitMiddleware_ResponseBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := &MockLimiter{
		allowFunc: func(ctx context.Context, key string) (*ratelimit.Result, error) {
			return &ratelimit.Result{
				Allowed:    false,
				Limit:      100,
				Remaining:  0,
				RetryAfter: 60 * time.Second,
			}, nil
		},
	}

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, ratelimit.IPKeyFunc))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "Too Many Requests")
	assert.Contains(t, w.Body.String(), "Rate limit exceeded")
	assert.Contains(t, w.Body.String(), "retry_after")
}
