package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
)

// TestCircuitBreakerMiddlewareWithCore tests the CircuitBreakerMiddlewareWithCore function
func TestCircuitBreakerMiddlewareWithCore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("allows request when circuit is closed", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Registry: registry,
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("records success on 2xx response", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Registry: registry,
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		cb := registry.Get("/test")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on 5xx response", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Registry: registry,
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusInternalServerError, "Error")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		cb := registry.Get("/test")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})

	t.Run("skip path", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger:    zap.NewNop(),
				SkipPaths: []string{"/skip"},
			},
			Registry: registry,
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nil))
		router.GET("/skip", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/skip", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// Circuit breaker should not be created for skipped path
		cb := registry.Get("/skip")
		assert.Nil(t, cb)
	})

	t.Run("custom name function", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Registry: registry,
		}

		nameFunc := func(c *gin.Context) string {
			return "custom-name"
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nameFunc))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		cb := registry.Get("custom-name")
		assert.NotNil(t, cb)
	})

	t.Run("open circuit returns service unavailable", func(t *testing.T) {
		config := &circuitbreaker.Config{
			MaxFailures: 1,
			Timeout:     0,
		}
		registry := circuitbreaker.NewRegistry(config, nil)

		// Force circuit open
		cb := registry.GetOrCreate("/test")
		cb.RecordFailure()
		cb.RecordFailure()

		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Registry: registry,
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Contains(t, w.Body.String(), "Circuit breaker is open")
	})

	t.Run("nil name function uses default", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			Registry: registry,
		}

		router := gin.New()
		router.Use(CircuitBreakerMiddlewareWithCore(coreConfig, nil))
		router.GET("/test/path", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test/path", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		cb := registry.Get("/test/path")
		assert.NotNil(t, cb)
	})
}

// TestCircuitBreakerMiddlewareWithConfig_NilNameFunc tests nil name function handling
func TestCircuitBreakerMiddlewareWithConfig_NilNameFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CircuitBreakerConfig{
		Registry: circuitbreaker.NewRegistry(nil, nil),
		NameFunc: nil, // Will use default
	}

	router := gin.New()
	router.Use(CircuitBreakerMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCircuitBreakerMiddleware_MultipleStatusCodes tests various status codes
func TestCircuitBreakerMiddleware_MultipleStatusCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		statusCode    int
		expectSuccess bool
		expectFailure bool
	}{
		{
			name:          "200 OK",
			statusCode:    http.StatusOK,
			expectSuccess: true,
		},
		{
			name:          "201 Created",
			statusCode:    http.StatusCreated,
			expectSuccess: true,
		},
		{
			name:          "204 No Content",
			statusCode:    http.StatusNoContent,
			expectSuccess: true,
		},
		{
			name:          "301 Moved Permanently",
			statusCode:    http.StatusMovedPermanently,
			expectSuccess: true,
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectSuccess: true, // 4xx is not a backend failure
		},
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectSuccess: true,
		},
		{
			name:          "404 Not Found",
			statusCode:    http.StatusNotFound,
			expectSuccess: true,
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectFailure: true,
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectFailure: true,
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectFailure: true,
		},
		{
			name:          "504 Gateway Timeout",
			statusCode:    http.StatusGatewayTimeout,
			expectFailure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := circuitbreaker.NewRegistry(nil, nil)

			router := gin.New()
			router.Use(CircuitBreakerMiddleware(registry))
			router.GET("/test", func(c *gin.Context) {
				c.String(tt.statusCode, "Response")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			cb := registry.Get("/test")
			assert.NotNil(t, cb)
			stats := cb.Stats()

			if tt.expectSuccess {
				assert.Equal(t, 1, stats.Successes)
				assert.Equal(t, 0, stats.Failures)
			}
			if tt.expectFailure {
				assert.Equal(t, 0, stats.Successes)
				assert.Equal(t, 1, stats.Failures)
			}
		})
	}
}

// TestCircuitBreakerStatusHandler_EmptyRegistry tests status handler with empty registry
func TestCircuitBreakerStatusHandler_EmptyRegistry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := circuitbreaker.NewRegistry(nil, nil)

	router := gin.New()
	router.GET("/status", CircuitBreakerStatusHandler(registry))

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "circuit_breakers")
	assert.Contains(t, w.Body.String(), `"count":0`)
}

// TestCircuitBreakerMiddlewareWithConfig_FallbackPriority tests fallback vs error handler priority
func TestCircuitBreakerMiddlewareWithConfig_FallbackPriority(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fallbackCalled := false
	errorHandlerCalled := false

	config := &circuitbreaker.Config{
		MaxFailures: 1,
		Timeout:     0,
	}
	registry := circuitbreaker.NewRegistry(config, nil)

	// Force circuit open
	cb := registry.GetOrCreate("/test")
	cb.RecordFailure()
	cb.RecordFailure()

	router := gin.New()
	router.Use(CircuitBreakerMiddlewareWithConfig(CircuitBreakerConfig{
		Registry: registry,
		FallbackHandler: func(c *gin.Context, err error) {
			fallbackCalled = true
			c.AbortWithStatusJSON(http.StatusOK, gin.H{"message": "fallback"})
		},
		ErrorHandler: func(c *gin.Context) {
			errorHandlerCalled = true
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "error handler"})
		},
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Fallback should be called first (has priority)
	assert.True(t, fallbackCalled)
	assert.False(t, errorHandlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}
