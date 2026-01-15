package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	assert.NotNil(t, config.NameFunc)

	// Test the default name function
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test/path", nil)

	name := config.NameFunc(c)
	assert.Equal(t, "/test/path", name)
}

func TestCircuitBreakerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("allows request when circuit is closed", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		router := gin.New()
		router.Use(CircuitBreakerMiddleware(registry))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})

	t.Run("records success on 2xx response", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		router := gin.New()
		router.Use(CircuitBreakerMiddleware(registry))
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
		assert.Equal(t, 0, stats.Failures)
	})

	t.Run("records failure on 5xx response", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		router := gin.New()
		router.Use(CircuitBreakerMiddleware(registry))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusInternalServerError, "Error")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		cb := registry.Get("/test")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 0, stats.Successes)
		assert.Equal(t, 1, stats.Failures)
	})
}

func TestCircuitBreakerMiddlewareWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		config         CircuitBreakerConfig
		path           string
		expectedStatus int
	}{
		{
			name: "skip path",
			config: CircuitBreakerConfig{
				Registry:  circuitbreaker.NewRegistry(nil, nil),
				SkipPaths: []string{"/skip"},
			},
			path:           "/skip",
			expectedStatus: http.StatusOK,
		},
		{
			name: "custom name function",
			config: CircuitBreakerConfig{
				Registry: circuitbreaker.NewRegistry(nil, nil),
				NameFunc: func(c *gin.Context) string {
					return "custom-name"
				},
			},
			path:           "/test",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CircuitBreakerMiddlewareWithConfig(tt.config))
			router.GET(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestCircuitBreakerMiddlewareWithConfig_NilRegistry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CircuitBreakerConfig{
		Registry: nil, // Will create default registry
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

func TestCircuitBreakerMiddlewareWithConfig_OpenCircuit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a circuit breaker that's already open
	config := &circuitbreaker.Config{
		MaxFailures:      1,
		Timeout:          0, // Never recover automatically
		HalfOpenMax:      1,
		SuccessThreshold: 1,
	}
	registry := circuitbreaker.NewRegistry(config, nil)

	// Get the circuit breaker and force it open by recording failures
	cb := registry.GetOrCreate("/test")
	cb.RecordFailure()
	cb.RecordFailure()

	router := gin.New()
	router.Use(CircuitBreakerMiddlewareWithConfig(CircuitBreakerConfig{
		Registry: registry,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Circuit breaker is open")
}

func TestCircuitBreakerMiddlewareWithConfig_FallbackHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fallbackCalled := false

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
			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"message": "fallback response",
			})
		},
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, fallbackCalled)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "fallback response")
}

func TestCircuitBreakerMiddlewareWithConfig_CustomErrorHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

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
		ErrorHandler: func(c *gin.Context) {
			errorHandlerCalled = true
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
				"error": "custom error",
			})
		},
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, errorHandlerCalled)
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "custom error")
}

func TestCircuitBreakerMiddlewareWithConfig_WithLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

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
		Logger:   logger,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

func TestBackendCircuitBreakerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := circuitbreaker.NewRegistry(nil, nil)

	router := gin.New()
	router.Use(BackendCircuitBreakerMiddleware(registry, "my-backend"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that circuit breaker was created with backend name
	cb := registry.Get("backend:my-backend")
	assert.NotNil(t, cb)
}

func TestMethodPathCircuitBreakerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := circuitbreaker.NewRegistry(nil, nil)

	router := gin.New()
	router.Use(MethodPathCircuitBreakerMiddleware(registry))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// GET request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// POST request
	req = httptest.NewRequest(http.MethodPost, "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check that separate circuit breakers were created
	getCB := registry.Get("GET:/test")
	postCB := registry.Get("POST:/test")
	assert.NotNil(t, getCB)
	assert.NotNil(t, postCB)
}

func TestCircuitBreakerStatusHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := circuitbreaker.NewRegistry(nil, nil)

	// Create some circuit breakers
	cb1 := registry.GetOrCreate("cb1")
	cb1.RecordSuccess()
	cb2 := registry.GetOrCreate("cb2")
	cb2.RecordFailure()

	router := gin.New()
	router.GET("/status", CircuitBreakerStatusHandler(registry))

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "circuit_breakers")
	assert.Contains(t, w.Body.String(), "cb1")
	assert.Contains(t, w.Body.String(), "cb2")
}

func TestCircuitBreakerResetHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := circuitbreaker.NewRegistry(nil, nil)

	// Create a circuit breaker with some state
	cb := registry.GetOrCreate("test-cb")
	cb.RecordFailure()
	cb.RecordFailure()

	router := gin.New()
	router.POST("/reset/:name", CircuitBreakerResetHandler(registry))

	t.Run("reset existing circuit breaker", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/reset/test-cb", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "circuit breaker reset")

		// Verify it was reset
		stats := cb.Stats()
		assert.Equal(t, 0, stats.Failures)
	})

	t.Run("reset non-existent circuit breaker", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/reset/non-existent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "circuit breaker not found")
	})

	t.Run("reset without name", func(t *testing.T) {
		router2 := gin.New()
		router2.POST("/reset", CircuitBreakerResetHandler(registry))

		req := httptest.NewRequest(http.MethodPost, "/reset", nil)
		w := httptest.NewRecorder()

		router2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "circuit breaker name is required")
	})
}

func TestCircuitBreakerMiddleware_4xxDoesNotCountAsFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := circuitbreaker.NewRegistry(nil, nil)

	router := gin.New()
	router.Use(CircuitBreakerMiddleware(registry))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusBadRequest, "Bad Request")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	cb := registry.Get("/test")
	assert.NotNil(t, cb)
	stats := cb.Stats()
	// 4xx should count as success (not a backend failure)
	assert.Equal(t, 1, stats.Successes)
	assert.Equal(t, 0, stats.Failures)
}
