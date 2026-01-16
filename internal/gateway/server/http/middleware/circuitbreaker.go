package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
)

// CircuitBreakerConfig holds configuration for the circuit breaker middleware.
type CircuitBreakerConfig struct {
	// Registry is the circuit breaker registry.
	Registry *circuitbreaker.Registry

	// NameFunc extracts the circuit breaker name from the request.
	// If nil, uses the request path.
	NameFunc func(*gin.Context) string

	// Logger for logging circuit breaker events.
	Logger *zap.Logger

	// SkipPaths is a list of paths to skip circuit breaker.
	SkipPaths []string

	// ErrorHandler is called when the circuit is open.
	ErrorHandler gin.HandlerFunc

	// FallbackHandler is called when the circuit is open (alternative to ErrorHandler).
	FallbackHandler func(*gin.Context, error)
}

// DefaultCircuitBreakerConfig returns a CircuitBreakerConfig with default values.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		NameFunc: func(c *gin.Context) string {
			return c.Request.URL.Path
		},
	}
}

// CircuitBreakerMiddleware returns a middleware that applies circuit breaker protection.
func CircuitBreakerMiddleware(registry *circuitbreaker.Registry) gin.HandlerFunc {
	return CircuitBreakerMiddlewareWithConfig(CircuitBreakerConfig{
		Registry: registry,
	})
}

// CircuitBreakerMiddlewareWithConfig returns a circuit breaker middleware with custom configuration.
func CircuitBreakerMiddlewareWithConfig(config CircuitBreakerConfig) gin.HandlerFunc {
	// Create core circuit breaker
	cbCore := core.NewCircuitBreakerCore(core.CircuitBreakerCoreConfig{
		BaseConfig: core.BaseConfig{
			Logger:    config.Logger,
			SkipPaths: config.SkipPaths,
		},
		Registry: config.Registry,
	})

	nameFunc := config.NameFunc
	if nameFunc == nil {
		nameFunc = func(c *gin.Context) string {
			return c.Request.URL.Path
		}
	}

	return func(c *gin.Context) {
		// Skip circuit breaker for certain paths
		if cbCore.ShouldSkip(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get circuit breaker name
		name := nameFunc(c)

		// Check if circuit allows the request
		if !cbCore.Allow(name) {
			// Call fallback handler if provided
			if config.FallbackHandler != nil {
				config.FallbackHandler(c, core.ErrCircuitOpen)
				return
			}

			// Call custom error handler if provided
			if config.ErrorHandler != nil {
				config.ErrorHandler(c)
				return
			}

			// Default error response
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": "Circuit breaker is open",
			})
			return
		}

		// Process request
		c.Next()

		// Record result based on response status
		statusCode := c.Writer.Status()
		if cbCore.IsHTTPFailure(statusCode) {
			cbCore.RecordFailure(name)
		} else {
			cbCore.RecordSuccess(name)
		}
	}
}

// CircuitBreakerMiddlewareWithCore returns a circuit breaker middleware using the core package directly.
func CircuitBreakerMiddlewareWithCore(
	coreConfig core.CircuitBreakerCoreConfig,
	nameFunc func(*gin.Context) string,
) gin.HandlerFunc {
	cbCore := core.NewCircuitBreakerCore(coreConfig)

	if nameFunc == nil {
		nameFunc = func(c *gin.Context) string {
			return c.Request.URL.Path
		}
	}

	return func(c *gin.Context) {
		// Skip circuit breaker for certain paths
		if cbCore.ShouldSkip(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get circuit breaker name
		name := nameFunc(c)

		// Check if circuit allows the request
		if !cbCore.Allow(name) {
			// Default error response
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": "Circuit breaker is open",
			})
			return
		}

		// Process request
		c.Next()

		// Record result based on response status
		statusCode := c.Writer.Status()
		if cbCore.IsHTTPFailure(statusCode) {
			cbCore.RecordFailure(name)
		} else {
			cbCore.RecordSuccess(name)
		}
	}
}

// BackendCircuitBreakerMiddleware returns a middleware that applies circuit breaker per backend.
func BackendCircuitBreakerMiddleware(registry *circuitbreaker.Registry, backendName string) gin.HandlerFunc {
	return CircuitBreakerMiddlewareWithConfig(CircuitBreakerConfig{
		Registry: registry,
		NameFunc: func(c *gin.Context) string {
			return "backend:" + backendName
		},
	})
}

// MethodPathCircuitBreakerMiddleware returns a middleware that applies circuit breaker per method+path.
func MethodPathCircuitBreakerMiddleware(registry *circuitbreaker.Registry) gin.HandlerFunc {
	return CircuitBreakerMiddlewareWithConfig(CircuitBreakerConfig{
		Registry: registry,
		NameFunc: func(c *gin.Context) string {
			return c.Request.Method + ":" + c.Request.URL.Path
		},
	})
}

// CircuitBreakerStatusHandler returns a handler that shows circuit breaker status.
func CircuitBreakerStatusHandler(registry *circuitbreaker.Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := registry.Stats()

		response := make(map[string]interface{})
		for name, stat := range stats {
			response[name] = gin.H{
				"state":             stat.State.String(),
				"failures":          stat.Failures,
				"successes":         stat.Successes,
				"consecutive_fails": stat.ConsecutiveFails,
				"total_requests":    stat.TotalRequests,
				"failure_ratio":     stat.FailureRatio(),
				"last_failure":      stat.LastFailure,
				"last_state_change": stat.LastStateChange,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"circuit_breakers": response,
			"count":            len(stats),
		})
	}
}

// CircuitBreakerResetHandler returns a handler that resets a circuit breaker.
func CircuitBreakerResetHandler(registry *circuitbreaker.Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		if name == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "circuit breaker name is required",
			})
			return
		}

		cb := registry.Get(name)
		if cb == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "circuit breaker not found",
			})
			return
		}

		cb.Reset()

		c.JSON(http.StatusOK, gin.H{
			"message": "circuit breaker reset",
			"name":    name,
		})
	}
}
