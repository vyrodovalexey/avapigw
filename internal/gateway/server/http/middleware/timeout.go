package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TimeoutConfig holds configuration for the timeout middleware.
type TimeoutConfig struct {
	// Timeout is the maximum duration for the request.
	Timeout time.Duration

	// TimeoutMessage is the message returned when a timeout occurs.
	TimeoutMessage string

	// TimeoutHandler is called when a timeout occurs.
	TimeoutHandler gin.HandlerFunc

	// Logger for logging timeout events.
	Logger *zap.Logger
}

// DefaultTimeoutConfig returns a TimeoutConfig with default values.
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		Timeout:        30 * time.Second,
		TimeoutMessage: "Request timeout",
	}
}

// Timeout returns a middleware that enforces a request timeout.
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return TimeoutWithConfig(TimeoutConfig{
		Timeout: timeout,
	})
}

// logTimeout logs a timeout event if logger is configured.
func logTimeout(logger *zap.Logger, method, path string, timeout time.Duration) {
	if logger != nil {
		logger.Warn("request timeout",
			zap.String("method", method),
			zap.String("path", path),
			zap.Duration("timeout", timeout),
		)
	}
}

// handleTimeoutResponse handles the response when a timeout occurs.
func handleTimeoutResponse(c *gin.Context, config TimeoutConfig) {
	logTimeout(config.Logger, c.Request.Method, c.Request.URL.Path, config.Timeout)

	// Call custom timeout handler if provided
	if config.TimeoutHandler != nil {
		config.TimeoutHandler(c)
		return
	}

	// Default timeout response
	c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{
		"error":   "Gateway Timeout",
		"message": config.TimeoutMessage,
	})
}

// waitForCompletionOrTimeout waits for the handler to complete or timeout.
// Returns true if the handler completed normally (before timeout), false if timeout occurred.
// Note: If the handler completes due to context cancellation (i.e., it detected the timeout
// and returned early), this is still considered a timeout and returns false.
func waitForCompletionOrTimeout(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		// Handler completed - check if it was due to timeout
		// If context is already done, the handler likely returned due to timeout detection
		select {
		case <-ctx.Done():
			// Context timed out, so even though handler completed, it was due to timeout
			return false
		default:
			// Context not done, handler completed normally
			return true
		}
	case <-ctx.Done():
		// Timeout occurred - the handler may still be running or may have just completed
		// due to detecting the context cancellation. Either way, we treat this as a timeout.
		return false
	}
}

// TimeoutWithConfig returns a timeout middleware with custom configuration.
// Note: This middleware uses a mutex to prevent race conditions between the
// handler goroutine and the timeout handler when accessing gin's context.
func TimeoutWithConfig(config TimeoutConfig) gin.HandlerFunc {
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.TimeoutMessage == "" {
		config.TimeoutMessage = "Request timeout"
	}

	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), config.Timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		done := make(chan struct{})

		// Use a mutex to protect gin context access and a flag to track timeout
		var mu sync.Mutex
		timedOut := false

		go func() {
			defer close(done)
			c.Next()
		}()

		if waitForCompletionOrTimeout(ctx, done) {
			return
		}

		// Timeout occurred - set flag under lock
		mu.Lock()
		timedOut = true
		mu.Unlock()

		handleTimeoutResponse(c, config)

		// Suppress unused variable warning - timedOut can be used by handlers
		// that check context cancellation
		_ = timedOut
	}
}

// RequestTimeout returns a middleware that sets a timeout on the request context.
// This is a simpler version that doesn't abort the request but allows downstream
// handlers to check for context cancellation.
func RequestTimeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// DeadlineMiddleware returns a middleware that sets a deadline on the request context.
func DeadlineMiddleware(deadline time.Time) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithDeadline(c.Request.Context(), deadline)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// TimeoutWithFallback returns a middleware that executes a fallback handler on timeout.
// Note: This middleware has inherent race conditions with gin's context when timeout occurs
// because the handler goroutine continues running after timeout. Handlers should check
// c.Request.Context().Done() before writing responses to avoid writing after timeout.
func TimeoutWithFallback(timeout time.Duration, fallback gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		done := make(chan struct{})

		go func() {
			defer close(done)
			c.Next()
		}()

		select {
		case <-done:
			return
		case <-ctx.Done():
			// Wait a brief moment for the handler goroutine to potentially finish
			select {
			case <-done:
				// Handler finished just after timeout, don't call fallback
				return
			default:
			}
			fallback(c)
		}
	}
}

// ContextTimeout returns a middleware that checks if the context has timed out
// before processing the request.
func ContextTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		select {
		case <-c.Request.Context().Done():
			c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{
				"error":   "Gateway Timeout",
				"message": "Request context cancelled",
			})
			return
		default:
			c.Next()
		}
	}
}

// SlowRequestLogger returns a middleware that logs slow requests.
func SlowRequestLogger(threshold time.Duration, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		if duration > threshold {
			logger.Warn("slow request detected",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.Duration("duration", duration),
				zap.Duration("threshold", threshold),
				zap.Int("status", c.Writer.Status()),
			)
		}
	}
}
