package middleware

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"go.uber.org/zap"
)

// RetryConfig holds configuration for the retry middleware.
type RetryConfig struct {
	// Policy is the retry policy to use.
	Policy *retry.Policy

	// Logger for logging retry events.
	Logger *zap.Logger

	// SkipPaths is a list of paths to skip retry.
	SkipPaths []string

	// RetryableMethods is a list of HTTP methods that can be retried.
	// If empty, only idempotent methods (GET, HEAD, OPTIONS, PUT, DELETE) are retried.
	RetryableMethods []string

	// MaxBodySize is the maximum request body size to buffer for retry.
	// Requests with larger bodies will not be retried.
	MaxBodySize int64
}

// DefaultRetryConfig returns a RetryConfig with default values.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		Policy:           retry.DefaultPolicy(),
		RetryableMethods: []string{"GET", "HEAD", "OPTIONS", "PUT", "DELETE"},
		MaxBodySize:      1024 * 1024, // 1MB
	}
}

// RetryMiddleware returns a middleware that applies retry logic.
// Note: This middleware is primarily for demonstration. In practice,
// retry logic is typically applied at the proxy/backend level.
func RetryMiddleware(policy *retry.Policy) gin.HandlerFunc {
	return RetryMiddlewareWithConfig(RetryConfig{
		Policy: policy,
	})
}

// RetryMiddlewareWithConfig returns a retry middleware with custom configuration.
func RetryMiddlewareWithConfig(config RetryConfig) gin.HandlerFunc {
	if config.Policy == nil {
		config.Policy = retry.DefaultPolicy()
	}
	if len(config.RetryableMethods) == 0 {
		config.RetryableMethods = []string{"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
	}
	if config.MaxBodySize <= 0 {
		config.MaxBodySize = 1024 * 1024
	}

	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	retryableMethods := make(map[string]bool)
	for _, method := range config.RetryableMethods {
		retryableMethods[method] = true
	}

	return func(c *gin.Context) {
		// Skip retry for certain paths
		if skipPaths[c.Request.URL.Path] {
			c.Next()
			return
		}

		// Skip retry for non-retryable methods
		if !retryableMethods[c.Request.Method] {
			c.Next()
			return
		}

		// Store retry info in context for downstream handlers
		c.Set("retry_policy", config.Policy)
		c.Set("retry_enabled", true)

		c.Next()
	}
}

// responseWriter wraps gin.ResponseWriter to capture the response.
type responseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func newResponseWriter(w gin.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// GetRetryPolicy returns the retry policy from the context.
func GetRetryPolicy(c *gin.Context) *retry.Policy {
	if policy, exists := c.Get("retry_policy"); exists {
		return policy.(*retry.Policy)
	}
	return nil
}

// IsRetryEnabled returns whether retry is enabled for the request.
func IsRetryEnabled(c *gin.Context) bool {
	if enabled, exists := c.Get("retry_enabled"); exists {
		return enabled.(bool)
	}
	return false
}

// BufferRequestBody buffers the request body for potential retry.
func BufferRequestBody(c *gin.Context, maxSize int64) ([]byte, error) {
	if c.Request.Body == nil {
		return nil, nil
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxSize))
	if err != nil {
		return nil, err
	}

	// Restore body for the handler
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// RestoreRequestBody restores the request body from a buffer.
func RestoreRequestBody(c *gin.Context, body []byte) {
	if body != nil {
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
	}
}

// RetryableHandler wraps a handler with retry logic.
type RetryableHandler struct {
	handler gin.HandlerFunc
	policy  *retry.Policy
	logger  *zap.Logger
}

// NewRetryableHandler creates a new retryable handler.
func NewRetryableHandler(handler gin.HandlerFunc, policy *retry.Policy, logger *zap.Logger) *RetryableHandler {
	return &RetryableHandler{
		handler: handler,
		policy:  policy,
		logger:  logger,
	}
}

// Handle executes the handler with retry logic.
func (h *RetryableHandler) Handle(c *gin.Context) {
	// Buffer request body for retry
	body, err := BufferRequestBody(c, 1024*1024)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "failed to read request body",
		})
		return
	}

	// Execute with retry
	_, err = h.policy.Execute(c.Request.Context(), func() (interface{}, error) {
		// Restore body for each attempt
		RestoreRequestBody(c, body)

		// Create a response writer to capture the response
		rw := newResponseWriter(c.Writer)
		c.Writer = rw

		// Execute handler
		h.handler(c)

		// Check if we should retry based on status code
		if rw.statusCode >= 500 {
			return nil, &statusError{code: rw.statusCode}
		}

		return nil, nil
	})

	if err != nil && h.logger != nil {
		h.logger.Warn("all retry attempts failed",
			zap.Error(err),
			zap.String("path", c.Request.URL.Path),
		)
	}
}

// statusError represents an HTTP status error.
type statusError struct {
	code int
}

func (e *statusError) Error() string {
	return http.StatusText(e.code)
}
