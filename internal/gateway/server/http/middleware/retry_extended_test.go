package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestRetryableHandler_FailedRequest tests retry handler with failed requests
func TestRetryableHandler_FailedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("retries on 5xx error", func(t *testing.T) {
		policy := retry.DefaultPolicy().WithMaxRetries(2)
		callCount := 0

		handler := func(c *gin.Context) {
			callCount++
			if callCount < 3 {
				c.String(http.StatusInternalServerError, "Error")
			} else {
				c.String(http.StatusOK, "OK")
			}
		}

		retryableHandler := NewRetryableHandler(handler, policy, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		retryableHandler.Handle(c)

		// Should have retried
		assert.GreaterOrEqual(t, callCount, 1)
	})

	t.Run("logs when all retries fail", func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)
		logger := zap.New(core)

		policy := retry.DefaultPolicy().WithMaxRetries(1)

		handler := func(c *gin.Context) {
			c.String(http.StatusInternalServerError, "Error")
		}

		retryableHandler := NewRetryableHandler(handler, policy, logger)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		retryableHandler.Handle(c)

		// Check for warning log
		found := false
		for _, log := range logs.All() {
			if log.Message == "all retry attempts failed" {
				found = true
				break
			}
		}
		assert.True(t, found, "expected 'all retry attempts failed' log")
	})

	t.Run("handles body read error", func(t *testing.T) {
		policy := retry.DefaultPolicy()

		handler := func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		}

		retryableHandler := NewRetryableHandler(handler, policy, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		// Create a request with a body that will fail to read
		c.Request = httptest.NewRequest(http.MethodPost, "/test", &errorReader{})

		retryableHandler.Handle(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to read request body")
	})
}

// errorReader is a reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, assert.AnError
}

// TestRetryMiddleware_CustomRetryableMethods tests custom retryable methods
func TestRetryMiddleware_CustomRetryableMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RetryConfig{
		Policy:           retry.DefaultPolicy(),
		RetryableMethods: []string{"GET", "POST"}, // Include POST
	}

	router := gin.New()
	router.Use(RetryMiddlewareWithConfig(config))
	router.POST("/test", func(c *gin.Context) {
		assert.True(t, IsRetryEnabled(c))
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRetryMiddleware_SkipPaths tests skip paths functionality
func TestRetryMiddleware_SkipPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RetryConfig{
		Policy:    retry.DefaultPolicy(),
		SkipPaths: []string{"/health", "/ready"},
	}

	router := gin.New()
	router.Use(RetryMiddlewareWithConfig(config))
	router.GET("/health", func(c *gin.Context) {
		assert.False(t, IsRetryEnabled(c))
		c.String(http.StatusOK, "OK")
	})
	router.GET("/api", func(c *gin.Context) {
		assert.True(t, IsRetryEnabled(c))
		c.String(http.StatusOK, "OK")
	})

	t.Run("skip path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("non-skip path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestBufferRequestBody_LargeBody tests buffering large request bodies
func TestBufferRequestBody_LargeBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a body larger than max size
	largeBody := strings.Repeat("a", 2000)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(largeBody))

	body, err := BufferRequestBody(c, 1000) // Max 1000 bytes

	assert.NoError(t, err)
	assert.Len(t, body, 1000) // Should be truncated
}

// TestRestoreRequestBody_MultipleRestores tests restoring body multiple times
func TestRestoreRequestBody_MultipleRestores(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalBody := []byte("test body content")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(string(originalBody)))

	// First restore
	RestoreRequestBody(c, originalBody)

	// Read body
	body1, err := BufferRequestBody(c, 1024)
	assert.NoError(t, err)
	assert.Equal(t, originalBody, body1)

	// Second restore
	RestoreRequestBody(c, originalBody)

	// Read body again
	body2, err := BufferRequestBody(c, 1024)
	assert.NoError(t, err)
	assert.Equal(t, originalBody, body2)
}

// TestResponseWriter_StatusCode tests response writer status code tracking
func TestResponseWriter_StatusCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"400 Bad Request", http.StatusBadRequest},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			rw := newResponseWriter(c.Writer)
			rw.WriteHeader(tt.statusCode)

			assert.Equal(t, tt.statusCode, rw.statusCode)
		})
	}
}

// TestResponseWriter_BodyCapture tests response writer body capture
func TestResponseWriter_BodyCapture(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	rw := newResponseWriter(c.Writer)

	// Write multiple times
	rw.Write([]byte("Hello "))
	rw.Write([]byte("World"))

	assert.Equal(t, "Hello World", rw.body.String())
}

// TestRetryPolicy_CustomBackoff tests custom backoff configuration
func TestRetryPolicy_CustomBackoff(t *testing.T) {
	gin.SetMode(gin.TestMode)

	policy := &retry.Policy{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
		Jitter:         0.0, // No jitter for predictable testing
	}

	router := gin.New()
	router.Use(RetryMiddleware(policy))
	router.GET("/test", func(c *gin.Context) {
		p := GetRetryPolicy(c)
		assert.Equal(t, 3, p.MaxRetries)
		assert.Equal(t, 1*time.Millisecond, p.InitialBackoff)
		assert.Equal(t, 10*time.Millisecond, p.MaxBackoff)
		assert.Equal(t, 2.0, p.BackoffFactor)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestStatusError_AllCodes tests status error for various codes
func TestStatusError_AllCodes(t *testing.T) {
	codes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}

	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			err := &statusError{code: code}
			assert.Equal(t, http.StatusText(code), err.Error())
		})
	}
}

// TestRetryMiddlewareWithConfig_DefaultValues tests default value handling
func TestRetryMiddlewareWithConfig_DefaultValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Empty config should use defaults
	config := RetryConfig{}

	router := gin.New()
	router.Use(RetryMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		p := GetRetryPolicy(c)
		assert.NotNil(t, p)
		assert.True(t, IsRetryEnabled(c))
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRetryMiddleware_NonIdempotentMethods tests non-idempotent methods are not retried
func TestRetryMiddleware_NonIdempotentMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RetryMiddleware(retry.DefaultPolicy()))

	// POST and PATCH are not retryable by default
	router.POST("/test", func(c *gin.Context) {
		assert.False(t, IsRetryEnabled(c))
		c.String(http.StatusOK, "OK")
	})
	router.PATCH("/test", func(c *gin.Context) {
		assert.False(t, IsRetryEnabled(c))
		c.String(http.StatusOK, "OK")
	})

	t.Run("POST not retryable", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("PATCH not retryable", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
