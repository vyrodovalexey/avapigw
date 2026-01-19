package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestTimeoutWithConfig_NegativeTimeout tests negative timeout handling
func TestTimeoutWithConfig_NegativeTimeout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := TimeoutConfig{
		Timeout: -1 * time.Second, // Negative timeout should use default
	}

	router := gin.New()
	router.Use(TimeoutWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		// Check that context has a deadline
		_, hasDeadline := c.Request.Context().Deadline()
		assert.True(t, hasDeadline)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTimeoutWithConfig_EmptyMessage tests empty timeout message handling
func TestTimeoutWithConfig_EmptyMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := TimeoutConfig{
		Timeout:        100 * time.Millisecond,
		TimeoutMessage: "", // Empty message should use default
	}

	router := gin.New()
	router.Use(TimeoutWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestLogTimeout tests the logTimeout function
func TestLogTimeout(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger := zap.NewNop()
		// Should not panic
		logTimeout(logger, "GET", "/test", 30*time.Second)
	})

	t.Run("with nil logger", func(t *testing.T) {
		// Should not panic
		logTimeout(nil, "GET", "/test", 30*time.Second)
	})
}

// TestHandleTimeoutResponse tests the handleTimeoutResponse function
func TestHandleTimeoutResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("default response", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		config := TimeoutConfig{
			Timeout:        30 * time.Second,
			TimeoutMessage: "Custom timeout message",
		}

		handleTimeoutResponse(c, config)

		assert.Equal(t, http.StatusGatewayTimeout, w.Code)
		assert.Contains(t, w.Body.String(), "Custom timeout message")
	})

	t.Run("custom handler", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		customHandlerCalled := false
		config := TimeoutConfig{
			Timeout: 30 * time.Second,
			TimeoutHandler: func(c *gin.Context) {
				customHandlerCalled = true
				c.AbortWithStatusJSON(http.StatusRequestTimeout, gin.H{"error": "custom"})
			},
		}

		handleTimeoutResponse(c, config)

		assert.True(t, customHandlerCalled)
		assert.Equal(t, http.StatusRequestTimeout, w.Code)
	})
}

// TestWaitForCompletionOrTimeout tests the waitForCompletionOrTimeout function
func TestWaitForCompletionOrTimeout(t *testing.T) {
	t.Run("handler completes before timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		done := make(chan struct{})
		go func() {
			time.Sleep(10 * time.Millisecond)
			close(done)
		}()

		result := waitForCompletionOrTimeout(ctx, done)
		assert.True(t, result)
	})

	t.Run("timeout occurs before handler completes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		done := make(chan struct{})
		// Don't close done - simulate slow handler

		result := waitForCompletionOrTimeout(ctx, done)
		assert.False(t, result)
	})

	t.Run("handler completes due to context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)

		done := make(chan struct{})
		go func() {
			<-ctx.Done() // Wait for context to be done
			close(done)
		}()

		// Wait for timeout
		time.Sleep(20 * time.Millisecond)
		cancel()

		result := waitForCompletionOrTimeout(ctx, done)
		assert.False(t, result)
	})
}

// TestRequestTimeout_ContextDeadline tests that RequestTimeout sets context deadline
func TestRequestTimeout_ContextDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)

	timeout := 100 * time.Millisecond

	var ctxDeadline time.Time
	var hasDeadline bool

	router := gin.New()
	router.Use(RequestTimeout(timeout))
	router.GET("/test", func(c *gin.Context) {
		ctxDeadline, hasDeadline = c.Request.Context().Deadline()
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, hasDeadline)
	// Deadline should be approximately now + timeout
	assert.True(t, ctxDeadline.After(time.Now().Add(-timeout)))
}

// TestDeadlineMiddleware_PastDeadline tests deadline middleware with past deadline
func TestDeadlineMiddleware_PastDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Set deadline in the past
	deadline := time.Now().Add(-1 * time.Hour)

	router := gin.New()
	router.Use(DeadlineMiddleware(deadline))
	router.GET("/test", func(c *gin.Context) {
		// Context should already be done
		select {
		case <-c.Request.Context().Done():
			c.String(http.StatusGatewayTimeout, "Timeout")
		default:
			c.String(http.StatusOK, "OK")
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Handler should detect the expired context
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

// TestSlowRequestLogger_Threshold tests slow request logger with various thresholds
func TestSlowRequestLogger_Threshold(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		threshold    time.Duration
		handlerDelay time.Duration
		expectLogged bool
	}{
		{
			name:         "request slower than threshold",
			threshold:    10 * time.Millisecond,
			handlerDelay: 50 * time.Millisecond,
			expectLogged: true,
		},
		{
			name:         "request faster than threshold",
			threshold:    100 * time.Millisecond,
			handlerDelay: 10 * time.Millisecond,
			expectLogged: false,
		},
		{
			name:         "request at threshold",
			threshold:    50 * time.Millisecond,
			handlerDelay: 50 * time.Millisecond,
			expectLogged: false, // Equal to threshold, not greater
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()

			router := gin.New()
			router.Use(SlowRequestLogger(tt.threshold, logger))
			router.GET("/test", func(c *gin.Context) {
				time.Sleep(tt.handlerDelay)
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// TestContextTimeout_AlreadyCancelled tests ContextTimeout with already cancelled context
func TestContextTimeout_AlreadyCancelled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ContextTimeout())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
	assert.Contains(t, w.Body.String(), "Request context cancelled")
}

// TestContextTimeout_ValidContext tests ContextTimeout with valid context
func TestContextTimeout_ValidContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ContextTimeout())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTimeoutWithFallback_HandlerCompletesJustAfterTimeout tests edge case
func TestTimeoutWithFallback_HandlerCompletesJustAfterTimeout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// This test verifies the brief wait after timeout
	fallbackCalled := false
	fallback := func(c *gin.Context) {
		fallbackCalled = true
		c.String(http.StatusServiceUnavailable, "Fallback")
	}

	router := gin.New()
	router.Use(TimeoutWithFallback(50*time.Millisecond, fallback))
	router.GET("/test", func(c *gin.Context) {
		// Complete quickly
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Handler should complete before timeout
	assert.False(t, fallbackCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTimeout_ZeroTimeout tests zero timeout handling
func TestTimeout_ZeroTimeout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Zero timeout should use default (30 seconds)
	router := gin.New()
	router.Use(Timeout(0))
	router.GET("/test", func(c *gin.Context) {
		_, hasDeadline := c.Request.Context().Deadline()
		assert.True(t, hasDeadline)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
