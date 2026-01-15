package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/retry"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	assert.NotNil(t, config.Policy)
	assert.Equal(t, []string{"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}, config.RetryableMethods)
	assert.Equal(t, int64(1024*1024), config.MaxBodySize)
}

func TestRetryMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	policy := retry.DefaultPolicy()

	router := gin.New()
	router.Use(RetryMiddleware(policy))
	router.GET("/test", func(c *gin.Context) {
		// Check that retry info is set in context
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

func TestRetryMiddlewareWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		config      RetryConfig
		method      string
		path        string
		expectRetry bool
	}{
		{
			name: "retryable GET method",
			config: RetryConfig{
				Policy:           retry.DefaultPolicy(),
				RetryableMethods: []string{"GET"},
			},
			method:      http.MethodGet,
			path:        "/test",
			expectRetry: true,
		},
		{
			name: "non-retryable POST method",
			config: RetryConfig{
				Policy:           retry.DefaultPolicy(),
				RetryableMethods: []string{"GET"},
			},
			method:      http.MethodPost,
			path:        "/test",
			expectRetry: false,
		},
		{
			name: "skip path",
			config: RetryConfig{
				Policy:           retry.DefaultPolicy(),
				RetryableMethods: []string{"GET"},
				SkipPaths:        []string{"/skip"},
			},
			method:      http.MethodGet,
			path:        "/skip",
			expectRetry: false,
		},
		{
			name: "default retryable methods",
			config: RetryConfig{
				Policy:           retry.DefaultPolicy(),
				RetryableMethods: nil, // Will use defaults
			},
			method:      http.MethodGet,
			path:        "/test",
			expectRetry: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var retryEnabled bool

			router := gin.New()
			router.Use(RetryMiddlewareWithConfig(tt.config))
			router.Handle(tt.method, tt.path, func(c *gin.Context) {
				retryEnabled = IsRetryEnabled(c)
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectRetry, retryEnabled)
		})
	}
}

func TestRetryMiddlewareWithConfig_NilPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RetryConfig{
		Policy: nil, // Will use default policy
	}

	router := gin.New()
	router.Use(RetryMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		p := GetRetryPolicy(c)
		assert.NotNil(t, p)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetRetryPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns policy when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		policy := retry.DefaultPolicy()
		c.Set("retry_policy", policy)

		p := GetRetryPolicy(c)
		assert.NotNil(t, p)
		assert.Equal(t, policy, p)
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		p := GetRetryPolicy(c)
		assert.Nil(t, p)
	})
}

func TestIsRetryEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns true when enabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("retry_enabled", true)

		assert.True(t, IsRetryEnabled(c))
	})

	t.Run("returns false when disabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("retry_enabled", false)

		assert.False(t, IsRetryEnabled(c))
	})

	t.Run("returns false when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		assert.False(t, IsRetryEnabled(c))
	})
}

func TestBufferRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		body        string
		maxSize     int64
		expectError bool
	}{
		{
			name:        "small body",
			body:        "small body content",
			maxSize:     1024,
			expectError: false,
		},
		{
			name:        "body at max size",
			body:        strings.Repeat("a", 100),
			maxSize:     100,
			expectError: false,
		},
		{
			name:        "body exceeds max size (truncated)",
			body:        strings.Repeat("a", 200),
			maxSize:     100,
			expectError: false, // No error, just truncated
		},
		{
			name:        "empty body",
			body:        "",
			maxSize:     1024,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(tt.body))

			body, err := BufferRequestBody(c, tt.maxSize)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.body != "" {
					expectedLen := len(tt.body)
					if int64(expectedLen) > tt.maxSize {
						expectedLen = int(tt.maxSize)
					}
					assert.Len(t, body, expectedLen)
				}
			}
		})
	}
}

func TestBufferRequestBody_NilBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Body = nil

	body, err := BufferRequestBody(c, 1024)

	assert.NoError(t, err)
	assert.Nil(t, body)
}

func TestRestoreRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalBody := []byte("original body content")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(originalBody))

	// Read the body first
	_, _ = io.ReadAll(c.Request.Body)

	// Restore it
	RestoreRequestBody(c, originalBody)

	// Read again
	restoredBody, err := io.ReadAll(c.Request.Body)
	assert.NoError(t, err)
	assert.Equal(t, originalBody, restoredBody)
}

func TestRestoreRequestBody_NilBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not panic
	RestoreRequestBody(c, nil)
}

func TestNewRetryableHandler(t *testing.T) {
	policy := retry.DefaultPolicy()

	handler := func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	}

	retryableHandler := NewRetryableHandler(handler, policy, nil)

	assert.NotNil(t, retryableHandler)
	assert.NotNil(t, retryableHandler.handler)
	assert.NotNil(t, retryableHandler.policy)
}

func TestResponseWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	rw := newResponseWriter(c.Writer)

	// Write some data
	n, err := rw.Write([]byte("test data"))
	assert.NoError(t, err)
	assert.Equal(t, 9, n)

	// Write header
	rw.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rw.statusCode)

	// Check body was captured
	assert.Equal(t, "test data", rw.body.String())
}

func TestStatusError(t *testing.T) {
	err := &statusError{code: http.StatusInternalServerError}
	assert.Equal(t, "Internal Server Error", err.Error())

	err = &statusError{code: http.StatusBadGateway}
	assert.Equal(t, "Bad Gateway", err.Error())
}

func TestRetryMiddleware_AllMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	methods := []struct {
		method      string
		expectRetry bool
	}{
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodOptions, true},
		{http.MethodPut, true},
		{http.MethodDelete, true},
		{http.MethodPost, false},
		{http.MethodPatch, false},
	}

	for _, m := range methods {
		t.Run(m.method, func(t *testing.T) {
			var retryEnabled bool

			router := gin.New()
			router.Use(RetryMiddleware(retry.DefaultPolicy()))
			router.Handle(m.method, "/test", func(c *gin.Context) {
				retryEnabled = IsRetryEnabled(c)
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(m.method, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, m.expectRetry, retryEnabled, "method: %s", m.method)
		})
	}
}

func TestRetryMiddlewareWithConfig_MaxBodySize(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RetryConfig{
		Policy:      retry.DefaultPolicy(),
		MaxBodySize: 0, // Will use default
	}

	router := gin.New()
	router.Use(RetryMiddlewareWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRetryableHandler_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("successful request", func(t *testing.T) {
		policy := retry.DefaultPolicy().WithMaxRetries(3)
		callCount := 0

		handler := func(c *gin.Context) {
			callCount++
			c.String(http.StatusOK, "OK")
		}

		retryableHandler := NewRetryableHandler(handler, policy, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		retryableHandler.Handle(c)

		// Should only be called once on success
		assert.Equal(t, 1, callCount)
	})

	t.Run("request with body", func(t *testing.T) {
		policy := retry.DefaultPolicy().WithMaxRetries(1)

		handler := func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		}

		retryableHandler := NewRetryableHandler(handler, policy, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("body content"))

		retryableHandler.Handle(c)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRetryPolicy_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	policy := &retry.Policy{
		MaxRetries:     2,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		BackoffFactor:  2.0,
		Jitter:         0.1,
	}

	router := gin.New()
	router.Use(RetryMiddleware(policy))
	router.GET("/test", func(c *gin.Context) {
		p := GetRetryPolicy(c)
		assert.Equal(t, 2, p.MaxRetries)
		assert.Equal(t, 10*time.Millisecond, p.InitialBackoff)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
