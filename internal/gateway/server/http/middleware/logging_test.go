package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogging(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)

	// Check that request ID was set
	assert.NotEmpty(t, w.Header().Get(RequestIDHeader))
}

func TestLoggingWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		config         LoggingConfig
		path           string
		expectedLogged bool
		expectedStatus int
	}{
		{
			name: "normal request",
			config: LoggingConfig{
				Logger: zap.NewNop(),
			},
			path:           "/test",
			expectedLogged: true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "skip path",
			config: LoggingConfig{
				Logger:    zap.NewNop(),
				SkipPaths: []string{"/skip"},
			},
			path:           "/skip",
			expectedLogged: false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "skip health check",
			config: LoggingConfig{
				Logger:          zap.NewNop(),
				SkipHealthCheck: true,
			},
			path:           "/health",
			expectedLogged: false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "skip healthz",
			config: LoggingConfig{
				Logger:          zap.NewNop(),
				SkipHealthCheck: true,
			},
			path:           "/healthz",
			expectedLogged: false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "skip ready",
			config: LoggingConfig{
				Logger:          zap.NewNop(),
				SkipHealthCheck: true,
			},
			path:           "/ready",
			expectedLogged: false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "skip readyz",
			config: LoggingConfig{
				Logger:          zap.NewNop(),
				SkipHealthCheck: true,
			},
			path:           "/readyz",
			expectedLogged: false,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			tt.config.Logger = zap.New(core)

			router := gin.New()
			router.Use(LoggingWithConfig(tt.config))
			router.GET(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedLogged {
				assert.GreaterOrEqual(t, logs.Len(), 1)
			} else {
				assert.Equal(t, 0, logs.Len())
			}
		})
	}
}

func TestLogging_NilLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(LoggingWithConfig(LoggingConfig{Logger: nil}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogging_RequestIDFromHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Logging(zap.NewNop()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	customRequestID := "custom-request-id-123"
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(RequestIDHeader, customRequestID)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, customRequestID, w.Header().Get(RequestIDHeader))
}

func TestLogging_StatusCodeLogging(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		statusCode    int
		expectedLevel string
	}{
		{
			name:          "2xx status - info",
			statusCode:    http.StatusOK,
			expectedLevel: "info",
		},
		{
			name:          "4xx status - warn",
			statusCode:    http.StatusBadRequest,
			expectedLevel: "warn",
		},
		{
			name:          "5xx status - error",
			statusCode:    http.StatusInternalServerError,
			expectedLevel: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			logger := zap.New(core)

			router := gin.New()
			router.Use(Logging(logger))
			router.GET("/test", func(c *gin.Context) {
				c.String(tt.statusCode, "Response")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.statusCode, w.Code)
			assert.GreaterOrEqual(t, logs.Len(), 1)

			lastLog := logs.All()[logs.Len()-1]
			assert.Equal(t, tt.expectedLevel, lastLog.Level.String())
		})
	}
}

func TestLogging_WithErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.Error(assert.AnError)
		c.String(http.StatusInternalServerError, "Error")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)

	// Check that errors field is present
	lastLog := logs.All()[logs.Len()-1]
	found := false
	for _, field := range lastLog.Context {
		if field.Key == "errors" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected errors field in log")
}

func TestRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		requestID := GetRequestID(c)
		c.String(http.StatusOK, requestID)
	})

	t.Run("generates new request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get(RequestIDHeader))
		assert.NotEmpty(t, w.Body.String())
	})

	t.Run("uses existing request ID", func(t *testing.T) {
		customID := "my-custom-id"
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(RequestIDHeader, customID)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, customID, w.Header().Get(RequestIDHeader))
		assert.Equal(t, customID, w.Body.String())
	})
}

func TestGetRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns request ID when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(RequestIDKey, "test-id")

		id := GetRequestID(c)
		assert.Equal(t, "test-id", id)
	})

	t.Run("returns empty when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		id := GetRequestID(c)
		assert.Empty(t, id)
	})

	t.Run("returns empty when wrong type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(RequestIDKey, 123) // wrong type

		id := GetRequestID(c)
		assert.Empty(t, id)
	})
}

func TestStructuredLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, _ := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(RequestID())
	router.Use(StructuredLogger(logger))
	router.GET("/test", func(c *gin.Context) {
		l := GetLogger(c)
		assert.NotNil(t, l)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStructuredLogger_GeneratesRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, _ := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	var capturedRequestID string

	router := gin.New()
	router.Use(StructuredLogger(logger))
	router.GET("/test", func(c *gin.Context) {
		capturedRequestID = GetRequestID(c)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.NotEmpty(t, capturedRequestID)
}

func TestGetLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns logger when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		expectedLogger := zap.NewNop()
		c.Set("logger", expectedLogger)

		l := GetLogger(c)
		assert.NotNil(t, l)
	})

	t.Run("returns nop logger when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		l := GetLogger(c)
		assert.NotNil(t, l)
	})

	t.Run("returns nop logger when wrong type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("logger", "not a logger")

		l := GetLogger(c)
		assert.NotNil(t, l)
	})
}

func TestLogging_LogFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?foo=bar", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.GreaterOrEqual(t, logs.Len(), 1)

	lastLog := logs.All()[logs.Len()-1]
	fields := make(map[string]interface{})
	for _, f := range lastLog.Context {
		fields[f.Key] = f.Interface
	}

	assert.Contains(t, fields, "requestID")
	assert.Contains(t, fields, "method")
	assert.Contains(t, fields, "path")
	assert.Contains(t, fields, "query")
	assert.Contains(t, fields, "status")
	assert.Contains(t, fields, "latency")
	assert.Contains(t, fields, "clientIP")
	assert.Contains(t, fields, "userAgent")
	assert.Contains(t, fields, "bodySize")
}
