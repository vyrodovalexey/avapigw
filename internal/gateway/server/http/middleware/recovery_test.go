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

func TestRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})
	router.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	t.Run("recovers from panic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/panic", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Internal Server Error")
		assert.GreaterOrEqual(t, logs.Len(), 1)
	})

	t.Run("normal request passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ok", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})
}

func TestRecoveryWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name             string
		config           RecoveryConfig
		expectStackTrace bool
	}{
		{
			name: "with stack trace",
			config: RecoveryConfig{
				EnableStackTrace: true,
			},
			expectStackTrace: true,
		},
		{
			name: "without stack trace",
			config: RecoveryConfig{
				EnableStackTrace: false,
			},
			expectStackTrace: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			tt.config.Logger = zap.New(core)

			router := gin.New()
			router.Use(RecoveryWithConfig(tt.config))
			router.GET("/panic", func(c *gin.Context) {
				panic("test panic")
			})

			req := httptest.NewRequest(http.MethodGet, "/panic", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			assert.GreaterOrEqual(t, logs.Len(), 1)

			lastLog := logs.All()[logs.Len()-1]
			hasStack := false
			for _, field := range lastLog.Context {
				if field.Key == "stack" {
					hasStack = true
					break
				}
			}

			if tt.expectStackTrace {
				assert.True(t, hasStack, "expected stack trace in log")
			} else {
				assert.False(t, hasStack, "expected no stack trace in log")
			}
		})
	}
}

func TestRecoveryWithConfig_NilLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RecoveryWithConfig(RecoveryConfig{Logger: nil}))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	// Should not panic
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRecoveryWithConfig_CustomPanicHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	customHandlerCalled := false

	config := RecoveryConfig{
		Logger: zap.NewNop(),
		PanicHandler: func(c *gin.Context, err interface{}) {
			customHandlerCalled = true
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "custom error",
			})
		},
	}

	router := gin.New()
	router.Use(RecoveryWithConfig(config))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, customHandlerCalled)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "custom error")
}

func TestRecoveryWithConfig_WithRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(RequestID())
	router.Use(RecoveryWithConfig(RecoveryConfig{
		Logger:           logger,
		EnableStackTrace: true,
	}))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	req.Header.Set(RequestIDHeader, "test-request-id")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)

	lastLog := logs.All()[logs.Len()-1]
	hasRequestID := false
	for _, field := range lastLog.Context {
		if field.Key == "requestID" && field.String == "test-request-id" {
			hasRequestID = true
			break
		}
	}
	assert.True(t, hasRequestID, "expected requestID in log")
}

func TestRecoveryWithWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	customHandlerCalled := false
	customHandler := func(c *gin.Context, err interface{}) {
		customHandlerCalled = true
	}

	router := gin.New()
	router.Use(RecoveryWithWriter(logger, customHandler))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, customHandlerCalled)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

func TestRecoveryWithWriter_AbortedByHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, _ := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	customHandler := func(c *gin.Context, err interface{}) {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "aborted"})
	}

	router := gin.New()
	router.Use(RecoveryWithWriter(logger, customHandler))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "aborted")
}

func TestCustomRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	customHandlerCalled := false
	var capturedError interface{}

	customHandler := func(c *gin.Context, err interface{}) {
		customHandlerCalled = true
		capturedError = err
		c.AbortWithStatusJSON(http.StatusTeapot, gin.H{"error": "custom"})
	}

	router := gin.New()
	router.Use(CustomRecovery(logger, customHandler))
	router.GET("/panic", func(c *gin.Context) {
		panic("custom panic message")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, customHandlerCalled)
	assert.Equal(t, "custom panic message", capturedError)
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

func TestRecovery_DifferentPanicTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		panicValue interface{}
	}{
		{
			name:       "string panic",
			panicValue: "string error",
		},
		{
			name:       "error panic",
			panicValue: assert.AnError,
		},
		{
			name:       "int panic",
			panicValue: 42,
		},
		{
			name:       "struct panic",
			panicValue: struct{ msg string }{"struct error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			logger := zap.New(core)

			router := gin.New()
			router.Use(Recovery(logger))
			router.GET("/panic", func(c *gin.Context) {
				panic(tt.panicValue)
			})

			req := httptest.NewRequest(http.MethodGet, "/panic", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			assert.GreaterOrEqual(t, logs.Len(), 1)
		})
	}
}

func TestRecovery_LogFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.GreaterOrEqual(t, logs.Len(), 1)

	lastLog := logs.All()[logs.Len()-1]
	fields := make(map[string]bool)
	for _, f := range lastLog.Context {
		fields[f.Key] = true
	}

	assert.True(t, fields["error"], "expected error field")
	assert.True(t, fields["method"], "expected method field")
	assert.True(t, fields["path"], "expected path field")
	assert.True(t, fields["clientIP"], "expected clientIP field")
	assert.True(t, fields["stack"], "expected stack field")
}

func TestRecovery_NoPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
	// No panic recovery logs
	for _, log := range logs.All() {
		assert.NotEqual(t, "panic recovered", log.Message)
	}
}
