// Package logging provides structured logging for the API Gateway.
package logging

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultAccessLogConfig(t *testing.T) {
	config := DefaultAccessLogConfig()

	assert.NotNil(t, config)
	assert.True(t, config.SkipHealthCheck)
	assert.Equal(t, 1024, config.MaxBodySize)
	assert.NotEmpty(t, config.SensitiveHeaders)
	assert.NotEmpty(t, config.SensitiveParams)
	assert.NotEmpty(t, config.SensitiveFields)

	// Check sensitive headers
	assert.Contains(t, config.SensitiveHeaders, "Authorization")
	assert.Contains(t, config.SensitiveHeaders, "X-API-Key")
	assert.Contains(t, config.SensitiveHeaders, "Cookie")

	// Check sensitive params
	assert.Contains(t, config.SensitiveParams, "password")
	assert.Contains(t, config.SensitiveParams, "token")
	assert.Contains(t, config.SensitiveParams, "secret")

	// Check sensitive fields
	assert.Contains(t, config.SensitiveFields, "password")
	assert.Contains(t, config.SensitiveFields, "token")
	assert.Contains(t, config.SensitiveFields, "credit_card")
}

func TestAccessLogMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger, err := NewLogger(&Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	middleware := AccessLogMiddleware(logger)
	assert.NotNil(t, middleware)

	// Create test router
	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAccessLogMiddlewareWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		config     *AccessLogConfig
		path       string
		wantStatus int
	}{
		{
			name:       "with nil config",
			config:     nil,
			path:       "/test",
			wantStatus: http.StatusOK,
		},
		{
			name: "with custom config",
			config: &AccessLogConfig{
				SkipHealthCheck: true,
				MaxBodySize:     2048,
			},
			path:       "/test",
			wantStatus: http.StatusOK,
		},
		{
			name: "with skip paths",
			config: &AccessLogConfig{
				SkipPaths: []string{"/skip"},
			},
			path:       "/skip",
			wantStatus: http.StatusOK,
		},
		{
			name: "with custom fields function",
			config: &AccessLogConfig{
				CustomFields: func(c *gin.Context) []zap.Field {
					return []zap.Field{zap.String("custom", "value")}
				},
			},
			path:       "/test",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := AccessLogMiddlewareWithConfig(tt.config)
			assert.NotNil(t, middleware)

			router := gin.New()
			router.Use(middleware)
			router.GET(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestAccessLogMiddleware_SkipHealthCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &AccessLogConfig{
		SkipHealthCheck: true,
	}

	middleware := AccessLogMiddlewareWithConfig(config)

	healthPaths := []string{"/health", "/healthz", "/ready", "/readyz", "/livez", "/metrics"}

	for _, path := range healthPaths {
		t.Run("skip "+path, func(t *testing.T) {
			router := gin.New()
			router.Use(middleware)
			router.GET(path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestAccessLogMiddleware_StatusCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		statusCode int
	}{
		{"2xx success", http.StatusOK},
		{"3xx redirect", http.StatusMovedPermanently},
		{"4xx client error", http.StatusBadRequest},
		{"404 not found", http.StatusNotFound},
		{"5xx server error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &AccessLogConfig{
				Logger:          logger,
				SkipHealthCheck: false,
			}

			middleware := AccessLogMiddlewareWithConfig(config)

			router := gin.New()
			router.Use(middleware)
			router.GET("/test", func(c *gin.Context) {
				c.String(tt.statusCode, "Response")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.statusCode, w.Code)
		})
	}
}

func TestAccessLogMiddleware_WithHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	config := &AccessLogConfig{
		Logger: logger,
	}

	middleware := AccessLogMiddlewareWithConfig(config)

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	req.Header.Set("X-Request-ID", "test-request-id")
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "http://example.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHTTPAccessLogMiddleware(t *testing.T) {
	logger, err := NewLogger(&Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	middleware := HTTPAccessLogMiddleware(logger)
	assert.NotNil(t, middleware)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHTTPAccessLogMiddlewareWithConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     *AccessLogConfig
		path       string
		wantStatus int
	}{
		{
			name:       "with nil config",
			config:     nil,
			path:       "/test",
			wantStatus: http.StatusOK,
		},
		{
			name: "with custom config",
			config: &AccessLogConfig{
				SkipHealthCheck: true,
			},
			path:       "/test",
			wantStatus: http.StatusOK,
		},
		{
			name: "with skip paths",
			config: &AccessLogConfig{
				SkipPaths: []string{"/skip"},
			},
			path:       "/skip",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := HTTPAccessLogMiddlewareWithConfig(tt.config)
			assert.NotNil(t, middleware)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestHTTPAccessLogMiddleware_SkipHealthCheck(t *testing.T) {
	config := &AccessLogConfig{
		SkipHealthCheck: true,
	}

	middleware := HTTPAccessLogMiddlewareWithConfig(config)

	healthPaths := []string{"/health", "/healthz", "/ready", "/readyz", "/livez", "/metrics"}

	for _, path := range healthPaths {
		t.Run("skip "+path, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestHTTPAccessLogMiddleware_StatusCodes(t *testing.T) {
	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		statusCode int
	}{
		{"2xx success", http.StatusOK},
		{"4xx client error", http.StatusBadRequest},
		{"5xx server error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &AccessLogConfig{
				Logger:          logger,
				SkipHealthCheck: false,
			}

			middleware := HTTPAccessLogMiddlewareWithConfig(config)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("Response"))
			})

			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.statusCode, w.Code)
		})
	}
}

func TestAccessResponseWriter(t *testing.T) {
	t.Run("WriteHeader captures status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		arw := &accessResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		arw.WriteHeader(http.StatusNotFound)

		assert.Equal(t, http.StatusNotFound, arw.statusCode)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("Write captures size", func(t *testing.T) {
		w := httptest.NewRecorder()
		arw := &accessResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		data := []byte("Hello, World!")
		n, err := arw.Write(data)

		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, len(data), arw.size)
	})

	t.Run("multiple writes accumulate size", func(t *testing.T) {
		w := httptest.NewRecorder()
		arw := &accessResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		arw.Write([]byte("Hello"))
		arw.Write([]byte(", "))
		arw.Write([]byte("World!"))

		assert.Equal(t, 13, arw.size)
	})

	t.Run("Flush works", func(t *testing.T) {
		w := httptest.NewRecorder()
		arw := &accessResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Should not panic
		assert.NotPanics(t, func() {
			arw.Flush()
		})
	})
}

func TestIsHealthCheckPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/healthz", true},
		{"/ready", true},
		{"/readyz", true},
		{"/livez", true},
		{"/metrics", true},
		{"/api/v1/users", false},
		{"/", false},
		{"/health/check", false},
		{"/api/health", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isHealthCheckPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedactQueryParams(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		sensitiveParams map[string]bool
		expected        string
	}{
		{
			name:            "empty query",
			query:           "",
			sensitiveParams: map[string]bool{"password": true},
			expected:        "",
		},
		{
			name:            "no sensitive params",
			query:           "page=1&limit=10",
			sensitiveParams: map[string]bool{"password": true},
			expected:        "page=1&limit=10",
		},
		{
			name:            "single sensitive param",
			query:           "username=john&password=secret123",
			sensitiveParams: map[string]bool{"password": true},
			expected:        "username=john&password=[REDACTED]",
		},
		{
			name:            "multiple sensitive params",
			query:           "username=john&password=secret&token=abc123",
			sensitiveParams: map[string]bool{"password": true, "token": true},
			expected:        "username=john&password=[REDACTED]&token=[REDACTED]",
		},
		{
			name:            "case insensitive",
			query:           "PASSWORD=secret&Token=abc",
			sensitiveParams: map[string]bool{"password": true, "token": true},
			expected:        "PASSWORD=[REDACTED]&Token=[REDACTED]",
		},
		{
			name:            "param without value",
			query:           "flag&password=secret",
			sensitiveParams: map[string]bool{"password": true},
			expected:        "flag&password=[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactQueryParams(tt.query, tt.sensitiveParams)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedactHeaders(t *testing.T) {
	tests := []struct {
		name             string
		headers          http.Header
		sensitiveHeaders map[string]bool
		checkRedacted    []string
		checkNotRedacted []string
	}{
		{
			name: "redact authorization",
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
				"Content-Type":  []string{"application/json"},
			},
			sensitiveHeaders: map[string]bool{"authorization": true},
			checkRedacted:    []string{"Authorization"},
			checkNotRedacted: []string{"Content-Type"},
		},
		{
			name: "redact multiple headers",
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
				"X-Api-Key":     []string{"key123"},
				"Content-Type":  []string{"application/json"},
			},
			sensitiveHeaders: map[string]bool{"authorization": true, "x-api-key": true},
			checkRedacted:    []string{"Authorization", "X-Api-Key"},
			checkNotRedacted: []string{"Content-Type"},
		},
		{
			name:             "empty headers",
			headers:          http.Header{},
			sensitiveHeaders: map[string]bool{"authorization": true},
			checkRedacted:    []string{},
			checkNotRedacted: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactHeaders(tt.headers, tt.sensitiveHeaders)

			for _, h := range tt.checkRedacted {
				assert.Equal(t, []string{"[REDACTED]"}, result[h])
			}

			for _, h := range tt.checkNotRedacted {
				assert.Equal(t, tt.headers[h], result[h])
			}
		})
	}
}

func TestRedactJSON(t *testing.T) {
	tests := []struct {
		name            string
		data            string
		sensitiveFields []string
		checkContains   []string
		checkNotContain []string
	}{
		{
			name:            "redact password field",
			data:            `{"username":"john","password":"secret123"}`,
			sensitiveFields: []string{"password"},
			checkContains:   []string{`"password":"[REDACTED]"`},
			checkNotContain: []string{"secret123"},
		},
		{
			name:            "redact multiple fields",
			data:            `{"username":"john","password":"secret","token":"abc123"}`,
			sensitiveFields: []string{"password", "token"},
			checkContains:   []string{`"password":"[REDACTED]"`, `"token":"[REDACTED]"`},
			checkNotContain: []string{"secret", "abc123"},
		},
		{
			name:            "no sensitive fields",
			data:            `{"username":"john","email":"john@example.com"}`,
			sensitiveFields: []string{"password"},
			checkContains:   []string{`"username":"john"`, `"email":"john@example.com"`},
			checkNotContain: []string{},
		},
		{
			name:            "empty data",
			data:            "",
			sensitiveFields: []string{"password"},
			checkContains:   []string{},
			checkNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactJSON(tt.data, tt.sensitiveFields)

			for _, s := range tt.checkContains {
				assert.Contains(t, result, s)
			}

			for _, s := range tt.checkNotContain {
				assert.NotContains(t, result, s)
			}
		})
	}
}

func TestGetClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func() *http.Request
		expectedIP string
	}{
		{
			name: "from X-Forwarded-For single IP",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1")
				return req
			},
			expectedIP: "192.168.1.1",
		},
		{
			name: "from X-Forwarded-For multiple IPs",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1, 172.16.0.1")
				return req
			},
			expectedIP: "192.168.1.1",
		},
		{
			name: "from X-Real-IP",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Real-IP", "192.168.1.100")
				return req
			},
			expectedIP: "192.168.1.100",
		},
		{
			name: "X-Forwarded-For takes precedence over X-Real-IP",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1")
				req.Header.Set("X-Real-IP", "192.168.1.100")
				return req
			},
			expectedIP: "192.168.1.1",
		},
		{
			name: "fallback to RemoteAddr",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "192.168.1.50:12345"
				return req
			},
			expectedIP: "192.168.1.50:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			result := getClientIPFromRequest(req)
			assert.Equal(t, tt.expectedIP, result)
		})
	}
}

func TestAccessLogEntry_ToZapFields(t *testing.T) {
	tests := []struct {
		name      string
		entry     AccessLogEntry
		minFields int
	}{
		{
			name: "minimal entry",
			entry: AccessLogEntry{
				Method:     "GET",
				Path:       "/api/v1/users",
				StatusCode: 200,
			},
			minFields: 8, // timestamp, method, path, status_code, latency, latency_ms, client_ip, response_size
		},
		{
			name: "full entry",
			entry: AccessLogEntry{
				RequestID:     "req-123",
				Method:        "POST",
				Path:          "/api/v1/users",
				Query:         "page=1",
				StatusCode:    201,
				ClientIP:      "192.168.1.1",
				UserAgent:     "test-agent",
				ContentType:   "application/json",
				ContentLength: 1024,
				ResponseSize:  512,
				TraceID:       "trace-123",
				SpanID:        "span-456",
				Error:         "some error",
				Extra:         map[string]string{"custom": "value"},
			},
			minFields: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := tt.entry.ToZapFields()
			assert.GreaterOrEqual(t, len(fields), tt.minFields)
		})
	}
}

func TestAccessLogEntry_ToZapFields_OptionalFields(t *testing.T) {
	entry := AccessLogEntry{
		RequestID:     "req-123",
		Method:        "GET",
		Path:          "/test",
		Query:         "q=test",
		StatusCode:    200,
		UserAgent:     "test-agent",
		ContentType:   "application/json",
		ContentLength: 100,
		TraceID:       "trace-123",
		SpanID:        "span-456",
		Error:         "test error",
		Extra:         map[string]string{"key": "value"},
	}

	fields := entry.ToZapFields()

	// Check that optional fields are included
	fieldKeys := make(map[string]bool)
	for _, f := range fields {
		fieldKeys[f.Key] = true
	}

	assert.True(t, fieldKeys["request_id"])
	assert.True(t, fieldKeys["query"])
	assert.True(t, fieldKeys["user_agent"])
	assert.True(t, fieldKeys["content_type"])
	assert.True(t, fieldKeys["content_length"])
	assert.True(t, fieldKeys["trace_id"])
	assert.True(t, fieldKeys["span_id"])
	assert.True(t, fieldKeys["error"])
	assert.True(t, fieldKeys["key"]) // from Extra
}

func TestAccessLogMiddleware_WithErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	config := &AccessLogConfig{
		Logger: logger,
	}

	middleware := AccessLogMiddlewareWithConfig(config)

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.Error(assert.AnError)
		c.String(http.StatusInternalServerError, "Error")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHTTPAccessLogMiddleware_WithHeaders(t *testing.T) {
	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	config := &AccessLogConfig{
		Logger:          logger,
		SensitiveParams: []string{"password", "token"},
	}

	middleware := HTTPAccessLogMiddlewareWithConfig(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test?foo=bar&password=secret", nil)
	req.Header.Set("X-Request-ID", "test-123")
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 100
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
