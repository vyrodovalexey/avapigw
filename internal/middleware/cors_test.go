package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestDefaultCORSConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultCORSConfig()

	assert.Equal(t, []string{"*"}, cfg.AllowOrigins)
	assert.Contains(t, cfg.AllowMethods, "GET")
	assert.Contains(t, cfg.AllowMethods, "POST")
	assert.Contains(t, cfg.AllowMethods, "PUT")
	assert.Contains(t, cfg.AllowMethods, "DELETE")
	assert.Contains(t, cfg.AllowMethods, "OPTIONS")
	assert.Contains(t, cfg.AllowHeaders, "Content-Type")
	assert.Contains(t, cfg.AllowHeaders, "Authorization")
	assert.Equal(t, 86400, cfg.MaxAge)
	assert.False(t, cfg.AllowCredentials)
}

func TestCORS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		config              CORSConfig
		origin              string
		method              string
		expectedOrigin      string
		expectedMethods     string
		expectedHeaders     string
		expectedCredentials string
		expectedMaxAge      string
		expectedStatus      int
	}{
		{
			name: "allows wildcard origin",
			config: CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
				AllowHeaders: []string{"Content-Type"},
				MaxAge:       3600,
			},
			origin:          "http://example.com",
			method:          http.MethodGet,
			expectedOrigin:  "http://example.com",
			expectedMethods: "GET, POST",
			expectedHeaders: "Content-Type",
			expectedMaxAge:  "3600",
			expectedStatus:  http.StatusOK,
		},
		{
			name: "allows specific origin",
			config: CORSConfig{
				AllowOrigins: []string{"http://example.com"},
				AllowMethods: []string{"GET"},
			},
			origin:         "http://example.com",
			method:         http.MethodGet,
			expectedOrigin: "http://example.com",
			expectedStatus: http.StatusOK,
		},
		{
			name: "rejects non-matching origin",
			config: CORSConfig{
				AllowOrigins: []string{"http://allowed.com"},
			},
			origin:         "http://notallowed.com",
			method:         http.MethodGet,
			expectedOrigin: "",
			expectedStatus: http.StatusOK,
		},
		{
			name: "handles preflight OPTIONS request",
			config: CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
			},
			origin:          "http://example.com",
			method:          http.MethodOptions,
			expectedOrigin:  "http://example.com",
			expectedMethods: "GET, POST",
			expectedStatus:  http.StatusNoContent,
		},
		{
			name: "sets credentials header when enabled",
			config: CORSConfig{
				AllowOrigins:     []string{"*"},
				AllowCredentials: true,
			},
			origin:              "http://example.com",
			method:              http.MethodGet,
			expectedOrigin:      "http://example.com",
			expectedCredentials: "true",
			expectedStatus:      http.StatusOK,
		},
		{
			name: "sets expose headers",
			config: CORSConfig{
				AllowOrigins:  []string{"*"},
				ExposeHeaders: []string{"X-Custom-Header", "X-Another-Header"},
			},
			origin:         "http://example.com",
			method:         http.MethodGet,
			expectedOrigin: "http://example.com",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := CORS(tt.config)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedOrigin != "" {
				assert.Equal(t, tt.expectedOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
			}
			if tt.expectedMethods != "" {
				assert.Equal(t, tt.expectedMethods, rec.Header().Get("Access-Control-Allow-Methods"))
			}
			if tt.expectedHeaders != "" {
				assert.Equal(t, tt.expectedHeaders, rec.Header().Get("Access-Control-Allow-Headers"))
			}
			if tt.expectedCredentials != "" {
				assert.Equal(t, tt.expectedCredentials, rec.Header().Get("Access-Control-Allow-Credentials"))
			}
			if tt.expectedMaxAge != "" {
				assert.Equal(t, tt.expectedMaxAge, rec.Header().Get("Access-Control-Max-Age"))
			}
		})
	}
}

func TestCORS_NoOriginHeader(t *testing.T) {
	t.Parallel()

	cfg := CORSConfig{
		AllowOrigins: []string{"*"},
	}
	middleware := CORS(cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No Origin header set
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Should not set CORS headers without Origin
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *config.CORSConfig
		origin         string
		expectedOrigin string
	}{
		{
			name:           "nil config uses defaults",
			config:         nil,
			origin:         "http://example.com",
			expectedOrigin: "http://example.com",
		},
		{
			name: "uses provided config",
			config: &config.CORSConfig{
				AllowOrigins: []string{"http://specific.com"},
				AllowMethods: []string{"GET"},
			},
			origin:         "http://specific.com",
			expectedOrigin: "http://specific.com",
		},
		{
			name: "empty origins uses default",
			config: &config.CORSConfig{
				AllowOrigins: []string{},
			},
			origin:         "http://example.com",
			expectedOrigin: "http://example.com",
		},
		{
			name: "empty methods uses default",
			config: &config.CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{},
			},
			origin:         "http://example.com",
			expectedOrigin: "http://example.com",
		},
		{
			name: "empty headers uses default",
			config: &config.CORSConfig{
				AllowOrigins: []string{"*"},
				AllowHeaders: []string{},
			},
			origin:         "http://example.com",
			expectedOrigin: "http://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := CORSFromConfig(tt.config)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestNewCORSHeaders(t *testing.T) {
	t.Parallel()

	cfg := CORSConfig{
		AllowOrigins:     []string{"http://a.com", "http://b.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type"},
		ExposeHeaders:    []string{"X-Custom"},
		AllowCredentials: true,
		MaxAge:           3600,
	}

	headers := newCORSHeaders(cfg)

	assert.True(t, headers.allowOrigins["http://a.com"])
	assert.True(t, headers.allowOrigins["http://b.com"])
	assert.False(t, headers.allowOrigins["http://c.com"])
	assert.Equal(t, "GET, POST", headers.allowMethods)
	assert.Equal(t, "Content-Type", headers.allowHeaders)
	assert.Equal(t, "X-Custom", headers.exposeHeaders)
	assert.Equal(t, "3600", headers.maxAge)
	assert.True(t, headers.allowCredentials)
	assert.True(t, headers.hasAllowMethods)
	assert.True(t, headers.hasAllowHeaders)
	assert.True(t, headers.hasExposeHeaders)
	assert.True(t, headers.hasMaxAge)
}

func TestCORSHeaders_SetCORSHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		config        CORSConfig
		origin        string
		expectOrigin  bool
		expectMethods bool
		expectHeaders bool
		expectExpose  bool
		expectCreds   bool
		expectMaxAge  bool
	}{
		{
			name: "sets all headers for matching origin",
			config: CORSConfig{
				AllowOrigins:     []string{"http://example.com"},
				AllowMethods:     []string{"GET"},
				AllowHeaders:     []string{"Content-Type"},
				ExposeHeaders:    []string{"X-Custom"},
				AllowCredentials: true,
				MaxAge:           3600,
			},
			origin:        "http://example.com",
			expectOrigin:  true,
			expectMethods: true,
			expectHeaders: true,
			expectExpose:  true,
			expectCreds:   true,
			expectMaxAge:  true,
		},
		{
			name: "no headers for non-matching origin",
			config: CORSConfig{
				AllowOrigins: []string{"http://other.com"},
			},
			origin:       "http://example.com",
			expectOrigin: false,
		},
		{
			name: "wildcard matches any origin",
			config: CORSConfig{
				AllowOrigins: []string{"*"},
			},
			origin:       "http://any.com",
			expectOrigin: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			headers := newCORSHeaders(tt.config)
			rec := httptest.NewRecorder()

			headers.setCORSHeaders(rec, tt.origin)

			if tt.expectOrigin {
				assert.NotEmpty(t, rec.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}
