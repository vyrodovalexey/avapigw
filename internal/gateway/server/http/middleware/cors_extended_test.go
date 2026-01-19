package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestCORSContext_SetCommonHeaders tests the setCommonCORSHeaders method
func TestCORSContext_SetCommonHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                string
		config              CORSConfig
		origin              string
		expectedOrigin      string
		expectedCredentials string
		expectedExpose      string
	}{
		{
			name: "allow all origins without credentials",
			config: CORSConfig{
				AllowOrigins:     []string{"*"},
				AllowCredentials: false,
			},
			origin:         "http://example.com",
			expectedOrigin: "*",
		},
		{
			name: "allow all origins with credentials",
			config: CORSConfig{
				AllowOrigins:     []string{"*"},
				AllowCredentials: true,
			},
			origin:              "http://example.com",
			expectedOrigin:      "http://example.com",
			expectedCredentials: "true",
		},
		{
			name: "specific origin",
			config: CORSConfig{
				AllowOrigins:     []string{"http://example.com"},
				AllowCredentials: false,
			},
			origin:         "http://example.com",
			expectedOrigin: "http://example.com",
		},
		{
			name: "with expose headers",
			config: CORSConfig{
				AllowOrigins:  []string{"*"},
				ExposeHeaders: []string{"X-Custom-Header", "X-Another"},
			},
			origin:         "http://example.com",
			expectedOrigin: "*",
			expectedExpose: "X-Custom-Header, X-Another",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCORSContext(tt.config)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

			ctx.setCommonCORSHeaders(c, tt.origin)

			assert.Equal(t, tt.expectedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
			if tt.expectedCredentials != "" {
				assert.Equal(t, tt.expectedCredentials, w.Header().Get("Access-Control-Allow-Credentials"))
			}
			if tt.expectedExpose != "" {
				assert.Equal(t, tt.expectedExpose, w.Header().Get("Access-Control-Expose-Headers"))
			}
		})
	}
}

// TestCORSContext_SetPreflightHeaders tests the setPreflightHeaders method
func TestCORSContext_SetPreflightHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CORSConfig{
		AllowMethods: []string{"GET", "POST", "PUT"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:       3600,
	}

	ctx := newCORSContext(config)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodOptions, "/test", nil)

	ctx.setPreflightHeaders(c)

	assert.Equal(t, "GET, POST, PUT", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "3600", w.Header().Get("Access-Control-Max-Age"))
}

// TestNewCORSContext_Defaults tests default values in newCORSContext
func TestNewCORSContext_Defaults(t *testing.T) {
	tests := []struct {
		name           string
		config         CORSConfig
		expectAllowAll bool
	}{
		{
			name:           "empty origins uses default",
			config:         CORSConfig{},
			expectAllowAll: true,
		},
		{
			name: "empty methods uses default",
			config: CORSConfig{
				AllowOrigins: []string{"http://example.com"},
			},
			expectAllowAll: false,
		},
		{
			name: "empty headers uses default",
			config: CORSConfig{
				AllowOrigins: []string{"http://example.com"},
				AllowMethods: []string{"GET"},
			},
			expectAllowAll: false,
		},
		{
			name: "wildcard in origins",
			config: CORSConfig{
				AllowOrigins: []string{"http://example.com", "*"},
			},
			expectAllowAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCORSContext(tt.config)
			assert.Equal(t, tt.expectAllowAll, ctx.allowAllOrigins)
		})
	}
}

// TestIsOriginAllowed_WildcardPatterns tests wildcard pattern matching
func TestIsOriginAllowed_WildcardPatterns(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		allowWildcard  bool
		expected       bool
	}{
		{
			name:           "exact match",
			origin:         "http://example.com",
			allowedOrigins: []string{"http://example.com"},
			allowWildcard:  false,
			expected:       true,
		},
		{
			name:           "no match",
			origin:         "http://other.com",
			allowedOrigins: []string{"http://example.com"},
			allowWildcard:  false,
			expected:       false,
		},
		{
			name:           "wildcard suffix match",
			origin:         "http://sub.example.com",
			allowedOrigins: []string{"*.example.com"},
			allowWildcard:  true,
			expected:       true,
		},
		{
			name:           "wildcard prefix match",
			origin:         "http://example.org",
			allowedOrigins: []string{"http://example.*"},
			allowWildcard:  true,
			expected:       true,
		},
		{
			name:           "wildcard disabled",
			origin:         "http://sub.example.com",
			allowedOrigins: []string{"*.example.com"},
			allowWildcard:  false,
			expected:       false,
		},
		{
			name:           "multiple origins first match",
			origin:         "http://first.com",
			allowedOrigins: []string{"http://first.com", "http://second.com"},
			allowWildcard:  false,
			expected:       true,
		},
		{
			name:           "multiple origins second match",
			origin:         "http://second.com",
			allowedOrigins: []string{"http://first.com", "http://second.com"},
			allowWildcard:  false,
			expected:       true,
		},
		{
			name:           "wildcard suffix no match",
			origin:         "http://other.org",
			allowedOrigins: []string{"*.example.com"},
			allowWildcard:  true,
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOriginAllowed(tt.origin, tt.allowedOrigins, tt.allowWildcard)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCORSWithConfig_NotAllowedOrigin tests CORS with not allowed origin
func TestCORSWithConfig_NotAllowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CORSConfig{
		AllowOrigins: []string{"http://allowed.com"},
	}

	router := gin.New()
	router.Use(CORSWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://notallowed.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Request should still succeed, but no CORS headers
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORSWithConfig_PreflightNotAllowed tests preflight with not allowed origin
func TestCORSWithConfig_PreflightNotAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CORSConfig{
		AllowOrigins: []string{"http://allowed.com"},
	}

	router := gin.New()
	router.Use(CORSWithConfig(config))
	router.OPTIONS("/test", func(c *gin.Context) {})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "http://notallowed.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// No CORS headers for not allowed origin
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// TestAllowOrigins_WithCredentials tests AllowOrigins helper with credentials
func TestAllowOrigins_WithCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(AllowOrigins("http://example.com"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORS_MultipleOrigins tests CORS with multiple allowed origins
func TestCORS_MultipleOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CORSConfig{
		AllowOrigins: []string{"http://first.com", "http://second.com", "http://third.com"},
	}

	router := gin.New()
	router.Use(CORSWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	origins := []struct {
		origin   string
		expected string
	}{
		{"http://first.com", "http://first.com"},
		{"http://second.com", "http://second.com"},
		{"http://third.com", "http://third.com"},
		{"http://fourth.com", ""},
	}

	for _, o := range origins {
		t.Run(o.origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", o.origin)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, o.expected, w.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}
