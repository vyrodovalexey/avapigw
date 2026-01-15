package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestDefaultCORSConfig(t *testing.T) {
	config := DefaultCORSConfig()

	assert.Equal(t, []string{"*"}, config.AllowOrigins)
	assert.Contains(t, config.AllowMethods, "GET")
	assert.Contains(t, config.AllowMethods, "POST")
	assert.Contains(t, config.AllowMethods, "PUT")
	assert.Contains(t, config.AllowMethods, "DELETE")
	assert.Contains(t, config.AllowHeaders, "Authorization")
	assert.False(t, config.AllowCredentials)
	assert.Equal(t, 86400, config.MaxAge)
}

func TestCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CORS())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
		expectedStatus int
	}{
		{
			name:           "with origin header",
			origin:         "http://example.com",
			expectedOrigin: "*",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "without origin header",
			origin:         "",
			expectedOrigin: "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedOrigin != "" {
				assert.Equal(t, tt.expectedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestCORSWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                  string
		config                CORSConfig
		origin                string
		method                string
		expectedOrigin        string
		expectedCredentials   string
		expectedExposeHeaders string
		expectedStatus        int
		expectedAllowMethods  string
		expectedAllowHeaders  string
		expectedMaxAge        string
	}{
		{
			name: "allow all origins",
			config: CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
				AllowHeaders: []string{"Content-Type"},
			},
			origin:         "http://example.com",
			method:         http.MethodGet,
			expectedOrigin: "*",
			expectedStatus: http.StatusOK,
		},
		{
			name: "specific origin allowed",
			config: CORSConfig{
				AllowOrigins: []string{"http://example.com"},
				AllowMethods: []string{"GET", "POST"},
				AllowHeaders: []string{"Content-Type"},
			},
			origin:         "http://example.com",
			method:         http.MethodGet,
			expectedOrigin: "http://example.com",
			expectedStatus: http.StatusOK,
		},
		{
			name: "specific origin not allowed",
			config: CORSConfig{
				AllowOrigins: []string{"http://allowed.com"},
				AllowMethods: []string{"GET", "POST"},
				AllowHeaders: []string{"Content-Type"},
			},
			origin:         "http://notallowed.com",
			method:         http.MethodGet,
			expectedOrigin: "",
			expectedStatus: http.StatusOK,
		},
		{
			name: "with credentials",
			config: CORSConfig{
				AllowOrigins:     []string{"http://example.com"},
				AllowMethods:     []string{"GET", "POST"},
				AllowHeaders:     []string{"Content-Type"},
				AllowCredentials: true,
			},
			origin:              "http://example.com",
			method:              http.MethodGet,
			expectedOrigin:      "http://example.com",
			expectedCredentials: "true",
			expectedStatus:      http.StatusOK,
		},
		{
			name: "with expose headers",
			config: CORSConfig{
				AllowOrigins:  []string{"*"},
				AllowMethods:  []string{"GET"},
				AllowHeaders:  []string{"Content-Type"},
				ExposeHeaders: []string{"X-Custom-Header", "X-Another-Header"},
			},
			origin:                "http://example.com",
			method:                http.MethodGet,
			expectedOrigin:        "*",
			expectedExposeHeaders: "X-Custom-Header, X-Another-Header",
			expectedStatus:        http.StatusOK,
		},
		{
			name: "preflight request",
			config: CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST", "PUT"},
				AllowHeaders: []string{"Content-Type", "Authorization"},
				MaxAge:       3600,
			},
			origin:               "http://example.com",
			method:               http.MethodOptions,
			expectedOrigin:       "*",
			expectedAllowMethods: "GET, POST, PUT",
			expectedAllowHeaders: "Content-Type, Authorization",
			expectedMaxAge:       "3600",
			expectedStatus:       http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CORSWithConfig(tt.config))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})
			router.OPTIONS("/test", func(c *gin.Context) {
				// This won't be reached for preflight as CORS middleware handles it
			})

			req := httptest.NewRequest(tt.method, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedOrigin != "" {
				assert.Equal(t, tt.expectedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
			}
			if tt.expectedCredentials != "" {
				assert.Equal(t, tt.expectedCredentials, w.Header().Get("Access-Control-Allow-Credentials"))
			}
			if tt.expectedExposeHeaders != "" {
				assert.Equal(t, tt.expectedExposeHeaders, w.Header().Get("Access-Control-Expose-Headers"))
			}
			if tt.expectedAllowMethods != "" {
				assert.Equal(t, tt.expectedAllowMethods, w.Header().Get("Access-Control-Allow-Methods"))
			}
			if tt.expectedAllowHeaders != "" {
				assert.Equal(t, tt.expectedAllowHeaders, w.Header().Get("Access-Control-Allow-Headers"))
			}
			if tt.expectedMaxAge != "" {
				assert.Equal(t, tt.expectedMaxAge, w.Header().Get("Access-Control-Max-Age"))
			}
		})
	}
}

func TestCORSWithConfig_EmptyConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CORSWithConfig(CORSConfig{}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSWithConfig_WildcardOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		allowedOrigins []string
		origin         string
		allowWildcard  bool
		expectedMatch  bool
	}{
		{
			name:           "wildcard suffix match",
			allowedOrigins: []string{"*.example.com"},
			origin:         "http://sub.example.com",
			allowWildcard:  true,
			expectedMatch:  true,
		},
		{
			name:           "wildcard prefix match",
			allowedOrigins: []string{"http://example.*"},
			origin:         "http://example.com",
			allowWildcard:  true,
			expectedMatch:  true,
		},
		{
			name:           "wildcard disabled",
			allowedOrigins: []string{"*.example.com"},
			origin:         "http://sub.example.com",
			allowWildcard:  false,
			expectedMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CORSWithConfig(CORSConfig{
				AllowOrigins:  tt.allowedOrigins,
				AllowWildcard: tt.allowWildcard,
			}))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tt.expectedMatch {
				assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
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
			name:           "wildcard suffix",
			origin:         "http://sub.example.com",
			allowedOrigins: []string{"*.example.com"},
			allowWildcard:  true,
			expected:       true,
		},
		{
			name:           "wildcard prefix",
			origin:         "http://example.org",
			allowedOrigins: []string{"http://example.*"},
			allowWildcard:  true,
			expected:       true,
		},
		{
			name:           "empty allowed origins",
			origin:         "http://example.com",
			allowedOrigins: []string{},
			allowWildcard:  false,
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

func TestAllowAllOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(AllowAllOrigins())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestAllowOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(AllowOrigins("http://allowed1.com", "http://allowed2.com"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{
			name:           "first allowed origin",
			origin:         "http://allowed1.com",
			expectedOrigin: "http://allowed1.com",
		},
		{
			name:           "second allowed origin",
			origin:         "http://allowed2.com",
			expectedOrigin: "http://allowed2.com",
		},
		{
			name:           "not allowed origin",
			origin:         "http://notallowed.com",
			expectedOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tt.expectedOrigin != "" {
				assert.Equal(t, tt.expectedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
			} else {
				assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestCORS_PreflightRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CORSWithConfig(CORSConfig{
		AllowOrigins: []string{"http://example.com"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders: []string{"Content-Type", "Authorization", "X-Custom-Header"},
		MaxAge:       7200,
	}))
	router.OPTIONS("/test", func(c *gin.Context) {})
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, DELETE", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization, X-Custom-Header", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "7200", w.Header().Get("Access-Control-Max-Age"))
}

func TestCORS_NoOriginHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CORS())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No Origin header
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_CredentialsWithWildcard(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// When credentials are allowed and origin is *, should return the actual origin
	router := gin.New()
	router.Use(CORSWithConfig(CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// When credentials are true, should return the actual origin, not *
	assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}
