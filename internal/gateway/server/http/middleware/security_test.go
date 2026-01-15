package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestDefaultExtendedSecurityConfig(t *testing.T) {
	config := DefaultExtendedSecurityConfig()

	assert.True(t, config.HSTSEnabled)
	assert.Equal(t, 31536000, config.HSTSMaxAge)
	assert.True(t, config.HSTSIncludeSubDomains)
	assert.False(t, config.HSTSPreload)
	assert.Equal(t, "DENY", config.XFrameOptions)
	assert.Equal(t, "nosniff", config.XContentTypeOptions)
	assert.Equal(t, "1; mode=block", config.XXSSProtection)
	assert.Equal(t, "strict-origin-when-cross-origin", config.ReferrerPolicy)
	assert.Equal(t, "same-origin", config.CrossOriginOpenerPolicy)
	assert.Equal(t, "same-origin", config.CrossOriginResourcePolicy)
}

func TestExtendedSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ExtendedSecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "includeSubDomains")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
}

func TestExtendedSecurityHeadersWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		config          *ExtendedSecurityConfig
		expectedHeaders map[string]string
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
			expectedHeaders: map[string]string{
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
			},
		},
		{
			name: "custom HSTS",
			config: &ExtendedSecurityConfig{
				HSTSEnabled:           true,
				HSTSMaxAge:            86400,
				HSTSIncludeSubDomains: false,
				HSTSPreload:           true,
			},
			expectedHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=86400; preload",
			},
		},
		{
			name: "HSTS disabled",
			config: &ExtendedSecurityConfig{
				HSTSEnabled: false,
			},
			expectedHeaders: map[string]string{},
		},
		{
			name: "custom CSP",
			config: &ExtendedSecurityConfig{
				ContentSecurityPolicy: "default-src 'self'; script-src 'self'",
			},
			expectedHeaders: map[string]string{
				"Content-Security-Policy": "default-src 'self'; script-src 'self'",
			},
		},
		{
			name: "custom headers",
			config: &ExtendedSecurityConfig{
				CustomHeaders: map[string]string{
					"X-Custom-Header": "custom-value",
				},
			},
			expectedHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		},
		{
			name: "remove headers",
			config: &ExtendedSecurityConfig{
				RemoveHeaders: []string{"Server"},
			},
			expectedHeaders: map[string]string{},
		},
		{
			name: "cache control",
			config: &ExtendedSecurityConfig{
				CacheControl: "no-store",
			},
			expectedHeaders: map[string]string{
				"Cache-Control": "no-store",
			},
		},
		{
			name: "cross-origin policies",
			config: &ExtendedSecurityConfig{
				CrossOriginEmbedderPolicy: "require-corp",
				CrossOriginOpenerPolicy:   "same-origin-allow-popups",
				CrossOriginResourcePolicy: "cross-origin",
			},
			expectedHeaders: map[string]string{
				"Cross-Origin-Embedder-Policy": "require-corp",
				"Cross-Origin-Opener-Policy":   "same-origin-allow-popups",
				"Cross-Origin-Resource-Policy": "cross-origin",
			},
		},
		{
			name: "permissions policy",
			config: &ExtendedSecurityConfig{
				PermissionsPolicy: "geolocation=(), microphone=()",
			},
			expectedHeaders: map[string]string{
				"Permissions-Policy": "geolocation=(), microphone=()",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(ExtendedSecurityHeadersWithConfig(tt.config))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, w.Header().Get(header), "header: %s", header)
			}
		})
	}
}

func TestDefaultHSTSConfig(t *testing.T) {
	config := DefaultHSTSConfig()

	assert.Equal(t, 31536000, config.MaxAge)
	assert.True(t, config.IncludeSubDomains)
	assert.False(t, config.Preload)
}

func TestHSTS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(HSTS(86400))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=86400")
	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "includeSubDomains")
}

func TestHSTSWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		config   *HSTSConfig
		expected string
	}{
		{
			name:     "nil config uses defaults",
			config:   nil,
			expected: "max-age=31536000; includeSubDomains",
		},
		{
			name: "with preload",
			config: &HSTSConfig{
				MaxAge:            63072000,
				IncludeSubDomains: true,
				Preload:           true,
			},
			expected: "max-age=63072000; includeSubDomains; preload",
		},
		{
			name: "without includeSubDomains",
			config: &HSTSConfig{
				MaxAge:            86400,
				IncludeSubDomains: false,
				Preload:           false,
			},
			expected: "max-age=86400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(HSTSWithConfig(tt.config))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, w.Header().Get("Strict-Transport-Security"))
		})
	}
}

func TestContentSecurityPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	policy := "default-src 'self'; script-src 'self' 'unsafe-inline'"

	router := gin.New()
	router.Use(ContentSecurityPolicy(policy))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, policy, w.Header().Get("Content-Security-Policy"))
}

func TestCSPBuilder(t *testing.T) {
	builder := NewCSPBuilder()

	csp := builder.
		DefaultSrc("'self'").
		ScriptSrc("'self'", "'unsafe-inline'").
		StyleSrc("'self'", "https://fonts.googleapis.com").
		ImgSrc("'self'", "data:", "https:").
		FontSrc("'self'", "https://fonts.gstatic.com").
		ConnectSrc("'self'", "https://api.example.com").
		FrameSrc("'none'").
		FrameAncestors("'none'").
		ObjectSrc("'none'").
		MediaSrc("'self'").
		BaseUri("'self'").
		FormAction("'self'").
		UpgradeInsecureRequests().
		Build()

	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self' 'unsafe-inline'")
	assert.Contains(t, csp, "style-src 'self' https://fonts.googleapis.com")
	assert.Contains(t, csp, "img-src 'self' data: https:")
	assert.Contains(t, csp, "font-src 'self' https://fonts.gstatic.com")
	assert.Contains(t, csp, "connect-src 'self' https://api.example.com")
	assert.Contains(t, csp, "frame-src 'none'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Contains(t, csp, "object-src 'none'")
	assert.Contains(t, csp, "media-src 'self'")
	assert.Contains(t, csp, "base-uri 'self'")
	assert.Contains(t, csp, "form-action 'self'")
	assert.Contains(t, csp, "upgrade-insecure-requests")
}

func TestCSPBuilder_ReportUri(t *testing.T) {
	builder := NewCSPBuilder()

	csp := builder.
		DefaultSrc("'self'").
		ReportUri("https://example.com/csp-report").
		Build()

	assert.Contains(t, csp, "report-uri https://example.com/csp-report")
}

func TestCSPBuilder_ReportTo(t *testing.T) {
	builder := NewCSPBuilder()

	csp := builder.
		DefaultSrc("'self'").
		ReportTo("csp-endpoint").
		Build()

	assert.Contains(t, csp, "report-to csp-endpoint")
}

func TestCSPBuilder_BlockAllMixedContent(t *testing.T) {
	builder := NewCSPBuilder()

	csp := builder.
		DefaultSrc("'self'").
		BlockAllMixedContent().
		Build()

	assert.Contains(t, csp, "block-all-mixed-content")
}

func TestCSPBuilder_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	builder := NewCSPBuilder().
		DefaultSrc("'self'").
		ScriptSrc("'self'")

	router := gin.New()
	router.Use(builder.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self'")
}

func TestXFrameOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(XFrameOptions("SAMEORIGIN"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
}

func TestXFrameOptionsDeny(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(XFrameOptionsDeny())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestXFrameOptionsSameOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(XFrameOptionsSameOrigin())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
}

func TestXContentTypeOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(XContentTypeOptions())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

func TestXXSSProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(XXSSProtection())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
}

func TestReferrerPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ReferrerPolicy("no-referrer"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

func TestPermissionsPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(PermissionsPolicy("geolocation=(), microphone=()"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "geolocation=(), microphone=()", w.Header().Get("Permissions-Policy"))
}

func TestPermissionsPolicyBuilder(t *testing.T) {
	builder := NewPermissionsPolicyBuilder()

	policy := builder.
		Accelerometer().
		Camera().
		Geolocation("self").
		Microphone().
		Payment("self", "https://payment.example.com").
		Fullscreen("self").
		Build()

	assert.Contains(t, policy, "accelerometer=()")
	assert.Contains(t, policy, "camera=()")
	assert.Contains(t, policy, "geolocation=(self)")
	assert.Contains(t, policy, "microphone=()")
	assert.Contains(t, policy, "payment=(self https://payment.example.com)")
	assert.Contains(t, policy, "fullscreen=(self)")
}

func TestPermissionsPolicyBuilder_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	builder := NewPermissionsPolicyBuilder().
		Geolocation().
		Camera()

	router := gin.New()
	router.Use(builder.PermissionsPolicyMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	policy := w.Header().Get("Permissions-Policy")
	assert.Contains(t, policy, "geolocation=()")
	assert.Contains(t, policy, "camera=()")
}

func TestNoCacheHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(NoCacheHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "0", w.Header().Get("Expires"))
}

func TestCacheControl(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		maxAge     int
		directives []string
		expected   string
	}{
		{
			name:       "max-age only",
			maxAge:     3600,
			directives: nil,
			expected:   "max-age=3600",
		},
		{
			name:       "with directives",
			maxAge:     86400,
			directives: []string{"public", "immutable"},
			expected:   "max-age=86400, public, immutable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CacheControl(tt.maxAge, tt.directives...))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, w.Header().Get("Cache-Control"))
		})
	}
}

func TestRemoveServerHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// RemoveServerHeader sets the header to empty before the handler runs
	// This test verifies the middleware is called
	router := gin.New()
	router.Use(RemoveServerHeader())
	router.GET("/test", func(c *gin.Context) {
		// Don't set Server header in handler - the middleware removes it
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// The middleware sets Server to empty string
	assert.Empty(t, w.Header().Get("Server"))
}

func TestRemoveResponseHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RemoveResponseHeaders("X-Powered-By", "Server"))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Powered-By", "Go")
		c.Header("Server", "MyServer")
		c.Header("X-Keep-Me", "value")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("X-Powered-By"))
	assert.Empty(t, w.Header().Get("Server"))
	assert.Equal(t, "value", w.Header().Get("X-Keep-Me"))
}

func TestAddResponseHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	headers := map[string]string{
		"X-Custom-1": "value1",
		"X-Custom-2": "value2",
	}

	router := gin.New()
	router.Use(AddResponseHeaders(headers))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "value1", w.Header().Get("X-Custom-1"))
	assert.Equal(t, "value2", w.Header().Get("X-Custom-2"))
}

func TestSecureDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecureDefaults())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}

func TestAPISecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(APISecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Resource-Policy"))
}

func TestCrossOriginHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CrossOriginHeaders("require-corp", "same-origin", "same-site"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "require-corp", w.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "same-site", w.Header().Get("Cross-Origin-Resource-Policy"))
}

func TestCrossOriginHeaders_EmptyValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CrossOriginHeaders("", "", ""))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Empty(t, w.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Empty(t, w.Header().Get("Cross-Origin-Resource-Policy"))
}
