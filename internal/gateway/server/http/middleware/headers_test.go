package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestDefaultSecurityHeaders(t *testing.T) {
	config := DefaultSecurityHeaders()

	assert.Equal(t, "max-age=31536000; includeSubDomains", config.StrictTransportSecurity)
	assert.Equal(t, "nosniff", config.XContentTypeOptions)
	assert.Equal(t, "DENY", config.XFrameOptions)
	assert.Equal(t, "1; mode=block", config.XXSSProtection)
	assert.Equal(t, "strict-origin-when-cross-origin", config.ReferrerPolicy)
}

func TestHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                    string
		config                  HeadersConfig
		initialRequestHeaders   map[string]string
		expectedRequestHeaders  map[string]string
		expectedResponseHeaders map[string]string
	}{
		{
			name: "modify request headers - set",
			config: HeadersConfig{
				RequestHeaders: &HeaderModification{
					Set: map[string]string{
						"X-Custom-Header": "custom-value",
					},
				},
			},
			expectedRequestHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		},
		{
			name: "modify request headers - add",
			config: HeadersConfig{
				RequestHeaders: &HeaderModification{
					Add: map[string]string{
						"X-Added-Header": "added-value",
					},
				},
			},
			expectedRequestHeaders: map[string]string{
				"X-Added-Header": "added-value",
			},
		},
		{
			name: "modify request headers - remove",
			config: HeadersConfig{
				RequestHeaders: &HeaderModification{
					Remove: []string{"X-Remove-Me"},
				},
			},
			initialRequestHeaders: map[string]string{
				"X-Remove-Me": "should-be-removed",
			},
			expectedRequestHeaders: map[string]string{},
		},
		{
			name: "modify response headers - set",
			config: HeadersConfig{
				ResponseHeaders: &HeaderModification{
					Set: map[string]string{
						"X-Response-Header": "response-value",
					},
				},
			},
			expectedResponseHeaders: map[string]string{
				"X-Response-Header": "response-value",
			},
		},
		{
			name: "add security headers",
			config: HeadersConfig{
				SecurityHeaders: &SecurityHeadersConfig{
					XContentTypeOptions: "nosniff",
					XFrameOptions:       "DENY",
				},
			},
			expectedResponseHeaders: map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "DENY",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequestHeaders http.Header

			router := gin.New()
			router.Use(Headers(tt.config))
			router.GET("/test", func(c *gin.Context) {
				capturedRequestHeaders = c.Request.Header.Clone()
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.initialRequestHeaders {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			for k, v := range tt.expectedRequestHeaders {
				assert.Equal(t, v, capturedRequestHeaders.Get(k), "request header %s", k)
			}

			for k, v := range tt.expectedResponseHeaders {
				assert.Equal(t, v, w.Header().Get(k), "response header %s", k)
			}
		})
	}
}

func TestRequestHeaderModifier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modification := &HeaderModification{
		Set: map[string]string{
			"X-Set-Header": "set-value",
		},
		Add: map[string]string{
			"X-Add-Header": "add-value",
		},
		Remove: []string{"X-Remove-Header"},
	}

	var capturedHeaders http.Header

	router := gin.New()
	router.Use(RequestHeaderModifier(modification))
	router.GET("/test", func(c *gin.Context) {
		capturedHeaders = c.Request.Header.Clone()
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Remove-Header", "should-be-removed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "set-value", capturedHeaders.Get("X-Set-Header"))
	assert.Equal(t, "add-value", capturedHeaders.Get("X-Add-Header"))
	assert.Empty(t, capturedHeaders.Get("X-Remove-Header"))
}

func TestResponseHeaderModifier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modification := &HeaderModification{
		Set: map[string]string{
			"X-Set-Header": "set-value",
		},
		Add: map[string]string{
			"X-Add-Header": "add-value",
		},
		Remove: []string{"X-Remove-Header"},
	}

	router := gin.New()
	router.Use(ResponseHeaderModifier(modification))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Remove-Header", "should-be-removed")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "set-value", w.Header().Get("X-Set-Header"))
	assert.Equal(t, "add-value", w.Header().Get("X-Add-Header"))
	assert.Empty(t, w.Header().Get("X-Remove-Header"))
}

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "max-age=31536000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
}

func TestSecurityHeadersWithConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &SecurityHeadersConfig{
		StrictTransportSecurity: "max-age=86400",
		ContentSecurityPolicy:   "default-src 'self'",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "SAMEORIGIN",
		XXSSProtection:          "1",
		ReferrerPolicy:          "no-referrer",
		PermissionsPolicy:       "geolocation=()",
	}

	router := gin.New()
	router.Use(SecurityHeadersWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "max-age=86400", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "geolocation=()", w.Header().Get("Permissions-Policy"))
}

func TestSetHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SetHeader("X-Custom", "custom-value"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "custom-value", w.Header().Get("X-Custom"))
}

func TestAddHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(AddHeader("X-Custom", "value1"))
	router.Use(AddHeader("X-Custom", "value2"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	values := w.Header().Values("X-Custom")
	assert.Contains(t, values, "value1")
	assert.Contains(t, values, "value2")
}

func TestRemoveHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RemoveHeader("X-Remove-Me"))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Remove-Me", "should-be-removed")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("X-Remove-Me"))
}

func TestSetRequestHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedHeader string

	router := gin.New()
	router.Use(SetRequestHeader("X-Request-Header", "request-value"))
	router.GET("/test", func(c *gin.Context) {
		capturedHeader = c.Request.Header.Get("X-Request-Header")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "request-value", capturedHeader)
}

func TestAddRequestHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedHeaders []string

	router := gin.New()
	router.Use(AddRequestHeader("X-Request-Header", "value1"))
	router.Use(AddRequestHeader("X-Request-Header", "value2"))
	router.GET("/test", func(c *gin.Context) {
		capturedHeaders = c.Request.Header.Values("X-Request-Header")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Contains(t, capturedHeaders, "value1")
	assert.Contains(t, capturedHeaders, "value2")
}

func TestRemoveRequestHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedHeader string

	router := gin.New()
	router.Use(RemoveRequestHeader("X-Remove-Me"))
	router.GET("/test", func(c *gin.Context) {
		capturedHeader = c.Request.Header.Get("X-Remove-Me")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Remove-Me", "should-be-removed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Empty(t, capturedHeader)
}

func TestModifyRequestHeaders_NilModification(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not panic
	modifyRequestHeaders(c, nil)
}

func TestModifyResponseHeaders_NilModification(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not panic
	modifyResponseHeaders(c, nil)
}

func TestAddSecurityHeaders_NilConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not panic
	addSecurityHeaders(c, nil)
}

func TestHeaders_AllModifications(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := HeadersConfig{
		RequestHeaders: &HeaderModification{
			Set:    map[string]string{"X-Req-Set": "req-set"},
			Add:    map[string]string{"X-Req-Add": "req-add"},
			Remove: []string{"X-Req-Remove"},
		},
		ResponseHeaders: &HeaderModification{
			Set:    map[string]string{"X-Resp-Set": "resp-set"},
			Add:    map[string]string{"X-Resp-Add": "resp-add"},
			Remove: []string{"X-Resp-Remove"},
		},
		SecurityHeaders: &SecurityHeadersConfig{
			XContentTypeOptions: "nosniff",
		},
	}

	var capturedRequestHeaders http.Header

	router := gin.New()
	router.Use(Headers(config))
	router.GET("/test", func(c *gin.Context) {
		capturedRequestHeaders = c.Request.Header.Clone()
		c.Header("X-Resp-Remove", "should-be-removed")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Req-Remove", "should-be-removed")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Check request headers
	assert.Equal(t, "req-set", capturedRequestHeaders.Get("X-Req-Set"))
	assert.Equal(t, "req-add", capturedRequestHeaders.Get("X-Req-Add"))
	assert.Empty(t, capturedRequestHeaders.Get("X-Req-Remove"))

	// Check response headers
	assert.Equal(t, "resp-set", w.Header().Get("X-Resp-Set"))
	assert.Equal(t, "resp-add", w.Header().Get("X-Resp-Add"))
	assert.Empty(t, w.Header().Get("X-Resp-Remove"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}
