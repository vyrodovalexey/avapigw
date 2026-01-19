package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestHeaders_NilConfigs tests Headers middleware with nil configurations
func TestHeaders_NilConfigs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := HeadersConfig{
		RequestHeaders:  nil,
		ResponseHeaders: nil,
		SecurityHeaders: nil,
	}

	router := gin.New()
	router.Use(Headers(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestHeaders_ComplexModifications tests complex header modifications
func TestHeaders_ComplexModifications(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := HeadersConfig{
		RequestHeaders: &HeaderModification{
			Set: map[string]string{
				"X-Request-ID":    "generated-id",
				"X-Forwarded-For": "10.0.0.1",
			},
			Add: map[string]string{
				"X-Custom-Header": "custom-value",
			},
			Remove: []string{"X-Sensitive-Header"},
		},
		ResponseHeaders: &HeaderModification{
			Set: map[string]string{
				"X-Response-Time": "100ms",
			},
			Add: map[string]string{
				"X-Server": "api-gateway",
			},
			Remove: []string{"Server", "X-Powered-By"},
		},
		SecurityHeaders: &SecurityHeadersConfig{
			StrictTransportSecurity: "max-age=31536000",
			XContentTypeOptions:     "nosniff",
			XFrameOptions:           "DENY",
		},
	}

	var capturedRequestHeaders http.Header

	router := gin.New()
	router.Use(Headers(config))
	router.GET("/test", func(c *gin.Context) {
		capturedRequestHeaders = c.Request.Header.Clone()
		c.Header("Server", "nginx")
		c.Header("X-Powered-By", "Go")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Sensitive-Header", "secret")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Check request headers
	assert.Equal(t, "generated-id", capturedRequestHeaders.Get("X-Request-ID"))
	assert.Equal(t, "10.0.0.1", capturedRequestHeaders.Get("X-Forwarded-For"))
	assert.Equal(t, "custom-value", capturedRequestHeaders.Get("X-Custom-Header"))
	assert.Empty(t, capturedRequestHeaders.Get("X-Sensitive-Header"))

	// Check response headers
	assert.Equal(t, "100ms", w.Header().Get("X-Response-Time"))
	assert.Equal(t, "api-gateway", w.Header().Get("X-Server"))
	assert.Empty(t, w.Header().Get("Server"))
	assert.Empty(t, w.Header().Get("X-Powered-By"))

	// Check security headers
	assert.Equal(t, "max-age=31536000", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

// TestRequestHeaderModifier_EmptyModification tests empty modification
func TestRequestHeaderModifier_EmptyModification(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modification := &HeaderModification{}

	router := gin.New()
	router.Use(RequestHeaderModifier(modification))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Original", "value")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResponseHeaderModifier_EmptyModification tests empty modification
func TestResponseHeaderModifier_EmptyModification(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modification := &HeaderModification{}

	router := gin.New()
	router.Use(ResponseHeaderModifier(modification))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Original", "value")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "value", w.Header().Get("X-Original"))
}

// TestSecurityHeadersWithConfig_AllHeaders tests all security headers
func TestSecurityHeadersWithConfig_AllHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &SecurityHeadersConfig{
		StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
		ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline'",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "SAMEORIGIN",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "geolocation=(), microphone=()",
	}

	router := gin.New()
	router.Use(SecurityHeadersWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "max-age=31536000; includeSubDomains; preload", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "default-src 'self'; script-src 'self' 'unsafe-inline'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "geolocation=(), microphone=()", w.Header().Get("Permissions-Policy"))
}

// TestSecurityHeadersWithConfig_EmptyValues tests empty security header values
func TestSecurityHeadersWithConfig_EmptyValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &SecurityHeadersConfig{
		// All empty
	}

	router := gin.New()
	router.Use(SecurityHeadersWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
	assert.Empty(t, w.Header().Get("Content-Security-Policy"))
	assert.Empty(t, w.Header().Get("X-Content-Type-Options"))
	assert.Empty(t, w.Header().Get("X-Frame-Options"))
	assert.Empty(t, w.Header().Get("X-XSS-Protection"))
	assert.Empty(t, w.Header().Get("Referrer-Policy"))
	assert.Empty(t, w.Header().Get("Permissions-Policy"))
}

// TestSetHeader_Overwrite tests SetHeader overwrites existing header
func TestSetHeader_Overwrite(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SetHeader("X-Custom", "new-value"))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Custom", "old-value")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// SetHeader runs after handler, so it should overwrite
	assert.Equal(t, "new-value", w.Header().Get("X-Custom"))
}

// TestAddHeader_Multiple tests AddHeader adds multiple values
func TestAddHeader_Multiple(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(AddHeader("X-Custom", "value1"))
	router.Use(AddHeader("X-Custom", "value2"))
	router.Use(AddHeader("X-Custom", "value3"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	values := w.Header().Values("X-Custom")
	assert.Len(t, values, 3)
	assert.Contains(t, values, "value1")
	assert.Contains(t, values, "value2")
	assert.Contains(t, values, "value3")
}

// TestRemoveHeader_NonExistent tests RemoveHeader with non-existent header
func TestRemoveHeader_NonExistent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RemoveHeader("X-Non-Existent"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetRequestHeader_Overwrite tests SetRequestHeader overwrites existing header
func TestSetRequestHeader_Overwrite(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedHeader string

	router := gin.New()
	router.Use(SetRequestHeader("X-Custom", "new-value"))
	router.GET("/test", func(c *gin.Context) {
		capturedHeader = c.Request.Header.Get("X-Custom")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom", "old-value")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, "new-value", capturedHeader)
}

// TestAddRequestHeader_Multiple tests AddRequestHeader adds multiple values
func TestAddRequestHeader_Multiple(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedHeaders []string

	router := gin.New()
	router.Use(AddRequestHeader("X-Custom", "value1"))
	router.Use(AddRequestHeader("X-Custom", "value2"))
	router.GET("/test", func(c *gin.Context) {
		capturedHeaders = c.Request.Header.Values("X-Custom")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Len(t, capturedHeaders, 2)
	assert.Contains(t, capturedHeaders, "value1")
	assert.Contains(t, capturedHeaders, "value2")
}

// TestRemoveRequestHeader_NonExistent tests RemoveRequestHeader with non-existent header
func TestRemoveRequestHeader_NonExistent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RemoveRequestHeader("X-Non-Existent"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestModifyRequestHeaders_OrderOfOperations tests order of operations
func TestModifyRequestHeaders_OrderOfOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Order: Remove -> Set -> Add
	modification := &HeaderModification{
		Remove: []string{"X-Header"},
		Set:    map[string]string{"X-Header": "set-value"},
		Add:    map[string]string{"X-Header": "add-value"},
	}

	var capturedHeaders []string

	router := gin.New()
	router.Use(RequestHeaderModifier(modification))
	router.GET("/test", func(c *gin.Context) {
		capturedHeaders = c.Request.Header.Values("X-Header")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Header", "original-value")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Remove first, then Set, then Add
	// So we should have set-value and add-value
	assert.Contains(t, capturedHeaders, "set-value")
	assert.Contains(t, capturedHeaders, "add-value")
	assert.NotContains(t, capturedHeaders, "original-value")
}

// TestModifyResponseHeaders_OrderOfOperations tests order of operations
func TestModifyResponseHeaders_OrderOfOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modification := &HeaderModification{
		Remove: []string{"X-Header"},
		Set:    map[string]string{"X-Header": "set-value"},
		Add:    map[string]string{"X-Header": "add-value"},
	}

	router := gin.New()
	router.Use(ResponseHeaderModifier(modification))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Header", "original-value")
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	values := w.Header().Values("X-Header")
	assert.Contains(t, values, "set-value")
	assert.Contains(t, values, "add-value")
}
