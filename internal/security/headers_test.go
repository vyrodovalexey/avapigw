package security

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewHeadersMiddleware(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	middleware := NewHeadersMiddleware(config)

	assert.NotNil(t, middleware)
}

func TestNewHeadersMiddleware_WithOptions(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	logger := observability.NopLogger()

	middleware := NewHeadersMiddleware(config, WithHeadersLogger(logger))

	assert.NotNil(t, middleware)
}

func TestHeadersMiddleware_Handler_Disabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: false,
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// No security headers should be added when disabled
	assert.Empty(t, rec.Header().Get("X-Frame-Options"))
	assert.Empty(t, rec.Header().Get("X-Content-Type-Options"))
}

func TestHeadersMiddleware_Handler_BasicHeaders(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Headers: &HeadersConfig{
			Enabled:             true,
			XFrameOptions:       "DENY",
			XContentTypeOptions: "nosniff",
			XXSSProtection:      "1; mode=block",
			CacheControl:        "no-store",
			Pragma:              "no-cache",
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", rec.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

func TestHeadersMiddleware_Handler_CustomHeaders(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Headers: &HeadersConfig{
			Enabled: true,
			CustomHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
				"X-Another":       "another-value",
			},
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "custom-value", rec.Header().Get("X-Custom-Header"))
	assert.Equal(t, "another-value", rec.Header().Get("X-Another"))
}

func TestHeadersMiddleware_Handler_HSTS_HTTPS(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		HSTS: &HSTSConfig{
			Enabled:           true,
			MaxAge:            31536000,
			IncludeSubDomains: true,
			Preload:           true,
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// HTTPS request (via TLS)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{} // Simulate HTTPS
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	assert.Contains(t, hsts, "max-age=31536000")
	assert.Contains(t, hsts, "includeSubDomains")
	assert.Contains(t, hsts, "preload")
}

func TestHeadersMiddleware_Handler_HSTS_HTTP(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		HSTS: &HSTSConfig{
			Enabled: true,
			MaxAge:  31536000,
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// HTTP request (no TLS)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// HSTS should not be added for HTTP
	assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestHeadersMiddleware_Handler_HSTS_XForwardedProto(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		HSTS: &HSTSConfig{
			Enabled: true,
			MaxAge:  31536000,
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// HTTP request with X-Forwarded-Proto: https
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// HSTS should be added when X-Forwarded-Proto is https
	assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestHeadersMiddleware_Handler_CSP_Policy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled: true,
			Policy:  "default-src 'self'; script-src 'self' 'unsafe-inline'",
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self' 'unsafe-inline'")
}

func TestHeadersMiddleware_Handler_CSP_Directives(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled: true,
			Directives: &CSPDirectives{
				DefaultSrc:              []string{"'self'"},
				ScriptSrc:               []string{"'self'", "https://cdn.example.com"},
				StyleSrc:                []string{"'self'", "'unsafe-inline'"},
				ImgSrc:                  []string{"'self'", "data:", "https:"},
				FontSrc:                 []string{"'self'"},
				ConnectSrc:              []string{"'self'", "https://api.example.com"},
				FrameAncestors:          []string{"'none'"},
				UpgradeInsecureRequests: true,
			},
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self' https://cdn.example.com")
	assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'")
	assert.Contains(t, csp, "img-src 'self' data: https:")
	assert.Contains(t, csp, "font-src 'self'")
	assert.Contains(t, csp, "connect-src 'self' https://api.example.com")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Contains(t, csp, "upgrade-insecure-requests")
}

func TestHeadersMiddleware_Handler_CSP_ReportOnly(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled:    true,
			Policy:     "default-src 'self'",
			ReportOnly: true,
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should use Report-Only header
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy-Report-Only"))
	assert.Empty(t, rec.Header().Get("Content-Security-Policy"))
}

func TestHeadersMiddleware_Handler_CSP_ReportURI(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled:   true,
			Policy:    "default-src 'self'",
			ReportURI: "https://example.com/csp-report",
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "report-uri https://example.com/csp-report")
}

func TestHeadersMiddleware_Handler_PermissionsPolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		PermissionsPolicy: &PermissionsPolicyConfig{
			Enabled: true,
			Features: map[string][]string{
				"geolocation": {},
				"camera":      {"self"},
				"microphone":  {"self", "https://example.com"},
			},
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	pp := rec.Header().Get("Permissions-Policy")
	assert.Contains(t, pp, "geolocation=()")
	assert.Contains(t, pp, "camera=(self)")
	assert.Contains(t, pp, "microphone=(self https://example.com)")
}

func TestHeadersMiddleware_Handler_PermissionsPolicy_String(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		PermissionsPolicy: &PermissionsPolicyConfig{
			Enabled: true,
			Policy:  "geolocation=(), camera=(self)",
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	pp := rec.Header().Get("Permissions-Policy")
	assert.Equal(t, "geolocation=(), camera=(self)", pp)
}

func TestHeadersMiddleware_Handler_ReferrerPolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:        true,
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
}

func TestHeadersMiddleware_Handler_CrossOriginPolicies(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:                   true,
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginResourcePolicy: "same-origin",
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "same-origin", rec.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "require-corp", rec.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
}

func TestHeadersMiddleware_Handler_RemoveHeaders(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Headers: &HeadersConfig{
			Enabled:       true,
			RemoveHeaders: []string{"Server", "X-Powered-By"},
		},
	}

	middleware := NewHeadersMiddleware(config)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache")
		w.Header().Set("X-Powered-By", "PHP")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// These headers should be removed
	assert.Empty(t, rec.Header().Get("Server"))
	assert.Empty(t, rec.Header().Get("X-Powered-By"))
	// This header should remain
	assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
}

func TestIsSecureRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected bool
	}{
		{
			name: "TLS connection",
			setup: func(r *http.Request) {
				r.TLS = &tls.ConnectionState{}
			},
			expected: true,
		},
		{
			name: "X-Forwarded-Proto https",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
			},
			expected: true,
		},
		{
			name: "HTTPS scheme",
			setup: func(r *http.Request) {
				r.URL.Scheme = "https"
			},
			expected: true,
		},
		{
			name: "HTTP request",
			setup: func(r *http.Request) {
				// No TLS, no X-Forwarded-Proto, HTTP scheme
			},
			expected: false,
		},
		{
			name: "X-Forwarded-Proto http",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "http")
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
			tt.setup(req)

			result := isSecureRequest(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHeaderRemovingResponseWriter(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	wrapped := &headerRemovingResponseWriter{
		ResponseWriter: rec,
		removeHeaders:  []string{"Server", "X-Powered-By"},
	}

	// Set headers
	wrapped.Header().Set("Server", "Apache")
	wrapped.Header().Set("X-Powered-By", "PHP")
	wrapped.Header().Set("Content-Type", "text/plain")

	// Write header
	wrapped.WriteHeader(http.StatusOK)

	// Headers should be removed
	assert.Empty(t, rec.Header().Get("Server"))
	assert.Empty(t, rec.Header().Get("X-Powered-By"))
	assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
}

func TestHeaderRemovingResponseWriter_Write(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	wrapped := &headerRemovingResponseWriter{
		ResponseWriter: rec,
		removeHeaders:  []string{"Server"},
	}

	wrapped.Header().Set("Server", "Apache")

	// Write without calling WriteHeader
	n, err := wrapped.Write([]byte("Hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)

	// Server header should be removed
	assert.Empty(t, rec.Header().Get("Server"))
}

func TestHeaderRemovingResponseWriter_Unwrap(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	wrapped := &headerRemovingResponseWriter{
		ResponseWriter: rec,
	}

	assert.Equal(t, rec, wrapped.Unwrap())
}

func TestBuildCSPPolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled: true,
			Directives: &CSPDirectives{
				DefaultSrc:              []string{"'self'"},
				ScriptSrc:               []string{"'self'", "'unsafe-inline'"},
				StyleSrc:                []string{"'self'"},
				ImgSrc:                  []string{"'self'", "data:"},
				FontSrc:                 []string{"'self'"},
				ConnectSrc:              []string{"'self'"},
				MediaSrc:                []string{"'self'"},
				ObjectSrc:               []string{"'none'"},
				FrameSrc:                []string{"'none'"},
				FrameAncestors:          []string{"'none'"},
				FormAction:              []string{"'self'"},
				BaseURI:                 []string{"'self'"},
				UpgradeInsecureRequests: true,
				BlockAllMixedContent:    true,
			},
		},
	}

	middleware := NewHeadersMiddleware(config)
	policy := middleware.buildCSPPolicy(config.CSP.Directives)

	assert.Contains(t, policy, "default-src 'self'")
	assert.Contains(t, policy, "script-src 'self' 'unsafe-inline'")
	assert.Contains(t, policy, "style-src 'self'")
	assert.Contains(t, policy, "img-src 'self' data:")
	assert.Contains(t, policy, "font-src 'self'")
	assert.Contains(t, policy, "connect-src 'self'")
	assert.Contains(t, policy, "media-src 'self'")
	assert.Contains(t, policy, "object-src 'none'")
	assert.Contains(t, policy, "frame-src 'none'")
	assert.Contains(t, policy, "frame-ancestors 'none'")
	assert.Contains(t, policy, "form-action 'self'")
	assert.Contains(t, policy, "base-uri 'self'")
	assert.Contains(t, policy, "upgrade-insecure-requests")
	assert.Contains(t, policy, "block-all-mixed-content")
}

func TestBuildPermissionsPolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		PermissionsPolicy: &PermissionsPolicyConfig{
			Enabled: true,
			Features: map[string][]string{
				"geolocation": {},
				"camera":      {"self"},
			},
		},
	}

	middleware := NewHeadersMiddleware(config)
	policy := middleware.buildPermissionsPolicy(config.PermissionsPolicy.Features)

	assert.Contains(t, policy, "geolocation=()")
	assert.Contains(t, policy, "camera=(self)")
}
