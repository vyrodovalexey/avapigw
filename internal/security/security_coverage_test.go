package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// TestSecurityHeadersFromConfig tests SecurityHeadersFromConfig function.
func TestSecurityHeadersFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cfg           *config.SecurityConfig
		expectNil     bool
		expectHeaders map[string]string
		isHTTPS       bool
	}{
		{
			name:      "nil config",
			cfg:       nil,
			expectNil: true,
		},
		{
			name: "disabled config",
			cfg: &config.SecurityConfig{
				Enabled: false,
			},
			expectNil: true,
		},
		{
			name: "enabled with headers",
			cfg: &config.SecurityConfig{
				Enabled: true,
				Headers: &config.SecurityHeadersConfig{
					Enabled:             true,
					XFrameOptions:       "DENY",
					XContentTypeOptions: "nosniff",
				},
			},
			expectNil: false,
			expectHeaders: map[string]string{
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
			},
		},
		{
			name: "enabled with HSTS",
			cfg: &config.SecurityConfig{
				Enabled: true,
				HSTS: &config.SecurityHSTSConfig{
					Enabled:           true,
					MaxAge:            31536000,
					IncludeSubDomains: true,
				},
			},
			expectNil: false,
			isHTTPS:   true,
			expectHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			},
		},
		{
			name: "enabled with CSP",
			cfg: &config.SecurityConfig{
				Enabled: true,
				CSP: &config.CSPConfig{
					Enabled: true,
					Policy:  "default-src 'self'",
				},
			},
			expectNil: false,
			expectHeaders: map[string]string{
				"Content-Security-Policy": "default-src 'self'",
			},
		},
		{
			name: "enabled with referrer policy",
			cfg: &config.SecurityConfig{
				Enabled:        true,
				ReferrerPolicy: "strict-origin",
			},
			expectNil: false,
			expectHeaders: map[string]string{
				"Referrer-Policy": "strict-origin",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := SecurityHeadersFromConfig(tt.cfg)

			if tt.expectNil {
				assert.Nil(t, middleware)
				return
			}

			require.NotNil(t, middleware)

			// Test the middleware
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.isHTTPS {
				req.Header.Set("X-Forwarded-Proto", "https")
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			for header, value := range tt.expectHeaders {
				assert.Contains(t, rec.Header().Get(header), value)
			}
		})
	}
}

// TestConvertSecurityConfig tests convertSecurityConfig function.
func TestConvertSecurityConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.SecurityConfig
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "full config",
			cfg: &config.SecurityConfig{
				Enabled:        true,
				ReferrerPolicy: "no-referrer",
				Headers: &config.SecurityHeadersConfig{
					Enabled:             true,
					XFrameOptions:       "SAMEORIGIN",
					XContentTypeOptions: "nosniff",
					XXSSProtection:      "1; mode=block",
					CustomHeaders: map[string]string{
						"X-Custom": "value",
					},
				},
				HSTS: &config.SecurityHSTSConfig{
					Enabled:           true,
					MaxAge:            31536000,
					IncludeSubDomains: true,
					Preload:           true,
				},
				CSP: &config.CSPConfig{
					Enabled:    true,
					Policy:     "default-src 'self'",
					ReportOnly: true,
					ReportURI:  "https://example.com/csp",
				},
			},
		},
		{
			name: "partial config - headers only",
			cfg: &config.SecurityConfig{
				Enabled: true,
				Headers: &config.SecurityHeadersConfig{
					Enabled:       true,
					XFrameOptions: "DENY",
				},
			},
		},
		{
			name: "partial config - HSTS only",
			cfg: &config.SecurityConfig{
				Enabled: true,
				HSTS: &config.SecurityHSTSConfig{
					Enabled: true,
					MaxAge:  3600,
				},
			},
		},
		{
			name: "partial config - CSP only",
			cfg: &config.SecurityConfig{
				Enabled: true,
				CSP: &config.CSPConfig{
					Enabled: true,
					Policy:  "default-src 'none'",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := convertSecurityConfig(tt.cfg)

			if tt.cfg == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.cfg.Enabled, result.Enabled)
			assert.Equal(t, tt.cfg.ReferrerPolicy, result.ReferrerPolicy)

			if tt.cfg.Headers != nil {
				require.NotNil(t, result.Headers)
				assert.Equal(t, tt.cfg.Headers.Enabled, result.Headers.Enabled)
				assert.Equal(t, tt.cfg.Headers.XFrameOptions, result.Headers.XFrameOptions)
				assert.Equal(t, tt.cfg.Headers.XContentTypeOptions, result.Headers.XContentTypeOptions)
				assert.Equal(t, tt.cfg.Headers.XXSSProtection, result.Headers.XXSSProtection)
				assert.Equal(t, tt.cfg.Headers.CustomHeaders, result.Headers.CustomHeaders)
			}

			if tt.cfg.HSTS != nil {
				require.NotNil(t, result.HSTS)
				assert.Equal(t, tt.cfg.HSTS.Enabled, result.HSTS.Enabled)
				assert.Equal(t, tt.cfg.HSTS.MaxAge, result.HSTS.MaxAge)
				assert.Equal(t, tt.cfg.HSTS.IncludeSubDomains, result.HSTS.IncludeSubDomains)
				assert.Equal(t, tt.cfg.HSTS.Preload, result.HSTS.Preload)
			}

			if tt.cfg.CSP != nil {
				require.NotNil(t, result.CSP)
				assert.Equal(t, tt.cfg.CSP.Enabled, result.CSP.Enabled)
				assert.Equal(t, tt.cfg.CSP.Policy, result.CSP.Policy)
				assert.Equal(t, tt.cfg.CSP.ReportOnly, result.CSP.ReportOnly)
				assert.Equal(t, tt.cfg.CSP.ReportURI, result.CSP.ReportURI)
			}
		})
	}
}

// TestNewMetrics tests NewMetrics function.
func TestNewMetrics(t *testing.T) {
	// Create metrics with a unique namespace
	namespace := "test_security_metrics"

	// We need to use promauto with a custom registry, but since the code uses promauto,
	// we'll just verify the function doesn't panic and returns valid metrics
	metrics := NewMetrics(namespace)

	require.NotNil(t, metrics)
	assert.NotNil(t, metrics.headersApplied)
	assert.NotNil(t, metrics.hstsApplied)
	assert.NotNil(t, metrics.cspApplied)
	assert.NotNil(t, metrics.cspViolations)
}

// TestMetrics_RecordHeaderApplied tests RecordHeaderApplied method.
func TestMetrics_RecordHeaderApplied(t *testing.T) {
	metrics := NewMetrics("test_header_applied")

	// Should not panic
	assert.NotPanics(t, func() {
		metrics.RecordHeaderApplied("X-Frame-Options")
		metrics.RecordHeaderApplied("X-Content-Type-Options")
		metrics.RecordHeaderApplied("X-XSS-Protection")
	})
}

// TestMetrics_RecordHSTSApplied tests RecordHSTSApplied method.
func TestMetrics_RecordHSTSApplied(t *testing.T) {
	metrics := NewMetrics("test_hsts_applied")

	// Should not panic
	assert.NotPanics(t, func() {
		metrics.RecordHSTSApplied()
		metrics.RecordHSTSApplied()
	})
}

// TestMetrics_RecordCSPApplied tests RecordCSPApplied method.
func TestMetrics_RecordCSPApplied(t *testing.T) {
	metrics := NewMetrics("test_csp_applied")

	// Should not panic
	assert.NotPanics(t, func() {
		metrics.RecordCSPApplied()
		metrics.RecordCSPApplied()
	})
}

// TestMetrics_RecordCSPViolation tests RecordCSPViolation method.
func TestMetrics_RecordCSPViolation(t *testing.T) {
	metrics := NewMetrics("test_csp_violation")

	// Should not panic
	assert.NotPanics(t, func() {
		metrics.RecordCSPViolation("script-src", "https://evil.com")
		metrics.RecordCSPViolation("style-src", "inline")
	})
}

// TestGetHeadersToRemove_NilHeaders tests getHeadersToRemove with nil headers.
func TestGetHeadersToRemove_NilHeaders(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled: true,
		Headers: nil,
	}

	middleware := NewHeadersMiddleware(cfg)
	headers := middleware.getHeadersToRemove()

	assert.Nil(t, headers)
}

// TestAddCSPHeader_EmptyPolicy tests addCSPHeader with empty policy.
func TestAddCSPHeader_EmptyPolicy(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled:    true,
			Policy:     "",
			Directives: nil,
		},
	}

	middleware := NewHeadersMiddleware(cfg)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// CSP header should not be set when policy is empty
	assert.Empty(t, rec.Header().Get("Content-Security-Policy"))
}

// TestAddCSPHeader_ReportURIAlreadyInPolicy tests addCSPHeader when report-uri is already in policy.
func TestAddCSPHeader_ReportURIAlreadyInPolicy(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled: true,
		CSP: &CSPConfig{
			Enabled:   true,
			Policy:    "default-src 'self'; report-uri https://existing.com/csp",
			ReportURI: "https://new.com/csp", // Should not be added since already in policy
		},
	}

	middleware := NewHeadersMiddleware(cfg)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// Should contain the original report-uri, not the new one
	assert.Contains(t, csp, "report-uri https://existing.com/csp")
	assert.NotContains(t, csp, "https://new.com/csp")
}

// TestAddPermissionsPolicyHeader_EmptyPolicy tests addPermissionsPolicyHeader with empty policy.
func TestAddPermissionsPolicyHeader_EmptyPolicy(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled: true,
		PermissionsPolicy: &PermissionsPolicyConfig{
			Enabled:  true,
			Policy:   "",
			Features: nil,
		},
	}

	middleware := NewHeadersMiddleware(cfg)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Permissions-Policy header should not be set when policy is empty
	assert.Empty(t, rec.Header().Get("Permissions-Policy"))
}

// TestHeaderRemovingResponseWriter_MultipleWriteHeader tests multiple WriteHeader calls.
func TestHeaderRemovingResponseWriter_MultipleWriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	wrapped := &headerRemovingResponseWriter{
		ResponseWriter: rec,
		removeHeaders:  []string{"Server"},
	}

	wrapped.Header().Set("Server", "Apache")

	// First WriteHeader
	wrapped.WriteHeader(http.StatusOK)

	// Second WriteHeader (should be ignored by underlying ResponseWriter)
	wrapped.WriteHeader(http.StatusCreated)

	// Server header should be removed
	assert.Empty(t, rec.Header().Get("Server"))
	// Status should be from first call
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestAddHSTSHeader_MinimalConfig tests addHSTSHeader with minimal config.
func TestAddHSTSHeader_MinimalConfig(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled: true,
		HSTS: &HSTSConfig{
			Enabled:           true,
			MaxAge:            3600,
			IncludeSubDomains: false,
			Preload:           false,
		},
	}

	middleware := NewHeadersMiddleware(cfg)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	assert.Equal(t, "max-age=3600", hsts)
	assert.NotContains(t, hsts, "includeSubDomains")
	assert.NotContains(t, hsts, "preload")
}

// TestAddBasicSecurityHeaders_EmptyValues tests addBasicSecurityHeaders with empty values.
func TestAddBasicSecurityHeaders_EmptyValues(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled: true,
		Headers: &HeadersConfig{
			Enabled:             true,
			XFrameOptions:       "",
			XContentTypeOptions: "",
			XXSSProtection:      "",
			CacheControl:        "",
			Pragma:              "",
			CustomHeaders:       nil,
		},
	}

	middleware := NewHeadersMiddleware(cfg)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// No headers should be set when values are empty
	assert.Empty(t, rec.Header().Get("X-Frame-Options"))
	assert.Empty(t, rec.Header().Get("X-Content-Type-Options"))
	assert.Empty(t, rec.Header().Get("X-XSS-Protection"))
	assert.Empty(t, rec.Header().Get("Cache-Control"))
	assert.Empty(t, rec.Header().Get("Pragma"))
}

// TestAddSecurityHeaders_AllCrossOriginPolicies tests all cross-origin policies.
func TestAddSecurityHeaders_AllCrossOriginPolicies(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:                   true,
		CrossOriginOpenerPolicy:   "same-origin-allow-popups",
		CrossOriginEmbedderPolicy: "credentialless",
		CrossOriginResourcePolicy: "cross-origin",
	}

	middleware := NewHeadersMiddleware(cfg)
	handler := middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "same-origin-allow-popups", rec.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "credentialless", rec.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "cross-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
}
