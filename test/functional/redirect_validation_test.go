//go:build functional

// Package functional contains functional tests for the API Gateway.
package functional

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================================
// Functional Tests: Redirect URL Validation (Open Redirect Prevention)
// ============================================================================

// TestFunctional_RedirectValidation_SafeSchemes verifies that safe redirect
// schemes (http, https, empty) are allowed through the proxy.
func TestFunctional_RedirectValidation_SafeSchemes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		scheme         string
		uri            string
		code           int
		expectedStatus int
	}{
		{
			name:           "http scheme redirect allowed",
			scheme:         "http",
			uri:            "/new-path",
			code:           302,
			expectedStatus: http.StatusFound,
		},
		{
			name:           "https scheme redirect allowed",
			scheme:         "https",
			uri:            "/secure-path",
			code:           301,
			expectedStatus: http.StatusMovedPermanently,
		},
		{
			name:           "empty scheme redirect allowed (relative)",
			scheme:         "",
			uri:            "/relative-path",
			code:           302,
			expectedStatus: http.StatusFound,
		},
		{
			name:           "HTTP uppercase scheme allowed",
			scheme:         "HTTP",
			uri:            "/upper-path",
			code:           302,
			expectedStatus: http.StatusFound,
		},
		{
			name:           "HTTPS uppercase scheme allowed",
			scheme:         "HTTPS",
			uri:            "/upper-secure",
			code:           301,
			expectedStatus: http.StatusMovedPermanently,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router.New()
			logger := observability.NopLogger()
			registry := backend.NewRegistry(logger)

			routeName := "safe-redirect-" + tt.name
			route := config.Route{
				Name: routeName,
				Match: []config.RouteMatch{
					{
						URI: &config.URIMatch{
							Exact: "/" + routeName,
						},
					},
				},
				Redirect: &config.RedirectConfig{
					Scheme: tt.scheme,
					URI:    tt.uri,
					Code:   tt.code,
				},
			}
			err := r.AddRoute(route)
			require.NoError(t, err)

			p := proxy.NewReverseProxy(r, registry)

			req := httptest.NewRequest(http.MethodGet, "/"+routeName, nil)
			rec := httptest.NewRecorder()

			p.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code,
				"safe scheme %q should produce redirect status %d", tt.scheme, tt.expectedStatus)
			assert.NotEmpty(t, rec.Header().Get("Location"),
				"safe redirect should have Location header")
		})
	}
}

// TestFunctional_RedirectValidation_UnsafeSchemes verifies that dangerous
// redirect schemes are blocked with HTTP 400 Bad Request.
func TestFunctional_RedirectValidation_UnsafeSchemes(t *testing.T) {
	t.Parallel()

	unsafeSchemes := []struct {
		name   string
		scheme string
	}{
		{"javascript scheme", "javascript"},
		{"data scheme", "data"},
		{"vbscript scheme", "vbscript"},
		{"file scheme", "file"},
		{"ftp scheme", "ftp"},
		{"ssh scheme", "ssh"},
		{"telnet scheme", "telnet"},
		{"ldap scheme", "ldap"},
		{"gopher scheme", "gopher"},
		{"custom scheme", "myapp"},
	}

	for _, tt := range unsafeSchemes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router.New()
			logger := observability.NopLogger()
			registry := backend.NewRegistry(logger)

			routeName := "unsafe-" + tt.scheme
			route := config.Route{
				Name: routeName,
				Match: []config.RouteMatch{
					{
						URI: &config.URIMatch{
							Exact: "/" + routeName,
						},
					},
				},
				Redirect: &config.RedirectConfig{
					Scheme: tt.scheme,
					URI:    "/evil",
					Code:   302,
				},
			}
			err := r.AddRoute(route)
			require.NoError(t, err)

			p := proxy.NewReverseProxy(r, registry)

			req := httptest.NewRequest(http.MethodGet, "/"+routeName, nil)
			rec := httptest.NewRecorder()

			p.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code,
				"unsafe scheme %q should be blocked with 400", tt.scheme)
			assert.Contains(t, rec.Body.String(), "unsafe redirect",
				"response should indicate unsafe redirect for scheme %q", tt.scheme)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
				"error response should be JSON")
		})
	}
}

// TestFunctional_RedirectValidation_WithHostAndPort verifies that redirects
// with host and port changes still validate the scheme.
func TestFunctional_RedirectValidation_WithHostAndPort(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Safe redirect with host change
	safeRoute := config.Route{
		Name: "safe-host-redirect",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/safe-host"}},
		},
		Redirect: &config.RedirectConfig{
			Scheme: "https",
			Host:   "new-host.example.com",
			Port:   8443,
			URI:    "/new-path",
			Code:   301,
		},
	}
	err := r.AddRoute(safeRoute)
	require.NoError(t, err)

	// Unsafe redirect with host change
	unsafeRoute := config.Route{
		Name: "unsafe-host-redirect",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/unsafe-host"}},
		},
		Redirect: &config.RedirectConfig{
			Scheme: "javascript",
			Host:   "evil.com",
			URI:    "/payload",
			Code:   302,
		},
	}
	err = r.AddRoute(unsafeRoute)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	t.Run("safe redirect with host change", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/safe-host", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMovedPermanently, rec.Code)
		location := rec.Header().Get("Location")
		assert.Contains(t, location, "new-host.example.com")
	})

	t.Run("unsafe redirect with host change blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/unsafe-host", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "unsafe redirect")
	})
}

// TestFunctional_RedirectValidation_StripQuery verifies that strip query
// works correctly with safe redirects.
func TestFunctional_RedirectValidation_StripQuery(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "strip-query-redirect",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/strip-query"}},
		},
		Redirect: &config.RedirectConfig{
			URI:        "/clean-path",
			StripQuery: true,
			Code:       302,
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/strip-query?foo=bar&baz=qux", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "/clean-path")
	assert.NotContains(t, location, "foo=bar",
		"query parameters should be stripped")
}

// TestFunctional_RedirectValidation_DefaultCode verifies that redirect
// defaults to 302 when no code is specified.
func TestFunctional_RedirectValidation_DefaultCode(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "default-code-redirect",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/default-code"}},
		},
		Redirect: &config.RedirectConfig{
			URI:  "/new-location",
			Code: 0, // Should default to 302
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/default-code", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code,
		"default redirect code should be 302")
}

// TestFunctional_RedirectValidation_JSONErrorResponse verifies that blocked
// redirects return a proper JSON error response.
func TestFunctional_RedirectValidation_JSONErrorResponse(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	route := config.Route{
		Name: "json-error-redirect",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/json-error"}},
		},
		Redirect: &config.RedirectConfig{
			Scheme: "data",
			URI:    "/payload",
			Code:   302,
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	p := proxy.NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/json-error", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	body := rec.Body.String()
	assert.Contains(t, body, "bad request")
	assert.Contains(t, body, "unsafe redirect")
}
