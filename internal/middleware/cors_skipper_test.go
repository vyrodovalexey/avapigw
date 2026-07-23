package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// corsSkipperTestPolicy is the global policy used across skipper tests.
func corsSkipperTestPolicy() CORSConfig {
	return CORSConfig{
		AllowOrigins: []string{"https://global.example.com"},
		AllowMethods: []string{"GET", "OPTIONS"},
		AllowHeaders: []string{"Content-Type"},
		MaxAge:       600,
	}
}

// TestCORSWithSkipper_SkippedPreflightPassesThrough verifies the core of
// the route-CORS precedence fix: when skip returns true, the middleware
// must NOT answer preflight OPTIONS — the inner handler (the route chain
// with its own CORS middleware) owns the response.
func TestCORSWithSkipper_SkippedPreflightPassesThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Simulates the route chain's CORS middleware answering preflight.
		w.Header().Set("Access-Control-Allow-Origin", "https://route.example.com")
		w.Header().Set("Access-Control-Max-Age", "300")
		w.WriteHeader(http.StatusNoContent)
	})

	skip := func(*http.Request) bool { return true }
	handler := CORSWithSkipper(corsSkipperTestPolicy(), skip)(inner)

	req := httptest.NewRequest(http.MethodOptions, "/route-cors", nil)
	req.Header.Set("Origin", "https://route.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "https://route.example.com",
		rec.Header().Get("Access-Control-Allow-Origin"),
		"skipped preflight must carry the INNER (route) grant, not the global one")
	assert.Equal(t, "300", rec.Header().Get("Access-Control-Max-Age"),
		"route maxAge must not be replaced by the global policy")
}

// TestCORSWithSkipper_SkippedActualRequestKeepsInnerHeaders verifies the
// authority writer is bypassed on skipped requests: inner Access-Control-*
// headers survive.
func TestCORSWithSkipper_SkippedActualRequestKeepsInnerHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://route.example.com")
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSWithSkipper(corsSkipperTestPolicy(), func(*http.Request) bool { return true })(inner)

	req := httptest.NewRequest(http.MethodGet, "/route-cors", nil)
	req.Header.Set("Origin", "https://route.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "https://route.example.com",
		rec.Header().Get("Access-Control-Allow-Origin"),
		"inner grant must not be stripped when the request is skipped")
}

// TestCORSWithSkipper_NotSkippedKeepsGlobalBehavior verifies unchanged
// semantics when skip returns false (global authority + preflight answer).
func TestCORSWithSkipper_NotSkippedKeepsGlobalBehavior(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://backend-grant.example.com")
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSWithSkipper(corsSkipperTestPolicy(), func(*http.Request) bool { return false })(inner)

	t.Run("preflight answered by global policy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/global", nil)
		req.Header.Set("Origin", "https://global.example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://global.example.com",
			rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "600", rec.Header().Get("Access-Control-Max-Age"))
	})

	t.Run("actual request keeps single-grant authority", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/global", nil)
		req.Header.Set("Origin", "https://global.example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []string{"https://global.example.com"},
			rec.Header().Values("Access-Control-Allow-Origin"),
			"backend grant must be stripped and replaced by exactly one global grant")
	})
}

// TestCORSWithSkipper_NilSkipperEqualsCORS verifies CORS() delegates with a
// nil skipper and never skips.
func TestCORSWithSkipper_NilSkipperEqualsCORS(t *testing.T) {
	handler := CORS(corsSkipperTestPolicy())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://global.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code,
		"nil skipper must preserve the classic preflight short-circuit")
}

// TestCORSFromConfigWithSkipper covers the config wrapper (nil config
// default policy + skipper wiring).
func TestCORSFromConfigWithSkipper(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	t.Run("nil config default policy with skipper", func(t *testing.T) {
		handler := CORSFromConfigWithSkipper(nil, func(r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, "/skip")
		})(inner)

		// Skipped path: inner handler answers even for OPTIONS.
		req := httptest.NewRequest(http.MethodOptions, "/skip/me", nil)
		req.Header.Set("Origin", "https://any.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTeapot, rec.Code)

		// Non-skipped path: default policy answers preflight.
		req = httptest.NewRequest(http.MethodOptions, "/other", nil)
		req.Header.Set("Origin", "https://any.example.com")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("explicit config with skipper", func(t *testing.T) {
		cfg := &config.CORSConfig{AllowOrigins: []string{"https://cfg.example.com"}}
		handler := CORSFromConfigWithSkipper(cfg, nil)(inner)

		req := httptest.NewRequest(http.MethodOptions, "/", nil)
		req.Header.Set("Origin", "https://cfg.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://cfg.example.com",
			rec.Header().Get("Access-Control-Allow-Origin"))
	})
}
