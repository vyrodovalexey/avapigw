// CORS authority tests: when a gateway CORS policy is configured, it is
// the single source of truth for Access-Control-* response headers —
// backend-provided values must never leak through the middleware. Without
// a configured policy (no CORS middleware in the chain), backend headers
// pass through untouched.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// backendCORSHandler simulates a proxied backend response that emits its
// own permissive CORS headers (the reverse proxy copies backend response
// headers into the live header map before WriteHeader).
func backendCORSHandler(origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
		h.Set("Access-Control-Allow-Headers", "X-Backend-Header")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Access-Control-Expose-Headers", "X-Backend-Exposed")
		h.Set("Access-Control-Max-Age", "999")
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"backend":true}`))
	})
}

// serveCORS runs the handler with an optional Origin header and returns
// the recorder.
func serveCORS(handler http.Handler, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestCORS_Authority_BackendHeaderStripping is the backend CORS header
// stripping matrix: gateway policy configured -> backend Access-Control-*
// values are replaced by the gateway's grant decision.
func TestCORS_Authority_BackendHeaderStripping(t *testing.T) {
	t.Parallel()

	policy := CORSConfig{
		AllowOrigins:  []string{"https://app.example.com"},
		AllowMethods:  []string{"GET", "OPTIONS"},
		AllowHeaders:  []string{"Content-Type"},
		ExposeHeaders: []string{"X-Request-ID"},
		MaxAge:        120,
	}

	tests := []struct {
		name        string
		origin      string
		wantGrant   []string // expected Access-Control-Allow-Origin values
		wantMethods string
		wantExpose  string
	}{
		{
			name:        "allowed origin gets exactly the gateway grant",
			origin:      "https://app.example.com",
			wantGrant:   []string{"https://app.example.com"},
			wantMethods: "GET, OPTIONS",
			wantExpose:  "X-Request-ID",
		},
		{
			name:        "denied origin gets no grant despite backend grant",
			origin:      "https://evil.example.org",
			wantGrant:   nil,
			wantMethods: "GET, OPTIONS",
			wantExpose:  "X-Request-ID",
		},
		{
			name:        "no origin header gets no grant despite backend grant",
			origin:      "",
			wantGrant:   nil,
			wantMethods: "GET, OPTIONS",
			wantExpose:  "X-Request-ID",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := CORS(policy)(backendCORSHandler("*"))
			rec := serveCORS(handler, tt.origin)

			require.Equal(t, http.StatusOK, rec.Code,
				"actual request must reach the backend handler")
			assert.Equal(t, tt.wantGrant,
				rec.Header().Values("Access-Control-Allow-Origin"),
				"gateway policy must be authoritative for the grant")
			assert.Equal(t, tt.wantMethods,
				rec.Header().Get("Access-Control-Allow-Methods"),
				"backend allow-methods must be replaced by the gateway value")
			assert.Equal(t, tt.wantExpose,
				rec.Header().Get("Access-Control-Expose-Headers"),
				"backend expose-headers must be replaced by the gateway value")
			assert.NotEqual(t, "999", rec.Header().Get("Access-Control-Max-Age"),
				"backend max-age must never leak")
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"),
				"credentials are not granted by this policy")
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
				"non-CORS backend headers must pass through")
			assert.JSONEq(t, `{"backend":true}`, rec.Body.String(),
				"backend body must pass through unchanged")
		})
	}
}

// TestCORS_Authority_NoDuplicateGrant verifies an allowed origin never
// receives two Access-Control-Allow-Origin values (gateway + backend),
// which browsers reject.
func TestCORS_Authority_NoDuplicateGrant(t *testing.T) {
	t.Parallel()

	handler := CORS(CORSConfig{
		AllowOrigins: []string{"https://app.example.com"},
	})(backendCORSHandler("https://app.example.com"))

	rec := serveCORS(handler, "https://app.example.com")

	assert.Equal(t,
		[]string{"https://app.example.com"},
		rec.Header().Values("Access-Control-Allow-Origin"),
		"exactly one grant value must be emitted")
}

// TestCORS_Authority_PassthroughWithoutPolicy verifies backend CORS
// headers pass through untouched when no gateway CORS middleware is
// configured (no policy -> no authority).
func TestCORS_Authority_PassthroughWithoutPolicy(t *testing.T) {
	t.Parallel()

	rec := serveCORS(backendCORSHandler("*"), "https://evil.example.org")

	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"),
		"without a gateway policy the backend grant must pass through")
	assert.Equal(t, "999", rec.Header().Get("Access-Control-Max-Age"))
	assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORS_Authority_VaryMerged verifies the backend's Vary values are
// preserved and Origin is appended, never clobbered or duplicated.
func TestCORS_Authority_VaryMerged(t *testing.T) {
	t.Parallel()

	t.Run("backend vary preserved and origin appended", func(t *testing.T) {
		t.Parallel()

		handler := CORS(CORSConfig{
			AllowOrigins: []string{"https://app.example.com"},
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Vary", "Accept-Encoding")
			w.WriteHeader(http.StatusOK)
		}))

		rec := serveCORS(handler, "https://app.example.com")

		assert.ElementsMatch(t,
			[]string{"Accept-Encoding", "Origin"},
			rec.Header().Values("Vary"),
			"backend Vary must be merged with the CORS Vary: Origin")
	})

	t.Run("origin not duplicated when backend lists it", func(t *testing.T) {
		t.Parallel()

		handler := CORS(CORSConfig{
			AllowOrigins: []string{"https://app.example.com"},
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Vary", "Accept-Encoding, Origin")
			w.WriteHeader(http.StatusOK)
		}))

		rec := serveCORS(handler, "https://app.example.com")

		assert.Equal(t, []string{"Accept-Encoding, Origin"},
			rec.Header().Values("Vary"),
			"Origin already listed by the backend must not be duplicated")
	})
}

// TestCORS_Authority_ImplicitWritePaths verifies the policy is applied on
// every response-completion path, not just explicit WriteHeader calls.
func TestCORS_Authority_ImplicitWritePaths(t *testing.T) {
	t.Parallel()

	policy := CORSConfig{AllowOrigins: []string{"https://app.example.com"}}

	tests := []struct {
		name    string
		handler http.Handler
	}{
		{
			name: "implicit 200 via Write without WriteHeader",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				_, _ = w.Write([]byte("body"))
			}),
		},
		{
			name: "handler returns without writing anything",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := serveCORS(CORS(policy)(tt.handler), "https://app.example.com")

			assert.Equal(t,
				[]string{"https://app.example.com"},
				rec.Header().Values("Access-Control-Allow-Origin"),
				"policy must be enforced on this write path")
		})
	}
}

// TestCORS_Authority_PreflightUnchanged verifies preflight short-circuit
// semantics are unchanged by the authority writer (the inner handler never
// runs on OPTIONS).
func TestCORS_Authority_PreflightUnchanged(t *testing.T) {
	t.Parallel()

	reached := false
	handler := CORS(CORSConfig{
		AllowOrigins: []string{"https://app.example.com"},
		AllowMethods: []string{"GET", "OPTIONS"},
		MaxAge:       300,
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.False(t, reached, "preflight must never reach the inner handler")
	assert.Equal(t, "https://app.example.com",
		rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "300", rec.Header().Get("Access-Control-Max-Age"))
}

// TestCORS_Authority_DroppedHeadersMetric verifies the strip counter moves
// when upstream Access-Control-* headers are replaced.
func TestCORS_Authority_DroppedHeadersMetric(t *testing.T) {
	t.Parallel()

	before := testutil.ToFloat64(GetMiddlewareMetrics().corsUpstreamHeadersDropped)

	handler := CORS(CORSConfig{
		AllowOrigins: []string{"https://app.example.com"},
	})(backendCORSHandler("*"))
	serveCORS(handler, "https://evil.example.org")

	after := testutil.ToFloat64(GetMiddlewareMetrics().corsUpstreamHeadersDropped)
	assert.GreaterOrEqual(t, after, before+1,
		"dropping backend CORS headers must increment the counter")
}

// TestCORS_Authority_WriterInterfaces verifies the authority writer keeps
// the optional ResponseWriter interfaces required by streaming and
// WebSocket paths.
func TestCORS_Authority_WriterInterfaces(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	aw := newCORSAuthorityWriter(rec, newCORSHeaders(DefaultCORSConfig()), "")

	assert.Equal(t, rec, aw.Unwrap(), "Unwrap must expose the underlying writer")

	// httptest.ResponseRecorder implements Flusher but not Hijacker.
	aw.Flush()
	assert.True(t, rec.Flushed, "Flush must delegate to the underlying flusher")

	_, _, err := aw.Hijack()
	assert.ErrorIs(t, err, http.ErrNotSupported,
		"Hijack on a non-hijackable writer must report ErrNotSupported")
}
