// Regression tests for the unwired validator metrics (perf-run Finding 5):
// gateway_jwt_validation_total and gateway_apikey_validation_total stayed at
// 0 because validators built WITHOUT explicit metrics fell back to a private
// prometheus registry invisible on /metrics. These tests drive requests
// through the ACTUAL route middleware path (RouteMiddlewareManager ->
// auth.NewAuthenticator -> validator) and assert the SHARED singletons —
// the instances cmd/gateway registers with the /metrics registry — increment.
package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	authjwt "github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/openapi"
)

// signHS256 builds a minimal HS256 JWT for the given secret and claims.
func signHS256(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()

	encode := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	header := encode(map[string]string{"alg": "HS256", "typ": "JWT", "kid": "default"})
	payload := encode(claims)
	unsigned := header + "." + payload

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + sig
}

// counterSum gathers from g and sums all samples of a counter family.
func counterSum(t *testing.T, g prometheus.Gatherer, family string) float64 {
	t.Helper()
	families, err := g.Gather()
	require.NoError(t, err)
	var sum float64
	for _, mf := range families {
		if mf.GetName() != family {
			continue
		}
		for _, m := range mf.GetMetric() {
			sum += m.GetCounter().GetValue()
		}
	}
	return sum
}

// applyRouteAuth builds the route middleware chain for the route and serves
// one request through it, returning the response status code.
func applyRouteAuth(t *testing.T, route *config.Route, decorate func(*http.Request)) int {
	t.Helper()

	mgr := NewRouteMiddlewareManager(nil, observability.NopLogger())
	t.Cleanup(mgr.Stop)

	handler := mgr.ApplyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), route)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if decorate != nil {
		decorate(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

// TestRouteAuthMiddleware_JWTValidationMetricsRecorded proves that JWT
// validations performed by the ROUTE-level auth middleware land on the
// shared gateway_jwt_validation_total series (mirroring the production
// registration in cmd/gateway registerSubsystemMetrics).
func TestRouteAuthMiddleware_JWTValidationMetricsRecorded(t *testing.T) {
	const secret = "route-metrics-test-secret"

	registry := prometheus.NewRegistry()
	authjwt.GetSharedMetrics().MustRegister(registry)

	before := counterSum(t, registry, "gateway_jwt_validation_total")

	route := &config.Route{
		Name: "jwt-metrics-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled:   true,
				Secret:    secret,
				Algorithm: "HS256",
			},
		},
	}

	// Valid token -> 200, records status=success.
	token := signHS256(t, secret, map[string]any{
		"sub": "tester",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	code := applyRouteAuth(t, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	})
	require.Equal(t, http.StatusOK, code, "valid HS256 token must authenticate")

	// Garbage token -> 401, records status=error.
	code = applyRouteAuth(t, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer not-a-jwt")
	})
	require.Equal(t, http.StatusUnauthorized, code, "malformed token must be rejected")

	after := counterSum(t, registry, "gateway_jwt_validation_total")
	assert.GreaterOrEqual(t, after-before, 2.0,
		"route-level JWT validations must increment the shared gateway_jwt_validation_total")
}

// TestRouteAuthMiddleware_APIKeyValidationMetricsRecorded proves that API key
// validations performed by the ROUTE-level auth middleware land on the shared
// gateway_apikey_validation_total series.
func TestRouteAuthMiddleware_APIKeyValidationMetricsRecorded(t *testing.T) {
	registry := prometheus.NewRegistry()
	apikey.GetSharedMetrics().MustRegister(registry)

	before := counterSum(t, registry, "gateway_apikey_validation_total")

	route := &config.Route{
		Name: "apikey-metrics-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			APIKey: &config.APIKeyAuthConfig{
				Enabled: true,
				Header:  "X-API-Key",
			},
		},
	}

	// Unknown key -> 401; the validator runs and records status=error.
	code := applyRouteAuth(t, route, func(r *http.Request) {
		r.Header.Set("X-API-Key", "definitely-unknown-key")
	})
	require.Equal(t, http.StatusUnauthorized, code, "unknown API key must be rejected")

	after := counterSum(t, registry, "gateway_apikey_validation_total")
	assert.GreaterOrEqual(t, after-before, 1.0,
		"route-level API key validations must increment the shared gateway_apikey_validation_total")
}

// TestRouteOpenAPIMiddleware_SharedMetricsRecorded proves the OpenAPI
// validation metrics wiring end-to-end through the ACTUAL route middleware
// path (RouteMiddlewareManager -> openapi.MiddlewareFromConfig -> shared
// singleton): both successful and failed validations must land on the shared
// gateway_openapi_validation_requests_total series. This is the evidence for
// the FIX-2(a) verdict: the metric is wired; the perf suite's zero reading
// came from querying gateway_route_requests_total{route=~"pt-validated-.*"}
// instead (see the route-label fix).
func TestRouteOpenAPIMiddleware_SharedMetricsRecorded(t *testing.T) {
	// In this test binary the shared singleton initializes lazily against
	// prometheus.DefaultRegisterer (production binds it to the gateway
	// registry via openapi.InitSharedMetrics in registerSubsystemMetrics).
	_ = openapi.GetSharedMetrics()

	before := counterSum(t, prometheus.DefaultGatherer, "gateway_openapi_validation_requests_total")

	spec := `openapi: 3.0.0
info:
  title: t
  version: "1"
paths:
  /items:
    get:
      parameters:
        - name: limit
          in: query
          required: false
          schema: {type: integer}
      responses:
        "200":
          description: ok
`
	route := &config.Route{
		Name: "openapi-metrics-route",
		OpenAPIValidation: &config.OpenAPIValidationConfig{
			Enabled:               true,
			SpecInline:            spec,
			FailOnError:           boolPtr(true),
			ValidateRequestParams: boolPtr(true),
		},
	}

	mgr := NewRouteMiddlewareManager(nil, observability.NopLogger())
	t.Cleanup(mgr.Stop)
	handler := mgr.ApplyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), route)

	// Valid request -> success recorded.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/items?limit=5", nil))
	require.Equal(t, http.StatusOK, rec.Code, "valid request must pass validation")

	// Invalid parameter -> failure recorded (400 with failOnError).
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/items?limit=notanint", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code, "invalid request must be rejected")

	after := counterSum(t, prometheus.DefaultGatherer, "gateway_openapi_validation_requests_total")
	assert.GreaterOrEqual(t, after-before, 2.0,
		"route-level OpenAPI validations must increment the shared gateway_openapi_validation_requests_total")
}

// boolPtr returns a pointer to b.
func boolPtr(b bool) *bool { return &b }
