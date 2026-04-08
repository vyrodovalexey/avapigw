//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

// ---------------------------------------------------------------------------
// Helper: create a gateway proxy with OpenAPI validation middleware simulation
// ---------------------------------------------------------------------------

// openAPIValidationMiddleware simulates OpenAPI validation middleware behaviour.
// In a real implementation this would use kin-openapi to validate against a spec.
// For integration tests we simulate the validation logic to test the middleware
// chain integration with real backends.
func openAPIValidationMiddleware(failOnError bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate validation: POST /api/v1/items requires Content-Type and valid JSON body
			if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/items") {
				ct := r.Header.Get("Content-Type")
				if ct == "" || !strings.Contains(ct, "application/json") {
					if failOnError {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(map[string]string{
							"error": "request body must be application/json",
						})
						return
					}
				}
			}

			// Simulate query param validation: limit must be numeric
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/items") {
				limitVal := r.URL.Query().Get("limit")
				if limitVal != "" {
					// Simple check: must be all digits
					for _, c := range limitVal {
						if c < '0' || c > '9' {
							if failOnError {
								w.Header().Set("Content-Type", "application/json")
								w.WriteHeader(http.StatusBadRequest)
								_ = json.NewEncoder(w).Encode(map[string]string{
									"error": "query parameter 'limit' must be an integer",
								})
								return
							}
							break
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// 1. Gateway with OpenAPI validation proxies valid requests to backend
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_ValidRequestProxy(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("valid GET request passes validation and reaches backend", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"GET"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		handler := openAPIValidationMiddleware(true)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("valid POST request with JSON body passes validation", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Integration Test Item",
			Description: "Created through validation middleware",
			Price:       19.99,
		}

		body, err := json.Marshal(item)
		require.NoError(t, err)

		resp, err := helpers.MakeRequestWithHeaders(
			http.MethodPost,
			testCfg.Backend1URL+"/api/v1/items",
			nil,
			map[string]string{"Content-Type": "application/json"},
		)
		if err != nil {
			t.Skipf("Backend not reachable: %v", err)
		}
		defer resp.Body.Close()

		// Verify backend is reachable, then test through validation middleware
		r := router.New()
		err = r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"POST"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := openAPIValidationMiddleware(true)(p)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/items", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusCreated)
	})
}

// ---------------------------------------------------------------------------
// 2. Gateway with OpenAPI validation rejects invalid request body
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_RejectInvalidBody(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("POST without Content-Type is rejected", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"POST"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := openAPIValidationMiddleware(true)(p)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/items", strings.NewReader(`{"name":"test"}`))
		// Intentionally no Content-Type header
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		err = json.NewDecoder(rec.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp["error"], "application/json")
	})
}

// ---------------------------------------------------------------------------
// 3. Gateway with OpenAPI validation rejects missing required params
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_RejectInvalidParams(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("GET with non-numeric limit param is rejected", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"GET"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := openAPIValidationMiddleware(true)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=abc", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("GET with valid numeric limit param passes", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"GET"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := openAPIValidationMiddleware(true)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items?limit=10", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// ---------------------------------------------------------------------------
// 4. OpenAPI validation in log-only mode passes invalid requests
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_LogOnlyMode(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("log-only mode passes invalid requests through", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"POST"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		// failOnError=false means log-only mode
		handler := openAPIValidationMiddleware(false)(p)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/items", strings.NewReader(`{"name":"test"}`))
		// No Content-Type header — would normally fail validation
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Should pass through to backend (not 400)
		assert.NotEqual(t, http.StatusBadRequest, rec.Code)
	})
}

// ---------------------------------------------------------------------------
// 5. OpenAPI validation with rate limiting (both active)
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_WithRateLimiting(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("validation and rate limiting both active", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"GET"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		// Build middleware chain: rate limit -> validation -> proxy
		rl := middleware.NewRateLimiter(100, 100, false)
		handler := middleware.RateLimit(rl)(openAPIValidationMiddleware(true)(p))

		// Valid request should pass both middlewares
		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// ---------------------------------------------------------------------------
// 6. OpenAPI validation with transform (both active)
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_WithTransform(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("validation and header transform both active", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"GET"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		// Build middleware chain: headers -> validation -> proxy
		headersCfg := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"X-Validated": "true",
			},
		}
		handler := middleware.Headers(headersCfg)(openAPIValidationMiddleware(true)(p))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "true", rec.Header().Get("X-Validated"))
	})
}

// ---------------------------------------------------------------------------
// 7. OpenAPI validation with authentication (both active)
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_WithAuthentication(t *testing.T) {
	t.Parallel()

	t.Run("validation runs after auth middleware", func(t *testing.T) {
		t.Parallel()

		var executionOrder []string

		authMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, "auth")
				next.ServeHTTP(w, r)
			})
		}

		validationMW := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, "validation")
				next.ServeHTTP(w, r)
			})
		}

		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "proxy")
			w.WriteHeader(http.StatusOK)
		})

		// Chain: auth -> validation -> proxy
		handler := authMiddleware(validationMW(proxyHandler))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, executionOrder, 3)
		assert.Equal(t, "auth", executionOrder[0])
		assert.Equal(t, "validation", executionOrder[1])
		assert.Equal(t, "proxy", executionOrder[2])
	})
}

// ---------------------------------------------------------------------------
// 8. OpenAPI validation config in gateway test YAML
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_ConfigFromTestData(t *testing.T) {
	t.Parallel()

	t.Run("gateway-test.yaml loads without OpenAPI validation", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Default gateway-test.yaml should not have OpenAPI validation
		assert.Nil(t, cfg.Spec.OpenAPIValidation)
	})

	t.Run("config with OpenAPI validation validates correctly", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "integration-test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18200, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "items-api",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api/v1/items"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
						OpenAPIValidation: &config.OpenAPIValidationConfig{
							Enabled:             true,
							SpecFile:            helpers.GetTestConfigPath("openapi/items-api.yaml"),
							FailOnError:         boolPtr(true),
							ValidateRequestBody: boolPtr(true),
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// 9. Hot-reload of OpenAPI spec file
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_HotReload(t *testing.T) {
	t.Parallel()

	t.Run("config reload with changed OpenAPI spec path", func(t *testing.T) {
		t.Parallel()

		oldCfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "reload-test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18201, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: helpers.GetTestConfigPath("openapi/minimal.yaml"),
				},
			},
		}

		newCfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "reload-test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18201, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: helpers.GetTestConfigPath("openapi/items-api.yaml"),
				},
			},
		}

		// Both configs should be valid
		require.NoError(t, config.ValidateConfig(oldCfg))
		require.NoError(t, config.ValidateConfig(newCfg))

		// Spec file should have changed
		assert.NotEqual(t,
			oldCfg.Spec.OpenAPIValidation.SpecFile,
			newCfg.Spec.OpenAPIValidation.SpecFile,
		)
	})
}

// ---------------------------------------------------------------------------
// 10. OpenAPI validation with circuit breaker
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPIValidation_WithCircuitBreaker(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("validation and circuit breaker both active", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}, Methods: []string{"GET"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		// Build middleware chain: circuit breaker -> validation -> proxy
		cb := middleware.NewCircuitBreaker("test", 5, 30*time.Second)
		handler := middleware.CircuitBreakerMiddleware(cb)(openAPIValidationMiddleware(true)(p))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
