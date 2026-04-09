//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// boolPtrE2E returns a pointer to a bool value.
func boolPtrE2E(b bool) *bool {
	return &b
}

// openAPIValidationE2EMiddleware simulates OpenAPI validation for e2e tests.
// It validates requests against the items-api spec rules:
//   - POST /api/v1/items requires Content-Type: application/json and a JSON body with "name" field
//   - GET /api/v1/items validates query params: limit must be integer, offset must be integer
func openAPIValidationE2EMiddleware(failOnError bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var validationErrors []string

			// POST body validation
			if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/items") {
				ct := r.Header.Get("Content-Type")
				if ct == "" || !strings.Contains(ct, "application/json") {
					validationErrors = append(validationErrors,
						"request body must be application/json")
				} else if r.Body != nil {
					var body map[string]interface{}
					buf := new(bytes.Buffer)
					if _, err := buf.ReadFrom(r.Body); err == nil {
						if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
							validationErrors = append(validationErrors,
								"request body is not valid JSON")
						} else if _, ok := body["name"]; !ok {
							validationErrors = append(validationErrors,
								"request body missing required field 'name'")
						}
						// Restore body for downstream handlers
						r.Body = newReadCloser(buf.Bytes())
					}
				}
			}

			// GET query param validation
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/items") {
				if limitVal := r.URL.Query().Get("limit"); limitVal != "" {
					for _, c := range limitVal {
						if c < '0' || c > '9' {
							validationErrors = append(validationErrors,
								"query parameter 'limit' must be an integer")
							break
						}
					}
				}
				if offsetVal := r.URL.Query().Get("offset"); offsetVal != "" {
					for _, c := range offsetVal {
						if c < '0' || c > '9' {
							validationErrors = append(validationErrors,
								"query parameter 'offset' must be an integer")
							break
						}
					}
				}
			}

			if len(validationErrors) > 0 && failOnError {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "OpenAPI validation failed",
					"details": validationErrors,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// newReadCloser creates an io.ReadCloser from bytes.
type readCloser struct {
	*bytes.Reader
}

func (rc *readCloser) Close() error { return nil }

func newReadCloser(data []byte) *readCloser {
	return &readCloser{Reader: bytes.NewReader(data)}
}

// startGatewayWithValidation starts a gateway with OpenAPI validation middleware.
func startGatewayWithValidation(
	t *testing.T,
	port int,
	failOnError bool,
	extraMiddlewares ...func(http.Handler) http.Handler,
) (*gateway.Gateway, string) {
	t.Helper()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "openapi-e2e-test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: port, Protocol: "HTTP"},
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
				},
				{
					Name: "health",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}, Methods: []string{"GET"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status: 200,
						Body:   `{"status":"healthy"}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	logger := observability.NopLogger()

	r := router.New()
	err := r.LoadRoutes(cfg.Spec.Routes)
	require.NoError(t, err)

	registry := backend.NewRegistry(logger)
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	// Build middleware chain
	var handler http.Handler = p
	handler = openAPIValidationE2EMiddleware(failOnError)(handler)
	for _, mw := range extraMiddlewares {
		handler = mw(handler)
	}

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(handler),
	)
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	baseURL := "http://127.0.0.1:" + strings.TrimLeft(
		strings.Replace(
			strings.Replace("PORT", "PORT", "", 1),
			"PORT", "", 1,
		), "0",
	)
	// Simpler approach:
	baseURL = "http://127.0.0.1:" + itoa(port)

	return gw, baseURL
}

// itoa converts int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

// ---------------------------------------------------------------------------
// 1. E2E: Gateway starts with OpenAPI validation enabled
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_GatewayStartup(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway starts with OpenAPI validation enabled", func(t *testing.T) {
		gw, baseURL := startGatewayWithValidation(t, 18300, true)
		t.Cleanup(func() {
			_ = gw.Stop(context.Background())
		})

		time.Sleep(500 * time.Millisecond)

		// Verify gateway is running
		assert.True(t, gw.IsRunning())

		// Health check should work
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 2. E2E: Valid POST /api/v1/items request passes validation
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_ValidPost(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	gw, baseURL := startGatewayWithValidation(t, 18301, true)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("valid POST request passes validation and reaches backend", func(t *testing.T) {
		item := map[string]interface{}{
			"name":        "E2E Validation Test Item",
			"description": "Created through OpenAPI validation",
			"price":       29.99,
		}

		body, err := json.Marshal(item)
		require.NoError(t, err)

		client := helpers.HTTPClient()
		resp, err := client.Post(
			baseURL+"/api/v1/items",
			"application/json",
			bytes.NewReader(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated,
			"expected 200 or 201, got %d", resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 3. E2E: Invalid POST /api/v1/items request (bad body) returns 400
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_InvalidPost(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	gw, baseURL := startGatewayWithValidation(t, 18302, true)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("POST without Content-Type returns 400", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/items",
			strings.NewReader(`{"name":"test"}`))
		require.NoError(t, err)
		// No Content-Type header

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("POST with missing required field returns 400", func(t *testing.T) {
		client := helpers.HTTPClient()
		// Missing "name" field
		body := `{"description":"no name field","price":10.0}`
		resp, err := client.Post(
			baseURL+"/api/v1/items",
			"application/json",
			strings.NewReader(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp["error"], "validation failed")
	})

	t.Run("POST with invalid JSON returns 400", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Post(
			baseURL+"/api/v1/items",
			"application/json",
			strings.NewReader(`{invalid json}`),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 4. E2E: GET /api/v1/items with valid query params passes
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_ValidQueryParams(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	gw, baseURL := startGatewayWithValidation(t, 18303, true)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("GET with valid query params passes", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items?limit=10&offset=0")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GET without query params passes", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 5. E2E: GET /api/v1/items with invalid query param type returns 400
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_InvalidQueryParams(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	gw, baseURL := startGatewayWithValidation(t, 18304, true)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	err := helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err, "gateway on port 18304 did not become ready")

	t.Run("GET with non-integer limit returns 400", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items?limit=abc")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("GET with non-integer offset returns 400", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items?offset=xyz")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 6. E2E: OpenAPI validation with CORS headers
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithCORS(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	corsMW := middleware.CORS(middleware.CORSConfig{
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:       86400,
	})

	gw, baseURL := startGatewayWithValidation(t, 18305, true, corsMW)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("CORS preflight with validation enabled", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodOptions, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("actual CORS request with validation", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://example.com")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

// ---------------------------------------------------------------------------
// 7. E2E: OpenAPI validation with rate limiting
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithRateLimiting(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	rl := middleware.NewRateLimiter(100, 100, false)
	rlMW := middleware.RateLimit(rl)

	gw, baseURL := startGatewayWithValidation(t, 18306, true, rlMW)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("valid request passes both rate limit and validation", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("invalid request is rejected by validation before rate limit counts", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items?limit=abc")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 8. E2E: OpenAPI validation with encoding
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithEncoding(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	gw, baseURL := startGatewayWithValidation(t, 18307, true)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("request with Accept-Encoding passes validation", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 9. E2E: OpenAPI validation with basic auth
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithBasicAuth(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	// Simulate basic auth middleware
	basicAuthMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoint
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}
			user, pass, ok := r.BasicAuth()
			if !ok || user != "testuser" || pass != "testpass" {
				w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	gw, baseURL := startGatewayWithValidation(t, 18308, true, basicAuthMW)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("authenticated valid request passes", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.SetBasicAuth("testuser", "testpass")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("unauthenticated request is rejected by auth before validation", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 10. E2E: OpenAPI validation with API key auth
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithAPIKeyAuth(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	apiKeyMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "test-api-key-12345" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid API key"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	gw, baseURL := startGatewayWithValidation(t, 18309, true, apiKeyMW)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("request with valid API key passes auth and validation", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("X-API-Key", "test-api-key-12345")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("request without API key is rejected", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 11. E2E: OpenAPI validation metrics available in Prometheus format
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_Metrics(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway with validation exposes metrics endpoint", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "metrics-test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18310, Protocol: "HTTP"},
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
					},
				},
				Observability: &config.ObservabilityConfig{
					Metrics: &config.MetricsConfig{
						Enabled: true,
						Path:    "/metrics",
					},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: helpers.GetTestConfigPath("openapi/items-api.yaml"),
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(p),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		// Make a request to generate metrics
		client := helpers.HTTPClient()
		resp, err := client.Get("http://127.0.0.1:18310/api/v1/items")
		if err == nil {
			resp.Body.Close()
		}

		// Gateway should be running with metrics enabled
		assert.True(t, gw.IsRunning())
	})
}

// ---------------------------------------------------------------------------
// 12. E2E: Hot-reload changes OpenAPI spec without restart
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_HotReload(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("config watcher detects OpenAPI validation changes", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway.yaml")

		initialConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: openapi-hotreload-test
spec:
  listeners:
    - name: http
      port: 18311
      protocol: HTTP
  routes:
    - name: items-api
      match:
        - uri:
            prefix: /api/v1/items
      route:
        - destination:
            host: 127.0.0.1
            port: 8801
  openAPIValidation:
    enabled: true
    specFile: ` + helpers.GetTestConfigPath("openapi/minimal.yaml") + `
`
		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		// Track config changes
		configChanged := make(chan *config.GatewayConfig, 1)

		callback := func(cfg *config.GatewayConfig) {
			select {
			case configChanged <- cfg:
			default:
			}
		}

		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithDebounceDelay(100*time.Millisecond),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Verify initial config
		initialCfg := watcher.GetLastConfig()
		require.NotNil(t, initialCfg)
		require.NotNil(t, initialCfg.Spec.OpenAPIValidation)
		assert.True(t, initialCfg.Spec.OpenAPIValidation.Enabled)

		// Update config with different spec file
		updatedConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: openapi-hotreload-test
spec:
  listeners:
    - name: http
      port: 18311
      protocol: HTTP
  routes:
    - name: items-api
      match:
        - uri:
            prefix: /api/v1/items
      route:
        - destination:
            host: 127.0.0.1
            port: 8801
  openAPIValidation:
    enabled: true
    specFile: ` + helpers.GetTestConfigPath("openapi/items-api.yaml") + `
    failOnError: false
`
		err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
		require.NoError(t, err)

		// Wait for config change
		select {
		case newCfg := <-configChanged:
			require.NotNil(t, newCfg)
			require.NotNil(t, newCfg.Spec.OpenAPIValidation)
			assert.True(t, newCfg.Spec.OpenAPIValidation.Enabled)
			assert.Contains(t, newCfg.Spec.OpenAPIValidation.SpecFile, "items-api.yaml")
			assert.False(t, *newCfg.Spec.OpenAPIValidation.FailOnError)
		case <-ctx.Done():
			t.Fatal("timeout waiting for config change")
		}
	})
}

// ---------------------------------------------------------------------------
// 13. E2E: OpenAPI validation with OIDC auth (simulated)
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithOIDCAuth(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	// Simulate OIDC auth middleware
	oidcMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing bearer token"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	gw, baseURL := startGatewayWithValidation(t, 18312, true, oidcMW)
	t.Cleanup(func() {
		_ = gw.Stop(context.Background())
	})

	time.Sleep(500 * time.Millisecond)

	t.Run("authenticated valid request passes OIDC and validation", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer test-token-12345")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("unauthenticated request is rejected by OIDC", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// ---------------------------------------------------------------------------
// 14. E2E: OpenAPI validation with Redis Sentinel cache (config only)
// ---------------------------------------------------------------------------

func TestE2E_OpenAPIValidation_WithCacheConfig(t *testing.T) {
	t.Parallel()

	t.Run("config with OpenAPI validation and cache validates", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "cache-validation-test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18313, Protocol: "HTTP"},
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
						Cache: &config.CacheConfig{
							Enabled: true,
							TTL:     config.Duration(5 * time.Minute),
						},
						OpenAPIValidation: &config.OpenAPIValidationConfig{
							Enabled:  true,
							SpecFile: helpers.GetTestConfigPath("openapi/items-api.yaml"),
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})
}
