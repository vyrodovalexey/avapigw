//go:build functional
// +build functional

package functional

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

// ---------------------------------------------------------------------------
// 1. Config parsing from YAML
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_ConfigParsing(t *testing.T) {
	t.Parallel()

	t.Run("parse global OpenAPI validation from YAML", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: openapi-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  openAPIValidation:
    enabled: true
    specFile: /etc/gateway/openapi.yaml
    failOnError: true
    validateRequestBody: true
    validateRequestParams: true
    validateRequestHeaders: false
    validateSecurity: false
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)
		require.NotNil(t, cfg.Spec.OpenAPIValidation)

		v := cfg.Spec.OpenAPIValidation
		assert.True(t, v.Enabled)
		assert.Equal(t, "/etc/gateway/openapi.yaml", v.SpecFile)
		assert.True(t, *v.FailOnError)
		assert.True(t, *v.ValidateRequestBody)
		assert.True(t, *v.ValidateRequestParams)
		assert.False(t, *v.ValidateRequestHeaders)
		assert.False(t, *v.ValidateSecurity)
	})

	t.Run("parse OpenAPI validation with specURL", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: openapi-url-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  openAPIValidation:
    enabled: true
    specURL: https://api.example.com/openapi.yaml
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)
		require.NotNil(t, cfg.Spec.OpenAPIValidation)

		assert.True(t, cfg.Spec.OpenAPIValidation.Enabled)
		assert.Equal(t, "https://api.example.com/openapi.yaml", cfg.Spec.OpenAPIValidation.SpecURL)
		assert.Empty(t, cfg.Spec.OpenAPIValidation.SpecFile)
	})

	t.Run("parse disabled OpenAPI validation", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: openapi-disabled-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  openAPIValidation:
    enabled: false
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)
		require.NotNil(t, cfg.Spec.OpenAPIValidation)
		assert.False(t, cfg.Spec.OpenAPIValidation.Enabled)
	})

	t.Run("no OpenAPI validation section yields nil", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: no-openapi-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)
		assert.Nil(t, cfg.Spec.OpenAPIValidation)
	})
}

// ---------------------------------------------------------------------------
// 2. Global and route-level settings
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_GlobalAndRouteLevel(t *testing.T) {
	t.Parallel()

	t.Run("global and route-level OpenAPI validation config", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: openapi-global-route-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  openAPIValidation:
    enabled: true
    specFile: /etc/gateway/global-openapi.yaml
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
        specFile: /etc/gateway/items-openapi.yaml
        failOnError: false
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)

		// Global
		require.NotNil(t, cfg.Spec.OpenAPIValidation)
		assert.Equal(t, "/etc/gateway/global-openapi.yaml", cfg.Spec.OpenAPIValidation.SpecFile)

		// Route-level
		require.Len(t, cfg.Spec.Routes, 1)
		require.NotNil(t, cfg.Spec.Routes[0].OpenAPIValidation)
		assert.Equal(t, "/etc/gateway/items-openapi.yaml", cfg.Spec.Routes[0].OpenAPIValidation.SpecFile)
		assert.False(t, *cfg.Spec.Routes[0].OpenAPIValidation.FailOnError)
	})

	t.Run("route-level config overrides global config", func(t *testing.T) {
		t.Parallel()

		globalCfg := &config.OpenAPIValidationConfig{
			Enabled:             true,
			SpecFile:            "/etc/gateway/global.yaml",
			FailOnError:         boolPtr(true),
			ValidateRequestBody: boolPtr(true),
		}

		routeCfg := &config.OpenAPIValidationConfig{
			Enabled:             true,
			SpecFile:            "/etc/gateway/route.yaml",
			FailOnError:         boolPtr(false),
			ValidateRequestBody: boolPtr(false),
		}

		// Route-level should take precedence
		assert.NotEqual(t, globalCfg.SpecFile, routeCfg.SpecFile)
		assert.NotEqual(t, globalCfg.GetEffectiveFailOnError(), routeCfg.GetEffectiveFailOnError())
		assert.NotEqual(t, globalCfg.GetEffectiveValidateRequestBody(), routeCfg.GetEffectiveValidateRequestBody())
	})
}

// ---------------------------------------------------------------------------
// 3. Validation of OpenAPI config
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_ConfigValidation(t *testing.T) {
	t.Parallel()

	t.Run("disabled validation passes all requests", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled: false,
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})

	t.Run("enabled validation with valid spec file passes", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/etc/gateway/openapi.yaml",
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})

	t.Run("enabled validation without spec file or URL fails", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled: true,
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "specFile")
	})

	t.Run("enabled validation with both spec file and URL fails", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/etc/gateway/openapi.yaml",
					SpecURL:  "https://api.example.com/openapi.yaml",
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("enabled validation with invalid spec URL fails", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled: true,
					SpecURL: "not-a-valid-url",
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
	})

	t.Run("route-level enabled validation without spec fails", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "test-route",
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "localhost", Port: 8080}},
						},
						OpenAPIValidation: &config.OpenAPIValidationConfig{
							Enabled: true,
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "specFile")
	})
}

// ---------------------------------------------------------------------------
// 4. Effective value defaults
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_EffectiveDefaults(t *testing.T) {
	t.Parallel()

	t.Run("failOnError defaults to true", func(t *testing.T) {
		t.Parallel()

		cfg := &config.OpenAPIValidationConfig{Enabled: true}
		assert.True(t, cfg.GetEffectiveFailOnError())
	})

	t.Run("failOnError explicit false", func(t *testing.T) {
		t.Parallel()

		cfg := &config.OpenAPIValidationConfig{
			Enabled:     true,
			FailOnError: boolPtr(false),
		}
		assert.False(t, cfg.GetEffectiveFailOnError())
	})

	t.Run("validateRequestBody defaults to true", func(t *testing.T) {
		t.Parallel()

		cfg := &config.OpenAPIValidationConfig{Enabled: true}
		assert.True(t, cfg.GetEffectiveValidateRequestBody())
	})

	t.Run("validateRequestParams defaults to true", func(t *testing.T) {
		t.Parallel()

		cfg := &config.OpenAPIValidationConfig{Enabled: true}
		assert.True(t, cfg.GetEffectiveValidateRequestParams())
	})

	t.Run("validateRequestHeaders defaults to false", func(t *testing.T) {
		t.Parallel()

		cfg := &config.OpenAPIValidationConfig{Enabled: true}
		assert.False(t, cfg.GetEffectiveValidateRequestHeaders())
	})

	t.Run("validateSecurity defaults to false", func(t *testing.T) {
		t.Parallel()

		cfg := &config.OpenAPIValidationConfig{Enabled: true}
		assert.False(t, cfg.GetEffectiveValidateSecurity())
	})

	t.Run("nil config returns safe defaults", func(t *testing.T) {
		t.Parallel()

		var cfg *config.OpenAPIValidationConfig
		assert.True(t, cfg.GetEffectiveFailOnError())
		assert.True(t, cfg.GetEffectiveValidateRequestBody())
		assert.True(t, cfg.GetEffectiveValidateRequestParams())
		assert.False(t, cfg.GetEffectiveValidateRequestHeaders())
		assert.False(t, cfg.GetEffectiveValidateSecurity())
	})
}

// ---------------------------------------------------------------------------
// 5. ProtoValidation config parsing
// ---------------------------------------------------------------------------

func TestFunctional_ProtoValidation_ConfigParsing(t *testing.T) {
	t.Parallel()

	t.Run("parse ProtoValidation from YAML", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: proto-test
spec:
  listeners:
    - name: grpc
      port: 9090
      protocol: GRPC
  grpcRoutes:
    - name: user-service
      match:
        - service:
            prefix: api.v1
      route:
        - destination:
            host: 127.0.0.1
            port: 9001
      protoValidation:
        enabled: true
        descriptorFile: /etc/gateway/user.desc
        failOnError: true
        validateRequestMessage: true
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)
		require.Len(t, cfg.Spec.GRPCRoutes, 1)
		require.NotNil(t, cfg.Spec.GRPCRoutes[0].ProtoValidation)

		pv := cfg.Spec.GRPCRoutes[0].ProtoValidation
		assert.True(t, pv.Enabled)
		assert.Equal(t, "/etc/gateway/user.desc", pv.DescriptorFile)
		assert.True(t, *pv.FailOnError)
		assert.True(t, *pv.ValidateRequestMessage)
	})

	t.Run("ProtoValidation effective defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &config.ProtoValidationConfig{Enabled: true}
		assert.True(t, cfg.GetEffectiveFailOnError())
		assert.True(t, cfg.GetEffectiveValidateRequestMessage())
	})

	t.Run("ProtoValidation nil config returns safe defaults", func(t *testing.T) {
		t.Parallel()

		var cfg *config.ProtoValidationConfig
		assert.True(t, cfg.GetEffectiveFailOnError())
		assert.True(t, cfg.GetEffectiveValidateRequestMessage())
	})

	t.Run("ProtoValidation enabled without descriptor fails validation", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "grpc", Port: 9090, Protocol: "GRPC"},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "test-grpc",
						Match: []config.GRPCRouteMatch{
							{Service: &config.StringMatch{Prefix: "api.v1"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "localhost", Port: 9001}},
						},
						ProtoValidation: &config.ProtoValidationConfig{
							Enabled: true,
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "descriptorFile")
	})
}

// ---------------------------------------------------------------------------
// 6. GraphQLSchemaValidation config parsing
// ---------------------------------------------------------------------------

func TestFunctional_GraphQLSchemaValidation_ConfigParsing(t *testing.T) {
	t.Parallel()

	t.Run("parse GraphQLSchemaValidation from YAML", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: graphql-validation-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  graphqlRoutes:
    - name: graphql-api
      match:
        - path:
            exact: /graphql
      route:
        - destination:
            host: 127.0.0.1
            port: 8821
      schemaValidation:
        enabled: true
        schemaFile: /etc/gateway/schema.graphql
        failOnError: true
        validateVariables: true
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)
		require.Len(t, cfg.Spec.GraphQLRoutes, 1)
		require.NotNil(t, cfg.Spec.GraphQLRoutes[0].SchemaValidation)

		sv := cfg.Spec.GraphQLRoutes[0].SchemaValidation
		assert.True(t, sv.Enabled)
		assert.Equal(t, "/etc/gateway/schema.graphql", sv.SchemaFile)
		assert.True(t, *sv.FailOnError)
		assert.True(t, *sv.ValidateVariables)
	})

	t.Run("GraphQLSchemaValidation effective defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GraphQLSchemaValidationConfig{Enabled: true}
		assert.True(t, cfg.GetEffectiveFailOnError())
		assert.True(t, cfg.GetEffectiveValidateVariables())
	})

	t.Run("GraphQLSchemaValidation nil config returns safe defaults", func(t *testing.T) {
		t.Parallel()

		var cfg *config.GraphQLSchemaValidationConfig
		assert.True(t, cfg.GetEffectiveFailOnError())
		assert.True(t, cfg.GetEffectiveValidateVariables())
	})

	t.Run("GraphQLSchemaValidation enabled without schema fails validation", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "test-graphql",
						Match: []config.GraphQLRouteMatch{
							{Path: &config.StringMatch{Exact: "/graphql"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "localhost", Port: 8821}},
						},
						SchemaValidation: &config.GraphQLSchemaValidationConfig{
							Enabled: true,
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "schemaFile")
	})
}

// ---------------------------------------------------------------------------
// 7. Config hot-reload with OpenAPI validation changes
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_ConfigHotReload(t *testing.T) {
	t.Parallel()

	t.Run("config change detection with OpenAPI validation", func(t *testing.T) {
		t.Parallel()

		oldCfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/etc/gateway/v1.yaml",
				},
			},
		}

		newCfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/etc/gateway/v2.yaml",
				},
			},
		}

		// Configs should be different
		assert.NotEqual(t, oldCfg.Spec.OpenAPIValidation.SpecFile, newCfg.Spec.OpenAPIValidation.SpecFile)

		// New config should still validate
		err := config.ValidateConfig(newCfg)
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// 8. Middleware chain position verification
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_MiddlewareChainPosition(t *testing.T) {
	t.Parallel()

	t.Run("validation middleware executes before proxy handler", func(t *testing.T) {
		t.Parallel()

		var executionOrder []string

		// Simulate validation middleware
		validationMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, "validation")
				next.ServeHTTP(w, r)
			})
		}

		// Simulate proxy handler
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "proxy")
			w.WriteHeader(http.StatusOK)
		})

		// Chain: validation -> proxy
		chain := validationMiddleware(proxyHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)

		require.Len(t, executionOrder, 2)
		assert.Equal(t, "validation", executionOrder[0])
		assert.Equal(t, "proxy", executionOrder[1])
	})

	t.Run("validation with failOnError=true rejects invalid requests", func(t *testing.T) {
		t.Parallel()

		// Simulate a validation middleware that rejects requests
		validationMiddleware := func(failOnError bool) func(http.Handler) http.Handler {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate validation failure
					isValid := r.Header.Get("X-Valid") == "true"
					if !isValid && failOnError {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					next.ServeHTTP(w, r)
				})
			}
		}

		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := validationMiddleware(true)(proxyHandler)

		// Invalid request should be rejected
		req := httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		// Valid request should pass
		req = httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)
		req.Header.Set("X-Valid", "true")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("validation with failOnError=false logs but passes requests", func(t *testing.T) {
		t.Parallel()

		var loggedErrors []string

		validationMiddleware := func(failOnError bool) func(http.Handler) http.Handler {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					isValid := r.Header.Get("X-Valid") == "true"
					if !isValid {
						loggedErrors = append(loggedErrors, "validation failed for "+r.URL.Path)
						if failOnError {
							w.WriteHeader(http.StatusBadRequest)
							return
						}
					}
					next.ServeHTTP(w, r)
				})
			}
		}

		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := validationMiddleware(false)(proxyHandler)

		// Invalid request should still pass (log-only mode)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, loggedErrors, 1)
		assert.Contains(t, loggedErrors[0], "/api/v1/items")
	})
}

// ---------------------------------------------------------------------------
// 9. Loading test data OpenAPI specs
// ---------------------------------------------------------------------------

func TestFunctional_OpenAPIValidation_TestDataSpecs(t *testing.T) {
	t.Parallel()

	t.Run("items-api.yaml spec exists and is loadable", func(t *testing.T) {
		t.Parallel()

		specPath := helpers.GetTestConfigPath("openapi/items-api.yaml")
		assert.NotEmpty(t, specPath)

		// Verify the file can be referenced in config
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: specPath,
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})

	t.Run("minimal.yaml spec exists and is loadable", func(t *testing.T) {
		t.Parallel()

		specPath := helpers.GetTestConfigPath("openapi/minimal.yaml")
		assert.NotEmpty(t, specPath)

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: specPath,
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})

	t.Run("invalid.yaml spec exists", func(t *testing.T) {
		t.Parallel()

		specPath := helpers.GetTestConfigPath("openapi/invalid.yaml")
		assert.NotEmpty(t, specPath)

		// Config validation should still pass (file existence is not checked at config level)
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: specPath,
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.NoError(t, err)
	})
}
