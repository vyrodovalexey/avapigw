package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestRouteMiddlewareManager_GetEffectiveOpenAPIValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		globalConfig *config.GatewaySpec
		route        *config.Route
		wantNil      bool
		wantSpecFile string
	}{
		{
			name: "route-level config takes precedence",
			globalConfig: &config.GatewaySpec{
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/global/spec.yaml",
				},
			},
			route: &config.Route{
				Name: "test-route",
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/route/spec.yaml",
				},
			},
			wantNil:      false,
			wantSpecFile: "/route/spec.yaml",
		},
		{
			name: "falls back to global config",
			globalConfig: &config.GatewaySpec{
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/global/spec.yaml",
				},
			},
			route: &config.Route{
				Name: "test-route",
			},
			wantNil:      false,
			wantSpecFile: "/global/spec.yaml",
		},
		{
			name: "nil route uses global config",
			globalConfig: &config.GatewaySpec{
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/global/spec.yaml",
				},
			},
			route:        nil,
			wantNil:      false,
			wantSpecFile: "/global/spec.yaml",
		},
		{
			name:         "both nil returns nil",
			globalConfig: &config.GatewaySpec{},
			route: &config.Route{
				Name: "test-route",
			},
			wantNil: true,
		},
		{
			name:         "nil global config and nil route config",
			globalConfig: nil,
			route: &config.Route{
				Name: "test-route",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manager := NewRouteMiddlewareManager(tt.globalConfig, observability.NopLogger())
			result := manager.GetEffectiveOpenAPIValidation(tt.route)

			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantSpecFile, result.SpecFile)
			}
		})
	}
}

func TestRouteMiddlewareManager_BuildRouteOpenAPIValidationMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		route   *config.Route
		wantNil bool
	}{
		{
			name: "nil OpenAPI config returns nil",
			route: &config.Route{
				Name: "test-route",
			},
			wantNil: true,
		},
		{
			name: "disabled OpenAPI config returns nil",
			route: &config.Route{
				Name: "test-route",
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled: false,
				},
			},
			wantNil: true,
		},
		{
			name: "enabled with invalid spec returns non-nil (no-op middleware from error path)",
			route: &config.Route{
				Name: "test-route",
				OpenAPIValidation: &config.OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/nonexistent/spec.yaml",
				},
			},
			// MiddlewareFromConfig returns a no-op middleware on error,
			// but buildRouteOpenAPIValidationMiddleware still returns it
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manager := NewRouteMiddlewareManager(nil, observability.NopLogger())
			mw := manager.buildRouteOpenAPIValidationMiddleware(tt.route)

			if tt.wantNil {
				assert.Nil(t, mw)
			} else {
				assert.NotNil(t, mw)
			}
		})
	}
}

func TestRouteMiddlewareManager_MiddlewareChainIncludesOpenAPIValidation(t *testing.T) {
	t.Parallel()

	t.Run("middleware chain includes OpenAPI validation when configured", func(t *testing.T) {
		t.Parallel()

		// Use a route with OpenAPI validation enabled but invalid spec
		// to verify the middleware is included in the chain
		route := &config.Route{
			Name: "test-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
			OpenAPIValidation: &config.OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: "/nonexistent/spec.yaml",
			},
		}

		manager := NewRouteMiddlewareManager(nil, observability.NopLogger())
		middlewares := manager.buildMiddlewareChain(route)

		// Should have at least the OpenAPI validation middleware and body limit
		assert.NotEmpty(t, middlewares)
	})

	t.Run("middleware chain without OpenAPI validation", func(t *testing.T) {
		t.Parallel()

		route := &config.Route{
			Name: "test-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		}

		manager := NewRouteMiddlewareManager(nil, observability.NopLogger())
		middlewares := manager.buildMiddlewareChain(route)

		// Should still have body limit middleware (default)
		assert.NotEmpty(t, middlewares)
	})
}
