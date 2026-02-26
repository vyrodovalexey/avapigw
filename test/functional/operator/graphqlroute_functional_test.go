//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// TestFunctional_GraphQLRoute_Validation tests GraphQLRoute CRD validation.
func TestFunctional_GraphQLRoute_Validation(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("valid basic GraphQL route", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GraphQL route with all fields", func(t *testing.T) {
		t.Parallel()

		route := createFullGraphQLRoute()
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid path match - multiple match types", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Match[0].Path = &avapigwv1alpha1.StringMatch{
			Exact:  "/graphql",
			Prefix: "/graphql",
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one of exact, prefix, or regex")
	})

	t.Run("invalid path regex", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Match[0].Path = &avapigwv1alpha1.StringMatch{
			Regex: "[invalid",
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})

	t.Run("invalid operation type", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Match[0].OperationType = "invalid"
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "operationType must be one of")
	})

	t.Run("valid operation types", func(t *testing.T) {
		t.Parallel()

		validOps := []string{"query", "mutation", "subscription"}
		for _, op := range validOps {
			route := createBasicGraphQLRoute()
			route.Spec.Match[0].OperationType = op
			_, err := validator.ValidateCreate(context.Background(), route)
			assert.NoError(t, err, "operation type %q should be valid", op)
		}
	})

	t.Run("invalid operation name match - multiple match types", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Match[0].OperationName = &avapigwv1alpha1.StringMatch{
			Exact:  "GetUsers",
			Prefix: "Get",
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one of exact, prefix, or regex")
	})

	t.Run("invalid destination port", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Route[0].Destination.Port = 0
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid weight - negative", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Route[0].Weight = -1
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("invalid timeout duration", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Timeout = "invalid"
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timeout")
	})

	t.Run("invalid retry attempts", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Retries = &avapigwv1alpha1.RetryPolicy{
			Attempts: 0,
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attempts must be between 1 and 10")
	})

	t.Run("invalid header match - empty name", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.GraphQLHeaderMatch{
			{Name: "", Exact: "value"},
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("invalid header match - invalid regex", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.GraphQLHeaderMatch{
			{Name: "X-Test", Regex: "[invalid"},
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})

	t.Run("negative depth limit", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.DepthLimit = -1
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "depthLimit must be non-negative")
	})

	t.Run("negative complexity limit", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.ComplexityLimit = -1
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "complexityLimit must be non-negative")
	})

	t.Run("invalid allowed operations", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.AllowedOperations = []string{"query", "invalid"}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("valid allowed operations", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.AllowedOperations = []string{"query", "mutation", "subscription"}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})

	t.Run("zero depth and complexity limits are valid", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.DepthLimit = 0
		route.Spec.ComplexityLimit = 0
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GraphQLRoute_Authentication tests authentication configuration validation.
func TestFunctional_GraphQLRoute_Authentication(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	tests := []struct {
		name    string
		auth    *avapigwv1alpha1.AuthenticationConfig
		wantErr bool
	}{
		{
			name: "valid JWT authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled:   true,
					Issuer:    "https://auth.example.com",
					JWKSURL:   "https://auth.example.com/.well-known/jwks.json",
					Algorithm: "RS256",
				},
			},
			wantErr: false,
		},
		{
			name: "valid mTLS authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS: &avapigwv1alpha1.MTLSAuthConfig{
					Enabled:         true,
					CAFile:          "/certs/ca.crt",
					ExtractIdentity: "cn",
				},
			},
			wantErr: false,
		},
		{
			name: "disabled authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := createBasicGraphQLRoute()
			route.Spec.Authentication = tt.auth
			_, err := validator.ValidateCreate(context.Background(), route)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GraphQLRoute_Authorization tests authorization configuration validation.
func TestFunctional_GraphQLRoute_Authorization(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	tests := []struct {
		name    string
		authz   *avapigwv1alpha1.AuthorizationConfig
		wantErr bool
	}{
		{
			name: "valid RBAC authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.RBACPolicyConfig{
						{
							Name:      "graphql-policy",
							Roles:     []string{"user"},
							Resources: []string{"/graphql"},
							Actions:   []string{"*"},
							Effect:    "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "disabled authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := createBasicGraphQLRoute()
			route.Spec.Authorization = tt.authz
			_, err := validator.ValidateCreate(context.Background(), route)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GraphQLRoute_MaxSessions tests max sessions configuration validation.
func TestFunctional_GraphQLRoute_MaxSessions(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	tests := []struct {
		name        string
		maxSessions *avapigwv1alpha1.MaxSessionsConfig
		wantErr     bool
	}{
		{
			name: "valid max sessions config",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 500,
				QueueSize:     50,
				QueueTimeout:  "10s",
			},
			wantErr: false,
		},
		{
			name: "invalid max sessions - zero max concurrent",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 0,
			},
			wantErr: true,
		},
		{
			name: "disabled max sessions",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := createBasicGraphQLRoute()
			route.Spec.MaxSessions = tt.maxSessions
			_, err := validator.ValidateCreate(context.Background(), route)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GraphQLRoute_TLS tests TLS configuration validation.
func TestFunctional_GraphQLRoute_TLS(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("valid TLS config with Vault", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.TLS = &avapigwv1alpha1.RouteTLSConfig{
			SNIHosts: []string{"graphql.example.com"},
			Vault: &avapigwv1alpha1.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "graphql-route",
				CommonName: "graphql.example.com",
				TTL:        "24h",
			},
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GraphQLRoute_RateLimit tests rate limit configuration validation.
func TestFunctional_GraphQLRoute_RateLimit(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("valid rate limit", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GraphQLRoute_Update tests GraphQLRoute update validation.
func TestFunctional_GraphQLRoute_Update(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("valid update", func(t *testing.T) {
		t.Parallel()

		oldRoute := createBasicGraphQLRoute()
		newRoute := createBasicGraphQLRoute()
		newRoute.Spec.Timeout = "60s"
		warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		t.Parallel()

		oldRoute := createBasicGraphQLRoute()
		newRoute := createBasicGraphQLRoute()
		newRoute.Spec.Route[0].Destination.Port = 0
		_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.Error(t, err)
	})
}

// TestFunctional_GraphQLRoute_Delete tests GraphQLRoute delete validation.
func TestFunctional_GraphQLRoute_Delete(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		warnings, err := validator.ValidateDelete(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// TestFunctional_GraphQLRoute_CombinedFields tests combined GraphQL-specific fields.
func TestFunctional_GraphQLRoute_CombinedFields(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("valid route with all GraphQL-specific fields", func(t *testing.T) {
		t.Parallel()

		route := createFullGraphQLRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://auth.example.com",
				JWKSURL:   "https://auth.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
			},
		}
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:   "graphql-policy",
						Roles:  []string{"user"},
						Effect: "allow",
					},
				},
			},
		}
		route.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 500,
			QueueSize:     50,
			QueueTimeout:  "10s",
		}
		route.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   4194304,
			MaxHeaderSize: 65536,
		}
		_, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})
}

// Helper functions

func createBasicGraphQLRoute() *avapigwv1alpha1.GraphQLRoute {
	return &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "graphql-backend",
						Port: 8821,
					},
					Weight: 100,
				},
			},
			Timeout:         "30s",
			DepthLimit:      10,
			ComplexityLimit: 100,
		},
	}
}

func createFullGraphQLRoute() *avapigwv1alpha1.GraphQLRoute {
	route := createBasicGraphQLRoute()
	route.Name = "full-graphql-route"

	introspectionEnabled := true
	route.Spec.Match[0].Path = &avapigwv1alpha1.StringMatch{
		Exact: "/graphql",
	}
	route.Spec.Match[0].OperationType = "query"
	route.Spec.Match[0].OperationName = &avapigwv1alpha1.StringMatch{
		Prefix: "Get",
	}
	route.Spec.Match[0].Headers = []avapigwv1alpha1.GraphQLHeaderMatch{
		{Name: "X-API-Version", Exact: "v2"},
	}

	route.Spec.DepthLimit = 15
	route.Spec.ComplexityLimit = 200
	route.Spec.IntrospectionEnabled = &introspectionEnabled
	route.Spec.AllowedOperations = []string{"query", "mutation"}

	route.Spec.Retries = &avapigwv1alpha1.RetryPolicy{
		Attempts:      3,
		PerTryTimeout: "10s",
	}

	route.Spec.Headers = &avapigwv1alpha1.HeaderManipulation{
		Request: &avapigwv1alpha1.HeaderOperation{
			Set: map[string]string{"x-gateway": "avapigw"},
		},
	}

	route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
	}

	return route
}
