//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
package operator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// TestFunctional_GRPCRoute_Validation tests GRPCRoute CRD validation.
func TestFunctional_GRPCRoute_Validation(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid basic gRPC route", func(t *testing.T) {
		route := createBasicGRPCRoute()
		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid gRPC route with all fields", func(t *testing.T) {
		route := createFullGRPCRoute()
		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid service match - multiple match types", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Service = &avapigwv1alpha1.StringMatch{
			Exact:  "api.v1.UserService",
			Prefix: "api.v1",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one of exact, prefix, or regex")
	})

	t.Run("invalid service regex", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Service = &avapigwv1alpha1.StringMatch{
			Regex: "[invalid",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})

	t.Run("invalid method match - multiple match types", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Method = &avapigwv1alpha1.StringMatch{
			Exact:  "GetUser",
			Prefix: "Get",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one of exact, prefix, or regex")
	})

	t.Run("invalid destination port", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Route[0].Destination.Port = 0
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid weight - negative", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Route[0].Weight = -1
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("invalid timeout duration", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Timeout = "invalid"
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timeout")
	})

	t.Run("invalid retry attempts", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Retries = &avapigwv1alpha1.GRPCRetryPolicy{
			Attempts: 0,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attempts must be between 1 and 10")
	})

	t.Run("invalid retry condition", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Retries = &avapigwv1alpha1.GRPCRetryPolicy{
			Attempts: 3,
			RetryOn:  "invalid-condition",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "retries.retryOn contains invalid gRPC status")
	})

	t.Run("valid gRPC retry conditions", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Retries = &avapigwv1alpha1.GRPCRetryPolicy{
			Attempts: 3,
			RetryOn:  "unavailable,resource-exhausted,internal",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCRoute_MetadataMatch tests metadata matching validation.
func TestFunctional_GRPCRoute_MetadataMatch(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid metadata match - exact", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Metadata = []avapigwv1alpha1.MetadataMatch{
			{Name: "x-tenant-id", Exact: "tenant-123"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid metadata match - present", func(t *testing.T) {
		route := createBasicGRPCRoute()
		present := true
		route.Spec.Match[0].Metadata = []avapigwv1alpha1.MetadataMatch{
			{Name: "x-tenant-id", Present: &present},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid metadata match - absent", func(t *testing.T) {
		route := createBasicGRPCRoute()
		absent := true
		route.Spec.Match[0].Metadata = []avapigwv1alpha1.MetadataMatch{
			{Name: "x-internal", Absent: &absent},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid metadata match - empty name", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Metadata = []avapigwv1alpha1.MetadataMatch{
			{Name: "", Exact: "value"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("invalid metadata match - invalid regex", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Metadata = []avapigwv1alpha1.MetadataMatch{
			{Name: "x-tenant-id", Regex: "[invalid"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})
}

// TestFunctional_GRPCRoute_Authority tests authority matching validation.
func TestFunctional_GRPCRoute_Authority(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid authority match - exact", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Authority = &avapigwv1alpha1.StringMatch{
			Exact: "grpc.example.com",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid authority match - prefix", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Authority = &avapigwv1alpha1.StringMatch{
			Prefix: "grpc.",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid authority match - multiple match types", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Match[0].Authority = &avapigwv1alpha1.StringMatch{
			Exact:  "grpc.example.com",
			Prefix: "grpc.",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one of exact, prefix, or regex")
	})
}

// TestFunctional_GRPCRoute_Transform tests gRPC transform configuration validation.
func TestFunctional_GRPCRoute_Transform(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid transform with field mask", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Transform = &avapigwv1alpha1.GRPCTransformConfig{
			FieldMask: &avapigwv1alpha1.FieldMaskConfig{
				Paths: []string{"user.id", "user.name"},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid transform with metadata manipulation", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.Transform = &avapigwv1alpha1.GRPCTransformConfig{
			Metadata: &avapigwv1alpha1.MetadataManipulation{
				Static: map[string]string{
					"x-source": "gateway",
				},
				Dynamic: map[string]string{
					"x-request-id": "{{.RequestID}}",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCRoute_RateLimit tests rate limit configuration validation.
func TestFunctional_GRPCRoute_RateLimit(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid rate limit", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCRoute_TLS tests TLS configuration validation.
func TestFunctional_GRPCRoute_TLS(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid TLS config with Vault", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.TLS = &avapigwv1alpha1.RouteTLSConfig{
			SNIHosts: []string{"grpc.example.com"},
			Vault: &avapigwv1alpha1.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "grpc-route",
				CommonName: "grpc.example.com",
				TTL:        "24h",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCRoute_Authentication tests authentication configuration validation.
func TestFunctional_GRPCRoute_Authentication(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	tests := []struct {
		name    string
		auth    *avapigwv1alpha1.AuthenticationConfig
		wantErr bool
		errMsg  string
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
			name: "valid JWT with claim mapping",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled:   true,
					Issuer:    "https://auth.example.com",
					JWKSURL:   "https://auth.example.com/.well-known/jwks.json",
					Algorithm: "RS256",
					ClaimMapping: &avapigwv1alpha1.ClaimMappingConfig{
						Roles:  "roles",
						Scopes: "scope",
					},
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
			name: "valid OIDC authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:      "keycloak",
							IssuerURL: "https://keycloak.example.com/realms/myrealm",
							ClientID:  "grpc-client",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid authentication with skip paths",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					Issuer:  "https://auth.example.com",
					JWKSURL: "https://auth.example.com/.well-known/jwks.json",
				},
				SkipPaths: []string{"/grpc.health.v1.Health/*"},
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
			route := createBasicGRPCRoute()
			route.Spec.Authentication = tt.auth
			_, err := validator.ValidateCreate(nil, route)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GRPCRoute_Authorization tests authorization configuration validation.
func TestFunctional_GRPCRoute_Authorization(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	tests := []struct {
		name    string
		authz   *avapigwv1alpha1.AuthorizationConfig
		wantErr bool
		errMsg  string
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
							Name:      "service-policy",
							Roles:     []string{"service"},
							Resources: []string{"/api.v1.*"},
							Actions:   []string{"*"},
							Effect:    "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ABAC authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				ABAC: &avapigwv1alpha1.ABACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.ABACPolicyConfig{
						{
							Name:       "tenant-policy",
							Expression: "request.metadata['x-tenant-id'] == resource.tenant_id",
							Effect:     "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid external authorization with OPA",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				External: &avapigwv1alpha1.ExternalAuthzConfig{
					Enabled: true,
					OPA: &avapigwv1alpha1.OPAAuthzConfig{
						URL:    "http://opa:8181/v1/data/grpc/authz/allow",
						Policy: "grpc/authz/allow",
					},
					Timeout: "5s",
				},
			},
			wantErr: false,
		},
		{
			name: "valid authorization with cache",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.RBACPolicyConfig{
						{
							Name:   "basic-policy",
							Roles:  []string{"user"},
							Effect: "allow",
						},
					},
				},
				Cache: &avapigwv1alpha1.AuthzCacheConfig{
					Enabled: true,
					TTL:     "5m",
					MaxSize: 1000,
					Type:    "redis",
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
			route := createBasicGRPCRoute()
			route.Spec.Authorization = tt.authz
			_, err := validator.ValidateCreate(nil, route)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GRPCRoute_MaxSessions tests max sessions configuration validation.
func TestFunctional_GRPCRoute_MaxSessions(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	tests := []struct {
		name        string
		maxSessions *avapigwv1alpha1.MaxSessionsConfig
		wantErr     bool
		errMsg      string
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
			name: "valid max sessions without queue",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
				QueueSize:     0,
			},
			wantErr: false,
		},
		{
			name: "valid max sessions with large concurrent",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 10000,
				QueueSize:     1000,
				QueueTimeout:  "30s",
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
			route := createBasicGRPCRoute()
			route.Spec.MaxSessions = tt.maxSessions
			_, err := validator.ValidateCreate(nil, route)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GRPCRoute_RequestLimits tests request limits configuration validation.
func TestFunctional_GRPCRoute_RequestLimits(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	tests := []struct {
		name          string
		requestLimits *avapigwv1alpha1.RequestLimitsConfig
		wantErr       bool
		errMsg        string
	}{
		{
			name: "valid request limits",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize:   4194304,
				MaxHeaderSize: 65536,
			},
			wantErr: false,
		},
		{
			name: "valid request limits - body only",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize: 10485760,
			},
			wantErr: false,
		},
		{
			name: "valid request limits - header only",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxHeaderSize: 1048576,
			},
			wantErr: false,
		},
		{
			name: "valid request limits - large values",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize:   104857600,
				MaxHeaderSize: 10485760,
			},
			wantErr: false,
		},
		{
			name:          "nil request limits",
			requestLimits: nil,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := createBasicGRPCRoute()
			route.Spec.RequestLimits = tt.requestLimits
			_, err := validator.ValidateCreate(nil, route)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFunctional_GRPCRoute_CombinedNewFields tests combined new fields.
func TestFunctional_GRPCRoute_CombinedNewFields(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid route with all new fields", func(t *testing.T) {
		route := createBasicGRPCRoute()
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
						Name:   "service-policy",
						Roles:  []string{"service"},
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
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid full route with all fields", func(t *testing.T) {
		route := createFullGRPCRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled: true,
				Issuer:  "https://auth.example.com",
				JWKSURL: "https://auth.example.com/.well-known/jwks.json",
			},
		}
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:   "allow-all",
						Roles:  []string{"user"},
						Effect: "allow",
					},
				},
			},
		}
		route.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
		}
		route.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize: 10485760,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCRoute_Update tests GRPCRoute update validation.
func TestFunctional_GRPCRoute_Update(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid update", func(t *testing.T) {
		oldRoute := createBasicGRPCRoute()
		newRoute := createBasicGRPCRoute()
		newRoute.Spec.Timeout = "60s"
		warnings, err := validator.ValidateUpdate(nil, oldRoute, newRoute)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		oldRoute := createBasicGRPCRoute()
		newRoute := createBasicGRPCRoute()
		newRoute.Spec.Route[0].Destination.Port = 0
		_, err := validator.ValidateUpdate(nil, oldRoute, newRoute)
		assert.Error(t, err)
	})
}

// TestFunctional_GRPCRoute_Delete tests GRPCRoute delete validation.
func TestFunctional_GRPCRoute_Delete(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		route := createBasicGRPCRoute()
		warnings, err := validator.ValidateDelete(nil, route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// Helper functions

func createBasicGRPCRoute() *avapigwv1alpha1.GRPCRoute {
	return &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Prefix: "api.v1",
					},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 9000,
					},
					Weight: 100,
				},
			},
			Timeout: "30s",
		},
	}
}

func createFullGRPCRoute() *avapigwv1alpha1.GRPCRoute {
	route := createBasicGRPCRoute()
	route.Name = "full-grpc-route"

	present := true
	route.Spec.Match[0].Service = &avapigwv1alpha1.StringMatch{
		Exact: "api.v1.UserService",
	}
	route.Spec.Match[0].Method = &avapigwv1alpha1.StringMatch{
		Exact: "GetUser",
	}
	route.Spec.Match[0].Metadata = []avapigwv1alpha1.MetadataMatch{
		{Name: "x-tenant-id", Present: &present},
	}
	route.Spec.Match[0].Authority = &avapigwv1alpha1.StringMatch{
		Exact: "grpc.example.com",
	}

	route.Spec.Retries = &avapigwv1alpha1.GRPCRetryPolicy{
		Attempts:            3,
		PerTryTimeout:       "10s",
		RetryOn:             "unavailable,resource-exhausted",
		BackoffBaseInterval: "100ms",
		BackoffMaxInterval:  "1s",
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

	route.Spec.Transform = &avapigwv1alpha1.GRPCTransformConfig{
		FieldMask: &avapigwv1alpha1.FieldMaskConfig{
			Paths: []string{"user.id", "user.name"},
		},
		Metadata: &avapigwv1alpha1.MetadataManipulation{
			Static: map[string]string{"x-source": "gateway"},
		},
	}

	return route
}
