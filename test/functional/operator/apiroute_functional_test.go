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

// TestFunctional_APIRoute_Validation tests APIRoute CRD validation.
func TestFunctional_APIRoute_Validation(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid basic route", func(t *testing.T) {
		route := createBasicAPIRoute()
		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid route with all fields", func(t *testing.T) {
		route := createFullAPIRoute()
		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		// May have warnings for conflicting configs
		_ = warnings
	})

	t.Run("invalid URI match - multiple match types", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].URI = &avapigwv1alpha1.URIMatch{
			Exact:  "/api/v1",
			Prefix: "/api",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one of exact, prefix, or regex")
	})

	t.Run("invalid URI regex", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].URI = &avapigwv1alpha1.URIMatch{
			Regex: "[invalid",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})

	t.Run("invalid HTTP method", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].Methods = []string{"INVALID"}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HTTP method")
	})

	t.Run("invalid destination port", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Route[0].Destination.Port = 0
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid destination port - too high", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Route[0].Destination.Port = 70000
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid weight - negative", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Route[0].Weight = -1
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("invalid weight - too high", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Route[0].Weight = 150
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("invalid total weight", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Route = []avapigwv1alpha1.RouteDestination{
			{
				Destination: avapigwv1alpha1.Destination{Host: "backend1", Port: 8080},
				Weight:      60,
			},
			{
				Destination: avapigwv1alpha1.Destination{Host: "backend2", Port: 8080},
				Weight:      60,
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "total weight")
	})

	t.Run("invalid timeout duration", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Timeout = "invalid"
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timeout")
	})

	t.Run("invalid retry attempts", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Retries = &avapigwv1alpha1.RetryPolicy{
			Attempts: 0,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attempts must be between 1 and 10")
	})

	t.Run("invalid retry attempts - too high", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Retries = &avapigwv1alpha1.RetryPolicy{
			Attempts: 15,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attempts must be between 1 and 10")
	})

	t.Run("invalid retry condition", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Retries = &avapigwv1alpha1.RetryPolicy{
			Attempts: 3,
			RetryOn:  "invalid-condition",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid condition")
	})

	t.Run("invalid redirect code", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Redirect = &avapigwv1alpha1.RedirectConfig{
			URI:  "/new-path",
			Code: 200,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect.code must be one of")
	})

	t.Run("invalid redirect scheme", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Redirect = &avapigwv1alpha1.RedirectConfig{
			URI:    "/new-path",
			Scheme: "ftp",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect.scheme must be")
	})

	t.Run("invalid direct response status", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.DirectResponse = &avapigwv1alpha1.DirectResponseConfig{
			Status: 50,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directResponse.status must be between 100 and 599")
	})

	t.Run("invalid fault delay percentage", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Fault = &avapigwv1alpha1.FaultInjection{
			Delay: &avapigwv1alpha1.FaultDelay{
				FixedDelay: "100ms",
				Percentage: 150,
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "percentage must be between 0 and 100")
	})

	t.Run("invalid fault abort status", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Fault = &avapigwv1alpha1.FaultInjection{
			Abort: &avapigwv1alpha1.FaultAbort{
				HTTPStatus: 50,
				Percentage: 10,
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "httpStatus must be between 100 and 599")
	})

	t.Run("warning for redirect and route both specified", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Redirect = &avapigwv1alpha1.RedirectConfig{
			URI:  "/new-path",
			Code: 301,
		}
		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		assert.NotEmpty(t, warnings)
		assert.Contains(t, warnings[0], "redirect and route are both specified")
	})

	t.Run("warning for directResponse and route both specified", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.DirectResponse = &avapigwv1alpha1.DirectResponseConfig{
			Status: 200,
			Body:   `{"status":"ok"}`,
		}
		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		assert.NotEmpty(t, warnings)
		assert.Contains(t, warnings[0], "directResponse and route are both specified")
	})
}

// TestFunctional_APIRoute_HeaderMatch tests header matching validation.
func TestFunctional_APIRoute_HeaderMatch(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid header match - exact", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
			{Name: "Authorization", Exact: "Bearer token"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid header match - present", func(t *testing.T) {
		route := createBasicAPIRoute()
		present := true
		route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
			{Name: "Authorization", Present: &present},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid header match - regex", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
			{Name: "Authorization", Regex: "^Bearer .+$"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid header match - empty name", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
			{Name: "", Exact: "value"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("invalid header match - invalid regex", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
			{Name: "Authorization", Regex: "[invalid"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})
}

// TestFunctional_APIRoute_QueryParamMatch tests query parameter matching validation.
func TestFunctional_APIRoute_QueryParamMatch(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid query param match - exact", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].QueryParams = []avapigwv1alpha1.QueryParamMatch{
			{Name: "version", Exact: "v1"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid query param match - present", func(t *testing.T) {
		route := createBasicAPIRoute()
		present := true
		route.Spec.Match[0].QueryParams = []avapigwv1alpha1.QueryParamMatch{
			{Name: "debug", Present: &present},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid query param match - empty name", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].QueryParams = []avapigwv1alpha1.QueryParamMatch{
			{Name: "", Exact: "value"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("invalid query param match - invalid regex", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Match[0].QueryParams = []avapigwv1alpha1.QueryParamMatch{
			{Name: "version", Regex: "[invalid"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regex is invalid")
	})
}

// TestFunctional_APIRoute_RateLimit tests rate limit configuration validation.
func TestFunctional_APIRoute_RateLimit(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid rate limit", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
			PerClient:         true,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid rate limit - zero requests per second", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 0,
			Burst:             200,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
	})
}

// TestFunctional_APIRoute_CORS tests CORS configuration validation.
func TestFunctional_APIRoute_CORS(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid CORS config", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.CORS = &avapigwv1alpha1.CORSConfig{
			AllowOrigins:     []string{"https://example.com"},
			AllowMethods:     []string{"GET", "POST"},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			ExposeHeaders:    []string{"X-Request-ID"},
			MaxAge:           86400,
			AllowCredentials: true,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_APIRoute_MaxSessions tests max sessions configuration validation.
func TestFunctional_APIRoute_MaxSessions(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid max sessions config", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
			QueueSize:     100,
			QueueTimeout:  "10s",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid max sessions - zero max concurrent", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 0,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
	})
}

// TestFunctional_APIRoute_Cache tests cache configuration validation.
func TestFunctional_APIRoute_Cache(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid cache config", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
			Enabled:              true,
			TTL:                  "5m",
			KeyComponents:        []string{"path", "query"},
			StaleWhileRevalidate: "1m",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("invalid cache TTL", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
			Enabled: true,
			TTL:     "invalid",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cache.ttl is invalid")
	})
}

// TestFunctional_APIRoute_TLS tests TLS configuration validation.
func TestFunctional_APIRoute_TLS(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid TLS config with files", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.TLS = &avapigwv1alpha1.RouteTLSConfig{
			CertFile:   "/certs/tls.crt",
			KeyFile:    "/certs/tls.key",
			SNIHosts:   []string{"api.example.com"},
			MinVersion: "TLS12",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid TLS config with Vault", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.TLS = &avapigwv1alpha1.RouteTLSConfig{
			SNIHosts: []string{"api.example.com"},
			Vault: &avapigwv1alpha1.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "api-route",
				CommonName: "api.example.com",
				TTL:        "24h",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_APIRoute_Authentication tests authentication configuration validation.
func TestFunctional_APIRoute_Authentication(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

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
					Audience:  []string{"api.example.com"},
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
						Roles:       "roles",
						Permissions: "permissions",
						Email:       "email",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid API key authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
					Enabled:       true,
					Header:        "X-API-Key",
					HashAlgorithm: "sha256",
				},
			},
			wantErr: false,
		},
		{
			name: "valid API key with query parameter",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
					Enabled: true,
					Query:   "api_key",
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
					AllowedCNs:      []string{"client.example.com"},
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
							ClientID:  "gateway-client",
							Scopes:    []string{"openid", "profile"},
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
				SkipPaths: []string{"/health", "/metrics"},
			},
			wantErr: false,
		},
		{
			name: "valid authentication with allow anonymous",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					Issuer:  "https://auth.example.com",
					JWKSURL: "https://auth.example.com/.well-known/jwks.json",
				},
				AllowAnonymous: true,
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
			route := createBasicAPIRoute()
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

// TestFunctional_APIRoute_Authorization tests authorization configuration validation.
func TestFunctional_APIRoute_Authorization(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

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
							Name:      "admin-policy",
							Roles:     []string{"admin"},
							Resources: []string{"/api/v1/*"},
							Actions:   []string{"GET", "POST", "PUT", "DELETE"},
							Effect:    "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid RBAC with role hierarchy",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.RBACPolicyConfig{
						{
							Name:      "user-policy",
							Roles:     []string{"user"},
							Resources: []string{"/api/v1/users/*"},
							Actions:   []string{"GET"},
							Effect:    "allow",
						},
					},
					RoleHierarchy: map[string][]string{
						"admin": {"user", "moderator"},
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
							Name:       "owner-policy",
							Expression: "request.user.id == resource.owner_id",
							Resources:  []string{"/api/v1/documents/*"},
							Actions:    []string{"GET", "PUT", "DELETE"},
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
						URL:    "http://opa:8181/v1/data/authz/allow",
						Policy: "authz/allow",
					},
					Timeout:  "5s",
					FailOpen: false,
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
					Type:    "memory",
				},
			},
			wantErr: false,
		},
		{
			name: "valid authorization with skip paths",
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
				SkipPaths: []string{"/health", "/metrics", "/public/*"},
			},
			wantErr: false,
		},
		{
			name: "valid authorization with allow default policy",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "allow",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.RBACPolicyConfig{
						{
							Name:      "deny-admin",
							Roles:     []string{"guest"},
							Resources: []string{"/api/v1/admin/*"},
							Actions:   []string{"*"},
							Effect:    "deny",
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
			route := createBasicAPIRoute()
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

// TestFunctional_APIRoute_CombinedAuthAuthz tests combined authentication and authorization.
func TestFunctional_APIRoute_CombinedAuthAuthz(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid combined JWT auth with RBAC authz", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://auth.example.com",
				JWKSURL:   "https://auth.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
				ClaimMapping: &avapigwv1alpha1.ClaimMappingConfig{
					Roles: "roles",
				},
			},
		}
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/v1/*"},
						Actions:   []string{"*"},
						Effect:    "allow",
					},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid combined OIDC auth with ABAC authz", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			OIDC: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:      "keycloak",
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "gateway-client",
					},
				},
			},
		}
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			ABAC: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "owner-policy",
						Expression: "request.user.id == resource.owner_id",
						Effect:     "allow",
					},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid combined mTLS auth with external authz", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			MTLS: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "cn",
			},
		}
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			External: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL: "http://opa:8181/v1/data/authz/allow",
				},
				Timeout: "5s",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid full route with auth and authz", func(t *testing.T) {
		route := createFullAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://auth.example.com",
				JWKSURL:   "https://auth.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
			},
			SkipPaths: []string{"/health"},
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
			SkipPaths: []string{"/health"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_APIRoute_Update tests APIRoute update validation.
func TestFunctional_APIRoute_Update(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid update", func(t *testing.T) {
		oldRoute := createBasicAPIRoute()
		newRoute := createBasicAPIRoute()
		newRoute.Spec.Timeout = "60s"
		warnings, err := validator.ValidateUpdate(nil, oldRoute, newRoute)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		oldRoute := createBasicAPIRoute()
		newRoute := createBasicAPIRoute()
		newRoute.Spec.Route[0].Destination.Port = 0
		_, err := validator.ValidateUpdate(nil, oldRoute, newRoute)
		assert.Error(t, err)
	})
}

// TestFunctional_APIRoute_Delete tests APIRoute delete validation.
func TestFunctional_APIRoute_Delete(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		route := createBasicAPIRoute()
		warnings, err := validator.ValidateDelete(nil, route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// Helper functions

func createBasicAPIRoute() *avapigwv1alpha1.APIRoute {
	return &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend-service",
						Port: 8080,
					},
					Weight: 100,
				},
			},
			Timeout: "30s",
		},
	}
}

func createFullAPIRoute() *avapigwv1alpha1.APIRoute {
	route := createBasicAPIRoute()
	route.Name = "full-route"

	present := true
	route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
		{Name: "Authorization", Present: &present},
	}
	route.Spec.Match[0].QueryParams = []avapigwv1alpha1.QueryParamMatch{
		{Name: "version", Exact: "v1"},
	}

	route.Spec.Retries = &avapigwv1alpha1.RetryPolicy{
		Attempts:      3,
		PerTryTimeout: "10s",
		RetryOn:       "5xx,reset",
	}

	route.Spec.Headers = &avapigwv1alpha1.HeaderManipulation{
		Request: &avapigwv1alpha1.HeaderOperation{
			Set: map[string]string{"X-Gateway": "avapigw"},
		},
	}

	route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
	}

	route.Spec.CORS = &avapigwv1alpha1.CORSConfig{
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"},
	}

	route.Spec.Security = &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:       true,
			XFrameOptions: "DENY",
		},
	}

	return route
}
