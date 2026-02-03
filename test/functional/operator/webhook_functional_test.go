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

// TestFunctional_Webhook_DurationValidation tests duration validation.
func TestFunctional_Webhook_DurationValidation(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	validDurations := []string{
		"1s", "10s", "30s", "60s",
		"1m", "5m", "10m", "30m",
		"1h", "2h", "24h",
		"100ms", "500ms",
		"1m30s", "1h30m",
	}

	for _, d := range validDurations {
		t.Run("valid duration: "+d, func(t *testing.T) {
			route := createBasicAPIRoute()
			route.Spec.Timeout = avapigwv1alpha1.Duration(d)
			_, err := validator.ValidateCreate(nil, route)
			assert.NoError(t, err)
		})
	}

	invalidDurations := []string{
		"invalid",
		"1",
		"1x",
		"-1s",
		"",
	}

	for _, d := range invalidDurations {
		if d == "" {
			continue // Empty duration is valid (optional)
		}
		t.Run("invalid duration: "+d, func(t *testing.T) {
			route := createBasicAPIRoute()
			route.Spec.Timeout = avapigwv1alpha1.Duration(d)
			_, err := validator.ValidateCreate(nil, route)
			assert.Error(t, err)
		})
	}
}

// TestFunctional_Webhook_CommonValidation tests common validation functions.
func TestFunctional_Webhook_CommonValidation(t *testing.T) {
	t.Run("rate limit validation", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		// Valid rate limit
		route := createBasicAPIRoute()
		route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)

		// Invalid - zero requests per second when enabled
		route.Spec.RateLimit.RequestsPerSecond = 0
		_, err = validator.ValidateCreate(nil, route)
		assert.Error(t, err)
	})

	t.Run("CORS validation", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		// Valid CORS
		route := createBasicAPIRoute()
		route.Spec.CORS = &avapigwv1alpha1.CORSConfig{
			AllowOrigins:     []string{"https://example.com", "*"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			ExposeHeaders:    []string{"X-Request-ID"},
			MaxAge:           86400,
			AllowCredentials: true,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("max sessions validation", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		// Valid max sessions
		route := createBasicAPIRoute()
		route.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
			QueueSize:     100,
			QueueTimeout:  "10s",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)

		// Invalid - zero max concurrent when enabled
		route.Spec.MaxSessions.MaxConcurrent = 0
		_, err = validator.ValidateCreate(nil, route)
		assert.Error(t, err)
	})

	t.Run("route TLS validation", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		// Valid TLS with files
		route := createBasicAPIRoute()
		route.Spec.TLS = &avapigwv1alpha1.RouteTLSConfig{
			CertFile:   "/certs/tls.crt",
			KeyFile:    "/certs/tls.key",
			MinVersion: "TLS12",
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)

		// Valid TLS with Vault
		route.Spec.TLS = &avapigwv1alpha1.RouteTLSConfig{
			Vault: &avapigwv1alpha1.VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}
		_, err = validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_StatusConditions tests status condition types.
func TestFunctional_Webhook_StatusConditions(t *testing.T) {
	t.Run("condition types are defined", func(t *testing.T) {
		assert.Equal(t, avapigwv1alpha1.ConditionType("Ready"), avapigwv1alpha1.ConditionReady)
		assert.Equal(t, avapigwv1alpha1.ConditionType("Valid"), avapigwv1alpha1.ConditionValid)
		assert.Equal(t, avapigwv1alpha1.ConditionType("Healthy"), avapigwv1alpha1.ConditionHealthy)
	})

	t.Run("condition reasons are defined", func(t *testing.T) {
		assert.Equal(t, avapigwv1alpha1.ConditionReason("Reconciled"), avapigwv1alpha1.ReasonReconciled)
		assert.Equal(t, avapigwv1alpha1.ConditionReason("ReconcileFailed"), avapigwv1alpha1.ReasonReconcileFailed)
		assert.Equal(t, avapigwv1alpha1.ConditionReason("ValidationPassed"), avapigwv1alpha1.ReasonValidationPassed)
		assert.Equal(t, avapigwv1alpha1.ConditionReason("ValidationFailed"), avapigwv1alpha1.ReasonValidationFailed)
	})
}

// TestFunctional_Webhook_DefaultValues tests default value application.
func TestFunctional_Webhook_DefaultValues(t *testing.T) {
	t.Run("APIRoute defaults", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{
							Host: "backend",
							Port: 8080,
						},
						// Weight should default to 100
					},
				},
			},
		}

		validator := &webhook.APIRouteValidator{}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("Backend defaults", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-backend",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Hosts: []avapigwv1alpha1.BackendHost{
					{
						Address: "10.0.1.10",
						Port:    8080,
						// Weight should default to 1
					},
				},
			},
		}

		validator := &webhook.BackendValidator{}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_CrossFieldValidation tests cross-field validation.
func TestFunctional_Webhook_CrossFieldValidation(t *testing.T) {
	t.Run("redirect and route conflict", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Redirect = &avapigwv1alpha1.RedirectConfig{
			URI:  "/new-path",
			Code: 301,
		}

		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		assert.NotEmpty(t, warnings)
	})

	t.Run("directResponse and route conflict", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.DirectResponse = &avapigwv1alpha1.DirectResponseConfig{
			Status: 200,
			Body:   `{"status":"ok"}`,
		}

		warnings, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
		assert.NotEmpty(t, warnings)
	})

	t.Run("mutual TLS requires cert and key", func(t *testing.T) {
		validator := &webhook.BackendValidator{}

		backend := createBasicBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled: true,
			Mode:    "MUTUAL",
			CAFile:  "/certs/ca.crt",
			// Missing CertFile and KeyFile
		}

		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tls.certFile or tls.vault is required for MUTUAL TLS mode")
	})

	t.Run("OIDC auth requires issuer and client ID", func(t *testing.T) {
		validator := &webhook.BackendValidator{}

		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC:        &avapigwv1alpha1.BackendOIDCConfig{
					// Missing IssuerURL and ClientID
				},
			},
		}

		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
	})
}

// TestFunctional_Webhook_EdgeCases tests edge cases in validation.
func TestFunctional_Webhook_EdgeCases(t *testing.T) {
	t.Run("empty match conditions", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Match = nil

		_, err := validator.ValidateCreate(nil, route)
		// Empty match is valid - matches all requests
		assert.NoError(t, err)
	})

	t.Run("empty route destinations", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Route = nil

		_, err := validator.ValidateCreate(nil, route)
		// Empty route is valid if redirect or directResponse is set
		assert.NoError(t, err)
	})

	t.Run("single destination with weight 0", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Route[0].Weight = 0

		_, err := validator.ValidateCreate(nil, route)
		// Single destination with weight 0 is valid
		assert.NoError(t, err)
	})

	t.Run("multiple destinations with weight 0", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Route = []avapigwv1alpha1.RouteDestination{
			{
				Destination: avapigwv1alpha1.Destination{Host: "backend1", Port: 8080},
				Weight:      0,
			},
			{
				Destination: avapigwv1alpha1.Destination{Host: "backend2", Port: 8080},
				Weight:      0,
			},
		}

		_, err := validator.ValidateCreate(nil, route)
		// Multiple destinations with all weights 0 is valid (equal distribution)
		assert.NoError(t, err)
	})

	t.Run("very long timeout", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Timeout = "24h"

		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("very short timeout", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Timeout = "1ms"

		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_SpecialCharacters tests handling of special characters.
func TestFunctional_Webhook_SpecialCharacters(t *testing.T) {
	t.Run("URI with special characters", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Match[0].URI = &avapigwv1alpha1.URIMatch{
			Prefix: "/api/v1/users/{id}",
		}

		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("header name with special characters", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Match[0].Headers = []avapigwv1alpha1.HeaderMatch{
			{Name: "X-Custom-Header", Exact: "value"},
		}

		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("regex with special characters", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

		route := createBasicAPIRoute()
		route.Spec.Match[0].URI = &avapigwv1alpha1.URIMatch{
			Regex: `^/api/v[0-9]+/users/[a-zA-Z0-9\-]+$`,
		}

		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_LoadBalancerAlgorithms tests load balancer algorithm validation.
func TestFunctional_Webhook_LoadBalancerAlgorithms(t *testing.T) {
	validator := &webhook.BackendValidator{}

	algorithms := []avapigwv1alpha1.LoadBalancerAlgorithm{
		avapigwv1alpha1.LoadBalancerRoundRobin,
		avapigwv1alpha1.LoadBalancerWeighted,
		avapigwv1alpha1.LoadBalancerLeastConn,
		avapigwv1alpha1.LoadBalancerRandom,
	}

	for _, algo := range algorithms {
		t.Run("algorithm: "+string(algo), func(t *testing.T) {
			backend := createBasicBackend()
			backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: algo,
			}

			_, err := validator.ValidateCreate(nil, backend)
			assert.NoError(t, err)
		})
	}
}

// TestFunctional_Webhook_TLSVersions tests TLS version validation.
func TestFunctional_Webhook_TLSVersions(t *testing.T) {
	validator := &webhook.BackendValidator{}

	validVersions := []string{"TLS12", "TLS13"}

	for _, version := range validVersions {
		t.Run("TLS version: "+version, func(t *testing.T) {
			backend := createBasicBackend()
			backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				Mode:       "SIMPLE",
				MinVersion: version,
			}

			_, err := validator.ValidateCreate(nil, backend)
			assert.NoError(t, err)
		})
	}
}

// TestFunctional_Webhook_AuthenticationValidation tests authentication validation.
func TestFunctional_Webhook_AuthenticationValidation(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid JWT authentication with all fields", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://auth.example.com",
				Audience:  []string{"api.example.com", "app.example.com"},
				JWKSURL:   "https://auth.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
				ClaimMapping: &avapigwv1alpha1.ClaimMappingConfig{
					Roles:       "roles",
					Permissions: "permissions",
					Groups:      "groups",
					Scopes:      "scope",
					Email:       "email",
					Name:        "name",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid JWT with HMAC algorithm", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://auth.example.com",
				Secret:    "my-secret-key",
				Algorithm: "HS256",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid API key authentication with header", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled:       true,
				Header:        "X-API-Key",
				HashAlgorithm: "sha256",
				VaultPath:     "secret/api-keys",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid API key authentication with query", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled:       true,
				Query:         "api_key",
				HashAlgorithm: "sha512",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid mTLS authentication", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			MTLS: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "cn",
				AllowedCNs:      []string{"client1.example.com", "client2.example.com"},
				AllowedOUs:      []string{"Engineering", "Operations"},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid mTLS with SAN extraction", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			MTLS: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "san",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid OIDC authentication with multiple providers", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			OIDC: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:         "keycloak",
						IssuerURL:    "https://keycloak.example.com/realms/myrealm",
						ClientID:     "gateway-client",
						ClientSecret: "secret",
						Scopes:       []string{"openid", "profile", "email"},
					},
					{
						Name:      "google",
						IssuerURL: "https://accounts.google.com",
						ClientID:  "google-client-id",
						ClientSecretRef: &avapigwv1alpha1.SecretKeySelector{
							Name: "google-secret",
							Key:  "client-secret",
						},
						Scopes: []string{"openid", "email"},
					},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_AuthorizationValidation tests authorization validation.
func TestFunctional_Webhook_AuthorizationValidation(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid RBAC with multiple policies", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:      "admin-full-access",
						Roles:     []string{"admin", "superadmin"},
						Resources: []string{"/api/v1/*"},
						Actions:   []string{"*"},
						Effect:    "allow",
						Priority:  100,
					},
					{
						Name:      "user-read-access",
						Roles:     []string{"user"},
						Resources: []string{"/api/v1/users/*", "/api/v1/products/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
						Priority:  50,
					},
					{
						Name:      "deny-admin-endpoints",
						Roles:     []string{"user", "guest"},
						Resources: []string{"/api/v1/admin/*"},
						Actions:   []string{"*"},
						Effect:    "deny",
						Priority:  200,
					},
				},
				RoleHierarchy: map[string][]string{
					"superadmin": {"admin"},
					"admin":      {"user"},
					"user":       {"guest"},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid ABAC with CEL expressions", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			ABAC: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "owner-access",
						Expression: "request.user.id == resource.owner_id",
						Resources:  []string{"/api/v1/documents/*"},
						Actions:    []string{"GET", "PUT", "DELETE"},
						Effect:     "allow",
						Priority:   100,
					},
					{
						Name:       "department-access",
						Expression: "request.user.department in resource.allowed_departments",
						Resources:  []string{"/api/v1/reports/*"},
						Actions:    []string{"GET"},
						Effect:     "allow",
						Priority:   50,
					},
					{
						Name:       "time-based-access",
						Expression: "request.time.hour >= 9 && request.time.hour <= 17",
						Resources:  []string{"/api/v1/sensitive/*"},
						Actions:    []string{"*"},
						Effect:     "allow",
						Priority:   75,
					},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid external authorization with OPA", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			External: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL:    "http://opa:8181/v1/data/authz/allow",
					Policy: "authz/allow",
					Headers: map[string]string{
						"X-OPA-Token": "secret-token",
					},
				},
				Timeout:  "5s",
				FailOpen: false,
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid external authorization with fail open", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			External: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL: "http://opa:8181/v1/data/authz/allow",
				},
				Timeout:  "10s",
				FailOpen: true,
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid authorization with redis cache", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
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
				TTL:     "10m",
				MaxSize: 10000,
				Type:    "redis",
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_BackendTransformValidation tests backend transform validation.
func TestFunctional_Webhook_BackendTransformValidation(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid transform with complex template", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Request: &avapigwv1alpha1.BackendRequestTransform{
				Template: `{
					"data": {{.Body}},
					"metadata": {
						"timestamp": "{{.Timestamp}}",
						"source": "gateway"
					}
				}`,
				Headers: &avapigwv1alpha1.HeaderOperation{
					Set: map[string]string{
						"Content-Type":      "application/json",
						"X-Backend-Request": "true",
					},
					Add: map[string]string{
						"X-Request-ID": "{{.RequestID}}",
						"X-Trace-ID":   "{{.TraceID}}",
					},
					Remove: []string{"X-Internal-Header", "X-Debug"},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid transform with response allow fields", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Response: &avapigwv1alpha1.BackendResponseTransform{
				AllowFields: []string{"id", "name", "email", "status", "created_at"},
				FieldMappings: map[string]string{
					"created_at": "createdAt",
					"updated_at": "updatedAt",
					"user_id":    "userId",
				},
				Headers: &avapigwv1alpha1.HeaderOperation{
					Set: map[string]string{
						"X-Response-Time": "{{.ResponseTime}}",
					},
					Remove: []string{"X-Internal-Response"},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid transform with response deny fields", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Response: &avapigwv1alpha1.BackendResponseTransform{
				DenyFields: []string{"password", "secret", "internal_id", "api_key"},
				FieldMappings: map[string]string{
					"created_at": "createdAt",
					"updated_at": "updatedAt",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_BackendCacheValidation tests backend cache validation.
func TestFunctional_Webhook_BackendCacheValidation(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid cache with all options", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled:              true,
			TTL:                  "15m",
			KeyComponents:        []string{"path", "query", "headers.authorization", "headers.x-tenant-id"},
			StaleWhileRevalidate: "5m",
			Type:                 "redis",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid cache with memory type", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled:       true,
			TTL:           "5m",
			KeyComponents: []string{"path"},
			Type:          "memory",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid cache TTL format", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "invalid-duration",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ttl is invalid")
	})

	t.Run("invalid stale while revalidate format", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled:              true,
			TTL:                  "5m",
			StaleWhileRevalidate: "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "staleWhileRevalidate is invalid")
	})
}

// TestFunctional_Webhook_BackendEncodingValidation tests backend encoding validation.
func TestFunctional_Webhook_BackendEncodingValidation(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid encoding with gzip compression", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Request: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/json",
			},
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/json",
				Compression: "gzip",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid encoding with deflate compression", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/json",
				Compression: "deflate",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid encoding with brotli compression", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/json",
				Compression: "br",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid encoding with no compression", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/json",
				Compression: "none",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_GRPCBackendTransformValidation tests gRPC backend transform validation.
func TestFunctional_Webhook_GRPCBackendTransformValidation(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid transform with field mask", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Transform = &avapigwv1alpha1.GRPCBackendTransformConfig{
			FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
				Paths: []string{"user.id", "user.name", "user.email", "user.profile.avatar"},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid transform with metadata manipulation", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Transform = &avapigwv1alpha1.GRPCBackendTransformConfig{
			Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
				Static: map[string]string{
					"x-backend-version": "v1",
					"x-source":          "gateway",
					"x-environment":     "production",
				},
				Dynamic: map[string]string{
					"x-request-id":   "{{.RequestID}}",
					"x-trace-id":     "{{.TraceID}}",
					"x-span-id":      "{{.SpanID}}",
					"x-forwarded-by": "{{.GatewayID}}",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid transform with full config", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Transform = &avapigwv1alpha1.GRPCBackendTransformConfig{
			FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
				Paths: []string{"id", "name", "status", "metadata"},
			},
			Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
				Static: map[string]string{
					"x-backend-version": "v1",
				},
				Dynamic: map[string]string{
					"x-request-id": "{{.RequestID}}",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_RequestLimitsValidation tests request limits validation.
func TestFunctional_Webhook_RequestLimitsValidation(t *testing.T) {
	t.Run("valid request limits for APIRoute", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}
		route := createBasicAPIRoute()
		route.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid request limits for GRPCRoute", func(t *testing.T) {
		validator := &webhook.GRPCRouteValidator{}
		route := createBasicGRPCRoute()
		route.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   4194304,
			MaxHeaderSize: 65536,
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid request limits for Backend", func(t *testing.T) {
		validator := &webhook.BackendValidator{}
		backend := createBasicBackend()
		backend.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   52428800,
			MaxHeaderSize: 2097152,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid large request limits", func(t *testing.T) {
		validator := &webhook.BackendValidator{}
		backend := createBasicBackend()
		backend.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   1073741824,
			MaxHeaderSize: 104857600,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Webhook_CombinedValidation tests combined validation scenarios.
func TestFunctional_Webhook_CombinedValidation(t *testing.T) {
	t.Run("valid APIRoute with all new fields", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}
		route := createFullAPIRoute()
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
			SkipPaths: []string{"/health", "/metrics"},
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
			Cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     "5m",
				Type:    "memory",
			},
			SkipPaths: []string{"/health", "/metrics"},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("valid Backend with all new fields", func(t *testing.T) {
		validator := &webhook.BackendValidator{}
		backend := createFullBackend()
		backend.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		}
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Request: &avapigwv1alpha1.BackendRequestTransform{
				Template: `{"wrapped": {{.Body}}}`,
			},
			Response: &avapigwv1alpha1.BackendResponseTransform{
				DenyFields: []string{"password", "secret"},
			},
		}
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "5m",
			Type:    "memory",
		}
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				Compression: "gzip",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid GRPCBackend with all new fields", func(t *testing.T) {
		validator := &webhook.GRPCBackendValidator{}
		backend := createFullGRPCBackend()
		backend.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
			QueueSize:     100,
			QueueTimeout:  "15s",
		}
		backend.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 500,
			Burst:             1000,
		}
		backend.Spec.Transform = &avapigwv1alpha1.GRPCBackendTransformConfig{
			FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
				Paths: []string{"id", "name"},
			},
		}
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "10m",
			Type:    "redis",
		}
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/grpc",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}
