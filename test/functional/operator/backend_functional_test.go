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

// TestFunctional_Backend_Validation tests Backend CRD validation.
func TestFunctional_Backend_Validation(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid basic backend", func(t *testing.T) {
		backend := createBasicBackend()
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid backend with all fields", func(t *testing.T) {
		backend := createFullBackend()
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid - no hosts", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Hosts = nil
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one host is required")
	})

	t.Run("invalid host address - empty", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Hosts[0].Address = ""
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "address is required")
	})

	t.Run("invalid host port - zero", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid host port - too high", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Hosts[0].Port = 70000
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid host weight - negative", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Hosts[0].Weight = -1
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("invalid host weight - too high", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Hosts[0].Weight = 150
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})
}

// TestFunctional_Backend_HealthCheck tests health check configuration validation.
func TestFunctional_Backend_HealthCheck(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid health check", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path:               "/health",
			Interval:           "10s",
			Timeout:            "5s",
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid health check - empty path", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path: "",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path is required")
	})

	t.Run("invalid health check - invalid interval", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path:     "/health",
			Interval: "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "interval is invalid")
	})

	t.Run("invalid health check - invalid timeout", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path:    "/health",
			Timeout: "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout is invalid")
	})

	t.Run("invalid health check - negative healthy threshold", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path:             "/health",
			HealthyThreshold: -1,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "healthyThreshold must be non-negative")
	})
}

// TestFunctional_Backend_LoadBalancer tests load balancer configuration validation.
func TestFunctional_Backend_LoadBalancer(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid load balancer - roundRobin", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
			Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid load balancer - weighted", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
			Algorithm: avapigwv1alpha1.LoadBalancerWeighted,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid load balancer - leastConn", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
			Algorithm: avapigwv1alpha1.LoadBalancerLeastConn,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid load balancer - random", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
			Algorithm: avapigwv1alpha1.LoadBalancerRandom,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Backend_TLS tests TLS configuration validation.
func TestFunctional_Backend_TLS(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid TLS - simple mode", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled:    true,
			Mode:       "SIMPLE",
			CAFile:     "/certs/ca.crt",
			MinVersion: "TLS12",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid TLS - mutual mode", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled:  true,
			Mode:     "MUTUAL",
			CAFile:   "/certs/ca.crt",
			CertFile: "/certs/client.crt",
			KeyFile:  "/certs/client.key",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid TLS - with Vault", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled: true,
			Mode:    "MUTUAL",
			Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "backend-client",
				CommonName: "gateway-client",
				TTL:        "24h",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid TLS - mutual mode without cert", func(t *testing.T) {
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
}

// TestFunctional_Backend_CircuitBreaker tests circuit breaker configuration validation.
func TestFunctional_Backend_CircuitBreaker(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid circuit breaker", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        5,
			Timeout:          "30s",
			HalfOpenRequests: 3,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid circuit breaker - zero threshold", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 0,
			Timeout:   "30s",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold must be at least 1")
	})

	t.Run("invalid circuit breaker - invalid timeout", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
			Timeout:   "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout is invalid")
	})
}

// TestFunctional_Backend_Authentication tests authentication configuration validation.
func TestFunctional_Backend_Authentication(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid JWT auth - static token", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "test-token",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid JWT auth - OIDC", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					IssuerURL:    "https://keycloak.example.com/realms/myrealm",
					ClientID:     "gateway-client",
					ClientSecret: "secret",
					Scopes:       []string{"openid"},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid JWT auth - OIDC with secret ref", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					IssuerURL: "https://keycloak.example.com/realms/myrealm",
					ClientID:  "gateway-client",
					ClientSecretRef: &avapigwv1alpha1.SecretKeySelector{
						Name: "keycloak-secret",
						Key:  "client-secret",
					},
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid Basic auth", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "basic",
			Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid Basic auth - Vault", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "basic",
			Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
				Enabled:   true,
				VaultPath: "secret/backend/credentials",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid mTLS auth", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "mtls",
			MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/certs/client.crt",
				KeyFile:  "/certs/client.key",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid JWT auth - OIDC without issuer", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					ClientID: "gateway-client",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuerUrl is required")
	})

	t.Run("invalid JWT auth - OIDC without client ID", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					IssuerURL: "https://keycloak.example.com/realms/myrealm",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "clientId is required")
	})
}

// TestFunctional_Backend_MaxSessions tests max sessions configuration validation.
func TestFunctional_Backend_MaxSessions(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid max sessions", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 500,
			QueueSize:     50,
			QueueTimeout:  "10s",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid max sessions - zero max concurrent", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 0,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
	})
}

// TestFunctional_Backend_RateLimit tests rate limit configuration validation.
func TestFunctional_Backend_RateLimit(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid rate limit", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Backend_RequestLimits tests request limits configuration validation.
func TestFunctional_Backend_RequestLimits(t *testing.T) {
	validator := &webhook.BackendValidator{}

	tests := []struct {
		name          string
		requestLimits *avapigwv1alpha1.RequestLimitsConfig
		wantErr       bool
		errMsg        string
	}{
		{
			name: "valid request limits",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
			},
			wantErr: false,
		},
		{
			name: "valid request limits - body only",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize: 52428800,
			},
			wantErr: false,
		},
		{
			name: "valid request limits - header only",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxHeaderSize: 2097152,
			},
			wantErr: false,
		},
		{
			name: "valid request limits - large values",
			requestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize:   1073741824,
				MaxHeaderSize: 104857600,
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
			backend := createBasicBackend()
			backend.Spec.RequestLimits = tt.requestLimits
			_, err := validator.ValidateCreate(nil, backend)
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

// TestFunctional_Backend_Transform tests transform configuration validation.
func TestFunctional_Backend_Transform(t *testing.T) {
	validator := &webhook.BackendValidator{}

	tests := []struct {
		name      string
		transform *avapigwv1alpha1.BackendTransformConfig
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid transform with request template",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Request: &avapigwv1alpha1.BackendRequestTransform{
					Template: `{"wrapped": {{.Body}}}`,
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with request headers",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Request: &avapigwv1alpha1.BackendRequestTransform{
					Headers: &avapigwv1alpha1.HeaderOperation{
						Set: map[string]string{
							"X-Backend-Request": "true",
						},
						Add: map[string]string{
							"X-Request-ID": "{{.RequestID}}",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with response allow fields",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					AllowFields: []string{"id", "name", "status"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with response deny fields",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					DenyFields: []string{"password", "secret", "token"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with field mappings",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					FieldMappings: map[string]string{
						"created_at": "createdAt",
						"updated_at": "updatedAt",
						"user_id":    "userId",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with full config",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Request: &avapigwv1alpha1.BackendRequestTransform{
					Template: `{"wrapped": {{.Body}}}`,
					Headers: &avapigwv1alpha1.HeaderOperation{
						Set: map[string]string{
							"X-Backend-Request": "true",
						},
					},
				},
				Response: &avapigwv1alpha1.BackendResponseTransform{
					AllowFields: []string{"id", "name", "status"},
					FieldMappings: map[string]string{
						"created_at": "createdAt",
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "nil transform",
			transform: nil,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := createBasicBackend()
			backend.Spec.Transform = tt.transform
			_, err := validator.ValidateCreate(nil, backend)
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

// TestFunctional_Backend_Cache tests cache configuration validation.
func TestFunctional_Backend_Cache(t *testing.T) {
	validator := &webhook.BackendValidator{}

	tests := []struct {
		name    string
		cache   *avapigwv1alpha1.BackendCacheConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid cache with memory type",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:       true,
				TTL:           "5m",
				KeyComponents: []string{"path", "query"},
				Type:          "memory",
			},
			wantErr: false,
		},
		{
			name: "valid cache with redis type",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:       true,
				TTL:           "10m",
				KeyComponents: []string{"path", "query", "headers"},
				Type:          "redis",
			},
			wantErr: false,
		},
		{
			name: "valid cache with stale while revalidate",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:              true,
				TTL:                  "5m",
				StaleWhileRevalidate: "1m",
				Type:                 "memory",
			},
			wantErr: false,
		},
		{
			name: "valid cache with minimal config",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     "1m",
			},
			wantErr: false,
		},
		{
			name: "invalid cache TTL",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     "invalid",
			},
			wantErr: true,
			errMsg:  "ttl is invalid",
		},
		{
			name: "disabled cache",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name:    "nil cache",
			cache:   nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := createBasicBackend()
			backend.Spec.Cache = tt.cache
			_, err := validator.ValidateCreate(nil, backend)
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

// TestFunctional_Backend_Encoding tests encoding configuration validation.
func TestFunctional_Backend_Encoding(t *testing.T) {
	validator := &webhook.BackendValidator{}

	tests := []struct {
		name     string
		encoding *avapigwv1alpha1.BackendEncodingConfig
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid encoding with request config",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with response config",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "gzip",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with deflate compression",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "deflate",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with br compression",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "br",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with full config",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
				},
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "gzip",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with no compression",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "none",
				},
			},
			wantErr: false,
		},
		{
			name:     "nil encoding",
			encoding: nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := createBasicBackend()
			backend.Spec.Encoding = tt.encoding
			_, err := validator.ValidateCreate(nil, backend)
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

// TestFunctional_Backend_CombinedNewFields tests combined new fields.
func TestFunctional_Backend_CombinedNewFields(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid backend with all new fields", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		}
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Request: &avapigwv1alpha1.BackendRequestTransform{
				Template: `{"wrapped": {{.Body}}}`,
				Headers: &avapigwv1alpha1.HeaderOperation{
					Set: map[string]string{
						"X-Backend-Request": "true",
					},
				},
			},
			Response: &avapigwv1alpha1.BackendResponseTransform{
				DenyFields: []string{"password", "secret"},
				FieldMappings: map[string]string{
					"created_at": "createdAt",
				},
			},
		}
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled:       true,
			TTL:           "5m",
			KeyComponents: []string{"path", "query"},
			Type:          "memory",
		}
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

	t.Run("valid full backend with all fields", func(t *testing.T) {
		backend := createFullBackend()
		backend.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   52428800,
			MaxHeaderSize: 2097152,
		}
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Response: &avapigwv1alpha1.BackendResponseTransform{
				DenyFields: []string{"password", "secret", "token"},
			},
		}
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "10m",
			Type:    "redis",
		}
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				Compression: "gzip",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_Backend_Update tests Backend update validation.
func TestFunctional_Backend_Update(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid update", func(t *testing.T) {
		oldBackend := createBasicBackend()
		newBackend := createBasicBackend()
		newBackend.Spec.Hosts[0].Weight = 50
		warnings, err := validator.ValidateUpdate(nil, oldBackend, newBackend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		oldBackend := createBasicBackend()
		newBackend := createBasicBackend()
		newBackend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateUpdate(nil, oldBackend, newBackend)
		assert.Error(t, err)
	})
}

// TestFunctional_Backend_Delete tests Backend delete validation.
func TestFunctional_Backend_Delete(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		backend := createBasicBackend()
		warnings, err := validator.ValidateDelete(nil, backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// Helper functions

func createBasicBackend() *avapigwv1alpha1.Backend {
	return &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "10.0.1.10",
					Port:    8080,
					Weight:  1,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:               "/health",
				Interval:           "10s",
				Timeout:            "5s",
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
		},
	}
}

func createFullBackend() *avapigwv1alpha1.Backend {
	backend := createBasicBackend()
	backend.Name = "full-backend"

	backend.Spec.Hosts = []avapigwv1alpha1.BackendHost{
		{Address: "10.0.1.10", Port: 8080, Weight: 50},
		{Address: "10.0.1.11", Port: 8080, Weight: 30},
		{Address: "10.0.1.12", Port: 8080, Weight: 20},
	}

	backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
		Algorithm: avapigwv1alpha1.LoadBalancerWeighted,
	}

	backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
		Enabled:    true,
		Mode:       "MUTUAL",
		CAFile:     "/certs/ca.crt",
		CertFile:   "/certs/client.crt",
		KeyFile:    "/certs/client.key",
		MinVersion: "TLS12",
	}

	backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
		Enabled:          true,
		Threshold:        5,
		Timeout:          "30s",
		HalfOpenRequests: 3,
	}

	backend.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 500,
		QueueSize:     50,
		QueueTimeout:  "10s",
	}

	backend.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
	}

	backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
		Type: "jwt",
		JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: "oidc",
			OIDC: &avapigwv1alpha1.BackendOIDCConfig{
				IssuerURL:     "https://keycloak.example.com/realms/myrealm",
				ClientID:      "gateway-client",
				ClientSecret:  "secret",
				Scopes:        []string{"openid", "profile"},
				TokenCacheTTL: "5m",
			},
			HeaderName:   "Authorization",
			HeaderPrefix: "Bearer",
		},
	}

	return backend
}
