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

// TestFunctional_GRPCBackend_Validation tests GRPCBackend CRD validation.
func TestFunctional_GRPCBackend_Validation(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid basic gRPC backend", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid gRPC backend with all fields", func(t *testing.T) {
		backend := createFullGRPCBackend()
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid - no hosts", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts = nil
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one host is required")
	})

	t.Run("invalid host address - empty", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts[0].Address = ""
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "address is required")
	})

	t.Run("invalid host port - zero", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid host weight - negative", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts[0].Weight = -1
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})
}

// TestFunctional_GRPCBackend_HealthCheck tests gRPC health check configuration validation.
func TestFunctional_GRPCBackend_HealthCheck(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid gRPC health check - overall health", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
			Enabled:            true,
			Service:            "",
			Interval:           "10s",
			Timeout:            "5s",
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid gRPC health check - specific service", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
			Enabled:  true,
			Service:  "grpc.health.v1.Health",
			Interval: "10s",
			Timeout:  "5s",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid gRPC health check - invalid interval", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
			Enabled:  true,
			Interval: "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "interval is invalid")
	})

	t.Run("invalid gRPC health check - invalid timeout", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
			Enabled: true,
			Timeout: "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout is invalid")
	})
}

// TestFunctional_GRPCBackend_ConnectionPool tests connection pool configuration validation.
func TestFunctional_GRPCBackend_ConnectionPool(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid connection pool", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: 100,
			IdleConnTimeout: "5m",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid connection pool - negative max idle conns", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
			MaxIdleConns:    -1,
			MaxConnsPerHost: 100,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maxIdleConns must be non-negative")
	})

	t.Run("invalid connection pool - negative max conns per host", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: -1,
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maxConnsPerHost must be non-negative")
	})

	t.Run("invalid connection pool - invalid idle timeout", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: 100,
			IdleConnTimeout: "invalid",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "idleConnTimeout is invalid")
	})
}

// TestFunctional_GRPCBackend_TLS tests TLS configuration validation.
func TestFunctional_GRPCBackend_TLS(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid TLS - simple mode", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled:    true,
			Mode:       "SIMPLE",
			ServerName: "grpc-backend.internal",
			MinVersion: "TLS12",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid TLS - mutual mode with Vault", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled:    true,
			Mode:       "MUTUAL",
			ServerName: "grpc-backend.internal",
			Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "grpc-client",
				CommonName: "gateway-grpc-client",
				TTL:        "24h",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCBackend_CircuitBreaker tests circuit breaker configuration validation.
func TestFunctional_GRPCBackend_CircuitBreaker(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid circuit breaker", func(t *testing.T) {
		backend := createBasicGRPCBackend()
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
		backend := createBasicGRPCBackend()
		backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 0,
			Timeout:   "30s",
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold must be at least 1")
	})
}

// TestFunctional_GRPCBackend_Authentication tests authentication configuration validation.
func TestFunctional_GRPCBackend_Authentication(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid JWT auth - OIDC", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "jwt",
			JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					IssuerURL:    "https://keycloak.example.com/realms/myrealm",
					ClientID:     "grpc-client",
					ClientSecret: "secret",
					Scopes:       []string{"openid"},
				},
				HeaderName:   "authorization",
				HeaderPrefix: "Bearer",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid mTLS auth", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
			Type: "mtls",
			MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-client",
					CommonName: "gateway-grpc-client",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCBackend_MaxSessions tests max sessions configuration validation.
func TestFunctional_GRPCBackend_MaxSessions(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

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
				MaxConcurrent: 1000,
				QueueSize:     100,
				QueueTimeout:  "15s",
			},
			wantErr: false,
		},
		{
			name: "valid max sessions without queue",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 500,
				QueueSize:     0,
			},
			wantErr: false,
		},
		{
			name: "valid max sessions with large concurrent",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 50000,
				QueueSize:     5000,
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
		{
			name:        "nil max sessions",
			maxSessions: nil,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := createBasicGRPCBackend()
			backend.Spec.MaxSessions = tt.maxSessions
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

// TestFunctional_GRPCBackend_RateLimit tests rate limit configuration validation.
func TestFunctional_GRPCBackend_RateLimit(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	tests := []struct {
		name      string
		rateLimit *avapigwv1alpha1.RateLimitConfig
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid rate limit",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 500,
				Burst:             1000,
			},
			wantErr: false,
		},
		{
			name: "valid rate limit with high values",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10000,
				Burst:             20000,
			},
			wantErr: false,
		},
		{
			name: "invalid rate limit - zero requests per second",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0,
				Burst:             100,
			},
			wantErr: true,
		},
		{
			name: "disabled rate limit",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name:      "nil rate limit",
			rateLimit: nil,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := createBasicGRPCBackend()
			backend.Spec.RateLimit = tt.rateLimit
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

// TestFunctional_GRPCBackend_Transform tests transform configuration validation.
func TestFunctional_GRPCBackend_Transform(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	tests := []struct {
		name      string
		transform *avapigwv1alpha1.GRPCBackendTransformConfig
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid transform with field mask",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
					Paths: []string{"id", "name", "status"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with nested field mask",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
					Paths: []string{"user.id", "user.name", "user.profile.email"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with static metadata",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Static: map[string]string{
						"x-backend-version": "v1",
						"x-source":          "gateway",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with dynamic metadata",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Dynamic: map[string]string{
						"x-request-id": "{{.RequestID}}",
						"x-trace-id":   "{{.TraceID}}",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid transform with full config",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
					Paths: []string{"id", "name", "status"},
				},
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Static: map[string]string{
						"x-backend-version": "v1",
					},
					Dynamic: map[string]string{
						"x-request-id": "{{.RequestID}}",
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
			backend := createBasicGRPCBackend()
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

// TestFunctional_GRPCBackend_Cache tests cache configuration validation.
func TestFunctional_GRPCBackend_Cache(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	tests := []struct {
		name    string
		cache   *avapigwv1alpha1.BackendCacheConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid cache with memory type",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     "5m",
				Type:    "memory",
			},
			wantErr: false,
		},
		{
			name: "valid cache with redis type",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     "10m",
				Type:    "redis",
			},
			wantErr: false,
		},
		{
			name: "valid cache with key components",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:       true,
				TTL:           "5m",
				KeyComponents: []string{"service", "method", "metadata"},
				Type:          "memory",
			},
			wantErr: false,
		},
		{
			name: "valid cache with stale while revalidate",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:              true,
				TTL:                  "10m",
				StaleWhileRevalidate: "2m",
				Type:                 "redis",
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
			backend := createBasicGRPCBackend()
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

// TestFunctional_GRPCBackend_Encoding tests encoding configuration validation.
func TestFunctional_GRPCBackend_Encoding(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

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
					ContentType: "application/grpc",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with response config",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/grpc",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with full config",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/grpc",
				},
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/grpc",
				},
			},
			wantErr: false,
		},
		{
			name: "valid encoding with grpc+proto",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/grpc+proto",
				},
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/grpc+proto",
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
			backend := createBasicGRPCBackend()
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

// TestFunctional_GRPCBackend_CombinedNewFields tests combined new fields.
func TestFunctional_GRPCBackend_CombinedNewFields(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid backend with all new fields", func(t *testing.T) {
		backend := createBasicGRPCBackend()
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
				Paths: []string{"id", "name", "status"},
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
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "10m",
			Type:    "redis",
		}
		backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
			Request: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/grpc",
			},
			Response: &avapigwv1alpha1.BackendEncodingSettings{
				ContentType: "application/grpc",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("valid full backend with all fields", func(t *testing.T) {
		backend := createFullGRPCBackend()
		backend.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 5000,
			QueueSize:     500,
			QueueTimeout:  "30s",
		}
		backend.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1000,
			Burst:             2000,
		}
		backend.Spec.Transform = &avapigwv1alpha1.GRPCBackendTransformConfig{
			FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
				Paths: []string{"user.id", "user.name"},
			},
		}
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "5m",
			Type:    "memory",
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

// TestFunctional_GRPCBackend_Update tests GRPCBackend update validation.
func TestFunctional_GRPCBackend_Update(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid update", func(t *testing.T) {
		oldBackend := createBasicGRPCBackend()
		newBackend := createBasicGRPCBackend()
		newBackend.Spec.Hosts[0].Weight = 50
		warnings, err := validator.ValidateUpdate(nil, oldBackend, newBackend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		oldBackend := createBasicGRPCBackend()
		newBackend := createBasicGRPCBackend()
		newBackend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateUpdate(nil, oldBackend, newBackend)
		assert.Error(t, err)
	})
}

// TestFunctional_GRPCBackend_Delete tests GRPCBackend delete validation.
func TestFunctional_GRPCBackend_Delete(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		warnings, err := validator.ValidateDelete(nil, backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// Helper functions

func createBasicGRPCBackend() *avapigwv1alpha1.GRPCBackend {
	return &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service.default.svc.cluster.local",
					Port:    9000,
					Weight:  1,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Enabled:            true,
				Service:            "",
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

func createFullGRPCBackend() *avapigwv1alpha1.GRPCBackend {
	backend := createBasicGRPCBackend()
	backend.Name = "full-grpc-backend"

	backend.Spec.Hosts = []avapigwv1alpha1.BackendHost{
		{Address: "grpc-service-1.default.svc.cluster.local", Port: 9000, Weight: 60},
		{Address: "grpc-service-2.default.svc.cluster.local", Port: 9000, Weight: 40},
	}

	backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
		Enabled:            true,
		Service:            "grpc.health.v1.Health",
		Interval:           "10s",
		Timeout:            "5s",
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}

	backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
		Algorithm: avapigwv1alpha1.LoadBalancerWeighted,
	}

	backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
		Enabled:    true,
		Mode:       "MUTUAL",
		ServerName: "grpc-backend.internal",
		MinVersion: "TLS12",
		Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "grpc-client",
			CommonName: "gateway-grpc-client",
			TTL:        "24h",
		},
	}

	backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
		MaxIdleConns:    10,
		MaxConnsPerHost: 100,
		IdleConnTimeout: "5m",
	}

	backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
		Enabled:          true,
		Threshold:        5,
		Timeout:          "30s",
		HalfOpenRequests: 3,
	}

	backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
		Type: "jwt",
		JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: "oidc",
			OIDC: &avapigwv1alpha1.BackendOIDCConfig{
				IssuerURL:     "https://keycloak.example.com/realms/myrealm",
				ClientID:      "grpc-client",
				ClientSecret:  "secret",
				Scopes:        []string{"openid"},
				TokenCacheTTL: "5m",
			},
			HeaderName:   "authorization",
			HeaderPrefix: "Bearer",
		},
	}

	return backend
}
