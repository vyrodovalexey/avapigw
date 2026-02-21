//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// TestFunctional_GRPCBackend_Validation tests GRPCBackend CRD validation.
func TestFunctional_GRPCBackend_Validation(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid basic gRPC backend", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		warnings, err := validator.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid gRPC backend with all fields", func(t *testing.T) {
		backend := createFullGRPCBackend()
		warnings, err := validator.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid - no hosts", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts = nil
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one host is required")
	})

	t.Run("invalid host address - empty", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts[0].Address = ""
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "address is required")
	})

	t.Run("invalid host port - zero", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid host weight - negative", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Hosts[0].Weight = -1
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid gRPC health check - invalid interval", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
			Enabled:  true,
			Interval: "invalid",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "interval is invalid")
	})

	t.Run("invalid gRPC health check - invalid timeout", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.GRPCHealthCheckConfig{
			Enabled: true,
			Timeout: "invalid",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid connection pool - negative max idle conns", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
			MaxIdleConns:    -1,
			MaxConnsPerHost: 100,
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maxIdleConns must be non-negative")
	})

	t.Run("invalid connection pool - negative max conns per host", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.ConnectionPool = &avapigwv1alpha1.GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: -1,
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid circuit breaker - zero threshold", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 0,
			Timeout:   "30s",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
			_, err := validator.ValidateCreate(context.Background(), backend)
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
			_, err := validator.ValidateCreate(context.Background(), backend)
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
			_, err := validator.ValidateCreate(context.Background(), backend)
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
			_, err := validator.ValidateCreate(context.Background(), backend)
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
			_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
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
		_, err := validator.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})
}

// TestFunctional_GRPCBackend_ConfigConversion tests GRPCBackendToBackend conversion.
func TestFunctional_GRPCBackend_ConfigConversion(t *testing.T) {
	t.Parallel()

	t.Run("basic conversion preserves name and hosts", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-svc",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 60},
				{Address: "10.0.0.2", Port: 9000, Weight: 40},
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.Equal(t, "grpc-svc", b.Name)
		assert.Len(t, b.Hosts, 2)
		assert.Equal(t, "10.0.0.1", b.Hosts[0].Address)
		assert.Equal(t, 9000, b.Hosts[0].Port)
		assert.Equal(t, 60, b.Hosts[0].Weight)
		assert.Equal(t, "10.0.0.2", b.Hosts[1].Address)
		assert.Equal(t, 40, b.Hosts[1].Weight)
	})

	t.Run("conversion with health check enabled", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-hc",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			HealthCheck: &config.GRPCHealthCheckConfig{
				Enabled:            true,
				Service:            "grpc.health.v1.Health",
				Interval:           config.Duration(10 * time.Second),
				Timeout:            config.Duration(5 * time.Second),
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.HealthCheck)
		assert.Equal(t, "/grpc.health.v1.Health/Check", b.HealthCheck.Path)
		assert.Equal(t, config.Duration(10*time.Second), b.HealthCheck.Interval)
		assert.Equal(t, config.Duration(5*time.Second), b.HealthCheck.Timeout)
		assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, b.HealthCheck.UnhealthyThreshold)
	})

	t.Run("conversion with health check disabled", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-no-hc",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			HealthCheck: &config.GRPCHealthCheckConfig{
				Enabled: false,
			},
		}

		b := config.GRPCBackendToBackend(gb)
		assert.Nil(t, b.HealthCheck)
	})

	t.Run("conversion with nil health check", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-nil-hc",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			HealthCheck: nil,
		}

		b := config.GRPCBackendToBackend(gb)
		assert.Nil(t, b.HealthCheck)
	})

	t.Run("conversion with TLS simple mode", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-tls",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: &config.TLSConfig{
				Enabled:    true,
				Mode:       "SIMPLE",
				CertFile:   "/certs/tls.crt",
				KeyFile:    "/certs/tls.key",
				CAFile:     "/certs/ca.crt",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.TLS)
		assert.True(t, b.TLS.Enabled)
		assert.Equal(t, "SIMPLE", b.TLS.Mode)
		assert.Equal(t, "/certs/tls.crt", b.TLS.CertFile)
		assert.Equal(t, "/certs/tls.key", b.TLS.KeyFile)
		assert.Equal(t, "/certs/ca.crt", b.TLS.CAFile)
		assert.Equal(t, "TLS12", b.TLS.MinVersion)
		assert.Equal(t, "TLS13", b.TLS.MaxVersion)
		assert.Nil(t, b.TLS.Vault)
	})

	t.Run("conversion with TLS and Vault config", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-vault-tls",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: &config.TLSConfig{
				Enabled:    true,
				Mode:       "MUTUAL",
				MinVersion: "TLS12",
				Vault: &config.VaultGRPCTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-client",
					CommonName: "gateway-grpc-client",
					AltNames:   []string{"gateway.local"},
				},
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.TLS)
		assert.True(t, b.TLS.Enabled)
		assert.Equal(t, "MUTUAL", b.TLS.Mode)
		assert.NotNil(t, b.TLS.Vault)
		assert.True(t, b.TLS.Vault.Enabled)
		assert.Equal(t, "pki", b.TLS.Vault.PKIMount)
		assert.Equal(t, "grpc-client", b.TLS.Vault.Role)
		assert.Equal(t, "gateway-grpc-client", b.TLS.Vault.CommonName)
		assert.Equal(t, []string{"gateway.local"}, b.TLS.Vault.AltNames)
	})

	t.Run("conversion with Vault TLS disabled", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-vault-disabled",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: &config.TLSConfig{
				Enabled: true,
				Mode:    "SIMPLE",
				Vault: &config.VaultGRPCTLSConfig{
					Enabled: false,
				},
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.TLS)
		assert.Nil(t, b.TLS.Vault, "Vault should be nil when disabled")
	})

	t.Run("conversion with circuit breaker", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-cb",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          config.Duration(30 * time.Second),
				HalfOpenRequests: 3,
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.CircuitBreaker)
		assert.True(t, b.CircuitBreaker.Enabled)
		assert.Equal(t, 5, b.CircuitBreaker.Threshold)
		assert.Equal(t, config.Duration(30*time.Second), b.CircuitBreaker.Timeout)
		assert.Equal(t, 3, b.CircuitBreaker.HalfOpenRequests)
	})

	t.Run("conversion with load balancer", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-lb",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			LoadBalancer: &config.LoadBalancer{
				Algorithm: "roundRobin",
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.LoadBalancer)
		assert.Equal(t, "roundRobin", b.LoadBalancer.Algorithm)
	})

	t.Run("conversion with authentication", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-auth",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			Authentication: &config.BackendAuthConfig{
				Type: "jwt",
				JWT: &config.BackendJWTAuthConfig{
					Enabled:      true,
					TokenSource:  "static",
					StaticToken:  "test-token",
					HeaderName:   "authorization",
					HeaderPrefix: "Bearer",
				},
			},
		}

		b := config.GRPCBackendToBackend(gb)

		assert.NotNil(t, b.Authentication)
		assert.Equal(t, "jwt", b.Authentication.Type)
		assert.NotNil(t, b.Authentication.JWT)
		assert.True(t, b.Authentication.JWT.Enabled)
		assert.Equal(t, "static", b.Authentication.JWT.TokenSource)
	})

	t.Run("conversion with nil TLS", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "grpc-no-tls",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: nil,
		}

		b := config.GRPCBackendToBackend(gb)
		assert.Nil(t, b.TLS)
	})
}

// TestFunctional_GRPCBackend_BatchConversion tests GRPCBackendsToBackends batch conversion.
func TestFunctional_GRPCBackend_BatchConversion(t *testing.T) {
	t.Parallel()

	t.Run("empty slice returns empty", func(t *testing.T) {
		t.Parallel()

		result := config.GRPCBackendsToBackends([]config.GRPCBackend{})
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("nil slice returns empty", func(t *testing.T) {
		t.Parallel()

		result := config.GRPCBackendsToBackends(nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("multiple backends converted correctly", func(t *testing.T) {
		t.Parallel()

		gbs := []config.GRPCBackend{
			{
				Name: "backend-1",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 9000, Weight: 1},
				},
				HealthCheck: &config.GRPCHealthCheckConfig{
					Enabled:  true,
					Interval: config.Duration(10 * time.Second),
					Timeout:  config.Duration(5 * time.Second),
				},
			},
			{
				Name: "backend-2",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.2", Port: 9001, Weight: 1},
				},
				TLS: &config.TLSConfig{
					Enabled: true,
					Mode:    "SIMPLE",
				},
			},
			{
				Name: "backend-3",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.3", Port: 9002, Weight: 1},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:   true,
					Threshold: 5,
					Timeout:   config.Duration(30 * time.Second),
				},
			},
		}

		result := config.GRPCBackendsToBackends(gbs)

		assert.Len(t, result, 3)
		assert.Equal(t, "backend-1", result[0].Name)
		assert.NotNil(t, result[0].HealthCheck)
		assert.Equal(t, "backend-2", result[1].Name)
		assert.NotNil(t, result[1].TLS)
		assert.Equal(t, "backend-3", result[2].Name)
		assert.NotNil(t, result[2].CircuitBreaker)
	})

	t.Run("single backend converted correctly", func(t *testing.T) {
		t.Parallel()

		gbs := []config.GRPCBackend{
			{
				Name: "single-backend",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 9000, Weight: 100},
				},
			},
		}

		result := config.GRPCBackendsToBackends(gbs)

		assert.Len(t, result, 1)
		assert.Equal(t, "single-backend", result[0].Name)
		assert.Equal(t, 100, result[0].Hosts[0].Weight)
	})
}

// TestFunctional_GRPCBackend_Update tests GRPCBackend update validation.
func TestFunctional_GRPCBackend_Update(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid update", func(t *testing.T) {
		oldBackend := createBasicGRPCBackend()
		newBackend := createBasicGRPCBackend()
		newBackend.Spec.Hosts[0].Weight = 50
		warnings, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		oldBackend := createBasicGRPCBackend()
		newBackend := createBasicGRPCBackend()
		newBackend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
		assert.Error(t, err)
	})
}

// TestFunctional_GRPCBackend_Delete tests GRPCBackend delete validation.
func TestFunctional_GRPCBackend_Delete(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		warnings, err := validator.ValidateDelete(context.Background(), backend)
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
