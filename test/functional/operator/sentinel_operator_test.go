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

// TestFunctional_Operator_CRDWithSentinelCache tests CRD with sentinel cache config.
func TestFunctional_Operator_CRDWithSentinelCache(t *testing.T) {
	validator := &webhook.BackendValidator{}

	t.Run("valid backend with sentinel cache", func(t *testing.T) {
		backend := createBackendWithSentinelCache()
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("valid backend with sentinel cache and all sentinel fields", func(t *testing.T) {
		backend := createBackendWithSentinelCache()
		backend.Spec.Cache.Sentinel = &avapigwv1alpha1.RedisSentinelSpec{
			MasterName: "mymaster",
			SentinelAddrs: []string{
				"sentinel-0.sentinel:26379",
				"sentinel-1.sentinel:26379",
				"sentinel-2.sentinel:26379",
			},
			SentinelPassword: "sentinel-pass",
			Password:         "master-pass",
			DB:               2,
		}
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("valid backend with sentinel cache minimal config", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "5m",
			Type:    "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
		}
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("valid backend with memory cache (no sentinel)", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled:       true,
			TTL:           "5m",
			KeyComponents: []string{"path", "query"},
			Type:          "memory",
		}
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("valid backend with redis cache without sentinel", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "10m",
			Type:    "redis",
		}
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid backend cache TTL with sentinel", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "invalid",
			Type:    "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ttl is invalid")
	})

	t.Run("disabled cache with sentinel is valid", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: false,
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
		}
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("nil cache is valid", func(t *testing.T) {
		backend := createBasicBackend()
		backend.Spec.Cache = nil
		warnings, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
		_ = warnings
	})
}

// TestFunctional_Operator_WebhookSentinelValidation tests webhook validates sentinel config.
func TestFunctional_Operator_WebhookSentinelValidation(t *testing.T) {
	t.Run("backend update with sentinel cache", func(t *testing.T) {
		validator := &webhook.BackendValidator{}

		oldBackend := createBasicBackend()
		newBackend := createBackendWithSentinelCache()

		warnings, err := validator.ValidateUpdate(nil, oldBackend, newBackend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("backend update from standalone to sentinel cache", func(t *testing.T) {
		validator := &webhook.BackendValidator{}

		oldBackend := createBasicBackend()
		oldBackend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "5m",
			Type:    "redis",
		}

		newBackend := createBackendWithSentinelCache()

		warnings, err := validator.ValidateUpdate(nil, oldBackend, newBackend)
		assert.NoError(t, err)
		_ = warnings
	})

	t.Run("backend delete with sentinel cache", func(t *testing.T) {
		validator := &webhook.BackendValidator{}

		backend := createBackendWithSentinelCache()
		warnings, err := validator.ValidateDelete(nil, backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("sentinel spec in authorization cache", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}

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
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName: "mymaster",
					SentinelAddrs: []string{
						"sentinel-0:26379",
						"sentinel-1:26379",
						"sentinel-2:26379",
					},
					Password: "master-pass",
				},
			},
		}
		_, err := validator.ValidateCreate(nil, route)
		assert.NoError(t, err)
	})

	t.Run("sentinel spec fields are correctly set", func(t *testing.T) {
		spec := &avapigwv1alpha1.RedisSentinelSpec{
			MasterName: "mymaster",
			SentinelAddrs: []string{
				"host1:26379",
				"host2:26379",
				"host3:26379",
			},
			SentinelPassword: "sentinel-pass",
			Password:         "master-pass",
			DB:               3,
		}

		assert.Equal(t, "mymaster", spec.MasterName)
		assert.Len(t, spec.SentinelAddrs, 3)
		assert.Equal(t, "sentinel-pass", spec.SentinelPassword)
		assert.Equal(t, "master-pass", spec.Password)
		assert.Equal(t, 3, spec.DB)
	})

	t.Run("backend cache sentinel spec in CRD", func(t *testing.T) {
		cache := &avapigwv1alpha1.BackendCacheConfig{
			Enabled:       true,
			TTL:           "10m",
			KeyComponents: []string{"path", "query", "headers.authorization"},
			Type:          "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName: "mymaster",
				SentinelAddrs: []string{
					"sentinel-0.sentinel:26379",
					"sentinel-1.sentinel:26379",
					"sentinel-2.sentinel:26379",
				},
				Password: "redis-master-password",
				DB:       0,
			},
		}

		assert.True(t, cache.Enabled)
		assert.Equal(t, "redis", cache.Type)
		assert.NotNil(t, cache.Sentinel)
		assert.Equal(t, "mymaster", cache.Sentinel.MasterName)
		assert.Len(t, cache.Sentinel.SentinelAddrs, 3)
	})

	t.Run("combined backend with all fields including sentinel cache", func(t *testing.T) {
		validator := &webhook.BackendValidator{}

		backend := createFullBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled:       true,
			TTL:           "10m",
			KeyComponents: []string{"path", "query"},
			Type:          "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379", "sentinel-1:26379"},
				Password:      "master-pass",
			},
		}
		backend.Spec.RequestLimits = &avapigwv1alpha1.RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		}
		backend.Spec.Transform = &avapigwv1alpha1.BackendTransformConfig{
			Response: &avapigwv1alpha1.BackendResponseTransform{
				DenyFields: []string{"password", "secret"},
			},
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

// TestFunctional_Operator_GRPCBackendSentinelCache tests gRPC backend with sentinel cache.
func TestFunctional_Operator_GRPCBackendSentinelCache(t *testing.T) {
	validator := &webhook.GRPCBackendValidator{}

	t.Run("valid gRPC backend with sentinel cache", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "5m",
			Type:    "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
				Password:      "master-pass",
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.NoError(t, err)
	})

	t.Run("invalid gRPC backend cache TTL with sentinel", func(t *testing.T) {
		backend := createBasicGRPCBackend()
		backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
			Enabled: true,
			TTL:     "invalid",
			Type:    "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
		}
		_, err := validator.ValidateCreate(nil, backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ttl is invalid")
	})
}

// Helper function to create a backend with sentinel cache config.
func createBackendWithSentinelCache() *avapigwv1alpha1.Backend {
	return &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sentinel-cache-backend",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "10.0.1.10",
					Port:    8080,
					Weight:  50,
				},
				{
					Address: "10.0.1.11",
					Port:    8080,
					Weight:  50,
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
			Cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:       true,
				TTL:           "10m",
				KeyComponents: []string{"path", "query"},
				Type:          "redis",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName: "mymaster",
					SentinelAddrs: []string{
						"sentinel-0.sentinel:26379",
						"sentinel-1.sentinel:26379",
						"sentinel-2.sentinel:26379",
					},
					Password: "redis-master-password",
					DB:       0,
				},
			},
		},
	}
}
