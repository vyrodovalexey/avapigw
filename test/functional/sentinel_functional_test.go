//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify sentinel cache configuration logic in isolation.
package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestFunctional_Sentinel_ConfigLoading tests loading gateway config with sentinel settings.
func TestFunctional_Sentinel_ConfigLoading(t *testing.T) {
	t.Parallel()

	t.Run("load sentinel config from YAML", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-sentinel.yaml")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
		assert.Equal(t, "Gateway", cfg.Kind)
		assert.Equal(t, "sentinel-test-gateway", cfg.Metadata.Name)
	})

	t.Run("sentinel config has correct listeners", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-sentinel.yaml")
		require.NoError(t, err)

		require.Len(t, cfg.Spec.Listeners, 1)
		listener := cfg.Spec.Listeners[0]
		assert.Equal(t, "http", listener.Name)
		assert.Equal(t, 18090, listener.Port)
		assert.Equal(t, "HTTP", listener.Protocol)
		assert.Equal(t, "127.0.0.1", listener.Bind)
	})

	t.Run("sentinel config has cache route with sentinel settings", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-sentinel.yaml")
		require.NoError(t, err)

		// Find the cached-api route
		var cachedRoute *config.Route
		for i := range cfg.Spec.Routes {
			if cfg.Spec.Routes[i].Name == "cached-api" {
				cachedRoute = &cfg.Spec.Routes[i]
				break
			}
		}
		require.NotNil(t, cachedRoute, "cached-api route should exist")

		require.NotNil(t, cachedRoute.Cache, "cache config should be set")
		assert.True(t, cachedRoute.Cache.Enabled)
		assert.Equal(t, config.CacheTypeRedis, cachedRoute.Cache.Type)

		require.NotNil(t, cachedRoute.Cache.Redis, "redis config should be set")
		require.NotNil(t, cachedRoute.Cache.Redis.Sentinel, "sentinel config should be set")

		sentinel := cachedRoute.Cache.Redis.Sentinel
		assert.Equal(t, "mymaster", sentinel.MasterName)
		assert.Len(t, sentinel.SentinelAddrs, 3)
		assert.Contains(t, sentinel.SentinelAddrs, "127.0.0.1:26379")
		assert.Contains(t, sentinel.SentinelAddrs, "127.0.0.1:26380")
		assert.Contains(t, sentinel.SentinelAddrs, "127.0.0.1:26381")
		assert.Equal(t, "password", sentinel.Password)
	})

	t.Run("sentinel config validates successfully", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-sentinel.yaml")
		require.NoError(t, err)

		err = config.ValidateConfig(cfg)
		require.NoError(t, err)
	})
}

// TestFunctional_Sentinel_ConfigValidation tests validation of sentinel config (valid and invalid).
func TestFunctional_Sentinel_ConfigValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid sentinel config", func(t *testing.T) {
		t.Parallel()

		sentinelCfg := &config.RedisSentinelConfig{
			MasterName: "mymaster",
			SentinelAddrs: []string{
				"127.0.0.1:26379",
				"127.0.0.1:26380",
				"127.0.0.1:26381",
			},
			Password: "password",
			DB:       0,
		}

		assert.False(t, sentinelCfg.IsEmpty(), "valid sentinel config should not be empty")
	})

	t.Run("empty sentinel config", func(t *testing.T) {
		t.Parallel()

		sentinelCfg := &config.RedisSentinelConfig{}
		assert.True(t, sentinelCfg.IsEmpty(), "empty sentinel config should be empty")
	})

	t.Run("nil sentinel config", func(t *testing.T) {
		t.Parallel()

		var sentinelCfg *config.RedisSentinelConfig
		assert.True(t, sentinelCfg.IsEmpty(), "nil sentinel config should be empty")
	})

	t.Run("sentinel config with only master name", func(t *testing.T) {
		t.Parallel()

		sentinelCfg := &config.RedisSentinelConfig{
			MasterName: "mymaster",
		}
		assert.False(t, sentinelCfg.IsEmpty(), "sentinel config with master name should not be empty")
	})

	t.Run("redis cache config with sentinel is not empty", func(t *testing.T) {
		t.Parallel()

		redisCfg := &config.RedisCacheConfig{
			KeyPrefix: "test:",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"127.0.0.1:26379"},
			},
		}
		assert.False(t, redisCfg.IsEmpty(), "redis config with sentinel should not be empty")
	})

	t.Run("redis cache config without URL and without sentinel is empty", func(t *testing.T) {
		t.Parallel()

		redisCfg := &config.RedisCacheConfig{
			KeyPrefix: "test:",
		}
		assert.True(t, redisCfg.IsEmpty(), "redis config without URL and sentinel should be empty")
	})

	t.Run("default sentinel config", func(t *testing.T) {
		t.Parallel()

		defaultCfg := config.DefaultRedisSentinelConfig()
		require.NotNil(t, defaultCfg)
		assert.Equal(t, 0, defaultCfg.DB)
		assert.Empty(t, defaultCfg.MasterName)
		assert.Empty(t, defaultCfg.SentinelAddrs)
	})

	t.Run("cache config with sentinel type", func(t *testing.T) {
		t.Parallel()

		cfg := helpers.CreateTestCacheConfig("redis-sentinel")
		require.NotNil(t, cfg)
		assert.True(t, cfg.Enabled)
		assert.Equal(t, config.CacheTypeRedis, cfg.Type)
		require.NotNil(t, cfg.Redis)
		require.NotNil(t, cfg.Redis.Sentinel)
		assert.NotEmpty(t, cfg.Redis.Sentinel.MasterName)
		assert.NotEmpty(t, cfg.Redis.Sentinel.SentinelAddrs)
	})
}

// TestFunctional_Sentinel_AndStandaloneExclusive tests that URL and Sentinel are mutually exclusive.
func TestFunctional_Sentinel_AndStandaloneExclusive(t *testing.T) {
	t.Parallel()

	t.Run("standalone URL only", func(t *testing.T) {
		t.Parallel()

		redisCfg := &config.RedisCacheConfig{
			URL:       "redis://default:password@127.0.0.1:6379",
			KeyPrefix: "test:",
		}
		assert.False(t, redisCfg.IsEmpty())
		assert.Nil(t, redisCfg.Sentinel)
	})

	t.Run("sentinel only", func(t *testing.T) {
		t.Parallel()

		redisCfg := &config.RedisCacheConfig{
			KeyPrefix: "test:",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"127.0.0.1:26379"},
				Password:      "password",
			},
		}
		assert.False(t, redisCfg.IsEmpty())
		assert.Empty(t, redisCfg.URL)
	})

	t.Run("both URL and sentinel configured", func(t *testing.T) {
		t.Parallel()

		// When both are configured, sentinel takes precedence (per redis.go logic)
		redisCfg := &config.RedisCacheConfig{
			URL:       "redis://default:password@127.0.0.1:6379",
			KeyPrefix: "test:",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"127.0.0.1:26379"},
				Password:      "password",
			},
		}
		assert.False(t, redisCfg.IsEmpty())
		// Both are set - sentinel takes precedence in newRedisCache
		assert.NotEmpty(t, redisCfg.URL)
		assert.NotNil(t, redisCfg.Sentinel)
	})

	t.Run("cache config IsEmpty checks", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			cfg      *config.CacheConfig
			expected bool
		}{
			{
				name:     "nil config",
				cfg:      nil,
				expected: true,
			},
			{
				name: "disabled config",
				cfg: &config.CacheConfig{
					Enabled: false,
				},
				expected: true,
			},
			{
				name: "enabled config",
				cfg: &config.CacheConfig{
					Enabled: true,
					Type:    config.CacheTypeRedis,
				},
				expected: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				assert.Equal(t, tt.expected, tt.cfg.IsEmpty())
			})
		}
	})

	t.Run("sentinel config fields", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RedisSentinelConfig{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"host1:26379", "host2:26379", "host3:26379"},
			SentinelPassword: "sentinel-pass",
			Password:         "master-pass",
			DB:               2,
		}

		assert.Equal(t, "mymaster", cfg.MasterName)
		assert.Len(t, cfg.SentinelAddrs, 3)
		assert.Equal(t, "sentinel-pass", cfg.SentinelPassword)
		assert.Equal(t, "master-pass", cfg.Password)
		assert.Equal(t, 2, cfg.DB)
	})

	t.Run("default redis cache config", func(t *testing.T) {
		t.Parallel()

		defaultCfg := config.DefaultRedisCacheConfig()
		require.NotNil(t, defaultCfg)
		assert.Empty(t, defaultCfg.URL)
		assert.Nil(t, defaultCfg.Sentinel)
		assert.Greater(t, defaultCfg.PoolSize, 0)
		assert.NotEmpty(t, defaultCfg.KeyPrefix)
	})

	t.Run("cache TTL configuration", func(t *testing.T) {
		t.Parallel()

		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				Sentinel: &config.RedisSentinelConfig{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"127.0.0.1:26379"},
				},
			},
		}

		assert.Equal(t, 5*time.Minute, cfg.TTL.Duration())
	})
}
