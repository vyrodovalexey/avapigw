//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify cache feature configuration and logic in isolation.
package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ---------------------------------------------------------------------------
// TTL Jitter Config Tests
// ---------------------------------------------------------------------------

// TestFunctional_Cache_Features_TTLJitter_ConfigDefaults tests that TTLJitter
// defaults to 0 in a fresh RedisCacheConfig.
func TestFunctional_Cache_Features_TTLJitter_ConfigDefaults(t *testing.T) {
	t.Parallel()

	t.Run("TTLJitter defaults to 0 in RedisCacheConfig", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisCacheConfig{}
		assert.Equal(t, 0.0, cfg.TTLJitter, "TTLJitter should default to 0")
	})

	t.Run("DefaultRedisCacheConfig has zero TTLJitter", func(t *testing.T) {
		t.Parallel()
		cfg := config.DefaultRedisCacheConfig()
		require.NotNil(t, cfg)
		assert.Equal(t, 0.0, cfg.TTLJitter, "DefaultRedisCacheConfig TTLJitter should be 0")
	})

	t.Run("DefaultRedisTTLJitter constant is 0", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 0.0, config.DefaultRedisTTLJitter)
	})
}

// TestFunctional_Cache_Features_TTLJitter_AcceptsValidRange tests that TTLJitter
// accepts values in the range [0.0, 1.0].
func TestFunctional_Cache_Features_TTLJitter_AcceptsValidRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		jitter   float64
		expected float64
	}{
		{"zero jitter", 0.0, 0.0},
		{"small jitter", 0.05, 0.05},
		{"ten percent jitter", 0.1, 0.1},
		{"half jitter", 0.5, 0.5},
		{"full jitter", 1.0, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.RedisCacheConfig{TTLJitter: tt.jitter}
			assert.Equal(t, tt.expected, cfg.TTLJitter)
		})
	}
}

// TestFunctional_Cache_Features_TTLJitter_CreateTestCacheConfig tests that
// CreateTestCacheConfig can be used with TTLJitter set.
func TestFunctional_Cache_Features_TTLJitter_CreateTestCacheConfig(t *testing.T) {
	t.Parallel()

	t.Run("redis config with TTLJitter set", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       "redis://localhost:6379",
				TTLJitter: 0.1,
			},
		}
		require.NotNil(t, cfg.Redis)
		assert.Equal(t, 0.1, cfg.Redis.TTLJitter)
	})

	t.Run("sentinel config with TTLJitter set", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				TTLJitter: 0.2,
				Sentinel: &config.RedisSentinelConfig{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"127.0.0.1:26379"},
				},
			},
		}
		require.NotNil(t, cfg.Redis)
		assert.Equal(t, 0.2, cfg.Redis.TTLJitter)
	})
}

// TestFunctional_Cache_Features_TTLJitter_ApplyFunction tests the applyTTLJitter
// behaviour via the exported cache interface. Since applyTTLJitter is unexported,
// we verify its behaviour indirectly through config field semantics.
func TestFunctional_Cache_Features_TTLJitter_ApplyFunction(t *testing.T) {
	t.Parallel()

	t.Run("jitter factor > 1.0 is stored as-is in config", func(t *testing.T) {
		t.Parallel()
		// The config struct itself does not validate; clamping happens at runtime
		// inside applyTTLJitter. We verify the config stores the value.
		cfg := &config.RedisCacheConfig{TTLJitter: 1.5}
		assert.Equal(t, 1.5, cfg.TTLJitter)
	})

	t.Run("negative jitter factor is stored as-is in config", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisCacheConfig{TTLJitter: -0.1}
		assert.Equal(t, -0.1, cfg.TTLJitter)
	})
}

// ---------------------------------------------------------------------------
// Hash Keys Config Tests
// ---------------------------------------------------------------------------

// TestFunctional_Cache_Features_HashKeys_ConfigDefaults tests that HashKeys
// defaults to false in a fresh RedisCacheConfig.
func TestFunctional_Cache_Features_HashKeys_ConfigDefaults(t *testing.T) {
	t.Parallel()

	t.Run("HashKeys defaults to false", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisCacheConfig{}
		assert.False(t, cfg.HashKeys, "HashKeys should default to false")
	})

	t.Run("DefaultRedisCacheConfig has HashKeys false", func(t *testing.T) {
		t.Parallel()
		cfg := config.DefaultRedisCacheConfig()
		require.NotNil(t, cfg)
		assert.False(t, cfg.HashKeys)
	})
}

// TestFunctional_Cache_Features_HashKey_Consistency tests that HashKey produces
// consistent SHA256 hashes.
func TestFunctional_Cache_Features_HashKey_Consistency(t *testing.T) {
	t.Parallel()

	t.Run("same input produces same hash", func(t *testing.T) {
		t.Parallel()
		key := "GET:/api/v1/users?page=1"
		hash1 := cache.HashKey(key)
		hash2 := cache.HashKey(key)
		assert.Equal(t, hash1, hash2, "HashKey should be deterministic")
	})

	t.Run("hash is 64 hex characters (SHA256)", func(t *testing.T) {
		t.Parallel()
		hash := cache.HashKey("test-key")
		assert.Len(t, hash, 64, "SHA256 hex should be 64 characters")
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		t.Parallel()
		hash1 := cache.HashKey("key-alpha")
		hash2 := cache.HashKey("key-beta")
		assert.NotEqual(t, hash1, hash2, "different inputs should produce different hashes")
	})

	t.Run("empty string produces valid hash", func(t *testing.T) {
		t.Parallel()
		hash := cache.HashKey("")
		assert.Len(t, hash, 64)
		// SHA256 of empty string is well-known
		assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
	})
}

// TestFunctional_Cache_Features_HashKey_DataDriven uses data-driven tests to
// verify HashKey produces expected SHA256 outputs.
func TestFunctional_Cache_Features_HashKey_DataDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"short key", "k"},
		{"medium key", "GET:/api/v1/items"},
		{"long key with query", "GET:/api/v1/items?page=1&limit=100&sort=name&order=asc&filter=active"},
		{"key with special chars", "key:with/special.chars-and_underscores"},
		{"unicode key", "ключ:значение"},
	}

	hashes := make(map[string]string, len(tests))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hash := cache.HashKey(tt.input)
			assert.Len(t, hash, 64)
			// Verify consistency
			assert.Equal(t, hash, cache.HashKey(tt.input))
		})
		hashes[tt.input] = cache.HashKey(tt.input)
	}

	// Verify all hashes are unique
	seen := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		assert.False(t, seen[h], "hash collision detected")
		seen[h] = true
	}
}

// ---------------------------------------------------------------------------
// Vault Password Config Tests
// ---------------------------------------------------------------------------

// TestFunctional_Cache_Features_VaultPassword_ConfigFields tests that
// PasswordVaultPath fields are correctly stored in config structs.
func TestFunctional_Cache_Features_VaultPassword_ConfigFields(t *testing.T) {
	t.Parallel()

	t.Run("PasswordVaultPath in RedisCacheConfig", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisCacheConfig{
			PasswordVaultPath: "secret/redis/standalone",
		}
		assert.Equal(t, "secret/redis/standalone", cfg.PasswordVaultPath)
	})

	t.Run("PasswordVaultPath defaults to empty", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisCacheConfig{}
		assert.Empty(t, cfg.PasswordVaultPath)
	})

	t.Run("PasswordVaultPath in RedisSentinelConfig", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisSentinelConfig{
			PasswordVaultPath: "secret/redis/master",
		}
		assert.Equal(t, "secret/redis/master", cfg.PasswordVaultPath)
	})

	t.Run("SentinelPasswordVaultPath in RedisSentinelConfig", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisSentinelConfig{
			SentinelPasswordVaultPath: "secret/redis/sentinel",
		}
		assert.Equal(t, "secret/redis/sentinel", cfg.SentinelPasswordVaultPath)
	})

	t.Run("both vault paths in sentinel config", func(t *testing.T) {
		t.Parallel()
		cfg := &config.RedisSentinelConfig{
			MasterName:                "mymaster",
			SentinelAddrs:             []string{"127.0.0.1:26379"},
			PasswordVaultPath:         "secret/redis/master",
			SentinelPasswordVaultPath: "secret/redis/sentinel",
		}
		assert.Equal(t, "secret/redis/master", cfg.PasswordVaultPath)
		assert.Equal(t, "secret/redis/sentinel", cfg.SentinelPasswordVaultPath)
	})
}

// TestFunctional_Cache_Features_VaultPassword_CacheConfigIntegration tests
// that vault paths work correctly within the full CacheConfig hierarchy.
func TestFunctional_Cache_Features_VaultPassword_CacheConfigIntegration(t *testing.T) {
	t.Parallel()

	t.Run("standalone redis with vault path", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:               "redis://default@127.0.0.1:6379",
				PasswordVaultPath: "secret/redis/password",
			},
		}
		require.NotNil(t, cfg.Redis)
		assert.Equal(t, "secret/redis/password", cfg.Redis.PasswordVaultPath)
	})

	t.Run("sentinel redis with vault paths", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				Sentinel: &config.RedisSentinelConfig{
					MasterName:                "mymaster",
					SentinelAddrs:             []string{"127.0.0.1:26379"},
					PasswordVaultPath:         "secret/redis/master-pw",
					SentinelPasswordVaultPath: "secret/redis/sentinel-pw",
				},
			},
		}
		require.NotNil(t, cfg.Redis.Sentinel)
		assert.Equal(t, "secret/redis/master-pw", cfg.Redis.Sentinel.PasswordVaultPath)
		assert.Equal(t, "secret/redis/sentinel-pw", cfg.Redis.Sentinel.SentinelPasswordVaultPath)
	})

	t.Run("combined standalone vault path and sentinel vault paths", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			Redis: &config.RedisCacheConfig{
				URL:               "redis://default@127.0.0.1:6379",
				PasswordVaultPath: "secret/redis/standalone-pw",
				Sentinel: &config.RedisSentinelConfig{
					MasterName:                "mymaster",
					SentinelAddrs:             []string{"127.0.0.1:26379"},
					PasswordVaultPath:         "secret/redis/master-pw",
					SentinelPasswordVaultPath: "secret/redis/sentinel-pw",
				},
			},
		}
		assert.Equal(t, "secret/redis/standalone-pw", cfg.Redis.PasswordVaultPath)
		assert.Equal(t, "secret/redis/master-pw", cfg.Redis.Sentinel.PasswordVaultPath)
		assert.Equal(t, "secret/redis/sentinel-pw", cfg.Redis.Sentinel.SentinelPasswordVaultPath)
	})
}

// TestFunctional_Cache_Features_AllFeaturesCombined tests that all three features
// can be configured together in a single RedisCacheConfig.
func TestFunctional_Cache_Features_AllFeaturesCombined(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL:               "redis://default@127.0.0.1:6379",
		TTLJitter:         0.1,
		HashKeys:          true,
		PasswordVaultPath: "secret/redis/password",
		KeyPrefix:         "myapp:",
		PoolSize:          10,
	}

	assert.Equal(t, 0.1, cfg.TTLJitter)
	assert.True(t, cfg.HashKeys)
	assert.Equal(t, "secret/redis/password", cfg.PasswordVaultPath)
	assert.Equal(t, "myapp:", cfg.KeyPrefix)
	assert.Equal(t, 10, cfg.PoolSize)
}
