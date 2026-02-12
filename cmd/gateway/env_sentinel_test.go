package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestApplyRedisSentinelEnv_AllVarsSet(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "sentinel1:26379,sentinel2:26379,sentinel3:26379")
	t.Setenv("REDIS_SENTINEL_PASSWORD", "sentinelpass")
	t.Setenv("REDIS_MASTER_PASSWORD", "masterpass")

	redisCfg := &config.RedisCacheConfig{}
	applyRedisSentinelEnv(redisCfg)

	require.NotNil(t, redisCfg.Sentinel)
	assert.Equal(t, "mymaster", redisCfg.Sentinel.MasterName)
	assert.Equal(t, []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"}, redisCfg.Sentinel.SentinelAddrs)
	assert.Equal(t, "sentinelpass", redisCfg.Sentinel.SentinelPassword)
	assert.Equal(t, "masterpass", redisCfg.Sentinel.Password)
}

func TestApplyRedisSentinelEnv_PartialVars(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "sentinel1:26379")

	redisCfg := &config.RedisCacheConfig{}
	applyRedisSentinelEnv(redisCfg)

	require.NotNil(t, redisCfg.Sentinel)
	assert.Equal(t, "mymaster", redisCfg.Sentinel.MasterName)
	assert.Equal(t, []string{"sentinel1:26379"}, redisCfg.Sentinel.SentinelAddrs)
	assert.Empty(t, redisCfg.Sentinel.SentinelPassword)
	assert.Empty(t, redisCfg.Sentinel.Password)
}

func TestApplyRedisSentinelEnv_NoVars(t *testing.T) {
	// Ensure env vars are not set (t.Setenv not called)
	redisCfg := &config.RedisCacheConfig{
		URL: "redis://localhost:6379",
	}
	applyRedisSentinelEnv(redisCfg)

	// Sentinel should not be initialized
	assert.Nil(t, redisCfg.Sentinel)
	// URL should remain unchanged
	assert.Equal(t, "redis://localhost:6379", redisCfg.URL)
}

func TestApplyRedisSentinelEnv_NilConfig(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")

	// Should not panic
	applyRedisSentinelEnv(nil)
}

func TestApplyRedisSentinelEnv_OverridesExistingConfig(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "newmaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "new-sentinel:26379")

	redisCfg := &config.RedisCacheConfig{
		Sentinel: &config.RedisSentinelConfig{
			MasterName:    "oldmaster",
			SentinelAddrs: []string{"old-sentinel:26379"},
			Password:      "oldpass",
		},
	}
	applyRedisSentinelEnv(redisCfg)

	assert.Equal(t, "newmaster", redisCfg.Sentinel.MasterName)
	assert.Equal(t, []string{"new-sentinel:26379"}, redisCfg.Sentinel.SentinelAddrs)
	// Password should remain unchanged since REDIS_MASTER_PASSWORD is not set
	assert.Equal(t, "oldpass", redisCfg.Sentinel.Password)
}

func TestApplyRedisSentinelEnv_AddrsWithSpaces(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", " sentinel1:26379 , sentinel2:26379 , sentinel3:26379 ")

	redisCfg := &config.RedisCacheConfig{}
	applyRedisSentinelEnv(redisCfg)

	require.NotNil(t, redisCfg.Sentinel)
	assert.Equal(t, []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"}, redisCfg.Sentinel.SentinelAddrs)
}

func TestApplyRedisSentinelEnv_AddrsWithEmptyEntries(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "sentinel1:26379,,sentinel2:26379,")

	redisCfg := &config.RedisCacheConfig{}
	applyRedisSentinelEnv(redisCfg)

	require.NotNil(t, redisCfg.Sentinel)
	// Empty entries should be filtered out
	assert.Equal(t, []string{"sentinel1:26379", "sentinel2:26379"}, redisCfg.Sentinel.SentinelAddrs)
}

func TestApplyRedisSentinelEnv_OnlyPasswordSet(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_PASSWORD", "sentinelpass")

	redisCfg := &config.RedisCacheConfig{}
	applyRedisSentinelEnv(redisCfg)

	require.NotNil(t, redisCfg.Sentinel)
	assert.Empty(t, redisCfg.Sentinel.MasterName)
	assert.Equal(t, "sentinelpass", redisCfg.Sentinel.SentinelPassword)
}

func TestApplyRedisSentinelEnv_OnlyMasterPasswordSet(t *testing.T) {
	t.Setenv("REDIS_MASTER_PASSWORD", "masterpass")

	redisCfg := &config.RedisCacheConfig{}
	applyRedisSentinelEnv(redisCfg)

	require.NotNil(t, redisCfg.Sentinel)
	assert.Equal(t, "masterpass", redisCfg.Sentinel.Password)
}

func TestApplyRedisSentinelEnvToConfig_NilConfig(t *testing.T) {
	// Should not panic
	applyRedisSentinelEnvToConfig(nil)
}

func TestApplyRedisSentinelEnvToConfig_NoRoutes(t *testing.T) {
	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{},
		},
	}

	// Should not panic
	applyRedisSentinelEnvToConfig(cfg)
}

func TestApplyRedisSentinelEnvToConfig_AppliesToRedisRoutes(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "sentinel1:26379")

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{
					Name: "redis-route",
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeRedis,
						Redis: &config.RedisCacheConfig{
							URL: "redis://localhost:6379",
						},
					},
				},
				{
					Name: "memory-route",
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeMemory,
					},
				},
				{
					Name: "no-cache-route",
				},
			},
		},
	}

	applyRedisSentinelEnvToConfig(cfg)

	// Redis route should have sentinel config applied
	require.NotNil(t, cfg.Spec.Routes[0].Cache.Redis.Sentinel)
	assert.Equal(t, "mymaster", cfg.Spec.Routes[0].Cache.Redis.Sentinel.MasterName)
	assert.Equal(t, []string{"sentinel1:26379"}, cfg.Spec.Routes[0].Cache.Redis.Sentinel.SentinelAddrs)

	// Memory route should not be affected
	assert.Nil(t, cfg.Spec.Routes[1].Cache.Redis)

	// No-cache route should not be affected
	assert.Nil(t, cfg.Spec.Routes[2].Cache)
}

func TestApplyRedisSentinelEnvToConfig_SkipsNonRedisRoutes(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "sentinel1:26379")

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{
					Name: "memory-route",
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeMemory,
					},
				},
			},
		},
	}

	applyRedisSentinelEnvToConfig(cfg)

	// Memory route should not have Redis config
	assert.Nil(t, cfg.Spec.Routes[0].Cache.Redis)
}

func TestApplyRedisSentinelEnvToConfig_SkipsRoutesWithNilRedis(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	t.Setenv("REDIS_SENTINEL_ADDRS", "sentinel1:26379")

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{
					Name: "redis-route-no-redis-cfg",
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeRedis,
						Redis:   nil, // nil Redis config
					},
				},
			},
		},
	}

	applyRedisSentinelEnvToConfig(cfg)

	// Should not panic, Redis config remains nil
	assert.Nil(t, cfg.Spec.Routes[0].Cache.Redis)
}

func TestEnvRedisSentinelConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "REDIS_SENTINEL_MASTER_NAME", envRedisSentinelMasterName)
	assert.Equal(t, "REDIS_SENTINEL_ADDRS", envRedisSentinelAddrs)
	assert.Equal(t, "REDIS_SENTINEL_PASSWORD", envRedisSentinelPassword)
	assert.Equal(t, "REDIS_MASTER_PASSWORD", envRedisMasterPassword)
}

// --- Redis Feature ENV Tests ---

func TestApplyRedisFeatureEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		initial *config.RedisCacheConfig
		check   func(t *testing.T, cfg *config.RedisCacheConfig)
	}{
		{
			name: "REDIS_TTL_JITTER sets jitter factor",
			envVars: map[string]string{
				"REDIS_TTL_JITTER": "0.15",
			},
			initial: &config.RedisCacheConfig{},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				assert.InDelta(t, 0.15, cfg.TTLJitter, 0.001)
			},
		},
		{
			name: "REDIS_HASH_KEYS=true enables hash keys",
			envVars: map[string]string{
				"REDIS_HASH_KEYS": "true",
			},
			initial: &config.RedisCacheConfig{HashKeys: false},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				assert.True(t, cfg.HashKeys)
			},
		},
		{
			name: "REDIS_HASH_KEYS=false disables hash keys",
			envVars: map[string]string{
				"REDIS_HASH_KEYS": "false",
			},
			initial: &config.RedisCacheConfig{HashKeys: true},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				assert.False(t, cfg.HashKeys)
			},
		},
		{
			name: "REDIS_PASSWORD_VAULT_PATH sets vault path",
			envVars: map[string]string{
				"REDIS_PASSWORD_VAULT_PATH": "secret/redis-pw",
			},
			initial: &config.RedisCacheConfig{},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				assert.Equal(t, "secret/redis-pw",
					cfg.PasswordVaultPath)
			},
		},
		{
			name: "REDIS_SENTINEL_PASSWORD_VAULT_PATH sets sentinel vault path",
			envVars: map[string]string{
				"REDIS_SENTINEL_PASSWORD_VAULT_PATH": "secret/master-pw",
			},
			initial: &config.RedisCacheConfig{},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				require.NotNil(t, cfg.Sentinel)
				assert.Equal(t, "secret/master-pw",
					cfg.Sentinel.PasswordVaultPath)
			},
		},
		{
			name: "REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH sets sentinel auth vault path",
			envVars: map[string]string{
				"REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH": "secret/sentinel-pw",
			},
			initial: &config.RedisCacheConfig{},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				require.NotNil(t, cfg.Sentinel)
				assert.Equal(t, "secret/sentinel-pw",
					cfg.Sentinel.SentinelPasswordVaultPath)
			},
		},
		{
			name: "invalid REDIS_TTL_JITTER value is ignored",
			envVars: map[string]string{
				"REDIS_TTL_JITTER": "not-a-number",
			},
			initial: &config.RedisCacheConfig{TTLJitter: 0.5},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				assert.InDelta(t, 0.5, cfg.TTLJitter, 0.001,
					"invalid value should not change existing config")
			},
		},
		{
			name:    "empty env vars don't override config",
			envVars: map[string]string{},
			initial: &config.RedisCacheConfig{
				TTLJitter:         0.2,
				HashKeys:          true,
				PasswordVaultPath: "secret/existing",
			},
			check: func(t *testing.T, cfg *config.RedisCacheConfig) {
				t.Helper()
				assert.InDelta(t, 0.2, cfg.TTLJitter, 0.001)
				assert.True(t, cfg.HashKeys)
				assert.Equal(t, "secret/existing",
					cfg.PasswordVaultPath)
			},
		},
		{
			name:    "nil config does not panic",
			envVars: map[string]string{},
			initial: nil,
			check: func(t *testing.T, _ *config.RedisCacheConfig) {
				t.Helper()
				// Just verifying no panic occurred
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env vars for this test
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			applyRedisFeatureEnv(tt.initial)
			tt.check(t, tt.initial)
		})
	}
}

func TestApplyRedisFeatureEnv_SentinelVaultPathsInitializeSentinel(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_PASSWORD_VAULT_PATH", "secret/master")

	cfg := &config.RedisCacheConfig{}
	assert.Nil(t, cfg.Sentinel,
		"sentinel should be nil before applying env")

	applyRedisFeatureEnv(cfg)

	require.NotNil(t, cfg.Sentinel,
		"sentinel should be initialized by vault path env")
	assert.Equal(t, "secret/master",
		cfg.Sentinel.PasswordVaultPath)
}

func TestApplyRedisFeatureEnv_ExistingSentinelPreserved(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH",
		"secret/sentinel-auth")

	cfg := &config.RedisCacheConfig{
		Sentinel: &config.RedisSentinelConfig{
			MasterName: "mymaster",
			Password:   "existing-pw",
		},
	}

	applyRedisFeatureEnv(cfg)

	assert.Equal(t, "mymaster", cfg.Sentinel.MasterName,
		"existing sentinel config should be preserved")
	assert.Equal(t, "existing-pw", cfg.Sentinel.Password,
		"existing password should be preserved")
	assert.Equal(t, "secret/sentinel-auth",
		cfg.Sentinel.SentinelPasswordVaultPath)
}

func TestEnvRedisFeatureConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "REDIS_TTL_JITTER", envRedisTTLJitter)
	assert.Equal(t, "REDIS_HASH_KEYS", envRedisHashKeys)
	assert.Equal(t, "REDIS_PASSWORD_VAULT_PATH",
		envRedisPasswordVaultPath)
	assert.Equal(t, "REDIS_SENTINEL_PASSWORD_VAULT_PATH",
		envRedisSentinelPasswordVaultPath)
	assert.Equal(t, "REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH",
		envRedisSentinelSentinelPasswordVaultPath)
}
