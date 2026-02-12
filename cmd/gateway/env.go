package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// Redis Sentinel environment variable names.
const (
	// envRedisSentinelMasterName overrides the Redis Sentinel master name.
	envRedisSentinelMasterName = "REDIS_SENTINEL_MASTER_NAME"

	// envRedisSentinelAddrs overrides the Redis Sentinel addresses (comma-separated).
	envRedisSentinelAddrs = "REDIS_SENTINEL_ADDRS"

	// envRedisSentinelPassword overrides the Redis Sentinel authentication password.
	envRedisSentinelPassword = "REDIS_SENTINEL_PASSWORD"

	// envRedisMasterPassword overrides the Redis master password for Sentinel connections.
	envRedisMasterPassword = "REDIS_MASTER_PASSWORD"
)

// Redis cache feature environment variable names.
const (
	// envRedisTTLJitter overrides the Redis TTL jitter factor (e.g., "0.1" for 10%).
	envRedisTTLJitter = "REDIS_TTL_JITTER"

	// envRedisHashKeys enables key hashing ("true"/"false").
	envRedisHashKeys = "REDIS_HASH_KEYS"

	// envRedisPasswordVaultPath overrides the Vault path for Redis password.
	envRedisPasswordVaultPath = "REDIS_PASSWORD_VAULT_PATH"

	// envRedisSentinelPasswordVaultPath overrides the Vault path for Redis master password.
	envRedisSentinelPasswordVaultPath = "REDIS_SENTINEL_PASSWORD_VAULT_PATH"

	// envRedisSentinelSentinelPasswordVaultPath overrides the Vault path for Sentinel password.
	envRedisSentinelSentinelPasswordVaultPath = "REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH"
)

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool returns the environment variable as a boolean or a default.
// Accepts "true", "1", "yes" (case-insensitive) as true values.
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	// Parse common boolean representations
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultValue
	}
}

// applyRedisSentinelEnv applies Redis Sentinel environment variable overrides
// to the given RedisCacheConfig. Environment variables take priority over
// file-based configuration values.
func applyRedisSentinelEnv(redisCfg *config.RedisCacheConfig) {
	if redisCfg == nil {
		return
	}

	masterName := os.Getenv(envRedisSentinelMasterName)
	sentinelAddrs := os.Getenv(envRedisSentinelAddrs)
	sentinelPassword := os.Getenv(envRedisSentinelPassword)
	masterPassword := os.Getenv(envRedisMasterPassword)

	// If no sentinel env vars are set, nothing to do
	if masterName == "" && sentinelAddrs == "" && sentinelPassword == "" && masterPassword == "" {
		return
	}

	// Initialize sentinel config if not present
	if redisCfg.Sentinel == nil {
		redisCfg.Sentinel = &config.RedisSentinelConfig{}
	}

	if masterName != "" {
		redisCfg.Sentinel.MasterName = masterName
	}

	if sentinelAddrs != "" {
		addrs := strings.Split(sentinelAddrs, ",")
		trimmed := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if a := strings.TrimSpace(addr); a != "" {
				trimmed = append(trimmed, a)
			}
		}
		redisCfg.Sentinel.SentinelAddrs = trimmed
	}

	if sentinelPassword != "" {
		redisCfg.Sentinel.SentinelPassword = sentinelPassword
	}

	if masterPassword != "" {
		redisCfg.Sentinel.Password = masterPassword
	}
}

// applyRedisFeatureEnv applies Redis feature environment variable overrides
// (TTL jitter, hash keys, vault paths) to the given RedisCacheConfig.
// Environment variables take priority over file-based configuration values.
func applyRedisFeatureEnv(redisCfg *config.RedisCacheConfig) {
	if redisCfg == nil {
		return
	}

	// TTL jitter
	if jitterStr := os.Getenv(envRedisTTLJitter); jitterStr != "" {
		if jitter, err := strconv.ParseFloat(jitterStr, 64); err == nil {
			redisCfg.TTLJitter = jitter
		}
	}

	// Hash keys
	if hashKeysStr := os.Getenv(envRedisHashKeys); hashKeysStr != "" {
		redisCfg.HashKeys = getEnvBool(envRedisHashKeys, redisCfg.HashKeys)
	}

	// Vault paths for passwords
	if vaultPath := os.Getenv(envRedisPasswordVaultPath); vaultPath != "" {
		redisCfg.PasswordVaultPath = vaultPath
	}

	if vaultPath := os.Getenv(envRedisSentinelPasswordVaultPath); vaultPath != "" {
		if redisCfg.Sentinel == nil {
			redisCfg.Sentinel = &config.RedisSentinelConfig{}
		}
		redisCfg.Sentinel.PasswordVaultPath = vaultPath
	}

	if vaultPath := os.Getenv(envRedisSentinelSentinelPasswordVaultPath); vaultPath != "" {
		if redisCfg.Sentinel == nil {
			redisCfg.Sentinel = &config.RedisSentinelConfig{}
		}
		redisCfg.Sentinel.SentinelPasswordVaultPath = vaultPath
	}
}

// applyRedisSentinelEnvToConfig applies Redis Sentinel environment variable overrides
// to all Redis cache configurations in the gateway config. This includes route-level
// cache configurations that use Redis.
func applyRedisSentinelEnvToConfig(cfg *config.GatewayConfig) {
	if cfg == nil {
		return
	}

	// Apply to route-level cache configs
	for i := range cfg.Spec.Routes {
		route := &cfg.Spec.Routes[i]
		if route.Cache != nil && route.Cache.Type == config.CacheTypeRedis && route.Cache.Redis != nil {
			applyRedisSentinelEnv(route.Cache.Redis)
			applyRedisFeatureEnv(route.Cache.Redis)
		}
	}
}
