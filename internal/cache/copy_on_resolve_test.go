package cache

// Tests for T3.B2 (review M2): the redis cache constructors must follow the
// redisclient copy-on-resolve pattern — Vault-resolved passwords live only
// in private copies and are never written back into the caller's shared
// configuration structs. Also covers the T3.B1 TLS error propagation on the
// legacy cache builders.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestNewRedisCache_DoesNotMutateSharedConfig is the M2 acceptance
// criterion: after construction with Vault-resolved passwords, the caller's
// *config.CacheConfig must be byte-unchanged (no plaintext secret leaks
// into the shared GatewayConfig tree).
func TestNewRedisCache_DoesNotMutateSharedConfig(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()
	mr.RequireAuth("vault-password")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:               "redis://" + mr.Addr(),
			PasswordVaultPath: "secret/redis",
		},
	}

	before, err := json.Marshal(cfg)
	require.NoError(t, err)

	kv := &mockKVClient{readData: map[string]map[string]interface{}{
		"secret/redis": {"password": "vault-password"},
	}}
	vaultClient := &mockVaultClient{enabled: true, kv: kv}

	c, err := newRedisCache(context.Background(), cfg, observability.NopLogger(),
		&cacheOptions{vaultClient: vaultClient})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	after, err := json.Marshal(cfg)
	require.NoError(t, err)

	assert.Equal(t, string(before), string(after),
		"caller's CacheConfig must be byte-unchanged after Vault password resolution")
	assert.NotContains(t, string(after), "vault-password",
		"resolved password must never appear in the shared config")

	// The cache itself must work with the resolved credentials.
	require.NoError(t, c.Set(context.Background(), "k", []byte("v"), time.Minute))
	got, err := c.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

// TestNewRedisCache_SentinelPasswords_NotWrittenBack covers the sentinel
// resolution path: sentinel.Password/SentinelPassword must stay raw in the
// caller's config.
func TestNewRedisCache_SentinelPasswords_NotWrittenBack(t *testing.T) {
	t.Parallel()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:                "mymaster",
				SentinelAddrs:             []string{"127.0.0.1:1"}, // unreachable: construction fails after resolve
				PasswordVaultPath:         "secret/master",
				SentinelPasswordVaultPath: "secret/sentinel",
			},
		},
	}

	kv := &mockKVClient{readData: map[string]map[string]interface{}{
		"secret/master":   {"password": "resolved-secret"},
		"secret/sentinel": {"password": "resolved-secret"},
	}}
	vaultClient := &mockVaultClient{enabled: true, kv: kv}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Construction fails on connectivity (unreachable sentinel), but the
	// resolve step has already run — the assertion is about mutation.
	_, err := newRedisCache(ctx, cfg, observability.NopLogger(),
		&cacheOptions{vaultClient: vaultClient})
	require.Error(t, err)

	assert.Empty(t, cfg.Redis.Sentinel.Password,
		"resolved master password must not be written into the shared sentinel config")
	assert.Empty(t, cfg.Redis.Sentinel.SentinelPassword,
		"resolved sentinel password must not be written into the shared sentinel config")
}

// TestNewRedisCache_TLSFileErrorsSurface covers the T3.B1 requirement on
// the legacy cache builders: unreadable TLS material fails construction
// with a clear error instead of silently connecting with system trust.
func TestNewRedisCache_TLSFileErrorsSurface(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	t.Run("standalone", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			Redis: &config.RedisCacheConfig{
				URL: "redis://127.0.0.1:1",
				TLS: &config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.crt"},
			},
		}
		_, err := newRedisCache(ctx, cfg, observability.NopLogger(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read redis TLS CA file")
	})

	t.Run("sentinel", func(t *testing.T) {
		t.Parallel()
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			Redis: &config.RedisCacheConfig{
				Sentinel: &config.RedisSentinelConfig{
					MasterName:    "m",
					SentinelAddrs: []string{"127.0.0.1:1"},
				},
				TLS: &config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.crt"},
			},
		}
		_, err := newRedisCache(ctx, cfg, observability.NopLogger(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read redis TLS CA file")
	})
}
