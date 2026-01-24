package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// setupMiniRedis creates a miniredis server for testing.
func setupMiniRedis(t *testing.T) (*miniredis.Miniredis, func()) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	cleanup := func() {
		mr.Close()
	}

	return mr, cleanup
}

func TestNewRedisCache(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	tests := []struct {
		name      string
		cfg       *config.CacheConfig
		expectErr bool
	}{
		{
			name: "valid config",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				TTL:     config.Duration(5 * time.Minute),
				Redis: &config.RedisCacheConfig{
					URL: "redis://" + mr.Addr(),
				},
			},
			expectErr: false,
		},
		{
			name: "with pool size",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				TTL:     config.Duration(5 * time.Minute),
				Redis: &config.RedisCacheConfig{
					URL:      "redis://" + mr.Addr(),
					PoolSize: 10,
				},
			},
			expectErr: false,
		},
		{
			name: "with timeouts",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				TTL:     config.Duration(5 * time.Minute),
				Redis: &config.RedisCacheConfig{
					URL:            "redis://" + mr.Addr(),
					ConnectTimeout: config.Duration(5 * time.Second),
					ReadTimeout:    config.Duration(3 * time.Second),
					WriteTimeout:   config.Duration(3 * time.Second),
				},
			},
			expectErr: false,
		},
		{
			name: "with key prefix",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				TTL:     config.Duration(5 * time.Minute),
				Redis: &config.RedisCacheConfig{
					URL:       "redis://" + mr.Addr(),
					KeyPrefix: "test:",
				},
			},
			expectErr: false,
		},
		{
			name: "nil redis config",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				Redis:   nil,
			},
			expectErr: true,
		},
		{
			name: "empty URL",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				Redis: &config.RedisCacheConfig{
					URL: "",
				},
			},
			expectErr: true,
		},
		{
			name: "invalid URL",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				Redis: &config.RedisCacheConfig{
					URL: "invalid://url",
				},
			},
			expectErr: true,
		},
		{
			name: "connection failed",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeRedis,
				Redis: &config.RedisCacheConfig{
					URL: "redis://localhost:59999", // Non-existent port
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := newRedisCache(tt.cfg, observability.NopLogger())

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, cache)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cache)
				if cache != nil {
					_ = cache.Close()
				}
			}
		})
	}
}

func TestRedisCache_Get(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	tests := []struct {
		name      string
		setup     func()
		key       string
		expectErr error
		expectVal []byte
	}{
		{
			name:      "cache miss",
			setup:     func() {},
			key:       "nonexistent",
			expectErr: ErrCacheMiss,
			expectVal: nil,
		},
		{
			name: "cache hit",
			setup: func() {
				mr.Set("test:existing", "value123")
			},
			key:       "existing",
			expectErr: nil,
			expectVal: []byte("value123"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			val, err := cache.Get(ctx, tt.key)

			if tt.expectErr != nil {
				assert.ErrorIs(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectVal, val)
			}
		})
	}
}

func TestRedisCache_Get_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = cache.Get(ctx, "key")
	assert.Error(t, err)
}

func TestRedisCache_Set(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	tests := []struct {
		name  string
		key   string
		value []byte
		ttl   time.Duration
	}{
		{
			name:  "set with TTL",
			key:   "key1",
			value: []byte("value1"),
			ttl:   time.Minute,
		},
		{
			name:  "set with zero TTL uses default",
			key:   "key2",
			value: []byte("value2"),
			ttl:   0,
		},
		{
			name:  "set empty value",
			key:   "key3",
			value: []byte(""),
			ttl:   time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.Set(ctx, tt.key, tt.value, tt.ttl)
			assert.NoError(t, err)

			// Verify the value was set
			val, err := cache.Get(ctx, tt.key)
			assert.NoError(t, err)
			assert.Equal(t, tt.value, val)
		})
	}
}

func TestRedisCache_Set_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cache.Set(ctx, "key", []byte("value"), time.Minute)
	assert.Error(t, err)
}

func TestRedisCache_Delete(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Set a value first
	err = cache.Set(ctx, "to-delete", []byte("value"), time.Minute)
	require.NoError(t, err)

	// Verify it exists
	_, err = cache.Get(ctx, "to-delete")
	require.NoError(t, err)

	// Delete it
	err = cache.Delete(ctx, "to-delete")
	assert.NoError(t, err)

	// Verify it's gone
	_, err = cache.Get(ctx, "to-delete")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestRedisCache_Delete_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cache.Delete(ctx, "key")
	assert.Error(t, err)
}

func TestRedisCache_Exists(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Test non-existent key
	exists, err := cache.Exists(ctx, "nonexistent")
	assert.NoError(t, err)
	assert.False(t, exists)

	// Set a value
	err = cache.Set(ctx, "existing", []byte("value"), time.Minute)
	require.NoError(t, err)

	// Test existing key
	exists, err = cache.Exists(ctx, "existing")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisCache_Exists_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = cache.Exists(ctx, "key")
	assert.Error(t, err)
}

func TestRedisCache_Stats(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Initial stats
	stats := cache.Stats()
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)

	// Generate some hits and misses
	_ = cache.Set(ctx, "key", []byte("value"), time.Minute)
	_, _ = cache.Get(ctx, "key")         // Hit
	_, _ = cache.Get(ctx, "nonexistent") // Miss
	_, _ = cache.Get(ctx, "key")         // Hit

	stats = cache.Stats()
	assert.Equal(t, int64(2), stats.Hits)
	assert.Equal(t, int64(1), stats.Misses)
}

func TestRedisCache_GetWithTTL(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Test cache miss
	_, _, err = cache.GetWithTTL(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrCacheMiss)

	// Set a value with TTL
	err = cache.Set(ctx, "key", []byte("value"), time.Minute)
	require.NoError(t, err)

	// Get with TTL
	val, ttl, err := cache.GetWithTTL(ctx, "key")
	assert.NoError(t, err)
	assert.Equal(t, []byte("value"), val)
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, time.Minute)
}

func TestRedisCache_GetWithTTL_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = cache.GetWithTTL(ctx, "key")
	assert.Error(t, err)
}

func TestRedisCache_SetNX(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// First SetNX should succeed
	ok, err := cache.SetNX(ctx, "key", []byte("value1"), time.Minute)
	assert.NoError(t, err)
	assert.True(t, ok)

	// Second SetNX should fail (key exists)
	ok, err = cache.SetNX(ctx, "key", []byte("value2"), time.Minute)
	assert.NoError(t, err)
	assert.False(t, ok)

	// Verify original value is preserved
	val, err := cache.Get(ctx, "key")
	assert.NoError(t, err)
	assert.Equal(t, []byte("value1"), val)
}

func TestRedisCache_SetNX_ZeroTTL(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// SetNX with zero TTL should use default
	ok, err := cache.SetNX(ctx, "key", []byte("value"), 0)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestRedisCache_SetNX_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = cache.SetNX(ctx, "key", []byte("value"), time.Minute)
	assert.Error(t, err)
}

func TestRedisCache_Expire(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Set a value
	err = cache.Set(ctx, "key", []byte("value"), time.Hour)
	require.NoError(t, err)

	// Update TTL
	err = cache.Expire(ctx, "key", time.Minute)
	assert.NoError(t, err)

	// Verify TTL was updated
	_, ttl, err := cache.GetWithTTL(ctx, "key")
	assert.NoError(t, err)
	assert.LessOrEqual(t, ttl, time.Minute)
}

func TestRedisCache_Expire_ContextCanceled(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cache.Expire(ctx, "key", time.Minute)
	assert.Error(t, err)
}

func TestRedisCache_Close(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)

	err = cache.Close()
	assert.NoError(t, err)
}

func TestRedisCache_DefaultKeyPrefix(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "", // Empty prefix should use default
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	ctx := context.Background()

	// Set a value
	err = cache.Set(ctx, "key", []byte("value"), time.Minute)
	require.NoError(t, err)

	// Verify the key has the default prefix
	val, err := mr.Get("avapigw:key")
	assert.NoError(t, err)
	assert.Equal(t, "value", val)
}
