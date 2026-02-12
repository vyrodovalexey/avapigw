package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// --- Mock Vault Client and KV Client for testing ---

// mockKVClient implements vault.KVClient for testing.
type mockKVClient struct {
	readData map[string]map[string]interface{}
	readErr  error
}

func (m *mockKVClient) Read(
	_ context.Context, mount, path string,
) (map[string]interface{}, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	key := mount + "/" + path
	if data, ok := m.readData[key]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("secret not found at %s", key)
}

func (m *mockKVClient) Write(
	_ context.Context, _, _ string, _ map[string]interface{},
) error {
	return nil
}

func (m *mockKVClient) Delete(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockKVClient) List(
	_ context.Context, _, _ string,
) ([]string, error) {
	return nil, nil
}

// mockVaultClient implements vault.Client for testing.
type mockVaultClient struct {
	enabled bool
	kv      vault.KVClient
}

func (m *mockVaultClient) IsEnabled() bool { return m.enabled }
func (m *mockVaultClient) Authenticate(_ context.Context) error {
	return nil
}
func (m *mockVaultClient) RenewToken(_ context.Context) error {
	return nil
}
func (m *mockVaultClient) Health(
	_ context.Context,
) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClient) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClient) KV() vault.KVClient           { return m.kv }
func (m *mockVaultClient) Transit() vault.TransitClient { return nil }
func (m *mockVaultClient) Close() error                 { return nil }

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
			cache, err := newRedisCache(tt.cfg, observability.NopLogger(), nil)

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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
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

func TestIsRetryableError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "redis.Nil error",
			err:      redis.Nil,
			expected: false,
		},
		{
			name:     "context.Canceled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "context.DeadlineExceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			name:     "generic error is retryable",
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "network error is retryable",
			err:      errors.New("dial tcp: connection refused"),
			expected: true,
		},
		{
			name:     "timeout error is retryable",
			err:      errors.New("i/o timeout"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isRetryableError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		attempt     int
		minExpected time.Duration
		maxExpected time.Duration
	}{
		{
			name:        "attempt 0",
			attempt:     0,
			minExpected: 100 * time.Millisecond,
			maxExpected: 100 * time.Millisecond,
		},
		{
			name:        "attempt 1",
			attempt:     1,
			minExpected: 200 * time.Millisecond,
			maxExpected: 200 * time.Millisecond,
		},
		{
			name:        "attempt 2",
			attempt:     2,
			minExpected: 400 * time.Millisecond,
			maxExpected: 400 * time.Millisecond,
		},
		{
			name:        "attempt 3",
			attempt:     3,
			minExpected: 800 * time.Millisecond,
			maxExpected: 800 * time.Millisecond,
		},
		{
			name:        "attempt 4",
			attempt:     4,
			minExpected: 1600 * time.Millisecond,
			maxExpected: 1600 * time.Millisecond,
		},
		{
			name:        "attempt 5 - capped at max",
			attempt:     5,
			minExpected: 2 * time.Second,
			maxExpected: 2 * time.Second,
		},
		{
			name:        "attempt 10 - capped at max",
			attempt:     10,
			minExpected: 2 * time.Second,
			maxExpected: 2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := calculateBackoff(tt.attempt)
			assert.GreaterOrEqual(t, result, tt.minExpected)
			assert.LessOrEqual(t, result, tt.maxExpected)
		})
	}
}

func TestCalculateBackoff_ExponentialGrowth(t *testing.T) {
	t.Parallel()

	// Verify exponential growth pattern
	prev := calculateBackoff(0)
	for i := 1; i < 5; i++ {
		current := calculateBackoff(i)
		// Each step should be approximately double (within tolerance)
		expected := prev * 2
		if expected > redisMaxDelay {
			expected = redisMaxDelay
		}
		assert.Equal(t, expected, current, "attempt %d should be double of attempt %d", i, i-1)
		prev = current
	}
}

func TestCalculateBackoff_MaxDelayCap(t *testing.T) {
	t.Parallel()

	// Test that backoff is capped at redisMaxDelay
	for i := 5; i < 20; i++ {
		result := calculateBackoff(i)
		assert.Equal(t, redisMaxDelay, result, "attempt %d should be capped at max delay", i)
	}
}

func TestRedisConstants(t *testing.T) {
	t.Parallel()

	// Verify constants are set correctly
	assert.Equal(t, 3, redisMaxRetries)
	assert.Equal(t, 100*time.Millisecond, redisBaseDelay)
	assert.Equal(t, 2*time.Second, redisMaxDelay)
}

// --- Redis Sentinel Tests ---

func TestNewRedisCache_DispatchesToSentinel(t *testing.T) {
	// When sentinel config is present with MasterName, newRedisCache should
	// dispatch to newRedisSentinelCache. Since we can't run a real sentinel,
	// we test that it returns an error about sentinel addresses being empty.
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{}, // empty addrs should cause error
			},
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "at least one sentinel address is required")
}

func TestNewRedisCache_DispatchesToStandalone(t *testing.T) {
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

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
	assert.NoError(t, err)
	assert.NotNil(t, cache)
	if cache != nil {
		_ = cache.Close()
	}
}

func TestNewRedisCache_ErrorWhenNeitherURLNorSentinel(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "", // no URL
			// no sentinel
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "redis URL is required for standalone mode")
}

func TestNewRedisCache_NilRedisConfig(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		Redis:   nil,
	}

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "redis configuration is required")
}

func TestNewRedisSentinelCache_NoAddresses(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{},
			},
		},
	}

	cache, err := newRedisSentinelCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "at least one sentinel address is required")
}

func TestNewRedisSentinelCache_NilAddresses(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: nil,
			},
		},
	}

	cache, err := newRedisSentinelCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "at least one sentinel address is required")
}

func TestNewRedisSentinelCache_ConnectionFailed(t *testing.T) {
	// Use a non-routable address to ensure connection failure
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"localhost:59998"},
			},
			ConnectTimeout: config.Duration(1 * time.Second),
		},
	}

	cache, err := newRedisSentinelCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "redis sentinel connection failed")
}

func TestNewRedisSentinelCache_WithPoolAndTimeoutOverrides(t *testing.T) {
	// This test verifies that pool/timeout overrides are applied.
	// Since we can't connect to a real sentinel, we verify the error path
	// but the code path through the overrides is exercised.
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:       "mymaster",
				SentinelAddrs:    []string{"localhost:59997"},
				SentinelPassword: "sentinelpass",
				Password:         "masterpass",
				DB:               2,
			},
			PoolSize:       20,
			ConnectTimeout: config.Duration(2 * time.Second),
			ReadTimeout:    config.Duration(1 * time.Second),
			WriteTimeout:   config.Duration(1 * time.Second),
		},
	}

	cache, err := newRedisSentinelCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err) // Can't connect to sentinel
	assert.Nil(t, cache)
}

func TestNewRedisSentinelCache_WithTLS(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"localhost:59996"},
			},
			TLS: &config.TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			ConnectTimeout: config.Duration(1 * time.Second),
		},
	}

	cache, err := newRedisSentinelCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err) // Can't connect
	assert.Nil(t, cache)
}

func TestNewRedisCache_SentinelTakesPrecedenceOverURL(t *testing.T) {
	// When both sentinel and URL are configured, sentinel should take precedence.
	// Since sentinel can't connect, we expect a sentinel-specific error.
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://localhost:6379",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{}, // empty addrs
			},
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "at least one sentinel address is required")
}

func TestNewRedisCache_SentinelWithEmptyMasterNameFallsToStandalone(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	// Sentinel config with empty MasterName should fall through to standalone
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
			Sentinel: &config.RedisSentinelConfig{
				MasterName: "", // empty master name
			},
		},
	}

	cache, err := newRedisCache(cfg, observability.NopLogger(), nil)
	assert.NoError(t, err)
	assert.NotNil(t, cache)
	if cache != nil {
		_ = cache.Close()
	}
}

func TestResolveKeyPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefix   string
		expected string
	}{
		{
			name:     "empty prefix returns default",
			prefix:   "",
			expected: "avapigw:",
		},
		{
			name:     "non-empty prefix returned as-is",
			prefix:   "myapp:",
			expected: "myapp:",
		},
		{
			name:     "custom prefix without colon",
			prefix:   "custom",
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := resolveKeyPrefix(tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestApplyRedisPoolOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		redisCfg *config.RedisCacheConfig
		checkFn  func(t *testing.T, opts *redis.Options)
	}{
		{
			name: "all overrides applied",
			redisCfg: &config.RedisCacheConfig{
				PoolSize:       25,
				ConnectTimeout: config.Duration(10 * time.Second),
				ReadTimeout:    config.Duration(5 * time.Second),
				WriteTimeout:   config.Duration(7 * time.Second),
			},
			checkFn: func(t *testing.T, opts *redis.Options) {
				t.Helper()
				assert.Equal(t, 25, opts.PoolSize)
				assert.Equal(t, 10*time.Second, opts.DialTimeout)
				assert.Equal(t, 5*time.Second, opts.ReadTimeout)
				assert.Equal(t, 7*time.Second, opts.WriteTimeout)
			},
		},
		{
			name: "zero values do not override",
			redisCfg: &config.RedisCacheConfig{
				PoolSize:       0,
				ConnectTimeout: 0,
				ReadTimeout:    0,
				WriteTimeout:   0,
			},
			checkFn: func(t *testing.T, opts *redis.Options) {
				t.Helper()
				// Original values should be preserved
				assert.Equal(t, 10, opts.PoolSize)
				assert.Equal(t, 3*time.Second, opts.DialTimeout)
				assert.Equal(t, 2*time.Second, opts.ReadTimeout)
				assert.Equal(t, 4*time.Second, opts.WriteTimeout)
			},
		},
		{
			name: "partial overrides",
			redisCfg: &config.RedisCacheConfig{
				PoolSize:    30,
				ReadTimeout: config.Duration(8 * time.Second),
			},
			checkFn: func(t *testing.T, opts *redis.Options) {
				t.Helper()
				assert.Equal(t, 30, opts.PoolSize)
				assert.Equal(t, 3*time.Second, opts.DialTimeout) // unchanged
				assert.Equal(t, 8*time.Second, opts.ReadTimeout)
				assert.Equal(t, 4*time.Second, opts.WriteTimeout) // unchanged
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := &redis.Options{
				PoolSize:     10,
				DialTimeout:  3 * time.Second,
				ReadTimeout:  2 * time.Second,
				WriteTimeout: 4 * time.Second,
			}
			applyRedisPoolOptions(opts, tt.redisCfg)
			tt.checkFn(t, opts)
		})
	}
}

func TestNewRedisStandaloneCache_WithTLS(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	// TLS enabled but miniredis doesn't support TLS, so connection will fail
	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
			TLS: &config.TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
		},
	}

	// This may or may not fail depending on miniredis behavior with TLS
	cache, err := newRedisStandaloneCache(cfg, observability.NopLogger())
	if err != nil {
		assert.Nil(t, cache)
	} else if cache != nil {
		_ = cache.Close()
	}
}

func TestIsRetryableError_WrappedErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "wrapped redis.Nil",
			err:      errors.Join(errors.New("wrapper"), redis.Nil),
			expected: false,
		},
		{
			name:     "wrapped context.Canceled",
			err:      errors.Join(errors.New("wrapper"), context.Canceled),
			expected: false,
		},
		{
			name:     "wrapped context.DeadlineExceeded",
			err:      errors.Join(errors.New("wrapper"), context.DeadlineExceeded),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isRetryableError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- TTL Jitter Tests ---

func TestApplyTTLJitter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		ttl          time.Duration
		jitterFactor float64
		expectExact  bool
		expectedTTL  time.Duration
	}{
		{
			name:         "zero jitter factor returns exact TTL",
			ttl:          10 * time.Second,
			jitterFactor: 0.0,
			expectExact:  true,
			expectedTTL:  10 * time.Second,
		},
		{
			name:         "negative jitter factor returns exact TTL",
			ttl:          10 * time.Second,
			jitterFactor: -0.5,
			expectExact:  true,
			expectedTTL:  10 * time.Second,
		},
		{
			name:         "zero TTL returns zero",
			ttl:          0,
			jitterFactor: 0.1,
			expectExact:  true,
			expectedTTL:  0,
		},
		{
			name:         "negative TTL returns negative TTL",
			ttl:          -5 * time.Second,
			jitterFactor: 0.1,
			expectExact:  true,
			expectedTTL:  -5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := applyTTLJitter(tt.ttl, tt.jitterFactor)

			if tt.expectExact {
				assert.Equal(t, tt.expectedTTL, result)
			}
		})
	}
}

func TestApplyTTLJitter_JitterWithinRange(t *testing.T) {
	t.Parallel()

	baseTTL := 100 * time.Second
	jitterFactor := 0.1 // ±10%

	for i := 0; i < 100; i++ {
		result := applyTTLJitter(baseTTL, jitterFactor)

		minTTL := time.Duration(
			float64(baseTTL) * (1 - jitterFactor),
		)
		maxTTL := time.Duration(
			float64(baseTTL) * (1 + jitterFactor),
		)

		assert.GreaterOrEqual(t, result, minTTL,
			"result %v should be >= %v", result, minTTL)
		assert.LessOrEqual(t, result, maxTTL,
			"result %v should be <= %v", result, maxTTL)
	}
}

func TestApplyTTLJitter_ClampedToOne(t *testing.T) {
	t.Parallel()

	baseTTL := 100 * time.Second
	jitterFactor := 2.0 // should be clamped to 1.0

	for i := 0; i < 100; i++ {
		result := applyTTLJitter(baseTTL, jitterFactor)

		// With factor clamped to 1.0, range is [0, 200s]
		// But safety check prevents non-positive, so min is baseTTL
		// when result would be <= 0
		assert.Greater(t, result, time.Duration(0),
			"result should always be positive")
		maxTTL := time.Duration(float64(baseTTL) * 2)
		assert.LessOrEqual(t, result, maxTTL,
			"result %v should be <= %v", result, maxTTL)
	}
}

func TestApplyTTLJitter_ProducesDifferentValues(t *testing.T) {
	t.Parallel()

	baseTTL := 100 * time.Second
	jitterFactor := 0.5

	seen := make(map[time.Duration]bool)
	for i := 0; i < 50; i++ {
		result := applyTTLJitter(baseTTL, jitterFactor)
		seen[result] = true
	}

	// With 50 iterations and 50% jitter, we should see
	// multiple distinct values
	assert.Greater(t, len(seen), 1,
		"jitter should produce different values")
}

func TestApplyTTLJitter_SmallTTLNeverNegative(t *testing.T) {
	t.Parallel()

	baseTTL := 1 * time.Millisecond
	jitterFactor := 0.9

	for i := 0; i < 200; i++ {
		result := applyTTLJitter(baseTTL, jitterFactor)
		assert.Greater(t, result, time.Duration(0),
			"result should never be non-positive")
	}
}

// --- Hash Key / resolveKey Tests ---

func TestResolveKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		prefix    string
		hashKeys  bool
		key       string
		expectKey string
	}{
		{
			name:      "without hashing returns prefix + key",
			prefix:    "test:",
			hashKeys:  false,
			key:       "mykey",
			expectKey: "test:mykey",
		},
		{
			name:      "with hashing returns prefix + SHA256",
			prefix:    "test:",
			hashKeys:  true,
			key:       "mykey",
			expectKey: "test:" + HashKey("mykey"),
		},
		{
			name:      "empty key without hashing",
			prefix:    "pfx:",
			hashKeys:  false,
			key:       "",
			expectKey: "pfx:",
		},
		{
			name:      "empty key with hashing",
			prefix:    "pfx:",
			hashKeys:  true,
			key:       "",
			expectKey: "pfx:" + HashKey(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := &redisCache{
				keyPrefix: tt.prefix,
				hashKeys:  tt.hashKeys,
			}

			result := c.resolveKey(tt.key)
			assert.Equal(t, tt.expectKey, result)
		})
	}
}

func TestResolveKey_HashedKeyIsDeterministic(t *testing.T) {
	t.Parallel()

	c := &redisCache{
		keyPrefix: "test:",
		hashKeys:  true,
	}

	key := "some/complex/key?with=params&and=more"
	result1 := c.resolveKey(key)
	result2 := c.resolveKey(key)

	assert.Equal(t, result1, result2,
		"same input should produce same hashed key")
}

func TestResolveKey_DifferentKeysProduceDifferentHashes(t *testing.T) {
	t.Parallel()

	c := &redisCache{
		keyPrefix: "test:",
		hashKeys:  true,
	}

	result1 := c.resolveKey("key1")
	result2 := c.resolveKey("key2")

	assert.NotEqual(t, result1, result2,
		"different keys should produce different hashes")
}

func TestResolveKey_LongKeyWithHashing(t *testing.T) {
	t.Parallel()

	c := &redisCache{
		keyPrefix: "test:",
		hashKeys:  true,
	}

	// Create a very long key (1000 chars)
	longKey := ""
	for i := 0; i < 100; i++ {
		longKey += "abcdefghij"
	}
	assert.Len(t, longKey, 1000)

	result := c.resolveKey(longKey)

	// SHA256 hex is 64 chars, plus prefix "test:" = 69 chars
	assert.Equal(t, "test:"+HashKey(longKey), result)
	assert.Len(t, result, 5+64,
		"hashed key should have fixed length")
}

// --- Vault Password Resolution Tests ---

func TestResolveRedisPasswords_NoVaultPaths(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL: "redis://localhost:6379",
	}

	err := resolveRedisPasswords(
		cfg, nil, observability.NopLogger(),
	)
	assert.NoError(t, err)
	assert.Equal(t, "redis://localhost:6379", cfg.URL)
}

func TestResolveRedisPasswords_NilVaultClient(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL:               "redis://localhost:6379",
		PasswordVaultPath: "secret/redis",
	}

	err := resolveRedisPasswords(
		cfg, nil, observability.NopLogger(),
	)
	assert.NoError(t, err,
		"nil vault client should return nil error")
}

func TestResolveRedisPasswords_DisabledVaultClient(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL:               "redis://localhost:6379",
		PasswordVaultPath: "secret/redis",
	}

	client := &mockVaultClient{enabled: false, kv: nil}

	err := resolveRedisPasswords(
		cfg, client, observability.NopLogger(),
	)
	assert.NoError(t, err,
		"disabled vault client should return nil error")
}

func TestResolveRedisPasswords_StandalonePasswordResolved(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL:               "redis://user@localhost:6379",
		PasswordVaultPath: "secret/redis-creds",
	}

	kvClient := &mockKVClient{
		readData: map[string]map[string]interface{}{
			"secret/redis-creds": {
				"password": "s3cret",
			},
		},
	}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	err := resolveRedisPasswords(
		cfg, client, observability.NopLogger(),
	)
	require.NoError(t, err)
	assert.Contains(t, cfg.URL, "s3cret",
		"URL should contain the resolved password")
}

func TestResolveRedisPasswords_SentinelPasswordResolved(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		Sentinel: &config.RedisSentinelConfig{
			MasterName:        "mymaster",
			PasswordVaultPath: "secret/redis-master",
		},
	}

	kvClient := &mockKVClient{
		readData: map[string]map[string]interface{}{
			"secret/redis-master": {
				"password": "master-pw",
			},
		},
	}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	err := resolveRedisPasswords(
		cfg, client, observability.NopLogger(),
	)
	require.NoError(t, err)
	assert.Equal(t, "master-pw", cfg.Sentinel.Password)
}

func TestResolveRedisPasswords_SentinelSentinelPasswordResolved(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		Sentinel: &config.RedisSentinelConfig{
			MasterName:                "mymaster",
			SentinelPasswordVaultPath: "secret/sentinel-auth",
		},
	}

	kvClient := &mockKVClient{
		readData: map[string]map[string]interface{}{
			"secret/sentinel-auth": {
				"password": "sentinel-pw",
			},
		},
	}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	err := resolveRedisPasswords(
		cfg, client, observability.NopLogger(),
	)
	require.NoError(t, err)
	assert.Equal(t, "sentinel-pw", cfg.Sentinel.SentinelPassword)
}

func TestResolveRedisPasswords_VaultReadError(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL:               "redis://localhost:6379",
		PasswordVaultPath: "secret/redis-creds",
	}

	kvClient := &mockKVClient{
		readErr: errors.New("vault unavailable"),
	}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	err := resolveRedisPasswords(
		cfg, client, observability.NopLogger(),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read redis password")
}

func TestResolveRedisPasswords_MissingPasswordKey(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{
		URL:               "redis://localhost:6379",
		PasswordVaultPath: "secret/redis-creds",
	}

	kvClient := &mockKVClient{
		readData: map[string]map[string]interface{}{
			"secret/redis-creds": {
				"username": "admin", // no "password" key
			},
		},
	}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	err := resolveRedisPasswords(
		cfg, client, observability.NopLogger(),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(),
		"does not contain a valid 'password' key")
}

// --- readVaultPassword Tests ---

func TestReadVaultPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		vaultPath  string
		kvData     map[string]map[string]interface{}
		kvErr      error
		expectPW   string
		expectErr  bool
		errContain string
	}{
		{
			name:      "valid vault path returns password",
			vaultPath: "secret/redis",
			kvData: map[string]map[string]interface{}{
				"secret/redis": {
					"password": "mypassword",
				},
			},
			expectPW:  "mypassword",
			expectErr: false,
		},
		{
			name:      "missing password key returns error",
			vaultPath: "secret/redis",
			kvData: map[string]map[string]interface{}{
				"secret/redis": {
					"user": "admin",
				},
			},
			expectErr:  true,
			errContain: "does not contain a valid 'password' key",
		},
		{
			name:       "vault read error returns error",
			vaultPath:  "secret/redis",
			kvErr:      errors.New("connection refused"),
			expectErr:  true,
			errContain: "vault read failed",
		},
		{
			name:       "invalid vault path format",
			vaultPath:  "noslash",
			expectErr:  true,
			errContain: "invalid vault path format",
		},
		{
			name:      "empty password returns error",
			vaultPath: "secret/redis",
			kvData: map[string]map[string]interface{}{
				"secret/redis": {
					"password": "",
				},
			},
			expectErr:  true,
			errContain: "does not contain a valid 'password' key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kvClient := &mockKVClient{
				readData: tt.kvData,
				readErr:  tt.kvErr,
			}
			client := &mockVaultClient{
				enabled: true,
				kv:      kvClient,
			}

			pw, err := readVaultPassword(client, tt.vaultPath)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectPW, pw)
			}
		})
	}
}

// --- applyPasswordToRedisURL Tests ---

func TestApplyPasswordToRedisURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		url        string
		password   string
		expectURL  string
		expectErr  bool
		errContain string
	}{
		{
			name:      "URL without password gets password added",
			url:       "redis://localhost:6379",
			password:  "newpass",
			expectURL: "redis://:%s@localhost:6379",
		},
		{
			name:      "URL with existing password gets replaced",
			url:       "redis://:oldpass@localhost:6379",
			password:  "newpass",
			expectURL: "redis://:%s@localhost:6379",
		},
		{
			name:      "URL with user:password format",
			url:       "redis://admin:oldpass@localhost:6379",
			password:  "newpass",
			expectURL: "redis://admin:%s@localhost:6379",
		},
		{
			name:      "empty URL is no-op",
			url:       "",
			password:  "newpass",
			expectURL: "",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.RedisCacheConfig{URL: tt.url}
			err := applyPasswordToRedisURL(cfg, tt.password)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				assert.NoError(t, err)
				if tt.url != "" {
					expected := fmt.Sprintf(
						tt.expectURL, tt.password,
					)
					assert.Equal(t, expected, cfg.URL)
				}
			}
		})
	}
}

func TestApplyPasswordToRedisURL_InvalidURL(t *testing.T) {
	t.Parallel()

	cfg := &config.RedisCacheConfig{URL: "://invalid"}
	err := applyPasswordToRedisURL(cfg, "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse redis URL")
}

// --- hasVaultPasswordPaths Tests ---

func TestHasVaultPasswordPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    *config.RedisCacheConfig
		expect bool
	}{
		{
			name:   "no vault paths",
			cfg:    &config.RedisCacheConfig{},
			expect: false,
		},
		{
			name: "standalone password vault path",
			cfg: &config.RedisCacheConfig{
				PasswordVaultPath: "secret/redis",
			},
			expect: true,
		},
		{
			name: "sentinel password vault path",
			cfg: &config.RedisCacheConfig{
				Sentinel: &config.RedisSentinelConfig{
					PasswordVaultPath: "secret/master",
				},
			},
			expect: true,
		},
		{
			name: "sentinel sentinel-password vault path",
			cfg: &config.RedisCacheConfig{
				Sentinel: &config.RedisSentinelConfig{
					SentinelPasswordVaultPath: "secret/sentinel",
				},
			},
			expect: true,
		},
		{
			name: "nil sentinel config",
			cfg: &config.RedisCacheConfig{
				Sentinel: nil,
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := hasVaultPasswordPaths(tt.cfg)
			assert.Equal(t, tt.expect, result)
		})
	}
}
