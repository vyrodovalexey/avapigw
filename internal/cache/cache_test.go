// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrCacheMiss",
			err:      ErrCacheMiss,
			expected: "cache miss",
		},
		{
			name:     "ErrCacheDisabled",
			err:      ErrCacheDisabled,
			expected: "cache disabled",
		},
		{
			name:     "ErrInvalidConfig",
			err:      ErrInvalidConfig,
			expected: "invalid cache configuration",
		},
		{
			name:     "ErrConnectionFailed",
			err:      ErrConnectionFailed,
			expected: "cache connection failed",
		},
		{
			name:     "ErrKeyTooLong",
			err:      ErrKeyTooLong,
			expected: "cache key too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.CacheConfig
		expectErr bool
		errType   error
	}{
		{
			name:      "nil config returns error",
			cfg:       nil,
			expectErr: true,
			errType:   ErrInvalidConfig,
		},
		{
			name: "disabled cache",
			cfg: &config.CacheConfig{
				Enabled: false,
			},
			expectErr: false,
		},
		{
			name: "memory cache",
			cfg: &config.CacheConfig{
				Enabled:    true,
				Type:       config.CacheTypeMemory,
				MaxEntries: 100,
				TTL:        config.Duration(5 * time.Minute),
			},
			expectErr: false,
		},
		{
			name: "default type is memory",
			cfg: &config.CacheConfig{
				Enabled:    true,
				Type:       "",
				MaxEntries: 100,
			},
			expectErr: false,
		},
		{
			name: "unknown cache type",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    "unknown",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := New(tt.cfg, observability.NopLogger())

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cache)

			// Cleanup
			_ = cache.Close()
		})
	}
}

func TestNew_NilLogger(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		MaxEntries: 100,
	}

	cache, err := New(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)

	_ = cache.Close()
}

func TestDisabledCache(t *testing.T) {
	cache := newDisabledCache()
	ctx := context.Background()

	t.Run("Get returns ErrCacheDisabled", func(t *testing.T) {
		_, err := cache.Get(ctx, "key")
		assert.ErrorIs(t, err, ErrCacheDisabled)
	})

	t.Run("Set returns ErrCacheDisabled", func(t *testing.T) {
		err := cache.Set(ctx, "key", []byte("value"), time.Minute)
		assert.ErrorIs(t, err, ErrCacheDisabled)
	})

	t.Run("Delete returns ErrCacheDisabled", func(t *testing.T) {
		err := cache.Delete(ctx, "key")
		assert.ErrorIs(t, err, ErrCacheDisabled)
	})

	t.Run("Exists returns ErrCacheDisabled", func(t *testing.T) {
		_, err := cache.Exists(ctx, "key")
		assert.ErrorIs(t, err, ErrCacheDisabled)
	})

	t.Run("Close returns nil", func(t *testing.T) {
		err := cache.Close()
		assert.NoError(t, err)
	})
}

func TestCacheStats_HitRate(t *testing.T) {
	tests := []struct {
		name     string
		stats    CacheStats
		expected float64
	}{
		{
			name: "no requests",
			stats: CacheStats{
				Hits:   0,
				Misses: 0,
			},
			expected: 0,
		},
		{
			name: "all hits",
			stats: CacheStats{
				Hits:   100,
				Misses: 0,
			},
			expected: 100,
		},
		{
			name: "all misses",
			stats: CacheStats{
				Hits:   0,
				Misses: 100,
			},
			expected: 0,
		},
		{
			name: "50% hit rate",
			stats: CacheStats{
				Hits:   50,
				Misses: 50,
			},
			expected: 50,
		},
		{
			name: "75% hit rate",
			stats: CacheStats{
				Hits:   75,
				Misses: 25,
			},
			expected: 75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.stats.HitRate()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCacheEntry_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		entry    CacheEntry
		expected bool
	}{
		{
			name: "zero expiration - never expires",
			entry: CacheEntry{
				Value:     []byte("test"),
				CreatedAt: time.Now(),
				ExpiresAt: time.Time{},
			},
			expected: false,
		},
		{
			name: "future expiration - not expired",
			entry: CacheEntry{
				Value:     []byte("test"),
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "past expiration - expired",
			entry: CacheEntry{
				Value:     []byte("test"),
				CreatedAt: time.Now().Add(-time.Hour),
				ExpiresAt: time.Now().Add(-time.Minute),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCacheEntry_TTL(t *testing.T) {
	tests := []struct {
		name     string
		entry    CacheEntry
		checkTTL func(t *testing.T, ttl time.Duration)
	}{
		{
			name: "zero expiration - returns 0",
			entry: CacheEntry{
				ExpiresAt: time.Time{},
			},
			checkTTL: func(t *testing.T, ttl time.Duration) {
				assert.Equal(t, time.Duration(0), ttl)
			},
		},
		{
			name: "future expiration - returns positive TTL",
			entry: CacheEntry{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			checkTTL: func(t *testing.T, ttl time.Duration) {
				assert.True(t, ttl > 0)
				assert.True(t, ttl <= time.Hour)
			},
		},
		{
			name: "past expiration - returns 0",
			entry: CacheEntry{
				ExpiresAt: time.Now().Add(-time.Minute),
			},
			checkTTL: func(t *testing.T, ttl time.Duration) {
				assert.Equal(t, time.Duration(0), ttl)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl := tt.entry.TTL()
			tt.checkTTL(t, ttl)
		})
	}
}

func TestCacheEntry_Struct(t *testing.T) {
	now := time.Now()
	entry := CacheEntry{
		Value:     []byte("test value"),
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Stale:     false,
	}

	assert.Equal(t, []byte("test value"), entry.Value)
	assert.Equal(t, now, entry.CreatedAt)
	assert.Equal(t, now.Add(time.Hour), entry.ExpiresAt)
	assert.False(t, entry.Stale)
}

func TestCacheStats_Struct(t *testing.T) {
	stats := CacheStats{
		Hits:   100,
		Misses: 50,
		Size:   1000,
		Bytes:  1024000,
	}

	assert.Equal(t, int64(100), stats.Hits)
	assert.Equal(t, int64(50), stats.Misses)
	assert.Equal(t, int64(1000), stats.Size)
	assert.Equal(t, int64(1024000), stats.Bytes)
}
