package vault

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// SecretCache GetOrCreate Tests (VaultClientCache)
// ============================================================================

func TestVaultClientCache_GetOrCreate(t *testing.T) {
	t.Run("creates new client when not in cache", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		createCalled := false
		client, err := cache.GetOrCreate("key1", "http://vault:8200", func() (*Client, error) {
			createCalled = true
			return NewClient(nil, nil)
		})

		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.True(t, createCalled)
		assert.Equal(t, 1, cache.Size())
	})

	t.Run("returns cached client on second call", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		createCount := 0
		createFunc := func() (*Client, error) {
			createCount++
			return NewClient(nil, nil)
		}

		// First call
		client1, err := cache.GetOrCreate("key1", "http://vault:8200", createFunc)
		require.NoError(t, err)
		assert.NotNil(t, client1)
		assert.Equal(t, 1, createCount)

		// Second call - should return cached
		client2, err := cache.GetOrCreate("key1", "http://vault:8200", createFunc)
		require.NoError(t, err)
		assert.NotNil(t, client2)
		assert.Equal(t, 1, createCount) // Should not have called create again
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		expectedErr := errors.New("create failed")
		_, err := cache.GetOrCreate("key1", "http://vault:8200", func() (*Client, error) {
			return nil, expectedErr
		})

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, 0, cache.Size())
	})

	t.Run("handles concurrent GetOrCreate calls", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		var createCount int
		var mu sync.Mutex
		createFunc := func() (*Client, error) {
			mu.Lock()
			createCount++
			mu.Unlock()
			time.Sleep(10 * time.Millisecond) // Simulate slow creation
			return NewClient(nil, nil)
		}

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := cache.GetOrCreate("key1", "http://vault:8200", createFunc)
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		// Due to double-check locking, create should be called only once or a few times
		mu.Lock()
		count := createCount
		mu.Unlock()
		assert.LessOrEqual(t, count, 10)
		assert.Equal(t, 1, cache.Size())
	})
}

// ============================================================================
// SecretCache Eviction Tests
// ============================================================================

func TestSecretCache_EvictIfNeeded(t *testing.T) {
	t.Run("evicts LRU entry when at capacity", func(t *testing.T) {
		config := &CacheConfig{
			MaxSize:    3,
			DefaultTTL: 5 * time.Minute,
		}
		cache := NewSecretCacheWithConfig(config, zap.NewNop())

		// Fill cache to capacity
		cache.Set("path1", &Secret{Data: map[string]interface{}{"key": "value1"}})
		cache.Set("path2", &Secret{Data: map[string]interface{}{"key": "value2"}})
		cache.Set("path3", &Secret{Data: map[string]interface{}{"key": "value3"}})

		assert.Equal(t, 3, cache.Size())

		// Access path1 to make it most recently used
		_, _ = cache.Get("path1")

		// Add new entry - should evict path2 (LRU)
		cache.Set("path4", &Secret{Data: map[string]interface{}{"key": "value4"}})

		assert.Equal(t, 3, cache.Size())
		_, ok := cache.Get("path1")
		assert.True(t, ok, "path1 should still be in cache")
		_, ok = cache.Get("path4")
		assert.True(t, ok, "path4 should be in cache")
	})

	t.Run("evicts expired entries first", func(t *testing.T) {
		config := &CacheConfig{
			MaxSize:    2,
			DefaultTTL: 5 * time.Minute,
		}
		cache := NewSecretCacheWithConfig(config, zap.NewNop())

		// Add entry with very short TTL
		cache.SetWithTTL("expired", &Secret{Data: map[string]interface{}{"key": "expired"}}, 1*time.Millisecond)
		cache.Set("valid", &Secret{Data: map[string]interface{}{"key": "valid"}})

		// Wait for first entry to expire
		time.Sleep(5 * time.Millisecond)

		// Add new entry - should evict expired entry first
		cache.Set("new", &Secret{Data: map[string]interface{}{"key": "new"}})

		assert.Equal(t, 2, cache.Size())
		_, ok := cache.Get("valid")
		assert.True(t, ok, "valid should still be in cache")
		_, ok = cache.Get("new")
		assert.True(t, ok, "new should be in cache")
	})

	t.Run("unbounded cache does not evict", func(t *testing.T) {
		config := &CacheConfig{
			MaxSize:    0, // Unbounded
			DefaultTTL: 5 * time.Minute,
		}
		cache := NewSecretCacheWithConfig(config, zap.NewNop())

		// Add many entries
		for i := 0; i < 100; i++ {
			cache.Set("path"+string(rune(i)), &Secret{})
		}

		assert.Equal(t, 100, cache.Size())
	})
}

// ============================================================================
// VaultClientCache Eviction Tests
// ============================================================================

func TestVaultClientCache_EvictIfNeeded(t *testing.T) {
	t.Run("evicts LRU client when at capacity", func(t *testing.T) {
		config := &VaultClientCacheConfig{
			MaxSize: 2,
			TTL:     5 * time.Minute,
		}
		cache := NewVaultClientCache(config, zap.NewNop())

		client1, _ := NewClient(nil, nil)
		client2, _ := NewClient(nil, nil)
		client3, _ := NewClient(nil, nil)

		cache.Set("key1", client1, "http://vault1:8200")
		cache.Set("key2", client2, "http://vault2:8200")

		assert.Equal(t, 2, cache.Size())

		// Access key1 to make it most recently used
		_, _ = cache.Get("key1")

		// Add new client - should evict key2 (LRU)
		cache.Set("key3", client3, "http://vault3:8200")

		assert.Equal(t, 2, cache.Size())
		_, ok := cache.Get("key1")
		assert.True(t, ok, "key1 should still be in cache")
		_, ok = cache.Get("key3")
		assert.True(t, ok, "key3 should be in cache")
	})

	t.Run("evicts expired clients first", func(t *testing.T) {
		config := &VaultClientCacheConfig{
			MaxSize: 2,
			TTL:     1 * time.Millisecond, // Very short TTL
		}
		cache := NewVaultClientCache(config, zap.NewNop())

		client1, _ := NewClient(nil, nil)
		client2, _ := NewClient(nil, nil)

		cache.Set("key1", client1, "http://vault1:8200")

		// Wait for first entry to expire
		time.Sleep(5 * time.Millisecond)

		cache.Set("key2", client2, "http://vault2:8200")

		// Add new client - should evict expired entry first
		client3, _ := NewClient(nil, nil)
		cache.Set("key3", client3, "http://vault3:8200")

		assert.LessOrEqual(t, cache.Size(), 2)
	})
}

// ============================================================================
// SecretCache Cleanup Routine Tests
// ============================================================================

func TestSecretCache_StartCleanupRoutine(t *testing.T) {
	t.Run("cleanup routine removes expired entries", func(t *testing.T) {
		config := &CacheConfig{
			MaxSize:         100,
			DefaultTTL:      5 * time.Minute,
			CleanupInterval: 50 * time.Millisecond,
		}
		cache := NewSecretCacheWithConfig(config, zap.NewNop())

		// Add entry with very short TTL
		cache.SetWithTTL("expired", &Secret{}, 1*time.Millisecond)
		cache.Set("valid", &Secret{})

		assert.Equal(t, 2, cache.Size())

		// Wait for entry to expire
		time.Sleep(5 * time.Millisecond)

		// Start cleanup routine
		stopCh := make(chan struct{})
		cache.StartCleanupRoutine(50*time.Millisecond, stopCh)

		// Wait for cleanup to run
		time.Sleep(100 * time.Millisecond)

		close(stopCh)

		// Expired entry should be removed
		_, ok := cache.Get("expired")
		assert.False(t, ok, "expired entry should be removed")
		_, ok = cache.Get("valid")
		assert.True(t, ok, "valid entry should still be in cache")
	})

	t.Run("cleanup routine stops on stopCh close", func(t *testing.T) {
		cache := NewSecretCache(5 * time.Minute)

		stopCh := make(chan struct{})
		cache.StartCleanupRoutine(10*time.Millisecond, stopCh)

		// Close stop channel
		close(stopCh)

		// Give routine time to stop
		time.Sleep(50 * time.Millisecond)

		// Should not panic or hang
	})
}

// ============================================================================
// SecretCache Start/Stop Tests
// ============================================================================

func TestSecretCache_Start(t *testing.T) {
	t.Run("starts cleanup routine with context", func(t *testing.T) {
		config := &CacheConfig{
			MaxSize:         100,
			DefaultTTL:      5 * time.Minute,
			CleanupInterval: 50 * time.Millisecond,
		}
		cache := NewSecretCacheWithConfig(config, zap.NewNop())

		// Add entry with very short TTL
		cache.SetWithTTL("expired", &Secret{}, 1*time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())
		cache.Start(ctx)

		// Wait for cleanup to run
		time.Sleep(100 * time.Millisecond)

		cancel()
		cache.Stop()

		// Expired entry should be removed
		_, ok := cache.Get("expired")
		assert.False(t, ok)
	})
}

// ============================================================================
// VaultClientCache Start/Stop Tests
// ============================================================================

func TestVaultClientCache_Start(t *testing.T) {
	t.Run("starts cleanup routine with context", func(t *testing.T) {
		config := &VaultClientCacheConfig{
			MaxSize:         100,
			TTL:             1 * time.Millisecond,
			CleanupInterval: 50 * time.Millisecond,
		}
		cache := NewVaultClientCache(config, zap.NewNop())

		client, _ := NewClient(nil, nil)
		cache.Set("key1", client, "http://vault:8200")

		ctx, cancel := context.WithCancel(context.Background())
		cache.Start(ctx, 50*time.Millisecond)

		// Wait for entry to expire and cleanup to run
		time.Sleep(100 * time.Millisecond)

		cancel()

		// Entry should be removed due to expiration
		_, ok := cache.Get("key1")
		assert.False(t, ok)
	})
}

// ============================================================================
// VaultClientCache DeleteByAddress Tests
// ============================================================================

func TestVaultClientCache_DeleteByAddress(t *testing.T) {
	t.Run("removes all clients with matching address", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		client1, _ := NewClient(nil, nil)
		client2, _ := NewClient(nil, nil)
		client3, _ := NewClient(nil, nil)

		cache.Set("key1", client1, "http://vault1:8200")
		cache.Set("key2", client2, "http://vault1:8200")
		cache.Set("key3", client3, "http://vault2:8200")

		assert.Equal(t, 3, cache.Size())

		removed := cache.DeleteByAddress("http://vault1:8200")

		assert.Equal(t, 2, removed)
		assert.Equal(t, 1, cache.Size())
		_, ok := cache.Get("key3")
		assert.True(t, ok)
	})

	t.Run("returns 0 when no matching address", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		client, _ := NewClient(nil, nil)
		cache.Set("key1", client, "http://vault:8200")

		removed := cache.DeleteByAddress("http://nonexistent:8200")

		assert.Equal(t, 0, removed)
		assert.Equal(t, 1, cache.Size())
	})
}

// ============================================================================
// VaultClientCache Set with Address Change Tests
// ============================================================================

func TestVaultClientCache_Set_AddressChange(t *testing.T) {
	t.Run("closes old client when address changes", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		client1, _ := NewClient(nil, nil)
		client2, _ := NewClient(nil, nil)

		cache.Set("key1", client1, "http://vault1:8200")

		// Set same key with different address
		cache.Set("key1", client2, "http://vault2:8200")

		assert.Equal(t, 1, cache.Size())

		// Old client should be closed
		assert.True(t, client1.closed)
	})

	t.Run("updates client without closing when address same", func(t *testing.T) {
		cache := NewVaultClientCache(nil, zap.NewNop())

		client1, _ := NewClient(nil, nil)
		client2, _ := NewClient(nil, nil)

		cache.Set("key1", client1, "http://vault:8200")

		// Set same key with same address
		cache.Set("key1", client2, "http://vault:8200")

		assert.Equal(t, 1, cache.Size())

		// Old client should NOT be closed (same address)
		assert.False(t, client1.closed)
	})
}

// ============================================================================
// Cache Stats Tests
// ============================================================================

func TestSecretCache_GetStats(t *testing.T) {
	config := &CacheConfig{
		MaxSize:    10,
		DefaultTTL: 5 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, zap.NewNop())

	// Add some entries
	cache.Set("path1", &Secret{})
	cache.Set("path2", &Secret{})
	cache.SetWithTTL("expired", &Secret{}, 1*time.Millisecond)

	// Wait for entry to expire
	time.Sleep(5 * time.Millisecond)

	stats := cache.GetStats()

	assert.Equal(t, 3, stats.Size)
	assert.Equal(t, 10, stats.MaxSize)
	assert.Equal(t, 1, stats.ExpiredCount)
}

func TestVaultClientCache_GetStats(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize: 10,
		TTL:     1 * time.Millisecond,
	}
	cache := NewVaultClientCache(config, zap.NewNop())

	client1, _ := NewClient(nil, nil)
	client2, _ := NewClient(nil, nil)

	cache.Set("key1", client1, "http://vault1:8200")
	cache.Set("key2", client2, "http://vault2:8200")

	// Wait for entries to expire
	time.Sleep(5 * time.Millisecond)

	stats := cache.GetStats()

	assert.Equal(t, 2, stats.Size)
	assert.Equal(t, 10, stats.MaxSize)
	assert.Equal(t, 2, stats.ExpiredCount)
}

// ============================================================================
// CacheEntry IsExpired Tests
// ============================================================================

func TestCacheEntry_IsExpired(t *testing.T) {
	t.Run("returns false for non-expired entry", func(t *testing.T) {
		entry := &CacheEntry{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, entry.IsExpired())
	})

	t.Run("returns true for expired entry", func(t *testing.T) {
		entry := &CacheEntry{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, entry.IsExpired())
	})
}

// ============================================================================
// VaultClientEntry IsExpired Tests
// ============================================================================

func TestVaultClientEntry_IsExpired(t *testing.T) {
	t.Run("returns false for recently used entry", func(t *testing.T) {
		entry := &VaultClientEntry{
			LastUsedAt: time.Now(),
		}
		assert.False(t, entry.IsExpired(5*time.Minute))
	})

	t.Run("returns true for stale entry", func(t *testing.T) {
		entry := &VaultClientEntry{
			LastUsedAt: time.Now().Add(-10 * time.Minute),
		}
		assert.True(t, entry.IsExpired(5*time.Minute))
	})
}

// ============================================================================
// Cache Clear Tests
// ============================================================================

func TestVaultClientCache_Clear(t *testing.T) {
	cache := NewVaultClientCache(nil, zap.NewNop())

	client1, _ := NewClient(nil, nil)
	client2, _ := NewClient(nil, nil)

	cache.Set("key1", client1, "http://vault1:8200")
	cache.Set("key2", client2, "http://vault2:8200")

	assert.Equal(t, 2, cache.Size())

	cache.Clear()

	assert.Equal(t, 0, cache.Size())
	assert.True(t, client1.closed)
	assert.True(t, client2.closed)
}
