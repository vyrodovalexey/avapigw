package vault

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretCache(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)
	assert.NotNil(t, cache)
	assert.Equal(t, 5*time.Minute, cache.config.DefaultTTL)
}

func TestNewSecretCacheWithConfig(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         500,
		DefaultTTL:      10 * time.Minute,
		CleanupInterval: 2 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, nil)
	assert.NotNil(t, cache)
	assert.Equal(t, 500, cache.config.MaxSize)
	assert.Equal(t, 10*time.Minute, cache.config.DefaultTTL)
	assert.Equal(t, 2*time.Minute, cache.config.CleanupInterval)
}

func TestSecretCacheSetAndGet(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)

	secret := &Secret{
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	// Set
	cache.Set("test/path", secret)

	// Get
	retrieved, ok := cache.Get("test/path")
	assert.True(t, ok)
	assert.Equal(t, secret, retrieved)
}

func TestSecretCacheGetMiss(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)

	retrieved, ok := cache.Get("nonexistent/path")
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

func TestSecretCacheExpiry(t *testing.T) {
	cache := NewSecretCache(100 * time.Millisecond)

	secret := &Secret{
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	cache.Set("test/path", secret)

	// Should be available immediately
	retrieved, ok := cache.Get("test/path")
	assert.True(t, ok)
	assert.NotNil(t, retrieved)

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	retrieved, ok = cache.Get("test/path")
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

func TestSecretCacheSetWithTTL(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)

	secret := &Secret{
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	// Set with short TTL
	cache.SetWithTTL("test/path", secret, 100*time.Millisecond)

	// Should be available immediately
	retrieved, ok := cache.Get("test/path")
	assert.True(t, ok)
	assert.NotNil(t, retrieved)

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	retrieved, ok = cache.Get("test/path")
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

func TestSecretCacheDelete(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)

	secret := &Secret{
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	cache.Set("test/path", secret)

	// Verify it exists
	_, ok := cache.Get("test/path")
	assert.True(t, ok)

	// Delete
	cache.Delete("test/path")

	// Verify it's gone
	_, ok = cache.Get("test/path")
	assert.False(t, ok)
}

func TestSecretCacheClear(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)

	// Add multiple entries
	for i := 0; i < 5; i++ {
		cache.Set("test/path/"+string(rune('0'+i)), &Secret{})
	}

	assert.Equal(t, 5, cache.Size())

	// Clear
	cache.Clear()

	assert.Equal(t, 0, cache.Size())
}

func TestSecretCacheSize(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)

	assert.Equal(t, 0, cache.Size())

	cache.Set("path1", &Secret{})
	assert.Equal(t, 1, cache.Size())

	cache.Set("path2", &Secret{})
	assert.Equal(t, 2, cache.Size())

	cache.Delete("path1")
	assert.Equal(t, 1, cache.Size())
}

func TestSecretCacheCleanup(t *testing.T) {
	cache := NewSecretCache(100 * time.Millisecond)

	// Add entries
	cache.Set("path1", &Secret{})
	cache.Set("path2", &Secret{})

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Add a fresh entry
	cache.SetWithTTL("path3", &Secret{}, 5*time.Minute)

	// Cleanup should remove expired entries
	removed := cache.Cleanup()
	assert.Equal(t, 2, removed)
	assert.Equal(t, 1, cache.Size())
}

func TestCacheEntryIsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		entry := &CacheEntry{
			Secret:    &Secret{},
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, entry.IsExpired())
	})

	t.Run("expired", func(t *testing.T) {
		entry := &CacheEntry{
			Secret:    &Secret{},
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, entry.IsExpired())
	})
}

func TestSecretCacheStartCleanupRoutine(t *testing.T) {
	cache := NewSecretCache(50 * time.Millisecond)
	stopCh := make(chan struct{})

	// Add entries
	cache.Set("path1", &Secret{})
	cache.Set("path2", &Secret{})

	// Start cleanup routine
	cache.StartCleanupRoutine(100*time.Millisecond, stopCh)

	// Wait for entries to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Entries should be cleaned up
	require.Equal(t, 0, cache.Size())

	// Stop the routine
	close(stopCh)
}

// ============================================================================
// LRU Eviction Tests
// ============================================================================

func TestSecretCacheLRUEviction(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         3,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, nil)

	// Add 3 entries (at capacity)
	cache.Set("path1", &Secret{Data: map[string]interface{}{"key": "value1"}})
	cache.Set("path2", &Secret{Data: map[string]interface{}{"key": "value2"}})
	cache.Set("path3", &Secret{Data: map[string]interface{}{"key": "value3"}})

	assert.Equal(t, 3, cache.Size())

	// Access path1 to make it recently used
	_, ok := cache.Get("path1")
	assert.True(t, ok)

	// Add a 4th entry - should evict path2 (least recently used)
	cache.Set("path4", &Secret{Data: map[string]interface{}{"key": "value4"}})

	assert.Equal(t, 3, cache.Size())

	// path2 should be evicted
	_, ok = cache.Get("path2")
	assert.False(t, ok, "path2 should have been evicted")

	// path1, path3, path4 should still exist
	_, ok = cache.Get("path1")
	assert.True(t, ok, "path1 should still exist")
	_, ok = cache.Get("path3")
	assert.True(t, ok, "path3 should still exist")
	_, ok = cache.Get("path4")
	assert.True(t, ok, "path4 should still exist")
}

func TestSecretCacheLRUEvictionOrder(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         3,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, nil)

	// Add entries in order
	cache.Set("path1", &Secret{})
	cache.Set("path2", &Secret{})
	cache.Set("path3", &Secret{})

	// Access in reverse order to change LRU order
	cache.Get("path3")
	cache.Get("path2")
	cache.Get("path1")

	// Now path3 is LRU, path1 is MRU
	// Adding a new entry should evict path3
	cache.Set("path4", &Secret{})

	_, ok := cache.Get("path3")
	assert.False(t, ok, "path3 should have been evicted (LRU)")

	_, ok = cache.Get("path1")
	assert.True(t, ok, "path1 should still exist (MRU)")
}

func TestSecretCacheUpdateExistingEntry(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         3,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, nil)

	// Add entries
	cache.Set("path1", &Secret{Data: map[string]interface{}{"key": "value1"}})
	cache.Set("path2", &Secret{Data: map[string]interface{}{"key": "value2"}})
	cache.Set("path3", &Secret{Data: map[string]interface{}{"key": "value3"}})

	// Update path1 - should not increase size
	cache.Set("path1", &Secret{Data: map[string]interface{}{"key": "updated"}})

	assert.Equal(t, 3, cache.Size())

	// Verify the update
	secret, ok := cache.Get("path1")
	assert.True(t, ok)
	assert.Equal(t, "updated", secret.Data["key"])
}

func TestSecretCacheMaxSize(t *testing.T) {
	cache := NewSecretCache(5 * time.Minute)
	assert.Equal(t, 1000, cache.MaxSize()) // Default max size
}

func TestSecretCacheGetStats(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         10,
		DefaultTTL:      100 * time.Millisecond,
		CleanupInterval: 1 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, nil)

	// Add some entries
	cache.Set("path1", &Secret{})
	cache.Set("path2", &Secret{})
	cache.SetWithTTL("path3", &Secret{}, 5*time.Minute) // Long TTL

	// Wait for some to expire
	time.Sleep(150 * time.Millisecond)

	stats := cache.GetStats()
	assert.Equal(t, 3, stats.Size)
	assert.Equal(t, 10, stats.MaxSize)
	assert.Equal(t, 2, stats.ExpiredCount) // path1 and path2 expired
}

func TestSecretCacheStartAndStop(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         10,
		DefaultTTL:      50 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}
	cache := NewSecretCacheWithConfig(config, nil)

	ctx, cancel := context.WithCancel(context.Background())

	// Add entries
	cache.Set("path1", &Secret{})
	cache.Set("path2", &Secret{})

	// Start the cache
	cache.Start(ctx)

	// Wait for entries to expire and cleanup to run
	time.Sleep(150 * time.Millisecond)

	// Entries should be cleaned up
	assert.Equal(t, 0, cache.Size())

	// Stop the cache
	cancel()
	cache.Stop()
}

func TestSecretCacheConcurrentAccess(t *testing.T) {
	config := &CacheConfig{
		MaxSize:         100,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
	cache := NewSecretCacheWithConfig(config, nil)

	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "path" + string(rune('0'+id%10))
				cache.Set(key, &Secret{Data: map[string]interface{}{"id": id, "op": j}})
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "path" + string(rune('0'+id%10))
				cache.Get(key)
			}
		}(i)
	}

	wg.Wait()

	// Should not panic and cache should be in a valid state
	assert.True(t, cache.Size() <= 100)
}

// ============================================================================
// VaultClientCache Tests
// ============================================================================

func TestNewVaultClientCache(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         50,
		TTL:             15 * time.Minute,
		CleanupInterval: 3 * time.Minute,
	}
	cache := NewVaultClientCache(config, nil)
	assert.NotNil(t, cache)
	assert.Equal(t, 50, cache.maxSize)
	assert.Equal(t, 15*time.Minute, cache.ttl)
}

func TestVaultClientCacheSetAndGet(t *testing.T) {
	cache := NewVaultClientCache(nil, nil)

	// Create a mock client (we can't create a real one without Vault)
	// For testing, we'll use nil and just test the cache mechanics
	cache.Set("key1", nil, "http://vault1:8200")

	// Get should return the entry
	_, ok := cache.Get("key1")
	assert.True(t, ok)
}

func TestVaultClientCacheGetMiss(t *testing.T) {
	cache := NewVaultClientCache(nil, nil)

	_, ok := cache.Get("nonexistent")
	assert.False(t, ok)
}

func TestVaultClientCacheDelete(t *testing.T) {
	cache := NewVaultClientCache(nil, nil)

	cache.Set("key1", nil, "http://vault1:8200")

	// Verify it exists
	_, ok := cache.Get("key1")
	assert.True(t, ok)

	// Delete
	cache.Delete("key1")

	// Verify it's gone
	_, ok = cache.Get("key1")
	assert.False(t, ok)
}

func TestVaultClientCacheDeleteByAddress(t *testing.T) {
	cache := NewVaultClientCache(nil, nil)

	// Add clients with different addresses
	cache.Set("key1", nil, "http://vault1:8200")
	cache.Set("key2", nil, "http://vault1:8200")
	cache.Set("key3", nil, "http://vault2:8200")

	assert.Equal(t, 3, cache.Size())

	// Delete by address
	removed := cache.DeleteByAddress("http://vault1:8200")
	assert.Equal(t, 2, removed)
	assert.Equal(t, 1, cache.Size())

	// key3 should still exist
	_, ok := cache.Get("key3")
	assert.True(t, ok)
}

func TestVaultClientCacheClear(t *testing.T) {
	cache := NewVaultClientCache(nil, nil)

	cache.Set("key1", nil, "http://vault1:8200")
	cache.Set("key2", nil, "http://vault2:8200")

	assert.Equal(t, 2, cache.Size())

	cache.Clear()

	assert.Equal(t, 0, cache.Size())
}

func TestVaultClientCacheLRUEviction(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         3,
		TTL:             30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
	cache := NewVaultClientCache(config, nil)

	// Add 3 entries (at capacity)
	cache.Set("key1", nil, "http://vault1:8200")
	cache.Set("key2", nil, "http://vault2:8200")
	cache.Set("key3", nil, "http://vault3:8200")

	assert.Equal(t, 3, cache.Size())

	// Access key1 to make it recently used
	_, ok := cache.Get("key1")
	assert.True(t, ok)

	// Add a 4th entry - should evict key2 (least recently used)
	cache.Set("key4", nil, "http://vault4:8200")

	assert.Equal(t, 3, cache.Size())

	// key2 should be evicted
	_, ok = cache.Get("key2")
	assert.False(t, ok, "key2 should have been evicted")

	// key1, key3, key4 should still exist
	_, ok = cache.Get("key1")
	assert.True(t, ok, "key1 should still exist")
	_, ok = cache.Get("key3")
	assert.True(t, ok, "key3 should still exist")
	_, ok = cache.Get("key4")
	assert.True(t, ok, "key4 should still exist")
}

func TestVaultClientCacheTTLExpiry(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         10,
		TTL:             100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}
	cache := NewVaultClientCache(config, nil)

	cache.Set("key1", nil, "http://vault1:8200")

	// Should be available immediately
	_, ok := cache.Get("key1")
	assert.True(t, ok)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, ok = cache.Get("key1")
	assert.False(t, ok)
}

func TestVaultClientCacheCleanup(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         10,
		TTL:             100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}
	cache := NewVaultClientCache(config, nil)

	cache.Set("key1", nil, "http://vault1:8200")
	cache.Set("key2", nil, "http://vault2:8200")

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Cleanup should remove expired entries
	removed := cache.Cleanup()
	assert.Equal(t, 2, removed)
	assert.Equal(t, 0, cache.Size())
}

func TestVaultClientCacheGetStats(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         10,
		TTL:             100 * time.Millisecond,
		CleanupInterval: 5 * time.Minute,
	}
	cache := NewVaultClientCache(config, nil)

	cache.Set("key1", nil, "http://vault1:8200")
	cache.Set("key2", nil, "http://vault2:8200")

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	stats := cache.GetStats()
	assert.Equal(t, 2, stats.Size)
	assert.Equal(t, 10, stats.MaxSize)
	assert.Equal(t, 2, stats.ExpiredCount)
}

func TestVaultClientCacheStartAndStop(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         10,
		TTL:             50 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}
	cache := NewVaultClientCache(config, nil)

	ctx, cancel := context.WithCancel(context.Background())

	cache.Set("key1", nil, "http://vault1:8200")
	cache.Set("key2", nil, "http://vault2:8200")

	// Start the cache
	cache.Start(ctx, config.CleanupInterval)

	// Wait for entries to expire and cleanup to run
	time.Sleep(150 * time.Millisecond)

	// Entries should be cleaned up
	assert.Equal(t, 0, cache.Size())

	// Stop the cache
	cancel()
	cache.Stop()
}

func TestVaultClientCacheConcurrentAccess(t *testing.T) {
	config := &VaultClientCacheConfig{
		MaxSize:         100,
		TTL:             30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
	cache := NewVaultClientCache(config, nil)

	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key" + string(rune('0'+id%10))
				cache.Set(key, nil, "http://vault:8200")
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key" + string(rune('0'+id%10))
				cache.Get(key)
			}
		}(i)
	}

	wg.Wait()

	// Should not panic and cache should be in a valid state
	assert.True(t, cache.Size() <= 100)
}

func TestVaultClientCacheAddressChange(t *testing.T) {
	cache := NewVaultClientCache(nil, nil)

	// Add a client
	cache.Set("key1", nil, "http://vault1:8200")

	// Update with a different address - should replace
	cache.Set("key1", nil, "http://vault2:8200")

	assert.Equal(t, 1, cache.Size())

	// The entry should have the new address
	// (We can't directly check the address, but the entry should exist)
	_, ok := cache.Get("key1")
	assert.True(t, ok)
}

func TestVaultClientEntryIsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		entry := &VaultClientEntry{
			LastUsedAt: time.Now(),
		}
		assert.False(t, entry.IsExpired(30*time.Minute))
	})

	t.Run("expired", func(t *testing.T) {
		entry := &VaultClientEntry{
			LastUsedAt: time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, entry.IsExpired(30*time.Minute))
	})
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()
	assert.Equal(t, 1000, config.MaxSize)
	assert.Equal(t, 5*time.Minute, config.DefaultTTL)
	assert.Equal(t, 1*time.Minute, config.CleanupInterval)
}

func TestDefaultVaultClientCacheConfig(t *testing.T) {
	config := DefaultVaultClientCacheConfig()
	assert.Equal(t, 100, config.MaxSize)
	assert.Equal(t, 30*time.Minute, config.TTL)
	assert.Equal(t, 5*time.Minute, config.CleanupInterval)
}
