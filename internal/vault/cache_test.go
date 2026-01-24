package vault

import (
	"sync"
	"testing"
	"time"
)

func TestNewSecretCache(t *testing.T) {
	tests := []struct {
		name            string
		maxSize         int
		ttl             time.Duration
		expectedMaxSize int
		expectedTTL     time.Duration
	}{
		{
			name:            "default values for zero inputs",
			maxSize:         0,
			ttl:             0,
			expectedMaxSize: 1000,
			expectedTTL:     5 * time.Minute,
		},
		{
			name:            "default values for negative inputs",
			maxSize:         -1,
			ttl:             -1 * time.Second,
			expectedMaxSize: 1000,
			expectedTTL:     5 * time.Minute,
		},
		{
			name:            "custom values",
			maxSize:         500,
			ttl:             10 * time.Minute,
			expectedMaxSize: 500,
			expectedTTL:     10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newSecretCache(tt.maxSize, tt.ttl)
			defer cache.stop()

			if cache.maxSize != tt.expectedMaxSize {
				t.Errorf("maxSize = %v, want %v", cache.maxSize, tt.expectedMaxSize)
			}
			if cache.ttl != tt.expectedTTL {
				t.Errorf("ttl = %v, want %v", cache.ttl, tt.expectedTTL)
			}
			if cache.items == nil {
				t.Error("items map should not be nil")
			}
			if cache.lru == nil {
				t.Error("lru list should not be nil")
			}
		})
	}
}

func TestSecretCache_Get_Miss(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	value, ok := cache.get("nonexistent")
	if ok {
		t.Error("get() should return false for nonexistent key")
	}
	if value != nil {
		t.Error("get() should return nil for nonexistent key")
	}
}

func TestSecretCache_Get_Hit(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	expected := map[string]string{"key": "value"}
	cache.set("test-key", expected)

	value, ok := cache.get("test-key")
	if !ok {
		t.Error("get() should return true for existing key")
	}
	if value == nil {
		t.Error("get() should return non-nil value for existing key")
	}

	result, ok := value.(map[string]string)
	if !ok {
		t.Error("get() should return correct type")
	}
	if result["key"] != "value" {
		t.Errorf("get() returned wrong value: %v", result)
	}
}

func TestSecretCache_Get_Expired(t *testing.T) {
	// Use very short TTL for testing
	cache := newSecretCache(100, 10*time.Millisecond)
	defer cache.stop()

	cache.set("test-key", "test-value")

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	value, ok := cache.get("test-key")
	if ok {
		t.Error("get() should return false for expired key")
	}
	if value != nil {
		t.Error("get() should return nil for expired key")
	}
}

func TestSecretCache_Set_NewItem(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	cache.set("key1", "value1")

	if len(cache.items) != 1 {
		t.Errorf("items count = %v, want 1", len(cache.items))
	}
	if cache.lru.Len() != 1 {
		t.Errorf("lru length = %v, want 1", cache.lru.Len())
	}

	value, ok := cache.get("key1")
	if !ok || value != "value1" {
		t.Error("set() should store the value correctly")
	}
}

func TestSecretCache_Set_UpdateExisting(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	cache.set("key1", "value1")
	cache.set("key1", "value2")

	if len(cache.items) != 1 {
		t.Errorf("items count = %v, want 1", len(cache.items))
	}

	value, ok := cache.get("key1")
	if !ok || value != "value2" {
		t.Error("set() should update existing value")
	}
}

func TestSecretCache_Set_Eviction(t *testing.T) {
	cache := newSecretCache(3, 5*time.Minute)
	defer cache.stop()

	// Fill cache to capacity
	cache.set("key1", "value1")
	cache.set("key2", "value2")
	cache.set("key3", "value3")

	// Access key1 to make it recently used
	cache.get("key1")

	// Add new item, should evict key2 (least recently used)
	cache.set("key4", "value4")

	if len(cache.items) != 3 {
		t.Errorf("items count = %v, want 3", len(cache.items))
	}

	// key2 should be evicted
	_, ok := cache.get("key2")
	if ok {
		t.Error("key2 should have been evicted")
	}

	// key1, key3, key4 should still exist
	if _, ok := cache.get("key1"); !ok {
		t.Error("key1 should still exist")
	}
	if _, ok := cache.get("key3"); !ok {
		t.Error("key3 should still exist")
	}
	if _, ok := cache.get("key4"); !ok {
		t.Error("key4 should still exist")
	}
}

func TestSecretCache_Delete_Existing(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	cache.set("key1", "value1")
	cache.delete("key1")

	if len(cache.items) != 0 {
		t.Errorf("items count = %v, want 0", len(cache.items))
	}
	if cache.lru.Len() != 0 {
		t.Errorf("lru length = %v, want 0", cache.lru.Len())
	}

	_, ok := cache.get("key1")
	if ok {
		t.Error("get() should return false after delete")
	}
}

func TestSecretCache_Delete_NonExistent(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	// Should not panic
	cache.delete("nonexistent")

	if len(cache.items) != 0 {
		t.Errorf("items count = %v, want 0", len(cache.items))
	}
}

func TestSecretCache_RemoveExpired(t *testing.T) {
	cache := newSecretCache(100, 10*time.Millisecond)
	defer cache.stop()

	cache.set("key1", "value1")
	cache.set("key2", "value2")

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	cache.removeExpired()

	if len(cache.items) != 0 {
		t.Errorf("items count = %v, want 0 after removeExpired", len(cache.items))
	}
	if cache.lru.Len() != 0 {
		t.Errorf("lru length = %v, want 0 after removeExpired", cache.lru.Len())
	}
}

func TestSecretCache_Stop(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)

	// Stop should complete without blocking
	done := make(chan struct{})
	go func() {
		cache.stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("stop() should complete within timeout")
	}
}

func TestSecretCache_ConcurrentAccess(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key-" + string(rune('a'+id))
				cache.set(key, j)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key-" + string(rune('a'+id))
				cache.get(key)
			}
		}(i)
	}

	// Concurrent deletes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key-" + string(rune('a'+id))
				cache.delete(key)
			}
		}(i)
	}

	wg.Wait()
	// Test passes if no race conditions or panics occur
}

func TestSecretCache_LRUOrder(t *testing.T) {
	cache := newSecretCache(3, 5*time.Minute)
	defer cache.stop()

	// Add items in order
	cache.set("key1", "value1")
	cache.set("key2", "value2")
	cache.set("key3", "value3")

	// Access key1 to move it to front
	cache.get("key1")

	// Add key4, should evict key2 (now least recently used)
	cache.set("key4", "value4")

	// Verify key2 was evicted
	if _, ok := cache.get("key2"); ok {
		t.Error("key2 should have been evicted")
	}

	// Verify others exist
	if _, ok := cache.get("key1"); !ok {
		t.Error("key1 should exist")
	}
	if _, ok := cache.get("key3"); !ok {
		t.Error("key3 should exist")
	}
	if _, ok := cache.get("key4"); !ok {
		t.Error("key4 should exist")
	}
}

func TestSecretCache_EvictOldest_EmptyCache(t *testing.T) {
	cache := newSecretCache(100, 5*time.Minute)
	defer cache.stop()

	// Should not panic on empty cache
	cache.mu.Lock()
	cache.evictOldest()
	cache.mu.Unlock()

	if len(cache.items) != 0 {
		t.Error("cache should remain empty")
	}
}

func TestSecretCache_SetUpdatesExpiry(t *testing.T) {
	cache := newSecretCache(100, 50*time.Millisecond)
	defer cache.stop()

	cache.set("key1", "value1")

	// Wait a bit but not until expiry
	time.Sleep(30 * time.Millisecond)

	// Update the value, which should reset expiry
	cache.set("key1", "value2")

	// Wait another 30ms (total 60ms from first set, but only 30ms from update)
	time.Sleep(30 * time.Millisecond)

	// Should still be valid because expiry was reset
	value, ok := cache.get("key1")
	if !ok {
		t.Error("key should still be valid after update")
	}
	if value != "value2" {
		t.Errorf("value = %v, want value2", value)
	}
}

func TestSecretCache_GetMovesToFront(t *testing.T) {
	cache := newSecretCache(3, 5*time.Minute)
	defer cache.stop()

	cache.set("key1", "value1")
	cache.set("key2", "value2")
	cache.set("key3", "value3")

	// Access key1 multiple times to ensure it's at front
	cache.get("key1")
	cache.get("key1")

	// Add two more items to evict key2 and key3
	cache.set("key4", "value4")
	cache.set("key5", "value5")

	// key1 should still exist
	if _, ok := cache.get("key1"); !ok {
		t.Error("key1 should still exist after being accessed")
	}
}
