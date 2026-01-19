package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Constructor Tests
// ============================================================================

// TestNewMemoryStore tests the basic constructor.
func TestNewMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	require.NotNil(t, store)
	defer store.Close()

	assert.NotNil(t, store.cleanup)
	assert.NotNil(t, store.done)
	assert.False(t, store.closed)
}

// TestNewMemoryStoreWithCleanupInterval tests constructor with custom interval.
func TestNewMemoryStoreWithCleanupInterval(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(100 * time.Millisecond)
	require.NotNil(t, store)
	defer store.Close()

	assert.NotNil(t, store.cleanup)
	assert.NotNil(t, store.done)
	assert.False(t, store.closed)
}

// ============================================================================
// Get Tests
// ============================================================================

// TestMemoryStore_Get_Success tests successful Get operation.
func TestMemoryStore_Get_Success(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set a value
	err := store.Set(ctx, "key1", 100, time.Minute)
	require.NoError(t, err)

	// Get the value
	value, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)
}

// TestMemoryStore_Get_KeyNotFound tests Get with non-existent key.
func TestMemoryStore_Get_KeyNotFound(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	assert.Error(t, err)
	assert.True(t, IsKeyNotFound(err))
}

// TestMemoryStore_Get_ExpiredKey tests Get with expired key.
func TestMemoryStore_Get_ExpiredKey(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour) // Long interval to control cleanup
	defer store.Close()

	ctx := context.Background()

	// Set a key with very short expiration
	err := store.Set(ctx, "expiring", 100, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Get should return key not found
	_, err = store.Get(ctx, "expiring")
	assert.Error(t, err)
	assert.True(t, IsKeyNotFound(err))
}

// TestMemoryStore_Get_ContextCancelled tests Get with cancelled context.
func TestMemoryStore_Get_ContextCancelled(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := store.Get(ctx, "key1")
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestMemoryStore_Get_ContextDeadlineExceeded tests Get with deadline exceeded.
func TestMemoryStore_Get_ContextDeadlineExceeded(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	// Wait for deadline to pass
	time.Sleep(time.Millisecond)

	_, err := store.Get(ctx, "key1")
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
}

// ============================================================================
// Set Tests
// ============================================================================

// TestMemoryStore_Set_Success tests successful Set operation.
func TestMemoryStore_Set_Success(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	err := store.Set(ctx, "key1", 100, time.Minute)
	require.NoError(t, err)

	// Verify value was set
	value, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)
}

// TestMemoryStore_Set_WithExpiration tests Set with expiration.
func TestMemoryStore_Set_WithExpiration(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	err := store.Set(ctx, "key1", 100, 50*time.Millisecond)
	require.NoError(t, err)

	// Should exist immediately
	value, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Should not exist
	_, err = store.Get(ctx, "key1")
	assert.True(t, IsKeyNotFound(err))
}

// TestMemoryStore_Set_WithoutExpiration tests Set without expiration.
func TestMemoryStore_Set_WithoutExpiration(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set with zero expiration (no expiration)
	err := store.Set(ctx, "key1", 100, 0)
	require.NoError(t, err)

	// Should exist
	value, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)
}

// TestMemoryStore_Set_ContextCancelled tests Set with cancelled context.
func TestMemoryStore_Set_ContextCancelled(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := store.Set(ctx, "key1", 100, time.Minute)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestMemoryStore_Set_Overwrite tests overwriting existing key.
func TestMemoryStore_Set_Overwrite(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set initial value
	err := store.Set(ctx, "key1", 100, time.Minute)
	require.NoError(t, err)

	// Overwrite
	err = store.Set(ctx, "key1", 200, time.Minute)
	require.NoError(t, err)

	// Verify new value
	value, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(200), value)
}

// ============================================================================
// Increment Tests
// ============================================================================

// TestMemoryStore_Increment_Success tests successful Increment operation.
func TestMemoryStore_Increment_Success(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set initial value
	err := store.Set(ctx, "counter", 10, time.Minute)
	require.NoError(t, err)

	// Increment
	value, err := store.Increment(ctx, "counter", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(15), value)
}

// TestMemoryStore_Increment_NonExistentKey tests Increment on non-existent key.
func TestMemoryStore_Increment_NonExistentKey(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Increment non-existent key should create it
	value, err := store.Increment(ctx, "new_counter", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value)
}

// TestMemoryStore_Increment_ExpiredKey tests Increment on expired key.
func TestMemoryStore_Increment_ExpiredKey(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set a key with very short expiration
	err := store.Set(ctx, "counter", 100, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Increment should create new key with delta value
	value, err := store.Increment(ctx, "counter", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value)
}

// TestMemoryStore_Increment_ContextCancelled tests Increment with cancelled context.
func TestMemoryStore_Increment_ContextCancelled(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := store.Increment(ctx, "counter", 1)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestMemoryStore_Increment_NegativeDelta tests Increment with negative delta.
func TestMemoryStore_Increment_NegativeDelta(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set initial value
	err := store.Set(ctx, "counter", 10, time.Minute)
	require.NoError(t, err)

	// Decrement
	value, err := store.Increment(ctx, "counter", -3)
	require.NoError(t, err)
	assert.Equal(t, int64(7), value)
}

// TestMemoryStore_Increment_Multiple tests multiple increments.
func TestMemoryStore_Increment_Multiple(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Multiple increments
	value, err := store.Increment(ctx, "counter", 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), value)

	value, err = store.Increment(ctx, "counter", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(6), value)

	value, err = store.Increment(ctx, "counter", 10)
	require.NoError(t, err)
	assert.Equal(t, int64(16), value)
}

// ============================================================================
// IncrementWithExpiry Tests
// ============================================================================

// TestMemoryStore_IncrementWithExpiry_Success tests successful IncrementWithExpiry.
func TestMemoryStore_IncrementWithExpiry_Success(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Increment with expiry
	value, err := store.IncrementWithExpiry(ctx, "counter", 1, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), value)

	// Increment again
	value, err = store.IncrementWithExpiry(ctx, "counter", 1, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(2), value)
}

// TestMemoryStore_IncrementWithExpiry_NonExistentKey tests IncrementWithExpiry on non-existent key.
func TestMemoryStore_IncrementWithExpiry_NonExistentKey(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Increment non-existent key should create it with expiry
	value, err := store.IncrementWithExpiry(ctx, "new_counter", 5, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value)
}

// TestMemoryStore_IncrementWithExpiry_ExpiredKey tests IncrementWithExpiry on expired key.
func TestMemoryStore_IncrementWithExpiry_ExpiredKey(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour) // Long interval to control cleanup
	defer store.Close()

	ctx := context.Background()

	// Set a key with very short expiration
	err := store.Set(ctx, "counter", 100, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Increment should reset the value
	value, err := store.IncrementWithExpiry(ctx, "counter", 5, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value) // Should be 5, not 105
}

// TestMemoryStore_IncrementWithExpiry_ContextCancelled tests IncrementWithExpiry with cancelled context.
func TestMemoryStore_IncrementWithExpiry_ContextCancelled(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := store.IncrementWithExpiry(ctx, "counter", 1, time.Minute)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestMemoryStore_IncrementWithExpiry_NoExpiration tests IncrementWithExpiry with zero expiration.
func TestMemoryStore_IncrementWithExpiry_NoExpiration(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Increment with zero expiration (no expiration)
	value, err := store.IncrementWithExpiry(ctx, "counter", 5, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value)
}

// TestMemoryStore_IncrementWithExpiry_ResetAfterExpiry tests that value resets after expiry.
func TestMemoryStore_IncrementWithExpiry_ResetAfterExpiry(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// First increment
	value, err := store.IncrementWithExpiry(ctx, "counter", 1, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), value)

	// Second increment
	value, err = store.IncrementWithExpiry(ctx, "counter", 1, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(2), value)

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	// Should be reset
	value, err = store.IncrementWithExpiry(ctx, "counter", 1, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), value)
}

// ============================================================================
// Delete Tests
// ============================================================================

// TestMemoryStore_Delete_Success tests successful Delete operation.
func TestMemoryStore_Delete_Success(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set a value
	err := store.Set(ctx, "key1", 100, time.Minute)
	require.NoError(t, err)

	// Delete it
	err = store.Delete(ctx, "key1")
	require.NoError(t, err)

	// Should not exist
	_, err = store.Get(ctx, "key1")
	assert.True(t, IsKeyNotFound(err))
}

// TestMemoryStore_Delete_NonExistent tests Delete on non-existent key.
func TestMemoryStore_Delete_NonExistent(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Deleting non-existent key should not error
	err := store.Delete(ctx, "nonexistent")
	require.NoError(t, err)
}

// TestMemoryStore_Delete_ContextCancelled tests Delete with cancelled context.
func TestMemoryStore_Delete_ContextCancelled(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := store.Delete(ctx, "key1")
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// ============================================================================
// Close Tests
// ============================================================================

// TestMemoryStore_Close_Success tests successful Close operation.
func TestMemoryStore_Close_Success(t *testing.T) {
	store := NewMemoryStore()

	err := store.Close()
	require.NoError(t, err)
	assert.True(t, store.closed)
}

// TestMemoryStore_Close_Idempotent tests that Close is idempotent.
func TestMemoryStore_Close_Idempotent(t *testing.T) {
	store := NewMemoryStore()

	// First close
	err := store.Close()
	require.NoError(t, err)

	// Second close should also succeed
	err = store.Close()
	require.NoError(t, err)
}

// ============================================================================
// cleanupExpired Tests
// ============================================================================

// TestMemoryStore_CleanupExpired_RemovesExpiredEntries tests cleanup removes expired entries.
func TestMemoryStore_CleanupExpired_RemovesExpiredEntries(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour) // Long interval to control cleanup manually
	defer store.Close()

	ctx := context.Background()

	// Set entries with short expiration
	err := store.Set(ctx, "expired1", 100, 1*time.Millisecond)
	require.NoError(t, err)
	err = store.Set(ctx, "expired2", 200, 1*time.Millisecond)
	require.NoError(t, err)

	// Set entry without expiration
	err = store.Set(ctx, "permanent", 300, 0)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Manually trigger cleanup
	store.cleanupExpired()

	// Expired entries should be removed
	_, err = store.Get(ctx, "expired1")
	assert.True(t, IsKeyNotFound(err))
	_, err = store.Get(ctx, "expired2")
	assert.True(t, IsKeyNotFound(err))

	// Permanent entry should still exist
	value, err := store.Get(ctx, "permanent")
	require.NoError(t, err)
	assert.Equal(t, int64(300), value)
}

// TestMemoryStore_CleanupExpired_KeepsNonExpiredEntries tests cleanup keeps non-expired entries.
func TestMemoryStore_CleanupExpired_KeepsNonExpiredEntries(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set entries with long expiration
	err := store.Set(ctx, "key1", 100, time.Hour)
	require.NoError(t, err)
	err = store.Set(ctx, "key2", 200, time.Hour)
	require.NoError(t, err)

	// Manually trigger cleanup
	store.cleanupExpired()

	// All entries should still exist
	value, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)

	value, err = store.Get(ctx, "key2")
	require.NoError(t, err)
	assert.Equal(t, int64(200), value)
}

// TestMemoryStore_CleanupExpired_AutomaticCleanup tests automatic cleanup via ticker.
func TestMemoryStore_CleanupExpired_AutomaticCleanup(t *testing.T) {
	// Use short cleanup interval
	store := NewMemoryStoreWithCleanupInterval(50 * time.Millisecond)
	defer store.Close()

	ctx := context.Background()

	// Set entry with short expiration
	err := store.Set(ctx, "expiring", 100, 10*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration and cleanup
	time.Sleep(100 * time.Millisecond)

	// Entry should be cleaned up
	_, err = store.Get(ctx, "expiring")
	assert.True(t, IsKeyNotFound(err))
}

// ============================================================================
// Size Tests
// ============================================================================

// TestMemoryStore_Size_Empty tests Size on empty store.
func TestMemoryStore_Size_Empty(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	assert.Equal(t, 0, store.Size())
}

// TestMemoryStore_Size_WithEntries tests Size with entries.
func TestMemoryStore_Size_WithEntries(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	assert.Equal(t, 0, store.Size())

	store.Set(ctx, "key1", 1, time.Minute)
	assert.Equal(t, 1, store.Size())

	store.Set(ctx, "key2", 2, time.Minute)
	assert.Equal(t, 2, store.Size())

	store.Set(ctx, "key3", 3, time.Minute)
	assert.Equal(t, 3, store.Size())

	store.Delete(ctx, "key2")
	assert.Equal(t, 2, store.Size())
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

// TestMemoryStore_ConcurrentAccess tests concurrent access to the store.
func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Concurrent increments
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			store.Increment(ctx, "counter", 1)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Check final value
	value, err := store.Get(ctx, "counter")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)
}

// TestMemoryStore_ConcurrentIncrementWithExpiry tests concurrent IncrementWithExpiry.
func TestMemoryStore_ConcurrentIncrementWithExpiry(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Concurrent increments with expiry
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			store.IncrementWithExpiry(ctx, "counter", 1, time.Minute)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Check final value
	value, err := store.Get(ctx, "counter")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)
}

// TestMemoryStore_ConcurrentSetGet tests concurrent Set and Get operations.
func TestMemoryStore_ConcurrentSetGet(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent sets
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key"
			store.Set(ctx, key, int64(i), time.Minute)
		}(i)
	}

	// Concurrent gets
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Get(ctx, "key")
		}()
	}

	wg.Wait()
}

// TestMemoryStore_ConcurrentDelete tests concurrent Delete operations.
func TestMemoryStore_ConcurrentDelete(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set some keys
	for i := 0; i < 100; i++ {
		store.Set(ctx, "key", int64(i), time.Minute)
	}

	var wg sync.WaitGroup

	// Concurrent deletes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Delete(ctx, "key")
		}()
	}

	wg.Wait()
}

// ============================================================================
// Table-Driven Tests
// ============================================================================

// TestMemoryStore_TableDriven_Get tests Get with various scenarios.
func TestMemoryStore_TableDriven_Get(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(store *MemoryStore, ctx context.Context)
		key         string
		expected    int64
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name: "existing key with positive value",
			setup: func(store *MemoryStore, ctx context.Context) {
				store.Set(ctx, "positive", 42, time.Minute)
			},
			key:         "positive",
			expected:    42,
			expectError: false,
		},
		{
			name: "existing key with zero value",
			setup: func(store *MemoryStore, ctx context.Context) {
				store.Set(ctx, "zero", 0, time.Minute)
			},
			key:         "zero",
			expected:    0,
			expectError: false,
		},
		{
			name: "existing key with negative value",
			setup: func(store *MemoryStore, ctx context.Context) {
				store.Set(ctx, "negative", -10, time.Minute)
			},
			key:         "negative",
			expected:    -10,
			expectError: false,
		},
		{
			name:        "non-existent key",
			setup:       func(store *MemoryStore, ctx context.Context) {},
			key:         "nonexistent",
			expected:    0,
			expectError: true,
			errorCheck:  IsKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryStore()
			defer store.Close()

			ctx := context.Background()
			tt.setup(store, ctx)

			val, err := store.Get(ctx, tt.key)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCheck != nil {
					assert.True(t, tt.errorCheck(err), "error check failed for: %v", err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, val)
			}
		})
	}
}

// TestMemoryStore_TableDriven_Set tests Set with various scenarios.
func TestMemoryStore_TableDriven_Set(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      int64
		expiration time.Duration
	}{
		{
			name:       "positive value with expiration",
			key:        "set_pos",
			value:      100,
			expiration: time.Minute,
		},
		{
			name:       "zero value",
			key:        "set_zero",
			value:      0,
			expiration: time.Minute,
		},
		{
			name:       "negative value",
			key:        "set_neg",
			value:      -50,
			expiration: time.Minute,
		},
		{
			name:       "no expiration",
			key:        "set_no_exp",
			value:      200,
			expiration: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryStore()
			defer store.Close()

			ctx := context.Background()
			err := store.Set(ctx, tt.key, tt.value, tt.expiration)
			require.NoError(t, err)

			// Verify value was set
			val, err := store.Get(ctx, tt.key)
			require.NoError(t, err)
			assert.Equal(t, tt.value, val)
		})
	}
}

// TestMemoryStore_TableDriven_Increment tests Increment with various scenarios.
func TestMemoryStore_TableDriven_Increment(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(store *MemoryStore, ctx context.Context)
		key      string
		delta    int64
		expected int64
	}{
		{
			name:     "increment new key",
			setup:    func(store *MemoryStore, ctx context.Context) {},
			key:      "incr_new",
			delta:    5,
			expected: 5,
		},
		{
			name: "increment existing key",
			setup: func(store *MemoryStore, ctx context.Context) {
				store.Set(ctx, "incr_existing", 10, time.Minute)
			},
			key:      "incr_existing",
			delta:    3,
			expected: 13,
		},
		{
			name: "decrement existing key",
			setup: func(store *MemoryStore, ctx context.Context) {
				store.Set(ctx, "decr_existing", 10, time.Minute)
			},
			key:      "decr_existing",
			delta:    -4,
			expected: 6,
		},
		{
			name:     "increment by zero",
			setup:    func(store *MemoryStore, ctx context.Context) {},
			key:      "incr_zero",
			delta:    0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryStore()
			defer store.Close()

			ctx := context.Background()
			tt.setup(store, ctx)

			val, err := store.Increment(ctx, tt.key, tt.delta)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}

// ============================================================================
// Error Type Tests
// ============================================================================

// TestIsKeyNotFound tests the IsKeyNotFound helper function.
func TestIsKeyNotFound(t *testing.T) {
	err := &ErrKeyNotFound{Key: "test"}
	assert.True(t, IsKeyNotFound(err))
	assert.Equal(t, "key not found: test", err.Error())

	assert.False(t, IsKeyNotFound(nil))
	assert.False(t, IsKeyNotFound(context.Canceled))
}

// TestErrKeyNotFound_Error tests the Error method.
func TestErrKeyNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "simple key",
			key:      "test",
			expected: "key not found: test",
		},
		{
			name:     "empty key",
			key:      "",
			expected: "key not found: ",
		},
		{
			name:     "key with special characters",
			key:      "user/123/requests",
			expected: "key not found: user/123/requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ErrKeyNotFound{Key: tt.key}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestMemoryStore_LargeValue tests handling of large values.
func TestMemoryStore_LargeValue(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set a large value
	largeValue := int64(9223372036854775807) // Max int64
	err := store.Set(ctx, "large", largeValue, time.Minute)
	require.NoError(t, err)

	// Get the value
	value, err := store.Get(ctx, "large")
	require.NoError(t, err)
	assert.Equal(t, largeValue, value)
}

// TestMemoryStore_NegativeValue tests handling of negative values.
func TestMemoryStore_NegativeValue(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set a negative value
	negValue := int64(-9223372036854775808) // Min int64
	err := store.Set(ctx, "negative", negValue, time.Minute)
	require.NoError(t, err)

	// Get the value
	value, err := store.Get(ctx, "negative")
	require.NoError(t, err)
	assert.Equal(t, negValue, value)
}

// TestMemoryStore_EmptyKey tests handling of empty key.
func TestMemoryStore_EmptyKey(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Set with empty key
	err := store.Set(ctx, "", 100, time.Minute)
	require.NoError(t, err)

	// Get with empty key
	value, err := store.Get(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, int64(100), value)
}

// TestMemoryStore_SpecialCharacterKey tests handling of keys with special characters.
func TestMemoryStore_SpecialCharacterKey(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	specialKeys := []string{
		"key with spaces",
		"key/with/slashes",
		"key:with:colons",
		"key.with.dots",
		"key-with-dashes",
		"key_with_underscores",
		"key@with@at",
		"key#with#hash",
	}

	for _, key := range specialKeys {
		t.Run(key, func(t *testing.T) {
			err := store.Set(ctx, key, 100, time.Minute)
			require.NoError(t, err)

			value, err := store.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, int64(100), value)
		})
	}
}

// TestMemoryStore_Increment_ConcurrentRace tests concurrent increment race condition.
// This test attempts to trigger the LoadOrStore race condition path.
func TestMemoryStore_Increment_ConcurrentRace(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Run many concurrent increments on the same key to trigger race conditions
	var wg sync.WaitGroup
	numGoroutines := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Increment(ctx, "race_key", 1)
		}()
	}

	wg.Wait()

	// Final value should be numGoroutines
	value, err := store.Get(ctx, "race_key")
	require.NoError(t, err)
	assert.Equal(t, int64(numGoroutines), value)
}

// TestMemoryStore_IncrementWithExpiry_ConcurrentRace tests concurrent IncrementWithExpiry race condition.
func TestMemoryStore_IncrementWithExpiry_ConcurrentRace(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ctx := context.Background()

	// Run many concurrent increments on the same key to trigger race conditions
	var wg sync.WaitGroup
	numGoroutines := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.IncrementWithExpiry(ctx, "race_key", 1, time.Minute)
		}()
	}

	wg.Wait()

	// Final value should be numGoroutines
	value, err := store.Get(ctx, "race_key")
	require.NoError(t, err)
	assert.Equal(t, int64(numGoroutines), value)
}

// TestMemoryStore_Increment_CASRetryOnExpiredKey tests CAS retry when key expires during increment.
func TestMemoryStore_Increment_CASRetryOnExpiredKey(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set a key with very short expiration
	err := store.Set(ctx, "expiring", 100, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// Increment should handle the expired key and create a new one
	value, err := store.Increment(ctx, "expiring", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value)
}

// TestMemoryStore_IncrementWithExpiry_CASRetryOnExpiredKey tests CAS retry when key expires.
func TestMemoryStore_IncrementWithExpiry_CASRetryOnExpiredKey(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set a key with very short expiration
	err := store.Set(ctx, "expiring", 100, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// IncrementWithExpiry should handle the expired key and reset it
	value, err := store.IncrementWithExpiry(ctx, "expiring", 5, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(5), value)
}

// TestMemoryStore_Increment_PreservesExpiration tests that Increment preserves expiration.
func TestMemoryStore_Increment_PreservesExpiration(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set a key with expiration
	err := store.Set(ctx, "key", 100, 100*time.Millisecond)
	require.NoError(t, err)

	// Increment should preserve the expiration
	value, err := store.Increment(ctx, "key", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(105), value)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Key should be expired
	_, err = store.Get(ctx, "key")
	assert.True(t, IsKeyNotFound(err))
}

// TestMemoryStore_IncrementWithExpiry_PreservesOriginalExpiration tests that IncrementWithExpiry
// preserves the original expiration for existing keys.
func TestMemoryStore_IncrementWithExpiry_PreservesOriginalExpiration(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// First increment sets expiration
	_, err := store.IncrementWithExpiry(ctx, "key", 1, 100*time.Millisecond)
	require.NoError(t, err)

	// Second increment should preserve original expiration
	value, err := store.IncrementWithExpiry(ctx, "key", 1, time.Hour) // Different expiration
	require.NoError(t, err)
	assert.Equal(t, int64(2), value)

	// Wait for original expiration
	time.Sleep(150 * time.Millisecond)

	// Key should be expired (using original 100ms, not 1 hour)
	_, err = store.Get(ctx, "key")
	assert.True(t, IsKeyNotFound(err))
}

// TestMemoryStore_CleanupExpired_MixedEntries tests cleanup with mixed expired and non-expired entries.
func TestMemoryStore_CleanupExpired_MixedEntries(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set entries with different expirations
	err := store.Set(ctx, "expired1", 1, 1*time.Millisecond)
	require.NoError(t, err)
	err = store.Set(ctx, "valid1", 2, time.Hour)
	require.NoError(t, err)
	err = store.Set(ctx, "expired2", 3, 1*time.Millisecond)
	require.NoError(t, err)
	err = store.Set(ctx, "valid2", 4, time.Hour)
	require.NoError(t, err)
	err = store.Set(ctx, "permanent", 5, 0) // No expiration
	require.NoError(t, err)

	// Wait for some entries to expire
	time.Sleep(10 * time.Millisecond)

	// Trigger cleanup
	store.cleanupExpired()

	// Check results
	_, err = store.Get(ctx, "expired1")
	assert.True(t, IsKeyNotFound(err))
	_, err = store.Get(ctx, "expired2")
	assert.True(t, IsKeyNotFound(err))

	val, err := store.Get(ctx, "valid1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), val)

	val, err = store.Get(ctx, "valid2")
	require.NoError(t, err)
	assert.Equal(t, int64(4), val)

	val, err = store.Get(ctx, "permanent")
	require.NoError(t, err)
	assert.Equal(t, int64(5), val)
}

// TestMemoryStore_Size_AfterExpiration tests Size after entries expire.
func TestMemoryStore_Size_AfterExpiration(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(time.Hour)
	defer store.Close()

	ctx := context.Background()

	// Set entries
	store.Set(ctx, "key1", 1, 1*time.Millisecond)
	store.Set(ctx, "key2", 2, time.Hour)
	store.Set(ctx, "key3", 3, 1*time.Millisecond)

	// Size includes all entries (even expired ones until cleanup)
	assert.Equal(t, 3, store.Size())

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Trigger cleanup
	store.cleanupExpired()

	// Size should only include non-expired entries
	assert.Equal(t, 1, store.Size())
}

// TestMemoryStore_Close_StopsCleanup tests that Close stops the cleanup goroutine.
func TestMemoryStore_Close_StopsCleanup(t *testing.T) {
	store := NewMemoryStoreWithCleanupInterval(10 * time.Millisecond)

	// Close the store
	err := store.Close()
	require.NoError(t, err)

	// Wait a bit to ensure cleanup goroutine has stopped
	time.Sleep(50 * time.Millisecond)

	// Store should be closed
	assert.True(t, store.closed)
}
