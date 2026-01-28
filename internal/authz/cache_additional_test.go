package authz

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockCacheForAuthz implements cache.Cache for testing.
type mockCacheForAuthz struct {
	data      map[string][]byte
	mu        sync.RWMutex
	getErr    error
	setErr    error
	deleteErr error
}

func newMockCacheForAuthz() *mockCacheForAuthz {
	return &mockCacheForAuthz{
		data: make(map[string][]byte),
	}
}

func (m *mockCacheForAuthz) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getErr != nil {
		return nil, m.getErr
	}

	data, ok := m.data[key]
	if !ok {
		return nil, cache.ErrCacheMiss
	}
	return data, nil
}

func (m *mockCacheForAuthz) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.setErr != nil {
		return m.setErr
	}

	m.data[key] = value
	return nil
}

func (m *mockCacheForAuthz) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteErr != nil {
		return m.deleteErr
	}

	delete(m.data, key)
	return nil
}

func (m *mockCacheForAuthz) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.data[key]
	return ok, nil
}

func (m *mockCacheForAuthz) Close() error {
	return nil
}

// TestExternalDecisionCache_GetAndSet tests the external decision cache get and set.
func TestExternalDecisionCache_GetAndSet(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
		Reason:  "test",
		Policy:  "test-policy",
	}

	// Set
	c.Set(context.Background(), key, decision)

	// Get
	result, ok := c.Get(context.Background(), key)
	require.True(t, ok)
	assert.True(t, result.Allowed)
	assert.Equal(t, "test", result.Reason)
	assert.Equal(t, "test-policy", result.Policy)
}

// TestExternalDecisionCache_GetCacheMiss tests cache miss scenario.
func TestExternalDecisionCache_GetCacheMiss(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// TestExternalDecisionCache_GetError tests error handling during get.
func TestExternalDecisionCache_GetError(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	mockC.getErr = errors.New("cache error")
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// TestExternalDecisionCache_GetInvalidJSON tests invalid JSON handling.
func TestExternalDecisionCache_GetInvalidJSON(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Set invalid JSON directly
	cacheKey := "authz:" + key.String()
	mockC.data[cacheKey] = []byte("invalid json")

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// TestExternalDecisionCache_GetExpired tests expired entry handling.
func TestExternalDecisionCache_GetExpired(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Set expired decision directly
	decision := &CachedDecision{
		Allowed:   true,
		CachedAt:  time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	}
	data, _ := json.Marshal(decision)
	cacheKey := "authz:" + key.String()
	mockC.data[cacheKey] = data

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// TestExternalDecisionCache_SetError tests error handling during set.
func TestExternalDecisionCache_SetError(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	mockC.setErr = errors.New("set error")
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
	}

	// Should not panic
	c.Set(context.Background(), key, decision)
}

// TestExternalDecisionCache_Delete tests delete functionality.
func TestExternalDecisionCache_Delete(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
	}

	c.Set(context.Background(), key, decision)
	c.Delete(context.Background(), key)

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// TestExternalDecisionCache_DeleteError tests error handling during delete.
func TestExternalDecisionCache_DeleteError(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	mockC.deleteErr = errors.New("delete error")
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Should not panic
	c.Delete(context.Background(), key)
}

// TestExternalDecisionCache_Clear tests clear functionality.
func TestExternalDecisionCache_Clear(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	// Should not panic (no-op)
	c.Clear(context.Background())
}

// TestExternalDecisionCache_Close tests close functionality.
func TestExternalDecisionCache_Close(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute)

	err := c.Close()
	assert.NoError(t, err)
}

// TestExternalDecisionCache_WithOptions tests option functions.
func TestExternalDecisionCache_WithOptions(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	metrics := newNoopMetrics()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
		WithExternalCacheMetrics(metrics),
		WithExternalCachePrefix("custom:"),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
	}

	c.Set(context.Background(), key, decision)

	// Verify custom prefix was used
	cacheKey := "custom:" + key.String()
	_, ok := mockC.data[cacheKey]
	assert.True(t, ok)
}

// TestMemoryDecisionCache_CleanupLoop tests the cleanup loop.
func TestMemoryDecisionCache_CleanupLoop(t *testing.T) {
	t.Parallel()

	c := NewMemoryDecisionCache(10*time.Millisecond, 100).(*memoryDecisionCache)
	defer c.Close()

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
	}

	c.Set(context.Background(), key, decision)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Manually trigger cleanup
	c.cleanup()

	// Verify entry was removed
	c.mu.RLock()
	assert.Empty(t, c.entries)
	c.mu.RUnlock()
}

// TestMemoryDecisionCache_EvictionWithExpired tests eviction with expired entries.
func TestMemoryDecisionCache_EvictionWithExpired(t *testing.T) {
	t.Parallel()

	c := NewMemoryDecisionCache(10*time.Millisecond, 2).(*memoryDecisionCache)
	defer c.Close()

	// Add first entry
	key1 := &CacheKey{Subject: "user1", Resource: "/api/1", Action: "GET"}
	c.Set(context.Background(), key1, &CachedDecision{Allowed: true})

	// Wait for first entry to expire
	time.Sleep(15 * time.Millisecond)

	// Add second entry
	key2 := &CacheKey{Subject: "user2", Resource: "/api/2", Action: "GET"}
	c.Set(context.Background(), key2, &CachedDecision{Allowed: true})

	// Add third entry - should evict expired first
	key3 := &CacheKey{Subject: "user3", Resource: "/api/3", Action: "GET"}
	c.Set(context.Background(), key3, &CachedDecision{Allowed: true})

	// Verify entries
	c.mu.RLock()
	assert.Len(t, c.entries, 2)
	c.mu.RUnlock()
}

// TestMemoryDecisionCache_EvictionOldest tests eviction of oldest entry.
func TestMemoryDecisionCache_EvictionOldest(t *testing.T) {
	t.Parallel()

	c := NewMemoryDecisionCache(5*time.Minute, 2).(*memoryDecisionCache)
	defer c.Close()

	// Add first entry
	key1 := &CacheKey{Subject: "user1", Resource: "/api/1", Action: "GET"}
	c.Set(context.Background(), key1, &CachedDecision{Allowed: true})

	// Small delay to ensure different timestamps
	time.Sleep(time.Millisecond)

	// Add second entry
	key2 := &CacheKey{Subject: "user2", Resource: "/api/2", Action: "GET"}
	c.Set(context.Background(), key2, &CachedDecision{Allowed: true})

	// Small delay
	time.Sleep(time.Millisecond)

	// Add third entry - should evict oldest
	key3 := &CacheKey{Subject: "user3", Resource: "/api/3", Action: "GET"}
	c.Set(context.Background(), key3, &CachedDecision{Allowed: true})

	// Verify only 2 entries remain
	c.mu.RLock()
	assert.Len(t, c.entries, 2)
	c.mu.RUnlock()

	// First entry should be evicted
	_, ok := c.Get(context.Background(), key1)
	assert.False(t, ok)
}

// TestMemoryDecisionCache_WithMetrics tests metrics recording.
func TestMemoryDecisionCache_WithMetrics(t *testing.T) {
	t.Parallel()

	metrics := newNoopMetrics()
	c := NewMemoryDecisionCache(5*time.Minute, 100,
		WithMemoryCacheLogger(observability.NopLogger()),
		WithMemoryCacheMetrics(metrics),
	)
	defer c.Close()

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Cache miss
	_, ok := c.Get(context.Background(), key)
	assert.False(t, ok)

	// Set and get (cache hit)
	c.Set(context.Background(), key, &CachedDecision{Allowed: true})
	_, ok = c.Get(context.Background(), key)
	assert.True(t, ok)
}

// TestMemoryDecisionCache_ConcurrentOperations tests concurrent operations.
func TestMemoryDecisionCache_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	c := NewMemoryDecisionCache(5*time.Minute, 1000)
	defer c.Close()

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := &CacheKey{
				Subject:  "user" + string(rune(id)),
				Resource: "/api/users",
				Action:   "GET",
			}

			for j := 0; j < 100; j++ {
				c.Set(context.Background(), key, &CachedDecision{Allowed: true})
				c.Get(context.Background(), key)
				c.Delete(context.Background(), key)
			}
		}(i)
	}

	wg.Wait()
}
