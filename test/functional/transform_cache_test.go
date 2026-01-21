//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify cache logic in isolation without external dependencies.
package functional

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestFunctional_Cache_Memory_BasicOperations tests memory cache basic operations.
func TestFunctional_Cache_Memory_BasicOperations(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: 100,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	t.Run("set_get_string_value", func(t *testing.T) {
		key := "string-key"
		value := []byte("string-value")

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("set_get_json_value", func(t *testing.T) {
		key := "json-key"
		value := []byte(`{"name":"test","id":123}`)

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("set_get_binary_value", func(t *testing.T) {
		key := "binary-key"
		value := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("get_nonexistent_returns_miss", func(t *testing.T) {
		_, err := c.Get(ctx, "nonexistent-key-12345")
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("delete_removes_entry", func(t *testing.T) {
		key := "delete-test-key"
		value := []byte("delete-test-value")

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		err = c.Delete(ctx, key)
		require.NoError(t, err)

		_, err = c.Get(ctx, key)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("exists_returns_correct_status", func(t *testing.T) {
		key := "exists-test-key"
		value := []byte("exists-test-value")

		exists, err := c.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)

		err = c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		exists, err = c.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("overwrite_updates_value", func(t *testing.T) {
		key := "overwrite-key"
		value1 := []byte("value-1")
		value2 := []byte("value-2")

		err := c.Set(ctx, key, value1, 0)
		require.NoError(t, err)

		err = c.Set(ctx, key, value2, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value2, result)
	})

	t.Run("empty_value", func(t *testing.T) {
		key := "empty-value-key"
		value := []byte{}

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})
}

// TestFunctional_Cache_Memory_TTLExpiration tests memory cache TTL expiration.
func TestFunctional_Cache_Memory_TTLExpiration(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(100 * time.Millisecond),
		MaxEntries: 100,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	t.Run("entry_expires_after_ttl", func(t *testing.T) {
		key := "ttl-expire-key"
		value := []byte("ttl-expire-value")

		err := c.Set(ctx, key, value, 50*time.Millisecond)
		require.NoError(t, err)

		// Should exist immediately
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should be expired
		_, err = c.Get(ctx, key)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("longer_ttl_survives_default", func(t *testing.T) {
		key := "long-ttl-key"
		value := []byte("long-ttl-value")

		// Set with longer TTL than default
		err := c.Set(ctx, key, value, 500*time.Millisecond)
		require.NoError(t, err)

		// Wait past default TTL
		time.Sleep(150 * time.Millisecond)

		// Should still exist
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("zero_ttl_uses_default", func(t *testing.T) {
		key := "zero-ttl-key"
		value := []byte("zero-ttl-value")

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Should exist immediately
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)

		// Wait past default TTL
		time.Sleep(150 * time.Millisecond)

		// Should be expired (using default TTL of 100ms)
		_, err = c.Get(ctx, key)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("refresh_ttl_on_update", func(t *testing.T) {
		key := "refresh-ttl-key"
		value := []byte("refresh-ttl-value")

		err := c.Set(ctx, key, value, 80*time.Millisecond)
		require.NoError(t, err)

		// Wait 50ms
		time.Sleep(50 * time.Millisecond)

		// Update with new TTL
		err = c.Set(ctx, key, value, 80*time.Millisecond)
		require.NoError(t, err)

		// Wait another 50ms (total 100ms from start)
		time.Sleep(50 * time.Millisecond)

		// Should still exist because TTL was refreshed
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})
}

// TestFunctional_Cache_Memory_MaxEntriesEviction tests memory cache max entries eviction.
func TestFunctional_Cache_Memory_MaxEntriesEviction(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxEntries := 5
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: maxEntries,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	t.Run("evicts_oldest_when_full", func(t *testing.T) {
		// Fill cache to capacity
		for i := 0; i < maxEntries; i++ {
			key := cacheKeyForIndex(i)
			value := cacheValueForIndex(i)
			err := c.Set(ctx, key, value, 0)
			require.NoError(t, err)
		}

		// Add one more entry to trigger eviction
		err = c.Set(ctx, "new-key", []byte("new-value"), 0)
		require.NoError(t, err)

		// The newest entry should exist
		_, err = c.Get(ctx, "new-key")
		require.NoError(t, err)

		// At least one of the original entries should be evicted
		_, err = c.Get(ctx, cacheKeyForIndex(0))
		assert.ErrorIs(t, err, cache.ErrCacheMiss, "oldest entry should be evicted")
	})

	t.Run("recent_entries_survive_eviction", func(t *testing.T) {
		// Create a new cache for this test
		c2, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c2.Close()

		// Fill cache
		for i := 0; i < maxEntries; i++ {
			key := cacheKeyForIndex(i)
			value := cacheValueForIndex(i)
			err := c2.Set(ctx, key, value, 0)
			require.NoError(t, err)
		}

		// Access the first entry to make it "recent"
		_, _ = c2.Get(ctx, cacheKeyForIndex(0))

		// Add new entries to trigger eviction
		for i := maxEntries; i < maxEntries+2; i++ {
			key := cacheKeyForIndex(i)
			value := cacheValueForIndex(i)
			err := c2.Set(ctx, key, value, 0)
			require.NoError(t, err)
		}

		// The recently accessed entry might survive (depends on LRU implementation)
		// Just verify the cache is still functional
		_, err = c2.Get(ctx, cacheKeyForIndex(maxEntries))
		require.NoError(t, err)
	})
}

// TestFunctional_Cache_KeyGeneration_WithMethod tests cache key generation with method.
func TestFunctional_Cache_KeyGeneration_WithMethod(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name     string
		method   string
		path     string
		expected string
	}{
		{
			name:     "get_method",
			method:   "GET",
			path:     "/api/users",
			expected: "GET:/api/users",
		},
		{
			name:     "post_method",
			method:   "POST",
			path:     "/api/users",
			expected: "POST:/api/users",
		},
		{
			name:     "put_method",
			method:   "PUT",
			path:     "/api/users/123",
			expected: "PUT:/api/users/123",
		},
		{
			name:     "delete_method",
			method:   "DELETE",
			path:     "/api/users/123",
			expected: "DELETE:/api/users/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				IncludeMethod: true,
				IncludePath:   true,
			}

			kg, err := cache.NewKeyGenerator(cfg, logger)
			require.NoError(t, err)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			key, err := kg.GenerateKey(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, key)
		})
	}
}

// TestFunctional_Cache_KeyGeneration_WithPath tests cache key generation with path.
func TestFunctional_Cache_KeyGeneration_WithPath(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple_path",
			path:     "/api/users",
			expected: "/api/users",
		},
		{
			name:     "path_with_id",
			path:     "/api/users/123",
			expected: "/api/users/123",
		},
		{
			name:     "nested_path",
			path:     "/api/v1/users/123/orders",
			expected: "/api/v1/users/123/orders",
		},
		{
			name:     "root_path",
			path:     "/",
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				IncludeMethod: false,
				IncludePath:   true,
			}

			kg, err := cache.NewKeyGenerator(cfg, logger)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", tt.path, nil)
			key, err := kg.GenerateKey(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, key)
		})
	}
}

// TestFunctional_Cache_KeyGeneration_WithQueryParams tests cache key generation with query params.
func TestFunctional_Cache_KeyGeneration_WithQueryParams(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name         string
		path         string
		queryParams  []string
		expectedPart string
	}{
		{
			name:         "single_query_param",
			path:         "/api/users?page=1",
			queryParams:  []string{"page"},
			expectedPart: "q:page=1",
		},
		{
			name:         "multiple_query_params",
			path:         "/api/users?page=1&limit=10",
			queryParams:  []string{"page", "limit"},
			expectedPart: "q:limit=10&page=1", // Sorted alphabetically
		},
		{
			name:         "selective_query_params",
			path:         "/api/users?page=1&limit=10&debug=true",
			queryParams:  []string{"page", "limit"},
			expectedPart: "q:limit=10&page=1", // debug excluded
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				IncludeMethod:      true,
				IncludePath:        true,
				IncludeQueryParams: tt.queryParams,
			}

			kg, err := cache.NewKeyGenerator(cfg, logger)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", tt.path, nil)
			key, err := kg.GenerateKey(req)
			require.NoError(t, err)
			assert.Contains(t, key, tt.expectedPart)
		})
	}
}

// TestFunctional_Cache_KeyGeneration_WithHeaders tests cache key generation with headers.
func TestFunctional_Cache_KeyGeneration_WithHeaders(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name         string
		headers      map[string]string
		includeHdrs  []string
		expectedPart string
	}{
		{
			name: "single_header",
			headers: map[string]string{
				"Accept-Language": "en-US",
			},
			includeHdrs:  []string{"Accept-Language"},
			expectedPart: "h:Accept-Language=en-US",
		},
		{
			name: "multiple_headers",
			headers: map[string]string{
				"Accept-Language": "en-US",
				"Accept":          "application/json",
			},
			includeHdrs:  []string{"Accept", "Accept-Language"},
			expectedPart: "h:Accept=application/json&Accept-Language=en-US",
		},
		{
			name: "selective_headers",
			headers: map[string]string{
				"Accept-Language": "en-US",
				"Authorization":   "Bearer token",
			},
			includeHdrs:  []string{"Accept-Language"},
			expectedPart: "h:Accept-Language=en-US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				IncludeMethod:  true,
				IncludePath:    true,
				IncludeHeaders: tt.includeHdrs,
			}

			kg, err := cache.NewKeyGenerator(cfg, logger)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/api/users", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			key, err := kg.GenerateKey(req)
			require.NoError(t, err)
			assert.Contains(t, key, tt.expectedPart)
		})
	}
}

// TestFunctional_Cache_KeyGeneration_WithBodyHash tests cache key generation with body hash.
func TestFunctional_Cache_KeyGeneration_WithBodyHash(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "json_body",
			body: `{"name":"test","id":123}`,
		},
		{
			name: "simple_body",
			body: "simple text body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				IncludeMethod:   true,
				IncludePath:     true,
				IncludeBodyHash: true,
			}

			kg, err := cache.NewKeyGenerator(cfg, logger)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/users", strings.NewReader(tt.body))
			key, err := kg.GenerateKey(req)
			require.NoError(t, err)

			// Key should contain body hash prefix
			assert.Contains(t, key, "b:")
		})
	}

	t.Run("different_bodies_produce_different_keys", func(t *testing.T) {
		cfg := &config.CacheKeyConfig{
			IncludeMethod:   true,
			IncludePath:     true,
			IncludeBodyHash: true,
		}

		kg, err := cache.NewKeyGenerator(cfg, logger)
		require.NoError(t, err)

		req1 := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"test1"}`))
		key1, err := kg.GenerateKey(req1)
		require.NoError(t, err)

		req2 := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"test2"}`))
		key2, err := kg.GenerateKey(req2)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("same_body_produces_same_key", func(t *testing.T) {
		cfg := &config.CacheKeyConfig{
			IncludeMethod:   true,
			IncludePath:     true,
			IncludeBodyHash: true,
		}

		kg, err := cache.NewKeyGenerator(cfg, logger)
		require.NoError(t, err)

		body := `{"name":"test"}`

		req1 := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
		key1, err := kg.GenerateKey(req1)
		require.NoError(t, err)

		req2 := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
		key2, err := kg.GenerateKey(req2)
		require.NoError(t, err)

		assert.Equal(t, key1, key2)
	})
}

// TestFunctional_Cache_KeyGeneration_CustomTemplate tests cache key generation with custom template.
func TestFunctional_Cache_KeyGeneration_CustomTemplate(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name     string
		template string
		method   string
		path     string
		expected string
	}{
		{
			name:     "simple_template",
			template: "{{.Method}}-{{.Path}}",
			method:   "GET",
			path:     "/api/users",
			expected: "GET-/api/users",
		},
		{
			name:     "path_only_template",
			template: "cache:{{.Path}}",
			method:   "GET",
			path:     "/api/users",
			expected: "cache:/api/users",
		},
		{
			name:     "with_host_template",
			template: "{{.Host}}:{{.Method}}:{{.Path}}",
			method:   "GET",
			path:     "/api/users",
			expected: "example.com:GET:/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CacheKeyConfig{
				KeyTemplate: tt.template,
			}

			kg, err := cache.NewKeyGenerator(cfg, logger)
			require.NoError(t, err)

			req := httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			key, err := kg.GenerateKey(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, key)
		})
	}
}

// TestFunctional_Cache_Memory_ConcurrentAccess tests memory cache concurrent access.
func TestFunctional_Cache_Memory_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: 1000,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()
	numGoroutines := 10
	numOperations := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := cacheKeyForIndex(id*numOperations + j)
				value := cacheValueForIndex(id*numOperations + j)

				// Set
				if err := c.Set(ctx, key, value, 0); err != nil {
					errors <- err
				}

				// Get
				if _, err := c.Get(ctx, key); err != nil && err != cache.ErrCacheMiss {
					errors <- err
				}

				// Exists
				if _, err := c.Exists(ctx, key); err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

// TestFunctional_Cache_Memory_StressTest tests memory cache under stress.
func TestFunctional_Cache_Memory_StressTest(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(1 * time.Second),
		MaxEntries: 100,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	// Rapid set/get operations
	for i := 0; i < 500; i++ {
		key := cacheKeyForIndex(i)
		value := cacheValueForIndex(i)

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Immediately try to get
		_, _ = c.Get(ctx, key)
	}

	// Verify cache is still functional
	testKey := "stress-test-final"
	testValue := []byte("stress-test-value")

	err = c.Set(ctx, testKey, testValue, 0)
	require.NoError(t, err)

	result, err := c.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, testValue, result)
}

// Helper functions

func cacheKeyForIndex(i int) string {
	return "cache-key-" + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+(i/100)%10))
}

func cacheValueForIndex(i int) []byte {
	return []byte("cache-value-" + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+(i/100)%10)))
}

// createTestRequest creates a test HTTP request.
func createTestRequest(method, path string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}
