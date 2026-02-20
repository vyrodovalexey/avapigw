package middleware

import (
	"bytes"
	"context"
	"encoding/json"
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

// fakeCache is a simple in-memory cache implementation for testing.
type fakeCache struct {
	data map[string][]byte
	mu   sync.Mutex
}

func newFakeCache() *fakeCache {
	return &fakeCache{data: make(map[string][]byte)}
}

func (f *fakeCache) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.data[key]; ok {
		return v, nil
	}
	return nil, cache.ErrCacheMiss
}

func (f *fakeCache) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeCache) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}

func (f *fakeCache) Exists(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[key]
	return ok, nil
}

func (f *fakeCache) Close() error { return nil }

// helper to create a simple JSON backend handler.
func jsonBackendHandler(statusCode int, body map[string]interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(body)
	})
}

func TestCacheFromConfig_NilCache(t *testing.T) {
	t.Parallel()

	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	mw := CacheFromConfig(nil, cfg, nil)

	// Should be passthrough
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCacheFromConfig_NilConfig(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	mw := CacheFromConfig(fc, nil, nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCacheFromConfig_Disabled(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: false}
	mw := CacheFromConfig(fc, cfg, nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCacheFromConfig_DefaultTTL(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: 0} // zero TTL should default to 60s
	logger := observability.NopLogger()

	backend := jsonBackendHandler(http.StatusOK, map[string]interface{}{"key": "value"})
	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// First request - cache miss
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response was cached
	fc.mu.Lock()
	assert.NotEmpty(t, fc.data)
	fc.mu.Unlock()
}

func TestCacheFromConfig_CacheHit(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"hello"}`))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// First request - cache miss
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, 1, callCount)

	// Second request - cache hit
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, 1, callCount) // backend not called again
	assert.Equal(t, "HIT", rec2.Header().Get("X-Cache"))
}

func TestCacheFromConfig_CacheMiss(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	backend := jsonBackendHandler(http.StatusOK, map[string]interface{}{"result": "ok"})
	handler := CacheFromConfig(fc, cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEqual(t, "HIT", rec.Header().Get("X-Cache"))
}

func TestCacheFromConfig_OnlyGETCached(t *testing.T) {
	t.Parallel()

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			fc := newFakeCache()
			cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
			logger := observability.NopLogger()

			callCount := 0
			backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				callCount++
				w.WriteHeader(http.StatusOK)
			})

			handler := CacheFromConfig(fc, cfg, logger)(backend)

			// First request
			rec1 := httptest.NewRecorder()
			req1 := httptest.NewRequest(method, "/api/data", nil)
			handler.ServeHTTP(rec1, req1)

			// Second request - should still call backend
			rec2 := httptest.NewRecorder()
			req2 := httptest.NewRequest(method, "/api/data", nil)
			handler.ServeHTTP(rec2, req2)

			assert.Equal(t, 2, callCount, "non-GET method %s should not be cached", method)
		})
	}
}

func TestCacheFromConfig_Non2xxNotCached(t *testing.T) {
	t.Parallel()

	statusCodes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	}

	for _, code := range statusCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()

			fc := newFakeCache()
			cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
			logger := observability.NopLogger()

			callCount := 0
			backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				callCount++
				w.WriteHeader(code)
				_, _ = w.Write([]byte("error"))
			})

			handler := CacheFromConfig(fc, cfg, logger)(backend)

			// First request
			rec1 := httptest.NewRecorder()
			req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			handler.ServeHTTP(rec1, req1)

			// Second request - should still call backend
			rec2 := httptest.NewRecorder()
			req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			handler.ServeHTTP(rec2, req2)

			assert.Equal(t, 2, callCount, "non-2xx status %d should not be cached", code)
		})
	}
}

func TestCacheFromConfig_CacheControlNoStore(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// Request with Cache-Control: no-store
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Cache-Control", "no-store")
	handler.ServeHTTP(rec, req)

	// Second request with no-store
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req2.Header.Set("Cache-Control", "no-store")
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, 2, callCount, "no-store should bypass cache")
}

func TestCacheFromConfig_CacheControlNoCache(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// Request with Cache-Control: no-cache
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Cache-Control", "no-cache")
	handler.ServeHTTP(rec, req)

	// Second request with no-cache
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req2.Header.Set("Cache-Control", "no-cache")
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, 2, callCount, "no-cache should bypass cache")
}

func TestCacheFromConfig_LargeBodyNotCached(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	// Create a body larger than maxCacheBodySize (10MB)
	largeBody := strings.Repeat("x", maxCacheBodySize+1)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeBody))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// First request
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/large", nil)
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request - should still call backend because body was too large
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/large", nil)
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, 2, callCount, "large body should not be cached")
}

func TestCacheResponseRecorder_WriteHeaderDuplicate(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	crr := &cacheResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	// First WriteHeader should set the status
	crr.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, crr.statusCode)
	assert.True(t, crr.headerWritten)

	// Second WriteHeader should be suppressed
	crr.WriteHeader(http.StatusBadRequest)
	assert.Equal(t, http.StatusCreated, crr.statusCode) // unchanged
}

func TestCacheResponseRecorder_WriteImplicit200(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	crr := &cacheResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	// Write without calling WriteHeader first
	n, err := crr.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.True(t, crr.headerWritten)
	assert.Equal(t, http.StatusOK, crr.statusCode)
}

func TestCacheResponseRecorder_WriteBufferExceeded(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	crr := &cacheResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	// Write data that exceeds maxCacheBodySize
	bigChunk := make([]byte, maxCacheBodySize+1)
	for i := range bigChunk {
		bigChunk[i] = 'a'
	}

	n, err := crr.Write(bigChunk)
	require.NoError(t, err)
	assert.Equal(t, len(bigChunk), n)
	assert.True(t, crr.bufferExceeded)
	assert.Equal(t, 0, crr.body.Len()) // buffer should be reset
}

func TestBuildCacheKey_SimplePath(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	key := buildCacheKey(req)
	assert.Equal(t, "GET:/api/users", key)
}

func TestBuildCacheKey_WithQueryParams(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/users?page=1&limit=10", nil)
	key := buildCacheKey(req)
	assert.Equal(t, "GET:/api/users?limit=10&page=1", key)
}

func TestBuildCacheKey_QueryParamsSorted(t *testing.T) {
	t.Parallel()

	req1 := httptest.NewRequest(http.MethodGet, "/api/users?b=2&a=1", nil)
	req2 := httptest.NewRequest(http.MethodGet, "/api/users?a=1&b=2", nil)

	key1 := buildCacheKey(req1)
	key2 := buildCacheKey(req2)
	assert.Equal(t, key1, key2, "query params should be sorted for deterministic keys")
}

func TestBuildCacheKey_MultipleValuesForSameParam(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/users?tag=go&tag=rust", nil)
	key := buildCacheKey(req)
	assert.Contains(t, key, "tag=go")
	assert.Contains(t, key, "tag=rust")
}

func TestBuildCacheKey_NoQueryParams(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	key := buildCacheKey(req)
	assert.Equal(t, "GET:/api/health", key)
	assert.NotContains(t, key, "?")
}

func TestBuildCacheKey_DifferentPaths(t *testing.T) {
	t.Parallel()

	req1 := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req2 := httptest.NewRequest(http.MethodGet, "/api/posts", nil)

	key1 := buildCacheKey(req1)
	key2 := buildCacheKey(req2)
	assert.NotEqual(t, key1, key2)
}

func TestCloneHeaders(t *testing.T) {
	t.Parallel()

	original := http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token"},
		"Accept":        {"text/html", "application/json"},
	}

	cloned := cloneHeaders(original)

	assert.Equal(t, len(original), len(cloned))
	for k, v := range original {
		assert.Equal(t, v, cloned[k])
	}

	// Verify deep copy - modifying clone should not affect original
	cloned["Content-Type"] = []string{"text/plain"}
	assert.Equal(t, "application/json", original.Get("Content-Type"))
}

func TestCacheFromConfig_NilLogger(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}

	// Should not panic with nil logger
	backend := jsonBackendHandler(http.StatusOK, map[string]interface{}{"ok": true})
	handler := CacheFromConfig(fc, cfg, nil)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCacheFromConfig_CacheHitPreservesHeaders(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"test"}`))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// First request - populate cache
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec1, req1)

	// Second request - cache hit
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, "HIT", rec2.Header().Get("X-Cache"))
	assert.Equal(t, "application/json", rec2.Header().Get("Content-Type"))
	assert.Equal(t, "custom-value", rec2.Header().Get("X-Custom-Header"))
}

func TestCacheFromConfig_2xxStatusesCached(t *testing.T) {
	t.Parallel()

	statusCodes := []int{http.StatusOK, http.StatusCreated, http.StatusAccepted}

	for _, code := range statusCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()

			fc := newFakeCache()
			cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
			logger := observability.NopLogger()

			callCount := 0
			backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				callCount++
				w.WriteHeader(code)
				_, _ = w.Write([]byte("ok"))
			})

			handler := CacheFromConfig(fc, cfg, logger)(backend)

			// First request
			rec1 := httptest.NewRecorder()
			req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			handler.ServeHTTP(rec1, req1)

			// Second request
			rec2 := httptest.NewRecorder()
			req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			handler.ServeHTTP(rec2, req2)

			assert.Equal(t, 1, callCount, "2xx status %d should be cached", code)
		})
	}
}

func TestCacheFromConfig_300StatusNotCached(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Location", "/new-location")
		w.WriteHeader(http.StatusMultipleChoices)
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec1, req1)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, 2, callCount, "300 status should not be cached")
}

func TestCacheResponseRecorder_Flush(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	crr := &cacheResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	// Should not panic
	crr.Flush()
}

func TestCacheResponseRecorder_Hijack(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	crr := &cacheResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	// httptest.ResponseRecorder does not implement http.Hijacker
	_, _, err := crr.Hijack()
	assert.Error(t, err)
	assert.Equal(t, http.ErrNotSupported, err)
}

func TestCacheFromConfig_InvalidCachedData(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	// Pre-populate cache with invalid JSON
	key := "GET:/api/data"
	_ = fc.Set(context.Background(), key, []byte("not-valid-json"), time.Minute)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fresh"))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec, req)

	// Should fall through to backend because cached data is invalid
	assert.Equal(t, 1, callCount)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCacheFromConfig_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		method       string
		cacheControl string
		expectCached bool
	}{
		{
			name:         "GET request cached",
			method:       http.MethodGet,
			expectCached: true,
		},
		{
			name:         "POST not cached",
			method:       http.MethodPost,
			expectCached: false,
		},
		{
			name:         "PUT not cached",
			method:       http.MethodPut,
			expectCached: false,
		},
		{
			name:         "DELETE not cached",
			method:       http.MethodDelete,
			expectCached: false,
		},
		{
			name:         "HEAD not cached",
			method:       http.MethodHead,
			expectCached: false,
		},
		{
			name:         "GET with no-store not cached",
			method:       http.MethodGet,
			cacheControl: "no-store",
			expectCached: false,
		},
		{
			name:         "GET with no-cache not cached",
			method:       http.MethodGet,
			cacheControl: "no-cache",
			expectCached: false,
		},
		{
			name:         "GET with max-age cached",
			method:       http.MethodGet,
			cacheControl: "max-age=3600",
			expectCached: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fc := newFakeCache()
			cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
			logger := observability.NopLogger()

			callCount := 0
			backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				callCount++
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})

			handler := CacheFromConfig(fc, cfg, logger)(backend)

			// First request
			rec1 := httptest.NewRecorder()
			req1 := httptest.NewRequest(tt.method, "/api/test", nil)
			if tt.cacheControl != "" {
				req1.Header.Set("Cache-Control", tt.cacheControl)
			}
			handler.ServeHTTP(rec1, req1)

			// Second request
			rec2 := httptest.NewRecorder()
			req2 := httptest.NewRequest(tt.method, "/api/test", nil)
			if tt.cacheControl != "" {
				req2.Header.Set("Cache-Control", tt.cacheControl)
			}
			handler.ServeHTTP(rec2, req2)

			if tt.expectCached {
				assert.Equal(t, 1, callCount, "expected response to be cached")
			} else {
				assert.Equal(t, 2, callCount, "expected response NOT to be cached")
			}
		})
	}
}

func TestCacheFromConfig_CacheHitBody(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(60 * time.Second)}
	logger := observability.NopLogger()

	expectedBody := `{"message":"cached"}`
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedBody))
	})

	handler := CacheFromConfig(fc, cfg, logger)(backend)

	// First request - populate cache
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, expectedBody, rec1.Body.String())

	// Second request - cache hit
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, expectedBody, rec2.Body.String())
}

func TestBuildCacheKey_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "simple path",
			url:      "/api/users",
			expected: "GET:/api/users",
		},
		{
			name:     "path with single query param",
			url:      "/api/users?id=1",
			expected: "GET:/api/users?id=1",
		},
		{
			name:     "path with sorted query params",
			url:      "/api/users?z=3&a=1&m=2",
			expected: "GET:/api/users?a=1&m=2&z=3",
		},
		{
			name:     "root path",
			url:      "/",
			expected: "GET:/",
		},
		{
			name:     "path with empty query",
			url:      "/api/data",
			expected: "GET:/api/data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			key := buildCacheKey(req)
			assert.Equal(t, tt.expected, key)
		})
	}
}
