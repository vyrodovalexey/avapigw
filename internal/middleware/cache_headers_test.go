// Cache header-isolation tests: per-request headers (CORS grants,
// Set-Cookie) must never be baked into shared cache entries, and the cache
// fill must survive a client disconnect after the response is written.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

const (
	originA = "https://a.example.com"
	originB = "https://b.example.com"
)

// newCORSCacheChain builds a middleware chain mirroring the production
// route middleware order (see RouteMiddlewareManager buildMiddlewareChain):
// CORS runs BEFORE the cache middleware on the request path, so CORS
// response headers are set on the live header map for every request,
// including cache hits.
func newCORSCacheChain(fc cache.Cache, backend http.Handler) http.Handler {
	cacheCfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)}
	cacheMw := CacheFromConfig(fc, cacheCfg, observability.NopLogger())

	corsMw := CORS(CORSConfig{
		AllowOrigins:     []string{originA, originB},
		AllowMethods:     []string{http.MethodGet},
		AllowCredentials: true,
	})

	return corsMw(cacheMw(backend))
}

func serveWithOrigin(handler http.Handler, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeStoredEntry unmarshals the single entry stored in the fake cache.
func decodeStoredEntry(t *testing.T, fc *fakeCache) cachedResponse {
	t.Helper()

	fc.mu.Lock()
	defer fc.mu.Unlock()
	require.Len(t, fc.data, 1, "exactly one cache entry expected")

	var entry cachedResponse
	for _, raw := range fc.data {
		require.NoError(t, json.Unmarshal(raw, &entry))
	}
	return entry
}

// TestCache_CORSGrantNeverLeaksAcrossOrigins fills the cache through origin
// A and verifies a hit through origin B receives B's CORS grant — never
// A's — and that a request without an Origin gets no grant at all.
func TestCache_CORSGrantNeverLeaksAcrossOrigins(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	callCount := 0
	handler := newCORSCacheChain(fc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	// Fill via origin A.
	recA := serveWithOrigin(handler, originA)
	assert.Equal(t, http.StatusOK, recA.Code)
	assert.Equal(t, []string{originA}, recA.Header().Values("Access-Control-Allow-Origin"))

	// Hit via origin B: exactly B's grant, never A's.
	recB := serveWithOrigin(handler, originB)
	assert.Equal(t, http.StatusOK, recB.Code)
	assert.Equal(t, 1, callCount, "second request must be served from cache")
	assert.Equal(t, "HIT", recB.Header().Get("X-Cache"))
	assert.Equal(t, []string{originB}, recB.Header().Values("Access-Control-Allow-Origin"),
		"cache hit must carry the current request's CORS grant only")
	assert.Equal(t, "application/json", recB.Header().Get("Content-Type"),
		"backend headers must still be replayed from cache")

	// Hit without an Origin: no grant at all.
	recNone := serveWithOrigin(handler, "")
	assert.Equal(t, 1, callCount)
	assert.Empty(t, recNone.Header().Values("Access-Control-Allow-Origin"),
		"cache hit without an allowed origin must not receive any cached grant")

	// The stored entry itself must not contain any CORS headers.
	entry := decodeStoredEntry(t, fc)
	for header := range entry.Headers {
		assert.NotContains(t, http.CanonicalHeaderKey(header), "Access-Control-",
			"CORS headers must never be stored in cache entries")
	}
}

// TestCache_SetCookieNeverCached verifies Set-Cookie is stripped from the
// stored entry and never replayed to other clients.
func TestCache_SetCookieNeverCached(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	handler := newCORSCacheChain(fc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=fill-request-secret; HttpOnly")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))

	// Fill: the live response still carries the cookie for the client that
	// triggered it.
	recFill := serveWithOrigin(handler, originA)
	assert.NotEmpty(t, recFill.Header().Get("Set-Cookie"))

	// Hit: no cookie replay to other clients.
	recHit := serveWithOrigin(handler, originB)
	assert.Equal(t, "HIT", recHit.Header().Get("X-Cache"))
	assert.Empty(t, recHit.Header().Values("Set-Cookie"),
		"Set-Cookie must never be replayed from cache")

	entry := decodeStoredEntry(t, fc)
	assert.NotContains(t, entry.Headers, "Set-Cookie")
}

// TestCache_HopByHopHeadersNotCached verifies connection-scoped headers are
// excluded from cached entries.
func TestCache_HopByHopHeadersNotCached(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cacheCfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)}
	handler := CacheFromConfig(fc, cacheCfg, observability.NopLogger())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Keep-Alive", "timeout=5")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/data", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	entry := decodeStoredEntry(t, fc)
	assert.NotContains(t, entry.Headers, "Connection")
	assert.NotContains(t, entry.Headers, "Keep-Alive")
	assert.Contains(t, entry.Headers, "Content-Type")
}

// TestCache_VaryStoredAndLiveChainWins verifies the backend's Vary value is
// stored and replayed when the live chain does not set one, while a Vary
// set by the live chain (CORS) is not duplicated by the cached value.
func TestCache_VaryStoredAndLiveChainWins(t *testing.T) {
	t.Parallel()

	t.Run("backend vary replayed without live chain", func(t *testing.T) {
		t.Parallel()

		fc := newFakeCache()
		cacheCfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)}
		handler := CacheFromConfig(fc, cacheCfg, observability.NopLogger())(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Vary", "Accept-Encoding")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))

		// Fill, then hit.
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v", nil))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v", nil))

		assert.Equal(t, "HIT", rec.Header().Get("X-Cache"))
		assert.Equal(t, []string{"Accept-Encoding"}, rec.Header().Values("Vary"))
	})

	t.Run("live cors vary not duplicated on hit", func(t *testing.T) {
		t.Parallel()

		fc := newFakeCache()
		handler := newCORSCacheChain(fc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))

		serveWithOrigin(handler, originA)
		rec := serveWithOrigin(handler, originB)

		assert.Equal(t, "HIT", rec.Header().Get("X-Cache"))
		assert.Equal(t, []string{"Origin"}, rec.Header().Values("Vary"),
			"live Vary must not be duplicated by the cached value")
	})
}

// TestCache_HeaderSnapshotIsolatedFromLateMutations verifies headers added
// to the live map after WriteHeader do not leak into the cached entry.
func TestCache_HeaderSnapshotIsolatedFromLateMutations(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	cacheCfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)}
	handler := CacheFromConfig(fc, cacheCfg, observability.NopLogger())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Early", "kept")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			// Mutating the header map after the response was written is a
			// handler bug, but it must not corrupt the cached entry.
			w.Header().Set("X-Late", "dropped")
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/snap", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	entry := decodeStoredEntry(t, fc)
	assert.Contains(t, entry.Headers, "X-Early")
	assert.NotContains(t, entry.Headers, "X-Late",
		"headers set after WriteHeader must not be cached")
}

// TestCache_FillCompletesAfterClientDisconnect verifies the cache fill is
// decoupled from the client's request context: a disconnect right after
// the response is written (context canceled) must not lose the fill.
// Uses a real redis-backed cache via miniredis.
func TestCache_FillCompletesAfterClientDisconnect(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	redisCache, err := cache.New(&config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(time.Minute),
		Redis:   &config.RedisCacheConfig{URL: "redis://" + mr.Addr()},
	}, observability.NopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisCache.Close() })

	cacheCfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)}

	callCount := 0
	ctx, cancel := context.WithCancel(context.Background())
	handler := CacheFromConfig(redisCache, cacheCfg, observability.NopLogger())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("expensive"))
			// Simulate the client disconnecting as soon as it has the
			// response: the request context is canceled before the cache
			// fill write runs.
			cancel()
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/expensive", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// A second request must be served from cache: the fill completed
	// despite the canceled request context.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/expensive", nil))

	assert.Equal(t, 1, callCount, "fill must survive client disconnect")
	assert.Equal(t, "HIT", rec2.Header().Get("X-Cache"))
	assert.Equal(t, "expensive", rec2.Body.String())
}

// TestCache_ReplaySkipsLegacyPerRequestHeaders verifies defense in depth:
// entries stored by older gateway versions may still contain per-request
// headers, and replay must skip them.
func TestCache_ReplaySkipsLegacyPerRequestHeaders(t *testing.T) {
	t.Parallel()

	fc := newFakeCache()
	legacy := cachedResponse{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"Access-Control-Allow-Origin":      {originA},
			"Access-Control-Allow-Credentials": {"true"},
			"Set-Cookie":                       {"session=legacy"},
			"Content-Type":                     {"application/json"},
		},
		Body: []byte(`{"legacy":true}`),
	}
	raw, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, fc.Set(context.Background(), "GET:/api/legacy", raw, time.Minute))

	cacheCfg := &config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)}
	handler := CacheFromConfig(fc, cacheCfg, observability.NopLogger())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/legacy", nil))

	assert.Equal(t, "HIT", rec.Header().Get("X-Cache"))
	assert.Empty(t, rec.Header().Values("Access-Control-Allow-Origin"))
	assert.Empty(t, rec.Header().Values("Access-Control-Allow-Credentials"))
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}
