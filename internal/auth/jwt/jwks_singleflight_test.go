package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// singleflightTestKid is the key ID served by the test JWKS endpoints below.
const singleflightTestKid = "test-key-id"

// makeTestJWKS returns the JSON encoding of a JWKS containing one RSA key
// with the given key ID.
func makeTestJWKS(t *testing.T, keyID string) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, keyID))

	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(jwkKey))

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	return jwksJSON
}

// forceStale marks the cached key set as stale so the next Refresh fetches.
func forceStale(ks *JWKSKeySet) {
	ks.mu.Lock()
	ks.lastRefresh = time.Now().Add(-24 * time.Hour)
	ks.mu.Unlock()
}

// TestJWKSKeySet_GetKey_ConcurrentSingleFetch verifies that N concurrent
// GetKey callers against a slow JWKS server coalesce into exactly ONE HTTP
// fetch and that no caller blocks meaningfully longer than the single fetch.
func TestJWKSKeySet_GetKey_ConcurrentSingleFetch(t *testing.T) {
	t.Parallel()

	jwksJSON := makeTestJWKS(t, singleflightTestKid)

	const fetchDelay = 300 * time.Millisecond
	var fetches atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		time.Sleep(fetchDelay) // slow JWKS server
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	const callers = 20
	errCh := make(chan error, callers)
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, getErr := ks.GetKey(context.Background(), singleflightTestKid)
			errCh <- getErr
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)

	for getErr := range errCh {
		assert.NoError(t, getErr)
	}

	// All callers must coalesce into exactly one HTTP fetch.
	assert.Equal(t, int64(1), fetches.Load(), "expected exactly one coalesced JWKS fetch")

	// No caller blocks meaningfully longer than the single fetch duration.
	assert.Less(t, elapsed, 10*fetchDelay, "callers must not serialize on the fetch")
}

// TestJWKSKeySet_Refresh_FreshCacheNoFetch verifies that Refresh is a no-op
// with zero HTTP calls while the cached key set is still fresh.
func TestJWKSKeySet_Refresh_FreshCacheNoFetch(t *testing.T) {
	t.Parallel()

	jwksJSON := makeTestJWKS(t, singleflightTestKid)

	var fetches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// Prime the cache.
	require.NoError(t, ks.Refresh(context.Background()))
	require.Equal(t, int64(1), fetches.Load())

	// Fresh cache: subsequent refreshes are no-ops with zero HTTP calls.
	for i := 0; i < 5; i++ {
		require.NoError(t, ks.Refresh(context.Background()))
	}
	assert.Equal(t, int64(1), fetches.Load(), "fresh cache must not trigger HTTP fetches")

	// GetKey for a cached kid does not fetch either.
	key, err := ks.GetKey(context.Background(), singleflightTestKid)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, int64(1), fetches.Load())
}

// TestJWKSKeySet_GetKey_HungEndpointHonorsContext verifies that when the JWKS
// endpoint hangs, (1) a caller triggering a refresh returns within its own
// context deadline instead of waiting for the fetch, and (2) a concurrent
// GetKey for an already-cached kid returns promptly during the outage because
// no lock is held across the hung network call.
func TestJWKSKeySet_GetKey_HungEndpointHonorsContext(t *testing.T) {
	t.Parallel()

	jwksJSON := makeTestJWKS(t, singleflightTestKid)

	var fetches atomic.Int64
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fetches.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksJSON)
			return
		}
		// Simulate an IdP outage: hang until the test releases the handler.
		<-release
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	defer close(release) // runs before server.Close so Close cannot hang

	ks, err := NewJWKSKeySet(server.URL,
		WithCacheTTL(time.Hour),
		WithRetryConfig(RetryConfig{
			MaxAttempts:     1,
			InitialInterval: time.Millisecond,
			MaxInterval:     time.Millisecond,
			Multiplier:      1.0,
		}),
	)
	require.NoError(t, err)

	// Prime the cache, then force staleness so the next Refresh fetches.
	_, err = ks.GetKey(context.Background(), singleflightTestKid)
	require.NoError(t, err)
	forceStale(ks)

	// An unknown kid triggers a refresh against the hung endpoint; the caller
	// must return within its own deadline instead of waiting for the fetch.
	const deadline = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	_, err = ks.GetKey(ctx, "unknown-kid")
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 10*deadline, "caller must not block past its context deadline")

	// While the outage fetch is still in flight, an already-cached kid must be
	// served promptly: the write lock is never held across network I/O.
	promptCtx, promptCancel := context.WithTimeout(context.Background(), time.Second)
	defer promptCancel()

	start = time.Now()
	key, err := ks.GetKey(promptCtx, singleflightTestKid)
	elapsed = time.Since(start)

	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Less(t, elapsed, time.Second, "cached kid lookup must not block during the outage")
}

// TestJWKSKeySet_GetKey_UnknownKidCoalescedPerWindow verifies that unknown-kid
// lookups trigger at most one coalesced refresh per refresh window
// (cacheTTL/2): zero fetches while fresh, exactly one once stale.
func TestJWKSKeySet_GetKey_UnknownKidCoalescedPerWindow(t *testing.T) {
	t.Parallel()

	jwksJSON := makeTestJWKS(t, singleflightTestKid)

	var fetches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	// Prime the cache.
	require.NoError(t, ks.Refresh(context.Background()))
	require.Equal(t, int64(1), fetches.Load())

	lookupUnknown := func(callers int) {
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, getErr := ks.GetKey(context.Background(), "unknown-kid")
				assert.ErrorIs(t, getErr, ErrKeyNotFound)
			}()
		}
		wg.Wait()
	}

	// Fresh window: unknown-kid lookups must not trigger any fetch.
	lookupUnknown(10)
	assert.Equal(t, int64(1), fetches.Load(), "fresh window must not refetch for unknown kid")

	// New refresh window: concurrent unknown-kid lookups coalesce into at
	// most one additional fetch.
	forceStale(ks)
	lookupUnknown(10)
	assert.Equal(t, int64(2), fetches.Load(), "stale window must trigger exactly one coalesced fetch")
}

// TestJWKSKeySet_RefreshFlight_DoubleCheckFresh verifies that the flight body
// short-circuits without any HTTP call when a previous flight already
// refreshed the keys (double-checked freshness).
func TestJWKSKeySet_RefreshFlight_DoubleCheckFresh(t *testing.T) {
	t.Parallel()

	jwksJSON := makeTestJWKS(t, singleflightTestKid)

	var fetches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL, WithCacheTTL(time.Hour))
	require.NoError(t, err)

	require.NoError(t, ks.Refresh(context.Background()))
	require.Equal(t, int64(1), fetches.Load())

	// Direct flight invocation with a fresh cache must be a no-op.
	require.NoError(t, ks.refreshFlight(context.Background()))
	assert.Equal(t, int64(1), fetches.Load())
}

// TestJWKSKeySet_FetchWithRetry_ContextCanceled verifies the pre-attempt
// context check returns a wrapped fetch error and counts the failure.
func TestJWKSKeySet_FetchWithRetry_ContextCanceled(t *testing.T) {
	t.Parallel()

	ks, err := NewJWKSKeySet("https://example.com/.well-known/jwks.json")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = ks.fetchWithRetry(ctx)

	require.ErrorIs(t, err, ErrJWKSFetchFailed)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int64(1), ks.Stats().Errors)
}

// TestJWKSKeySet_FetchWithRetry_CanceledDuringBackoff verifies that a context
// expiring during the backoff sleep aborts the retry loop with a wrapped
// fetch error.
func TestJWKSKeySet_FetchWithRetry_CanceledDuringBackoff(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL,
		WithRetryConfig(RetryConfig{
			MaxAttempts:     2,
			InitialInterval: 300 * time.Millisecond,
			MaxInterval:     time.Second,
			Multiplier:      2.0,
		}),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = ks.fetchWithRetry(ctx)

	require.ErrorIs(t, err, ErrJWKSFetchFailed)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, int64(1), ks.Stats().Errors)
}

// TestSleepWithJitter_ContextCanceled verifies that the backoff sleep honors
// context cancellation immediately.
func TestSleepWithJitter_ContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := sleepWithJitter(ctx, time.Hour)

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
}

// TestSleepWithJitter_Completes verifies that the backoff sleep returns nil
// after the interval elapses.
func TestSleepWithJitter_Completes(t *testing.T) {
	t.Parallel()

	err := sleepWithJitter(context.Background(), time.Millisecond)
	assert.NoError(t, err)
}

// TestJWKSKeySet_NextInterval_CapsAtMax verifies the exponential backoff
// interval is capped at the configured maximum.
func TestJWKSKeySet_NextInterval_CapsAtMax(t *testing.T) {
	t.Parallel()

	ks, err := NewJWKSKeySet("https://example.com/.well-known/jwks.json",
		WithRetryConfig(RetryConfig{
			MaxAttempts:     3,
			InitialInterval: time.Second,
			MaxInterval:     1500 * time.Millisecond,
			Multiplier:      2.0,
		}),
	)
	require.NoError(t, err)

	// Below the cap: pure exponential growth.
	assert.Equal(t, 400*time.Millisecond, ks.nextInterval(200*time.Millisecond))

	// Above the cap: clamped to MaxInterval.
	assert.Equal(t, 1500*time.Millisecond, ks.nextInterval(time.Second))
}
