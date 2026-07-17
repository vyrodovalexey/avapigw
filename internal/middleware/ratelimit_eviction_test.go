package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// newEvictionTestLimiter builds a per-client rate limiter with the given
// capacity and TTL, registering Stop as test cleanup.
func newEvictionTestLimiter(t *testing.T, rps, burst, maxClients int, ttl time.Duration) *RateLimiter {
	t.Helper()
	rl := NewRateLimiter(rps, burst, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithMaxClients(maxClients),
		WithClientTTL(ttl),
	)
	t.Cleanup(rl.Stop)
	return rl
}

// hasClient reports whether the limiter currently tracks the given key.
func hasClient(rl *RateLimiter, key string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	_, ok := rl.clients[key]
	return ok
}

// evictionScanCount returns the total number of entries examined by
// eviction/cleanup loops so far.
func evictionScanCount(rl *RateLimiter) int64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.evictionScans
}

// assertLRUConsistent verifies the map and the LRU list describe exactly
// the same set of entries.
func assertLRUConsistent(t *testing.T, rl *RateLimiter) {
	t.Helper()
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	require.Equal(t, len(rl.clients), rl.lru.Len(),
		"clients map and LRU list must stay in sync")
	for e := rl.lru.Front(); e != nil; e = e.Next() {
		entry, ok := e.Value.(*clientEntry)
		require.True(t, ok, "LRU list must only contain *clientEntry values")
		mapped, exists := rl.clients[entry.key]
		require.True(t, exists, "LRU entry %q must exist in the map", entry.key)
		require.Same(t, entry, mapped, "map and LRU must reference the same entry")
	}
}

// TestRateLimiter_Eviction_TriggersAtMaxClients verifies that inserting
// one client beyond maxClients triggers eviction, that the map shrinks to
// the 90% target before the insert, and that exactly the oldest
// (least-recently-used) entry is removed.
func TestRateLimiter_Eviction_TriggersAtMaxClients(t *testing.T) {
	t.Parallel()

	const maxClients = 10
	rl := newEvictionTestLimiter(t, 100, 10, maxClients, time.Hour)

	for i := 0; i < maxClients; i++ {
		rl.Allow(fmt.Sprintf("client-%02d", i))
	}
	require.Equal(t, maxClients, rl.ClientCount())

	// One more unique client pushes the map past maxClients: the limiter
	// trims to 90% (9 entries) and then inserts the new client (10 total).
	rl.Allow("client-new")

	assert.Equal(t, maxClients, rl.ClientCount(),
		"count must stay bounded by maxClients after eviction")
	assert.False(t, hasClient(rl, "client-00"),
		"the least-recently-used entry must be evicted")
	assert.True(t, hasClient(rl, "client-01"),
		"the second-oldest entry must survive a single eviction")
	assert.True(t, hasClient(rl, "client-new"),
		"the newly inserted client must be present")
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_Eviction_ExpiredEntriesWithInjectedClock uses the
// injected clock to deterministically expire entries and verifies the
// TTL sweep inside eviction removes all of them without touching the
// fresh insert.
func TestRateLimiter_Eviction_ExpiredEntriesWithInjectedClock(t *testing.T) {
	t.Parallel()

	const maxClients = 5
	rl := newEvictionTestLimiter(t, 100, 10, maxClients, time.Minute)

	// Deterministic clock: all test steps control elapsed time explicitly.
	var clockMu sync.Mutex
	current := time.Unix(1_700_000_000, 0)
	rl.nowFunc = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return current
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		current = current.Add(d)
	}

	for i := 0; i < maxClients; i++ {
		rl.Allow(fmt.Sprintf("stale-%d", i))
	}
	require.Equal(t, maxClients, rl.ClientCount())

	// Everything inserted so far is now older than the TTL.
	advance(2 * time.Minute)

	// The next insert hits maxClients and evicts all expired entries in
	// the TTL sweep, leaving only the fresh client.
	rl.Allow("fresh-client")

	assert.Equal(t, 1, rl.ClientCount(),
		"all expired entries must be removed by the TTL sweep")
	assert.True(t, hasClient(rl, "fresh-client"))
	for i := 0; i < maxClients; i++ {
		assert.False(t, hasClient(rl, fmt.Sprintf("stale-%d", i)),
			"expired entry %d must be gone", i)
	}
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_Eviction_BoundedIterations_HighChurn inserts many more
// unique clients than maxClients and asserts — via the eviction scan
// counter, not wall-clock time — that the total eviction work stays
// linear in the number of inserts. The previous algorithm rescanned the
// full map once per evicted entry (roughly 90 eviction rounds × ~1000
// examined entries ≈ 10⁵ scans here); the LRU eviction examines about
// one entry per evicted client (~10³).
func TestRateLimiter_Eviction_BoundedIterations_HighChurn(t *testing.T) {
	t.Parallel()

	const (
		maxClients = 100
		inserts    = 1000
	)
	rl := newEvictionTestLimiter(t, 1000, 100, maxClients, time.Hour)

	for i := 0; i < inserts; i++ {
		rl.Allow(fmt.Sprintf("churn-client-%04d", i))
	}

	assert.LessOrEqual(t, rl.ClientCount(), maxClients,
		"client count must stay bounded under churn")

	scans := evictionScanCount(rl)
	assert.Positive(t, scans, "high churn must have triggered evictions")
	assert.LessOrEqual(t, scans, int64(3*inserts),
		"eviction work must stay linear in the number of inserts")
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_Eviction_ActiveClientNotStarved verifies that a client
// which keeps making requests is never evicted in favor of idle ones and
// keeps its limiter state (a recreated entry would hand out a fresh
// burst).
func TestRateLimiter_Eviction_ActiveClientNotStarved(t *testing.T) {
	t.Parallel()

	const maxClients = 10
	// rps=1/burst=1: the first request consumes the only token, so a
	// preserved entry must keep rejecting while a recreated one would
	// allow a burst again.
	rl := newEvictionTestLimiter(t, 1, 1, maxClients, time.Hour)

	require.True(t, rl.Allow("active-client"),
		"first request consumes the burst token")

	for i := 0; i < maxClients-1; i++ {
		rl.Allow(fmt.Sprintf("idle-%d", i))
	}
	require.Equal(t, maxClients, rl.ClientCount())

	// The active client makes another request: rejected (token spent)
	// but its recency is refreshed, moving it to the front of the LRU.
	require.False(t, rl.Allow("active-client"))

	// A new client triggers eviction; the LRU victim must be the oldest
	// idle client, never the recently active one.
	rl.Allow("trigger-eviction")

	assert.True(t, hasClient(rl, "active-client"),
		"recently active client must survive eviction")
	assert.False(t, hasClient(rl, "idle-0"),
		"least-recently-used idle client must be evicted")
	assert.False(t, rl.Allow("active-client"),
		"surviving client must keep its limiter state (no fresh burst)")
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_Eviction_LRUOrderFollowsAccess verifies that accessing
// an old client re-orders it ahead of newer-but-idle clients for
// eviction purposes.
func TestRateLimiter_Eviction_LRUOrderFollowsAccess(t *testing.T) {
	t.Parallel()

	const maxClients = 4
	rl := newEvictionTestLimiter(t, 100, 10, maxClients, time.Hour)

	rl.Allow("a")
	rl.Allow("b")
	rl.Allow("c")
	rl.Allow("d")
	// Refresh "a": eviction order becomes b, c, d, a.
	rl.Allow("a")

	// Trigger eviction: target is 90% of 4 -> 3 entries, so "b" goes.
	rl.Allow("e")

	assert.False(t, hasClient(rl, "b"), "oldest-by-access entry must be evicted")
	assert.True(t, hasClient(rl, "a"), "refreshed entry must survive")
	assert.True(t, hasClient(rl, "e"))
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_UpdateConfig_ResetsLRUState verifies that a config
// update clears both the map and the LRU list, and that eviction still
// works correctly afterwards (no stale list entries).
func TestRateLimiter_UpdateConfig_ResetsLRUState(t *testing.T) {
	t.Parallel()

	const maxClients = 5
	rl := newEvictionTestLimiter(t, 100, 10, maxClients, time.Hour)

	for i := 0; i < maxClients; i++ {
		rl.Allow(fmt.Sprintf("pre-update-%d", i))
	}
	require.Equal(t, maxClients, rl.ClientCount())

	rl.UpdateConfig(&config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 200,
		Burst:             50,
		PerClient:         true,
	})
	require.Equal(t, 0, rl.ClientCount(), "update must clear all entries")
	assertLRUConsistent(t, rl)

	// Refill past capacity: eviction must operate on post-update entries
	// only, without stale references to the cleared generation.
	for i := 0; i < maxClients+1; i++ {
		rl.Allow(fmt.Sprintf("post-update-%d", i))
	}

	assert.LessOrEqual(t, rl.ClientCount(), maxClients)
	assert.False(t, hasClient(rl, "post-update-0"),
		"oldest post-update entry must be evicted")
	assert.True(t, hasClient(rl, fmt.Sprintf("post-update-%d", maxClients)))
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_CleanupOldClients_LRUPartialExpiry verifies the
// LRU-tail based cleanup removes exactly the expired prefix using the
// injected clock instead of sleeping.
func TestRateLimiter_CleanupOldClients_LRUPartialExpiry(t *testing.T) {
	t.Parallel()

	rl := newEvictionTestLimiter(t, 100, 10, 100, time.Hour)

	var clockMu sync.Mutex
	current := time.Unix(1_700_000_000, 0)
	rl.nowFunc = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return current
	}

	for i := 0; i < 5; i++ {
		rl.Allow(fmt.Sprintf("old-%d", i))
	}

	clockMu.Lock()
	current = current.Add(10 * time.Minute)
	clockMu.Unlock()

	for i := 0; i < 5; i++ {
		rl.Allow(fmt.Sprintf("new-%d", i))
	}
	require.Equal(t, 10, rl.ClientCount())

	// Only the first batch is older than the cutoff.
	rl.CleanupOldClients(5 * time.Minute)

	assert.Equal(t, 5, rl.ClientCount())
	for i := 0; i < 5; i++ {
		assert.False(t, hasClient(rl, fmt.Sprintf("old-%d", i)))
		assert.True(t, hasClient(rl, fmt.Sprintf("new-%d", i)))
	}
	assertLRUConsistent(t, rl)
}

// TestRateLimiter_EvictOldest_DesyncGuard ensures the eviction loops
// terminate via the nil-back guard (instead of spinning forever) if the
// clients map ever held an entry that is missing from the LRU list.
func TestRateLimiter_EvictOldest_DesyncGuard(t *testing.T) {
	t.Parallel()

	// maxClients=0 forces the capacity phase to run for any map size.
	rl := newEvictionTestLimiter(t, 100, 10, 0, time.Hour)

	rl.mu.Lock()
	rl.clients["ghost"] = &clientEntry{
		limiter:    rate.NewLimiter(rate.Limit(1), 1),
		lastAccess: rl.nowFunc(),
		key:        "ghost",
	}
	// Must not deadlock, spin, or panic on the empty LRU list.
	rl.evictOldestLocked()
	remaining := len(rl.clients)
	rl.mu.Unlock()

	assert.Equal(t, 1, remaining,
		"entry unreachable via the LRU list is left in place; the guard just terminates the loop")
}

// TestRateLimiter_Eviction_ConcurrentChurn hammers the limiter with
// concurrent unique and repeat clients to exercise eviction under the
// race detector.
func TestRateLimiter_Eviction_ConcurrentChurn(t *testing.T) {
	t.Parallel()

	const maxClients = 50
	rl := newEvictionTestLimiter(t, 1000, 100, maxClients, time.Hour)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// Mix unique clients (churn) with a shared hot client.
				rl.Allow(fmt.Sprintf("w%d-client-%d", worker, i))
				rl.Allow("hot-client")
			}
		}(g)
	}
	wg.Wait()

	assert.LessOrEqual(t, rl.ClientCount(), maxClients)
	assert.True(t, hasClient(rl, "hot-client"),
		"continuously accessed client must survive concurrent churn")
	assertLRUConsistent(t, rl)
}
