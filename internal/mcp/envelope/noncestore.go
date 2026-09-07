package envelope

import (
	"context"
	"encoding/base64"
	"sync"
	"time"
)

// defaultMaxNonces bounds the in-memory NonceStore so a flood of retries cannot
// grow the set without bound (HUB-207 memory-leak fix). When the store reaches
// this size an eviction sweep removes expired entries before insertion.
const defaultMaxNonces = 100_000

// MemoryNonceStore is the default single-replica NonceStore. It records
// consumed nonces with a per-entry expiry and evicts expired entries lazily on
// Consume, so the set stays bounded (HUB-207). It is NOT cross-replica: use a
// RedisNonceStore for horizontally scaled deployments (HUB-501).
type MemoryNonceStore struct {
	now      func() time.Time
	maxSize  int
	mu       sync.Mutex
	consumed map[string]time.Time
}

// MemoryNonceStoreOption configures a MemoryNonceStore.
type MemoryNonceStoreOption func(*MemoryNonceStore)

// WithMemoryNonceStoreClock overrides the clock (test seam).
func WithMemoryNonceStoreClock(now func() time.Time) MemoryNonceStoreOption {
	return func(s *MemoryNonceStore) {
		if now != nil {
			s.now = now
		}
	}
}

// WithMemoryNonceStoreMaxSize overrides the bound before an eviction sweep.
// Non-positive values are ignored.
func WithMemoryNonceStoreMaxSize(n int) MemoryNonceStoreOption {
	return func(s *MemoryNonceStore) {
		if n > 0 {
			s.maxSize = n
		}
	}
}

// NewMemoryNonceStore constructs a bounded, TTL-evicting in-memory NonceStore.
func NewMemoryNonceStore(opts ...MemoryNonceStoreOption) *MemoryNonceStore {
	s := &MemoryNonceStore{
		now:      time.Now,
		maxSize:  defaultMaxNonces,
		consumed: make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Consume records nonce as used until now+ttl, returning ErrConsumed on reuse.
// The check-and-insert runs under a single lock so there is no
// time-of-check/time-of-use window (HUB-209). Expired entries are swept when
// the store reaches its size bound so it never grows without limit (HUB-207).
func (s *MemoryNonceStore) Consume(_ context.Context, nonce []byte, ttl time.Duration) error {
	key := base64.RawURLEncoding.EncodeToString(nonce)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if expiry, ok := s.consumed[key]; ok {
		if now.Before(expiry) {
			return ErrConsumed
		}
		// The prior record has expired; the envelope carrying this nonce is
		// itself expired and rejected by Open, so re-recording is a no-op
		// safety net rather than a replay window.
	}
	if len(s.consumed) >= s.maxSize {
		s.evictExpiredLocked(now)
	}
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	s.consumed[key] = now.Add(ttl)
	return nil
}

// evictExpiredLocked removes every expired entry. The caller holds the lock.
func (s *MemoryNonceStore) evictExpiredLocked(now time.Time) {
	for k, expiry := range s.consumed {
		if now.After(expiry) {
			delete(s.consumed, k)
		}
	}
}
