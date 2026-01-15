package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// maxCASRetries is the maximum number of CAS retry attempts to prevent
// infinite spinning under high contention.
const maxCASRetries = 100

// entry represents a stored value with expiration.
type entry struct {
	value      int64
	expiration time.Time
}

// MemoryStore implements Store using in-memory storage.
type MemoryStore struct {
	data    sync.Map
	cleanup *time.Ticker
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		cleanup: time.NewTicker(time.Minute),
		done:    make(chan struct{}),
	}

	go s.startCleanup()

	return s
}

// NewMemoryStoreWithCleanupInterval creates a new in-memory store with custom cleanup interval.
func NewMemoryStoreWithCleanupInterval(interval time.Duration) *MemoryStore {
	s := &MemoryStore{
		cleanup: time.NewTicker(interval),
		done:    make(chan struct{}),
	}

	go s.startCleanup()

	return s
}

// Get implements Store.
func (s *MemoryStore) Get(ctx context.Context, key string) (int64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	value, ok := s.data.Load(key)
	if !ok {
		return 0, &ErrKeyNotFound{Key: key}
	}

	e := value.(*entry)

	// Check if expired
	if !e.expiration.IsZero() && time.Now().After(e.expiration) {
		s.data.Delete(key)
		return 0, &ErrKeyNotFound{Key: key}
	}

	return e.value, nil
}

// Set implements Store.
func (s *MemoryStore) Set(ctx context.Context, key string, value int64, expiration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	}

	s.data.Store(key, &entry{
		value:      value,
		expiration: exp,
	})

	return nil
}

// Increment implements Store.
func (s *MemoryStore) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	for retries := 0; retries < maxCASRetries; retries++ {
		value, ok := s.data.Load(key)
		if !ok {
			// Key doesn't exist, create it
			newEntry := &entry{value: delta}
			if actual, loaded := s.data.LoadOrStore(key, newEntry); loaded {
				// Another goroutine created it, retry
				value = actual
			} else {
				return delta, nil
			}
		}

		e := value.(*entry)

		// Check if expired
		if !e.expiration.IsZero() && time.Now().After(e.expiration) {
			s.data.Delete(key)
			continue
		}

		// Create new entry with incremented value
		newEntry := &entry{
			value:      e.value + delta,
			expiration: e.expiration,
		}

		if s.data.CompareAndSwap(key, e, newEntry) {
			return newEntry.value, nil
		}
		// CAS failed, retry
	}

	return 0, fmt.Errorf("increment failed: max retries (%d) exceeded", maxCASRetries)
}

// IncrementWithExpiry implements Store.
func (s *MemoryStore) IncrementWithExpiry(ctx context.Context, key string, delta int64, expiration time.Duration) (int64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	}

	for retries := 0; retries < maxCASRetries; retries++ {
		value, ok := s.data.Load(key)
		if !ok {
			// Key doesn't exist, create it with expiration
			newEntry := &entry{
				value:      delta,
				expiration: exp,
			}
			if actual, loaded := s.data.LoadOrStore(key, newEntry); loaded {
				// Another goroutine created it, retry
				value = actual
			} else {
				return delta, nil
			}
		}

		e := value.(*entry)

		// Check if expired - use CAS to avoid race condition
		if !e.expiration.IsZero() && time.Now().After(e.expiration) {
			// Reset with new expiration using CAS
			newEntry := &entry{
				value:      delta,
				expiration: exp,
			}
			if s.data.CompareAndSwap(key, e, newEntry) {
				return delta, nil
			}
			// CAS failed, retry the loop
			continue
		}

		// Create new entry with incremented value (keep original expiration)
		newEntry := &entry{
			value:      e.value + delta,
			expiration: e.expiration,
		}

		if s.data.CompareAndSwap(key, e, newEntry) {
			return newEntry.value, nil
		}
		// CAS failed, retry
	}

	return 0, fmt.Errorf("increment with expiry failed: max retries (%d) exceeded", maxCASRetries)
}

// Delete implements Store.
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.data.Delete(key)
	return nil
}

// Close implements Store.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	s.cleanup.Stop()
	close(s.done)

	return nil
}

// startCleanup periodically removes expired entries.
func (s *MemoryStore) startCleanup() {
	for {
		select {
		case <-s.cleanup.C:
			s.cleanupExpired()
		case <-s.done:
			return
		}
	}
}

// cleanupExpired removes all expired entries.
func (s *MemoryStore) cleanupExpired() {
	now := time.Now()

	s.data.Range(func(key, value interface{}) bool {
		e := value.(*entry)
		if !e.expiration.IsZero() && now.After(e.expiration) {
			s.data.Delete(key)
		}
		return true
	})
}

// Size returns the number of entries in the store.
func (s *MemoryStore) Size() int {
	count := 0
	s.data.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}
