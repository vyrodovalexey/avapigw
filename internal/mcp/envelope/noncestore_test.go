package envelope

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryNonceStoreSingleUse proves a nonce is consumable once.
func TestMemoryNonceStoreSingleUse(t *testing.T) {
	t.Parallel()
	s := NewMemoryNonceStore()
	ctx := context.Background()
	nonce := []byte("nonce-1")

	require.NoError(t, s.Consume(ctx, nonce, time.Minute))
	require.ErrorIs(t, s.Consume(ctx, nonce, time.Minute), ErrConsumed)
	// A different nonce is unaffected.
	require.NoError(t, s.Consume(ctx, []byte("nonce-2"), time.Minute))
}

// TestMemoryNonceStoreEviction proves expired records are evicted so the store
// stays bounded (HUB-207).
func TestMemoryNonceStoreEviction(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	s := NewMemoryNonceStore(
		WithMemoryNonceStoreClock(clock),
		WithMemoryNonceStoreMaxSize(2),
	)
	ctx := context.Background()

	require.NoError(t, s.Consume(ctx, []byte("a"), time.Second))
	require.NoError(t, s.Consume(ctx, []byte("b"), time.Second))
	assert.Len(t, s.consumed, 2)

	// Advance past the TTL; the next Consume triggers an eviction sweep at the
	// size bound and inserts the new entry, so expired entries are gone.
	now = now.Add(2 * time.Second)
	require.NoError(t, s.Consume(ctx, []byte("c"), time.Second))
	assert.LessOrEqual(t, len(s.consumed), 2, "expired entries evicted at bound")
}

// TestMemoryNonceStoreExpiredAllowsReuse proves a record whose TTL elapsed no
// longer blocks (the envelope is expired and rejected by Open first).
func TestMemoryNonceStoreExpiredAllowsReuse(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	s := NewMemoryNonceStore(WithMemoryNonceStoreClock(func() time.Time { return now }))
	ctx := context.Background()
	nonce := []byte("n")
	require.NoError(t, s.Consume(ctx, nonce, time.Second))
	now = now.Add(2 * time.Second)
	require.NoError(t, s.Consume(ctx, nonce, time.Second), "expired record no longer blocks")
}

// fakeSetNX is a test double for NonceSetNXer.
type fakeSetNX struct {
	seen    map[string]bool
	err     error
	lastTTL time.Duration
}

func (f *fakeSetNX) SetNX(_ context.Context, key string, _ []byte, ttl time.Duration) (bool, error) {
	f.lastTTL = ttl
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

// TestRedisNonceStoreSingleUse proves the Redis store rejects a replayed nonce.
func TestRedisNonceStoreSingleUse(t *testing.T) {
	t.Parallel()
	backend := &fakeSetNX{}
	s, err := NewRedisNonceStore(backend)
	require.NoError(t, err)
	ctx := context.Background()
	nonce := []byte("nonce-x")

	require.NoError(t, s.Consume(ctx, nonce, time.Minute))
	require.ErrorIs(t, s.Consume(ctx, nonce, time.Minute), ErrConsumed)
}

// TestMemoryNonceStoreDefaultTTL proves a non-positive ttl defaults to
// DefaultNonceTTL (covers the ttl<=0 arm).
func TestMemoryNonceStoreDefaultTTL(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	s := NewMemoryNonceStore(WithMemoryNonceStoreClock(func() time.Time { return now }))
	ctx := context.Background()
	nonce := []byte("ttl-zero")

	require.NoError(t, s.Consume(ctx, nonce, 0))
	// The recorded expiry must be now + DefaultNonceTTL.
	key := base64.RawURLEncoding.EncodeToString(nonce)
	assert.Equal(t, now.Add(DefaultNonceTTL), s.consumed[key])
	// Immediate re-consume is still a replay.
	require.ErrorIs(t, s.Consume(ctx, nonce, 0), ErrConsumed)
}

// TestRedisNonceStoreDefaultTTL proves a non-positive ttl defaults to
// DefaultNonceTTL before hitting the backend (covers the ttl<=0 arm).
func TestRedisNonceStoreDefaultTTL(t *testing.T) {
	t.Parallel()
	backend := &fakeSetNX{}
	s, err := NewRedisNonceStore(backend)
	require.NoError(t, err)

	require.NoError(t, s.Consume(context.Background(), []byte("ttl-zero"), 0))
	assert.Equal(t, DefaultNonceTTL, backend.lastTTL)
}

// TestRedisNonceStoreBackendError proves a backend error fails closed (wrapped,
// not silently admitted).
func TestRedisNonceStoreBackendError(t *testing.T) {
	t.Parallel()
	s, err := NewRedisNonceStore(&fakeSetNX{err: errors.New("boom")})
	require.NoError(t, err)
	err = s.Consume(context.Background(), []byte("n"), time.Minute)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrConsumed)
}

// TestNewRedisNonceStoreNilBackend proves a nil backend is rejected.
func TestNewRedisNonceStoreNilBackend(t *testing.T) {
	t.Parallel()
	_, err := NewRedisNonceStore(nil)
	require.Error(t, err)
}

// TestAEADSealerWithNonceStore proves the sealer delegates single-use to an
// injected NonceStore (HUB-207).
func TestAEADSealerWithNonceStore(t *testing.T) {
	t.Parallel()
	backend := &fakeSetNX{}
	store, err := NewRedisNonceStore(backend)
	require.NoError(t, err)
	s, err := NewAEADSealer(testKey(), WithNonceStore(store), WithConsumeTTL(time.Minute))
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, s.Consume(ctx, []byte("shared")))
	require.ErrorIs(t, s.Consume(ctx, []byte("shared")), ErrConsumed)
}
