package envelope

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// nonceKeyPrefix namespaces single-use MRTR nonce keys in the shared Redis
// backend so they never collide with other users of the same instance.
const nonceKeyPrefix = "mcp:mrtr:nonce:"

// NonceSetNXer is the minimal Redis capability the RedisNonceStore needs: an
// atomic SET NX EX that reports whether the key was newly created. It is
// satisfied by internal/cache.redisCache and by a thin adapter over a
// go-redis UniversalClient, keeping this package free of a hard redis
// dependency (HUB-207/501).
type NonceSetNXer interface {
	// SetNX atomically sets key to value with the given TTL only if key does
	// not already exist, returning true when the key was created.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
}

// RedisNonceStore enforces single-use MRTR nonces across replicas using an
// atomic SET NX EX keyed by the nonce with the envelope TTL (HUB-207/209/501).
// Any replica that shares the backend rejects a replayed retry: the first
// Consume creates the key, every subsequent Consume observes it and returns
// ErrConsumed. The record self-expires after the TTL, matching the window in
// which the envelope itself could be replayed.
type RedisNonceStore struct {
	backend NonceSetNXer
}

// NewRedisNonceStore constructs a cross-replica NonceStore over the given
// SET-NX-capable backend. A nil backend is rejected so callers fall back to the
// in-memory store explicitly rather than silently losing single-use guarantees.
func NewRedisNonceStore(backend NonceSetNXer) (*RedisNonceStore, error) {
	if backend == nil {
		return nil, errors.New("envelope: nil redis nonce backend")
	}
	return &RedisNonceStore{backend: backend}, nil
}

// Consume records nonce via an atomic SET NX EX. It returns ErrConsumed when
// the key already exists (a replayed retry) and wraps any backend error so the
// caller fails closed rather than admitting an unverifiable retry (HUB-209).
func (s *RedisNonceStore) Consume(ctx context.Context, nonce []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	key := nonceKeyPrefix + base64.RawURLEncoding.EncodeToString(nonce)
	created, err := s.backend.SetNX(ctx, key, []byte{1}, ttl)
	if err != nil {
		return fmt.Errorf("envelope: redis nonce consume: %w", err)
	}
	if !created {
		return ErrConsumed
	}
	return nil
}
