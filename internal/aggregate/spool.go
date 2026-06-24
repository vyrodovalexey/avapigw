package aggregate

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	mathrand "math/rand/v2"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// spoolKeyPrefix namespaces all spool keys to avoid collisions with other cache
// users sharing the Redis instance.
const spoolKeyPrefix = "avapigw:aggregate:spool:"

// spoolTTLJitter is the maximum proportional jitter applied to spool TTLs to
// avoid synchronized expiry (thundering herd).
const spoolTTLJitter = 0.1

// SpoolStore is the minimal off-heap store contract used by the spooler. It is
// satisfied by internal/cache.Cache; injecting it keeps the aggregate package
// free of a hard cache dependency and import cycles.
type SpoolStore interface {
	// Get retrieves a previously spooled value.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value with the given TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a spooled value.
	Delete(ctx context.Context, key string) error
}

// Spooler buffers large per-target response bodies. When off-heap spooling is
// enabled and a store is available, bodies above the threshold are written to
// the store under namespaced, TTL'd, hashed keys; otherwise an in-memory
// fallback is used. Redis outages degrade gracefully to the memory fallback.
type Spooler struct {
	store          SpoolStore
	thresholdBytes int64
	ttl            time.Duration
	enabled        bool
	logger         observability.Logger
	metrics        *Metrics

	mem   map[string][]byte
	memMu sync.Mutex
	keys  []string
}

// NewSpooler creates a Spooler. When store is nil or opts disable spooling, the
// in-memory fallback is always used.
func NewSpooler(opts *SpoolOptions, store SpoolStore, logger observability.Logger, metrics *Metrics) *Spooler {
	if logger == nil {
		logger = observability.NopLogger()
	}
	if metrics == nil {
		metrics = NopMetrics()
	}
	s := &Spooler{
		logger:  logger,
		metrics: metrics,
		mem:     make(map[string][]byte),
	}
	if opts != nil {
		s.thresholdBytes = opts.ThresholdBytes
		s.ttl = opts.TTL
		s.enabled = opts.Enabled && opts.Backend == SpoolBackendRedis && store != nil
	}
	if s.thresholdBytes <= 0 {
		s.thresholdBytes = DefaultSpoolThresholdBytes
	}
	if s.ttl <= 0 {
		s.ttl = DefaultSpoolTTL
	}
	if s.enabled {
		s.store = store
	}
	return s
}

// Put spools a body, returning an opaque handle that can later resolve the body
// via Get. Bodies below the threshold (or when off-heap spooling is unavailable)
// are kept in memory. The body is always recoverable even if the off-heap write
// fails (memory fallback).
func (s *Spooler) Put(ctx context.Context, target string, body []byte) (string, error) {
	handle := s.newHandle(target)

	// Small bodies stay in memory; spilling them off-heap is not worth a round
	// trip.
	if int64(len(body)) < s.thresholdBytes || !s.enabled {
		s.putMem(handle, body)
		return handle, nil
	}

	if err := s.store.Set(ctx, handle, body, s.jitteredTTL()); err != nil {
		s.metrics.RecordSpoolError()
		s.logger.Warn("aggregate spool write failed, using memory fallback",
			observability.String("target", target),
			observability.Error(err),
		)
		s.putMem(handle, body)
		return handle, nil
	}

	s.trackKey(handle)
	s.metrics.RecordSpoolBytes(int64(len(body)))
	s.logger.Debug("aggregate spooled response off-heap",
		observability.String("target", target),
		observability.Int("bytes", len(body)),
	)
	return handle, nil
}

// trackKey records an off-heap spool key so Cleanup can delete it, preventing
// key leakage in the backing store.
func (s *Spooler) trackKey(handle string) {
	s.memMu.Lock()
	s.keys = append(s.keys, handle)
	s.memMu.Unlock()
}

// Get resolves a previously spooled body by handle.
func (s *Spooler) Get(ctx context.Context, handle string) ([]byte, error) {
	if body, ok := s.getMem(handle); ok {
		return body, nil
	}
	if !s.enabled {
		return nil, fmt.Errorf("aggregate: spool handle not found: %s", handle)
	}
	body, err := s.store.Get(ctx, handle)
	if err != nil {
		s.metrics.RecordSpoolError()
		return nil, err
	}
	return body, nil
}

// Cleanup removes all spooled entries for this aggregation. It is safe to call
// multiple times and never returns an error to the caller path; failures are
// logged and counted.
func (s *Spooler) Cleanup(ctx context.Context) {
	s.memMu.Lock()
	keys := s.keys
	s.keys = nil
	s.mem = make(map[string][]byte)
	s.memMu.Unlock()

	if !s.enabled {
		return
	}
	for _, key := range keys {
		if err := s.store.Delete(ctx, key); err != nil {
			s.metrics.RecordSpoolError()
			s.logger.Debug("aggregate spool cleanup failed",
				observability.String("key", key),
				observability.Error(err),
			)
		}
	}
}

// putMem stores a body in the in-memory fallback and tracks its key.
func (s *Spooler) putMem(handle string, body []byte) {
	s.memMu.Lock()
	s.mem[handle] = body
	s.keys = append(s.keys, handle)
	s.memMu.Unlock()
}

// getMem reads a body from the in-memory fallback.
func (s *Spooler) getMem(handle string) ([]byte, bool) {
	s.memMu.Lock()
	body, ok := s.mem[handle]
	s.memMu.Unlock()
	return body, ok
}

// newHandle builds a namespaced, hashed spool key incorporating a random nonce
// so concurrent aggregations never collide.
func (s *Spooler) newHandle(target string) string {
	var nonce [16]byte
	if _, err := cryptorand.Read(nonce[:]); err != nil {
		// Fall back to a time-based nonce; uniqueness is best-effort here and
		// collisions only affect a single in-flight aggregation.
		t := uint64(time.Now().UnixNano())
		for i := 0; i < len(nonce); i++ {
			nonce[i] = byte((t >> (uint(i%8) * 8)) & 0xff)
		}
	}
	sum := sha256.Sum256(append([]byte(target+":"), nonce[:]...))
	return spoolKeyPrefix + hex.EncodeToString(sum[:])
}

// jitteredTTL applies proportional jitter to the configured TTL.
func (s *Spooler) jitteredTTL() time.Duration {
	if spoolTTLJitter <= 0 {
		return s.ttl
	}
	//nolint:gosec // G404: jitter for cache TTL is not security-sensitive
	delta := float64(s.ttl) * spoolTTLJitter * mathrand.Float64()
	return s.ttl + time.Duration(delta)
}
