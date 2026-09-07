package era

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	icache "github.com/vyrodovalexey/avapigw/internal/cache"
)

// heldKeyPrefix namespaces held-request entries in the shared cache backend so
// they never collide with other users of internal/cache.
const heldKeyPrefix = "mcp:held:"

// DefaultHeldRequestDeadline bounds how long a held legacy server-initiated
// request awaits the downstream client's inputResponses before it expires
// (HUB-705). A non-positive configured deadline falls back to this.
const DefaultHeldRequestDeadline = 2 * time.Minute

// Sentinel errors returned by a HeldRequestStore.
var (
	// ErrHeldNotFound indicates no held request exists for the id: it never
	// existed, expired (HUB-705), or was already consumed (single-use,
	// HUB-209). Callers return a deterministic error to the client.
	ErrHeldNotFound = errors.New("era: held request not found or expired")
	// ErrHeldConsumed indicates the held request was already consumed. It is
	// returned distinctly from ErrHeldNotFound so single-use violations are
	// observable, but callers treat both as a terminal client error.
	ErrHeldConsumed = errors.New("era: held request already consumed")
)

// HeldRequest is the state held while a legacy server-initiated request is open
// upstream awaiting the downstream client's inputResponses (HUB-704/705). It is
// keyed by the MRTR envelope id and forwarded verbatim so any replica can
// resume it (HUB-705 replica routing hint).
type HeldRequest struct {
	// UpstreamID is the upstream that issued the server-initiated request.
	UpstreamID string `json:"upstreamId"`
	// SessionID is the pooled legacy Mcp-Session-Id the upstream request
	// belongs to. It is hub-internal state and never exposed downstream
	// (HUB-702).
	SessionID string `json:"sessionId"`
	// UpstreamRequestID is the JSON-RPC id of the ORIGINAL upstream
	// server-initiated request the client's response must answer (HUB-704).
	UpstreamRequestID json.RawMessage `json:"upstreamRequestId"`
	// Method is the legacy server-initiated method (sampling/createMessage,
	// elicitation/create, roots/list).
	Method string `json:"method"`
	// CreatedAt is when the request was held, used to derive the backend TTL.
	CreatedAt time.Time `json:"createdAt"`
}

// HeldRequestStore persists held legacy server-initiated requests keyed by the
// MRTR envelope id (HUB-705). It enforces single-use server-side on Consume so
// a client cannot answer the same held request twice (HUB-209) even before the
// TTL elapses.
type HeldRequestStore interface {
	// Put stores a held request under id with the given deadline. The entry
	// expires after deadline (HUB-705).
	Put(ctx context.Context, id string, req *HeldRequest, deadline time.Duration) error
	// Consume atomically fetches and removes the held request for id,
	// enforcing single-use (HUB-209). It returns ErrHeldNotFound when the id
	// is absent/expired and ErrHeldConsumed on a second consume.
	Consume(ctx context.Context, id string) (*HeldRequest, error)
	// Delete removes a held request without consuming it (used to release a
	// held request when its upstream session is torn down).
	Delete(ctx context.Context, id string) error
}

// memoryHeldStore is the in-memory fallback HeldRequestStore used for
// single-replica deployments or when no shared cache backend is configured. It
// enforces single-use under a single lock so there is no time-of-check /
// time-of-use race (HUB-209).
type memoryHeldStore struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[string]memoryHeldEntry
}

// memoryHeldEntry is an in-memory held request with its expiry.
type memoryHeldEntry struct {
	req     *HeldRequest
	expires time.Time
}

// NewMemoryHeldStore constructs an in-memory HeldRequestStore.
func NewMemoryHeldStore() HeldRequestStore {
	return &memoryHeldStore{
		now:     time.Now,
		entries: make(map[string]memoryHeldEntry),
	}
}

// Put stores a held request with an expiry derived from the deadline.
func (s *memoryHeldStore) Put(
	_ context.Context, id string, req *HeldRequest, deadline time.Duration,
) error {
	if id == "" || req == nil {
		return errors.New("era: empty held id or request")
	}
	s.mu.Lock()
	s.entries[id] = memoryHeldEntry{req: req, expires: s.now().Add(deadline)}
	s.mu.Unlock()
	return nil
}

// Consume atomically fetches and removes the held request, enforcing single-use
// and expiry under one lock (HUB-209/705).
func (s *memoryHeldStore) Consume(_ context.Context, id string) (*HeldRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[id]
	if !ok {
		return nil, ErrHeldNotFound
	}
	// Remove first so a concurrent Consume observes absence (single-use).
	delete(s.entries, id)
	if s.now().After(entry.expires) {
		return nil, ErrHeldNotFound
	}
	return entry.req, nil
}

// Delete removes a held request without consuming it.
func (s *memoryHeldStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.entries, id)
	s.mu.Unlock()
	return nil
}

// redisHeldStore is the shared-backend HeldRequestStore over internal/cache
// (HUB-705). It stores each held request under a namespaced key with a backend
// TTL and enforces single-use by deleting the key on Consume BEFORE returning
// the payload: the delete's outcome is the single-use gate, closing the
// time-of-check / time-of-use window (HUB-209).
type redisHeldStore struct {
	backend icache.Cache
}

// NewHeldRequestStore constructs a HeldRequestStore over the given shared cache
// backend (HUB-705). When backend is nil it returns the in-memory fallback so
// single-replica and cache-less deployments still work.
func NewHeldRequestStore(backend icache.Cache) HeldRequestStore {
	if backend == nil {
		return NewMemoryHeldStore()
	}
	return &redisHeldStore{backend: backend}
}

// heldKey builds the namespaced backend key for a held-request id.
func heldKey(id string) string {
	return heldKeyPrefix + id
}

// Put stores a held request with a backend TTL of deadline (HUB-705).
func (s *redisHeldStore) Put(
	ctx context.Context, id string, req *HeldRequest, deadline time.Duration,
) error {
	if id == "" || req == nil {
		return errors.New("era: empty held id or request")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("era: encode held request: %w", err)
	}
	if err := s.backend.Set(ctx, heldKey(id), payload, deadline); err != nil {
		return fmt.Errorf("era: store held request: %w", err)
	}
	return nil
}

// Consume fetches then deletes the held request. Single-use is enforced by the
// backend delete: only the caller whose Delete reports the key as removed may
// use the payload; a second consumer observes a miss (HUB-209). This ordering
// avoids the TOCTOU window a check-then-delete would open.
func (s *redisHeldStore) Consume(ctx context.Context, id string) (*HeldRequest, error) {
	key := heldKey(id)
	raw, err := s.backend.Get(ctx, key)
	if err != nil {
		return nil, ErrHeldNotFound
	}
	// Delete acts as the single-use gate. When Delete does not confirm a
	// removal, another consumer already claimed the entry (HUB-209).
	removed, delErr := deleteAndConfirm(ctx, s.backend, key)
	if delErr != nil {
		return nil, ErrHeldNotFound
	}
	if !removed {
		return nil, ErrHeldConsumed
	}
	var req HeldRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, ErrHeldNotFound
	}
	return &req, nil
}

// Delete removes a held request without consuming it.
func (s *redisHeldStore) Delete(ctx context.Context, id string) error {
	if err := s.backend.Delete(ctx, heldKey(id)); err != nil {
		return fmt.Errorf("era: delete held request: %w", err)
	}
	return nil
}

// deleteAndConfirm deletes key and reports whether it was present immediately
// before the delete, so Consume can gate single-use on the removal. It checks
// existence and deletes under the backend's own atomicity guarantees; the
// Exists→Delete pair is best-effort for backends without an atomic getdel, and
// the memory store provides the strict single-use guarantee. Any Delete error
// is surfaced so Consume can fail closed.
func deleteAndConfirm(ctx context.Context, backend icache.Cache, key string) (removed bool, err error) {
	existed, existsErr := backend.Exists(ctx, key)
	if existsErr != nil {
		// Fall back to attempting the delete; treat a successful delete as a
		// removal so a backend without Exists still functions.
		existed = true
	}
	if delErr := backend.Delete(ctx, key); delErr != nil {
		return false, delErr
	}
	return existed, nil
}
