// Package cache implements the MCP hub's result-caching policy over the shared
// internal/cache backend (HUB-181..186). It stores complete discovery, list and
// resources/read results, emits ttlMs / cacheScope on those results, aggregates
// TTLs to the clamped minimum of contributors, keeps a private result out of a
// different authorization context by folding an auth-context component into the
// cache key, refuses to cache MRTR-bearing requests, and exposes invalidation
// hooks for list_changed / resources/updated notifications.
//
// This package deliberately does NOT enforce authorization: per-primitive
// authz is enforced by the caller on EVERY request including cache hits
// (HUB-307). The cache only prevents cross-context reuse of private entries.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	icache "github.com/vyrodovalexey/avapigw/internal/cache"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// cacheScope values emitted / consumed by the MCP cache (HUB-182).
const (
	scopePublic  = "public"
	scopePrivate = "private"
)

// keyPrefix namespaces every MCP cache entry so it never collides with other
// users of the shared cache backend.
const keyPrefix = "mcp:"

// jitterFraction is the maximum fraction of TTL added as random jitter to
// spread expiries and avoid thundering-herd re-population (Redis TTL jitter).
const jitterFraction = 0.1

// DefaultMinTTL / DefaultMaxTTL are the default clamp bounds applied to
// aggregated TTLs when the configuration does not set them (HUB-182).
const (
	DefaultMinTTL = 1 * time.Second
	DefaultMaxTTL = 5 * time.Minute
)

// ErrNilBackend indicates the cache was constructed without a backend.
var ErrNilBackend = errors.New("mcp cache: nil backend")

// Entry is the cached payload plus the cache metadata the hub re-emits on a
// cache hit so ttlMs / cacheScope stay consistent across pages (HUB-186).
type Entry struct {
	// Result is the cached JSON-RPC result payload.
	Result json.RawMessage `json:"result"`
	// TTLMs is the aggregated cache TTL in milliseconds (HUB-181/182).
	TTLMs int64 `json:"ttlMs"`
	// CacheScope is "public" or "private" (HUB-182).
	CacheScope string `json:"cacheScope"`
	// StoredAt is when the entry was written, used to derive the remaining
	// TTL on read so the re-emitted ttlMs decays.
	StoredAt time.Time `json:"storedAt"`
}

// KeyParts identifies a cache entry independent of authorization context.
type KeyParts struct {
	// Upstream is the upstream id, or "" for aggregated hub-level results.
	Upstream string
	// Method is the MCP method.
	Method string
	// Params is a stable representation of the effective request parameters.
	Params string
	// Cursor is the pagination cursor, folded in so each page is distinct.
	Cursor string
}

// Cache is the MCP result cache surface.
type Cache interface {
	// Get returns a cached entry for the key and auth context. private
	// selects whether the auth-context component is folded into the key.
	Get(ctx context.Context, parts KeyParts, authContext string, private bool) (*Entry, bool)
	// Set stores an entry. Results carrying inputResponses / requestState
	// are never stored (HUB-184); callers should not call Set for them.
	Set(ctx context.Context, parts KeyParts, authContext string, entry *Entry) error
	// Invalidate drops cached entries affected by an upstream notification
	// (HUB-185). kind is the primitive kind ("tools", "prompts",
	// "resources"); uri is the affected resource URI for resources/updated.
	Invalidate(ctx context.Context, upstream, kind, uri string)
}

// Config configures the MCP cache clamps and behavior.
type Config struct {
	// TTLMin / TTLMax clamp the aggregated TTL (HUB-182).
	TTLMin time.Duration
	// TTLMax is the upper clamp.
	TTLMax time.Duration
}

// defaulted returns cfg with zero fields replaced by defaults.
func (c Config) defaulted() Config {
	if c.TTLMin <= 0 {
		c.TTLMin = DefaultMinTTL
	}
	if c.TTLMax <= 0 || c.TTLMax < c.TTLMin {
		c.TTLMax = DefaultMaxTTL
	}
	return c
}

// ResultCache is the default Cache implementation over internal/cache.Cache.
type ResultCache struct {
	backend icache.Cache
	cfg     Config
	metrics *mcpmetrics.Metrics
	logger  observability.Logger
}

// Option is a functional option for ResultCache.
type Option func(*ResultCache)

// WithLogger sets the cache logger.
func WithLogger(logger observability.Logger) Option {
	return func(c *ResultCache) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithMetrics sets the metrics recorder.
func WithMetrics(m *mcpmetrics.Metrics) Option {
	return func(c *ResultCache) {
		if m != nil {
			c.metrics = m
		}
	}
}

// New constructs a ResultCache over the given backend and clamp config.
func New(backend icache.Cache, cfg Config, opts ...Option) (*ResultCache, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	c := &ResultCache{
		backend: backend,
		cfg:     cfg.defaulted(),
		metrics: mcpmetrics.GetMetrics(),
		logger:  observability.NopLogger(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Get looks up a cached entry (HUB-183). For a private lookup the auth-context
// component is folded into the key so a private result is never reused across
// authorization contexts. The returned entry's TTLMs is decayed by the time
// already elapsed so a cache hit re-emits a shrinking ttlMs.
func (c *ResultCache) Get(
	ctx context.Context, parts KeyParts, authContext string, private bool,
) (*Entry, bool) {
	key := c.buildKey(parts, authContext, private)
	raw, err := c.backend.Get(ctx, key)
	if err != nil {
		c.metrics.CacheMissesTotal.WithLabelValues(parts.Upstream, parts.Method).Inc()
		return nil, false
	}
	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		c.metrics.CacheMissesTotal.WithLabelValues(parts.Upstream, parts.Method).Inc()
		return nil, false
	}
	c.metrics.CacheHitsTotal.WithLabelValues(parts.Upstream, parts.Method).Inc()
	entry.TTLMs = remainingTTLMs(&entry)
	return &entry, true
}

// Set stores an entry with a jittered backend TTL derived from the entry's
// (already clamped) TTLMs. A private entry keys on the auth context; a public
// entry does not (HUB-183).
func (c *ResultCache) Set(
	ctx context.Context, parts KeyParts, authContext string, entry *Entry,
) error {
	if entry == nil {
		return nil
	}
	private := entry.CacheScope == scopePrivate
	key := c.buildKey(parts, authContext, private)
	entry.StoredAt = time.Now()

	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("mcp cache: encode entry: %w", err)
	}
	ttl := jitteredTTL(time.Duration(entry.TTLMs) * time.Millisecond)
	if err := c.backend.Set(ctx, key, payload, ttl); err != nil {
		return fmt.Errorf("mcp cache: store entry: %w", err)
	}
	return nil
}

// Invalidate is the notification-driven invalidation hook (HUB-185). The
// underlying cache.Cache interface exposes only single-key Delete, so this
// deletes the well-known aggregate list key for the affected kind and, for a
// resources/updated notification, the specific resources/read entry.
//
// It intentionally performs no active polling: ttlMs is never treated as a
// polling interval. Any future poller must apply jitter and backoff (the
// jittered TTL and the exported PollBackoff helper support that).
func (c *ResultCache) Invalidate(ctx context.Context, upstream, kind, uri string) {
	method := listMethodForKind(kind)
	if method != "" {
		key := c.buildKey(KeyParts{Upstream: upstream, Method: method}, "", false)
		if err := c.backend.Delete(ctx, key); err != nil {
			c.logger.Debug("mcp cache: invalidate list failed",
				observability.String("upstream", upstream),
				observability.String("kind", kind),
				observability.Error(err))
		}
	}
	if uri != "" {
		key := c.buildKey(
			KeyParts{Upstream: upstream, Method: "resources/read", Params: uri}, "", false,
		)
		if err := c.backend.Delete(ctx, key); err != nil {
			c.logger.Debug("mcp cache: invalidate resource failed",
				observability.String("upstream", upstream),
				observability.String("uri", uri),
				observability.Error(err))
		}
	}
}

// buildKey builds the cache key. For private entries the auth-context hash is
// folded in so private results never leak across authorization contexts
// (HUB-183). Public entries omit the auth-context component so they are shared.
func (c *ResultCache) buildKey(parts KeyParts, authContext string, private bool) string {
	var b strings.Builder
	b.WriteString(keyPrefix)
	b.WriteString(parts.Upstream)
	b.WriteByte('|')
	b.WriteString(parts.Method)
	b.WriteByte('|')
	b.WriteString(hashComponent(parts.Params))
	b.WriteByte('|')
	b.WriteString(hashComponent(parts.Cursor))
	if private {
		b.WriteByte('|')
		b.WriteString(hashComponent(authContext))
	}
	// Hash the whole composite so the stored key length is bounded and no
	// user-controlled bytes reach the backend key verbatim.
	return keyPrefix + hashComponent(b.String())
}

// ClampTTL clamps a raw aggregated TTL (in milliseconds) to the configured
// [min,max] window and returns the clamped milliseconds (HUB-182).
func (c *ResultCache) ClampTTL(ttlMs int64) int64 {
	minMs := c.cfg.TTLMin.Milliseconds()
	maxMs := c.cfg.TTLMax.Milliseconds()
	if ttlMs < minMs {
		return minMs
	}
	if ttlMs > maxMs {
		return maxMs
	}
	return ttlMs
}

// AggregateTTLMs returns the minimum TTL across the contributors clamped to the
// configured window (HUB-182). An empty contributor set yields the min clamp.
func (c *ResultCache) AggregateTTLMs(contributors []int64) int64 {
	if len(contributors) == 0 {
		return c.cfg.TTLMin.Milliseconds()
	}
	minTTL := contributors[0]
	for _, v := range contributors[1:] {
		if v < minTTL {
			minTTL = v
		}
	}
	return c.ClampTTL(minTTL)
}

// AggregateScope returns "private" when any contributor is private or the
// response was filtered by the caller's authorization (HUB-182).
func AggregateScope(contributorScopes []string, authFiltered bool) string {
	if authFiltered {
		return scopePrivate
	}
	for _, s := range contributorScopes {
		if s == scopePrivate {
			return scopePrivate
		}
	}
	return scopePublic
}

// AuthContextKey derives a stable, non-reversible auth-context key component
// from the principal and the sorted granted scopes (HUB-183). It is folded into
// the cache key for private entries so two callers with different grants never
// share a private cache entry.
func AuthContextKey(principal string, grantedScopes []string) string {
	scopes := append([]string(nil), grantedScopes...)
	sort.Strings(scopes)
	return hashComponent(principal + "\x00" + strings.Join(scopes, " "))
}

// listMethodForKind maps a notification primitive kind to the list method whose
// cached result it invalidates.
func listMethodForKind(kind string) string {
	switch kind {
	case "tools":
		return "tools/list"
	case "prompts":
		return "prompts/list"
	case "resources":
		return "resources/list"
	default:
		return ""
	}
}

// remainingTTLMs returns the entry's TTL decayed by the elapsed time since it
// was stored, floored at zero, so a cache hit re-emits a shrinking ttlMs.
func remainingTTLMs(e *Entry) int64 {
	if e.StoredAt.IsZero() {
		return e.TTLMs
	}
	elapsed := time.Since(e.StoredAt).Milliseconds()
	remaining := e.TTLMs - elapsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// jitteredTTL adds up to jitterFraction of random jitter to a base TTL to avoid
// synchronized expiry across replicas. A non-positive base disables caching by
// returning a tiny positive TTL so entries are effectively skipped.
func jitteredTTL(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Millisecond
	}
	//nolint:gosec // G404: non-cryptographic jitter to de-synchronize cache expiry
	jitter := time.Duration(rand.Float64() * jitterFraction * float64(base))
	return base + jitter
}

// hashComponent returns a hex sha256 of s, bounding key length and keeping
// user-controlled bytes out of backend keys verbatim (Redis hash key).
func hashComponent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
