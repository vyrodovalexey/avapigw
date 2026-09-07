// Package era implements the MCP hub's HTTP dual-era bridging (Milestone M6,
// HUB-701..707, HUB-721..724): it lets a modern downstream client talk to a
// legacy (initialization-based) HTTP upstream without either side observing the
// other's era. The hub speaks the legacy handshake/session to the upstream,
// pools sessions per upstream (never per downstream client), translates legacy
// subscribe/unsubscribe and server-initiated requests, holds MRTR state, and
// normalizes legacy results into the modern shape.
//
// This package is HTTP/HTTPS only; stdio is out of scope. Modern-only
// deployments are unaffected: the era-aware wrapper delegates directly to the
// existing modern hub client whenever an upstream is modern.
package era

import (
	"context"
	"sync"
	"time"

	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
)

// Era is the determined protocol era of an upstream.
type Era string

const (
	// EraUnknown marks an upstream whose era has not yet been determined.
	EraUnknown Era = ""
	// EraModern marks a modern (stateless, per-request `_meta`) upstream.
	EraModern Era = "modern"
	// EraLegacy marks a legacy (initialize handshake, sessions) upstream.
	EraLegacy Era = "legacy"
)

// metricLabel maps an Era to its bounded metrics label value.
func (e Era) metricLabel() string {
	if e == EraLegacy {
		return mcpmetrics.EraLegacy
	}
	return mcpmetrics.EraModern
}

// DefaultEraCacheTTL bounds how long a cached era determination is trusted
// before it is treated as stale and re-probed (HUB-723). A non-positive
// configured TTL falls back to this.
const DefaultEraCacheTTL = 30 * time.Minute

// eraEntry is a cached era determination with its expiry.
type eraEntry struct {
	era     Era
	expires time.Time
}

// EraCache caches the era determination per upstream origin (HUB-723). It is an
// in-memory, concurrency-safe store keyed by origin; the era-aware client
// invalidates an entry when the cached assumption fails so the next request
// re-probes.
type EraCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.RWMutex
	entries map[string]eraEntry
}

// EraCacheOption configures an EraCache.
type EraCacheOption func(*EraCache)

// WithEraCacheTTL sets the cache entry TTL. A non-positive value is ignored.
func WithEraCacheTTL(ttl time.Duration) EraCacheOption {
	return func(c *EraCache) {
		if ttl > 0 {
			c.ttl = ttl
		}
	}
}

// WithEraCacheClock overrides the time source (test seam).
func WithEraCacheClock(now func() time.Time) EraCacheOption {
	return func(c *EraCache) {
		if now != nil {
			c.now = now
		}
	}
}

// NewEraCache constructs an EraCache.
func NewEraCache(opts ...EraCacheOption) *EraCache {
	c := &EraCache{
		ttl:     DefaultEraCacheTTL,
		now:     time.Now,
		entries: make(map[string]eraEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Get returns the cached era for an origin and whether a live (non-expired)
// entry exists (HUB-723).
func (c *EraCache) Get(origin string) (Era, bool) {
	c.mu.RLock()
	entry, ok := c.entries[origin]
	c.mu.RUnlock()
	if !ok {
		return EraUnknown, false
	}
	if c.now().After(entry.expires) {
		return EraUnknown, false
	}
	return entry.era, true
}

// Set records the era for an origin with a fresh TTL (HUB-723).
func (c *EraCache) Set(origin string, era Era) {
	c.mu.Lock()
	c.entries[origin] = eraEntry{era: era, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

// Invalidate drops the cached era for an origin so the next request re-probes
// (HUB-723).
func (c *EraCache) Invalidate(origin string) {
	c.mu.Lock()
	delete(c.entries, origin)
	c.mu.Unlock()
}

// Pin resolves a configuration era pin into a determined Era (HUB-724). An
// upstream pinned to "modern"/"legacy" (or carrying a PinnedVersion) bypasses
// probing. It returns EraUnknown when nothing is pinned.
func Pin(configuredEra, pinnedVersion string) Era {
	switch configuredEra {
	case string(EraModern):
		return EraModern
	case string(EraLegacy):
		return EraLegacy
	}
	// A pinned protocol version implies the legacy interop era: modern
	// upstreams negotiate the version per request via `_meta`, so an explicit
	// pin is only meaningful for the initialization-based legacy handshake.
	if pinnedVersion != "" {
		return EraLegacy
	}
	return EraUnknown
}

// Determiner resolves and caches the era of an upstream. It honors a
// configuration pin (HUB-724) first, then a cached determination (HUB-723),
// and finally delegates the live probe to a Prober (HUB-721). It records the
// determination metric exactly once per resolution.
type Determiner struct {
	cache   *EraCache
	metrics *mcpmetrics.Metrics
}

// NewDeterminer constructs a Determiner over the given cache. A nil cache
// yields a fresh in-memory cache; a nil metrics recorder falls back to the
// singleton.
func NewDeterminer(cache *EraCache, metrics *mcpmetrics.Metrics) *Determiner {
	if cache == nil {
		cache = NewEraCache()
	}
	if metrics == nil {
		metrics = mcpmetrics.GetMetrics()
	}
	return &Determiner{cache: cache, metrics: metrics}
}

// Prober performs a live era probe for an upstream when the era is neither
// pinned nor cached (HUB-721). It returns the determined era or an error.
type Prober interface {
	// Probe determines the era of the upstream identified by upstreamID whose
	// requests target origin. It attempts a modern request first and inspects
	// the body of a 400 before falling back to legacy (HUB-721).
	Probe(ctx context.Context, upstreamID, origin string) (Era, error)
}

// Determine resolves the era for an upstream: pin (HUB-724) → cache (HUB-723)
// → live probe (HUB-721). A successful probe result is cached and metered. A
// pinned era is cached so subsequent lookups are cheap but is not re-metered on
// cache hits.
func (d *Determiner) Determine(
	ctx context.Context, upstreamID, origin, configuredEra, pinnedVersion string, prober Prober,
) (Era, error) {
	if pinned := Pin(configuredEra, pinnedVersion); pinned != EraUnknown {
		d.cache.Set(origin, pinned)
		d.metrics.RecordEraDetermination(upstreamID, pinned.metricLabel())
		return pinned, nil
	}
	if cached, ok := d.cache.Get(origin); ok {
		return cached, nil
	}
	era, err := prober.Probe(ctx, upstreamID, origin)
	if err != nil {
		return EraUnknown, err
	}
	d.cache.Set(origin, era)
	d.metrics.RecordEraDetermination(upstreamID, era.metricLabel())
	return era, nil
}

// Invalidate drops the cached era for an origin so the next Determine re-probes
// (HUB-723). The era-aware client calls this when a cached assumption fails.
func (d *Determiner) Invalidate(origin string) {
	d.cache.Invalidate(origin)
}
