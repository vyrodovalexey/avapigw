// Package aggregate implements aggregate (fan-out) mirroring: a single client
// request is fanned out to multiple backends in parallel, their responses are
// optionally merged or wrapped in labeled envelopes, and a single aggregated
// result is returned.
//
// The package is intentionally free of api/v1alpha1, operator and proxy imports
// to avoid import cycles. Callers inject backend invokers via interfaces,
// mirroring the RouteMiddlewareApplier decoupling pattern used elsewhere.
package aggregate

import (
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// FailMode determines how partial backend failures are handled.
type FailMode string

// FailMode constants.
const (
	FailModeAll    FailMode = "all"
	FailModeAny    FailMode = "any"
	FailModeQuorum FailMode = "quorum"
)

// SpoolBackend constants.
const (
	SpoolBackendMemory = "memory"
	SpoolBackendRedis  = "redis"
)

// Default runtime constants.
const (
	// DefaultMaxParallel is the default bound on concurrent target invocations.
	DefaultMaxParallel = 8

	// DefaultTargetTimeout is the default per-target request timeout.
	DefaultTargetTimeout = 30 * time.Second

	// DefaultSpoolThresholdBytes is the default off-heap spool threshold.
	DefaultSpoolThresholdBytes = 1 << 20

	// DefaultSpoolTTL is the default spool entry lifetime.
	DefaultSpoolTTL = 5 * time.Minute
)

// Config is the runtime aggregate configuration consumed by the engine. It is a
// protocol-agnostic projection of config.AggregateConfig produced by the mapping
// layer (see mapper.go).
type Config struct {
	// Enabled reports whether aggregate fan-out is active.
	Enabled bool

	// Targets is the ordered list of fan-out targets.
	Targets []Target

	// Merge holds optional merge options (nil means labeled-envelope output).
	Merge *MergeOptions

	// Spool holds optional spool options (nil means in-memory buffering).
	Spool *SpoolOptions

	// FailMode controls partial-failure handling.
	FailMode FailMode

	// QuorumCount is the explicit quorum threshold (0 means majority).
	QuorumCount int

	// MaxParallel bounds concurrent target invocations.
	MaxParallel int

	// PerMessageMerge enables per-message merge for streaming traffic.
	PerMessageMerge bool
}

// Target is a single fan-out backend destination at runtime.
type Target struct {
	// Name is the unique label used in metrics, tracing and envelopes.
	Name string

	// Host is the backend host.
	Host string

	// Port is the backend port.
	Port int

	// Timeout is the per-target request timeout.
	Timeout time.Duration

	// Retries is the maximum number of retry attempts for transient errors.
	Retries int

	// TLS holds per-target TLS configuration (may be nil).
	TLS *config.BackendTLSConfig

	// Auth holds per-target authentication configuration (may be nil).
	Auth *config.BackendAuthConfig
}

// MergeOptions holds runtime merge options.
type MergeOptions struct {
	// Enabled reports whether merging is enabled.
	Enabled bool

	// Strategy is the merge strategy (deep|shallow|replace|ndjson).
	Strategy string

	// TimeField is the NDJSON sort key (ndjson strategy only). Empty disables
	// sorting. Default applied at config layer is "_time".
	TimeField string

	// KeyField is the NDJSON de-duplication key (ndjson strategy only). Empty
	// disables de-duplication.
	KeyField string

	// Limit caps the number of emitted NDJSON records (ndjson strategy only).
	// 0 means unlimited.
	Limit int
}

// SpoolOptions holds runtime spool options.
type SpoolOptions struct {
	// Enabled reports whether off-heap spooling is enabled.
	Enabled bool

	// Backend is the spool backend (memory|redis).
	Backend string

	// ThresholdBytes is the body-size threshold above which responses spool.
	ThresholdBytes int64

	// TTL is the spool entry lifetime.
	TTL time.Duration
}

// EffectiveMaxParallel returns the bound on concurrent target invocations,
// clamped to the number of targets.
func (c *Config) EffectiveMaxParallel() int {
	maxParallel := c.MaxParallel
	if maxParallel <= 0 {
		maxParallel = DefaultMaxParallel
	}
	if n := len(c.Targets); n > 0 && maxParallel > n {
		maxParallel = n
	}
	return maxParallel
}

// successThreshold returns the number of successful targets required for the
// aggregate request to be considered successful under the configured FailMode.
func (c *Config) successThreshold() int {
	total := len(c.Targets)
	switch c.FailMode {
	case FailModeAny:
		return 1
	case FailModeQuorum:
		if c.QuorumCount > 0 {
			return c.QuorumCount
		}
		return total/2 + 1
	case FailModeAll:
		return total
	default:
		return total
	}
}
