// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// FailMode determines how partial backend failures are handled during an
// aggregate (fan-out) request.
type FailMode string

// FailMode constants for aggregate fan-out partial-failure handling.
const (
	// FailModeAll requires every target to succeed; any failure fails the
	// aggregate request.
	FailModeAll FailMode = "all"

	// FailModeAny requires at least one target to succeed.
	FailModeAny FailMode = "any"

	// FailModeQuorum requires a quorum (majority, or QuorumCount when set) of
	// targets to succeed.
	FailModeQuorum FailMode = "quorum"
)

// Aggregate spool backend constants.
const (
	// SpoolBackendMemory keeps partial responses on-heap (default).
	SpoolBackendMemory = "memory"

	// SpoolBackendRedis spools partial responses to Redis (off-heap) for large
	// bodies and/or many targets.
	SpoolBackendRedis = "redis"
)

// Default aggregate configuration constants.
const (
	// DefaultAggregateMaxParallel is the default bound on parallel target
	// invocations.
	DefaultAggregateMaxParallel = 8

	// DefaultAggregateTargetTimeout is the default per-target request timeout.
	DefaultAggregateTargetTimeout = 30 * time.Second

	// DefaultAggregateSpoolThresholdBytes is the default body-size threshold
	// (in bytes) above which responses are spooled off-heap when spooling is
	// enabled.
	DefaultAggregateSpoolThresholdBytes = 1 << 20 // 1MB

	// MinAggregateTargets is the minimum number of targets for an aggregate
	// configuration.
	MinAggregateTargets = 1

	// defaultNDJSONTimeField is the default NDJSON sort key applied when the
	// ndjson merge strategy is selected without an explicit TimeField.
	defaultNDJSONTimeField = "_time"

	// envAggregateMaxParallel overrides AggregateConfig.MaxParallel.
	envAggregateMaxParallel = "AVAPIGW_AGGREGATE_MAX_PARALLEL"

	// envAggregateSpoolThreshold overrides SpoolOptions.ThresholdBytes.
	envAggregateSpoolThreshold = "AVAPIGW_AGGREGATE_SPOOL_THRESHOLD_BYTES"
)

// AggregateConfig represents aggregate (fan-out) mirroring configuration.
//
// This is distinct from MirrorConfig (single-destination, fire-and-forget
// shadow traffic). AggregateConfig fans a single client request out to multiple
// backends in parallel, optionally merges their responses, and returns a single
// aggregated response. Merge and Redis spooling are both optional.
type AggregateConfig struct {
	// Enabled enables aggregate fan-out for this route.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Targets is the list of backends to fan out to (at least one).
	Targets []AggregateTarget `yaml:"targets,omitempty" json:"targets,omitempty"`

	// Merge configures optional response merging.
	Merge *MergeOptions `yaml:"merge,omitempty" json:"merge,omitempty"`

	// Spool configures optional off-heap (Redis) spooling for large responses.
	Spool *SpoolOptions `yaml:"spool,omitempty" json:"spool,omitempty"`

	// FailMode controls partial-failure handling (all|any|quorum). Default: all.
	FailMode FailMode `yaml:"failMode,omitempty" json:"failMode,omitempty"`

	// QuorumCount is the explicit success threshold when FailMode is quorum.
	// When zero, a simple majority is used.
	QuorumCount int `yaml:"quorumCount,omitempty" json:"quorumCount,omitempty"`

	// MaxParallel bounds the number of concurrent target invocations.
	// Default: DefaultAggregateMaxParallel.
	MaxParallel int `yaml:"maxParallel,omitempty" json:"maxParallel,omitempty"`

	// PerMessageMerge enables per-message JSON merge for streaming traffic
	// (WS / gRPC streaming). Default: false (passthrough framed interleave).
	PerMessageMerge bool `yaml:"perMessageMerge,omitempty" json:"perMessageMerge,omitempty"`
}

// AggregateTarget describes a single fan-out backend destination.
type AggregateTarget struct {
	// Name is a stable, human-readable label for this target. Used in metrics,
	// tracing and the labeled-envelope output. Must be unique within a config.
	Name string `yaml:"name" json:"name"`

	// Destination is the backend destination (host + port).
	Destination Destination `yaml:"destination" json:"destination"`

	// Timeout is the per-target request timeout. Default:
	// DefaultAggregateTargetTimeout.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retries is the maximum number of retry attempts for transient errors.
	Retries int `yaml:"retries,omitempty" json:"retries,omitempty"`

	// TLS configures per-target TLS (including mTLS) for the backend connection.
	TLS *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Authentication configures per-target backend authentication
	// (basic/JWT/OIDC/mTLS). Sensitive values may reference Vault.
	Authentication *BackendAuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`
}

// MergeOptions configures optional response merging for aggregate fan-out.
type MergeOptions struct {
	// Enabled enables merging. When false the labeled-envelope output is used.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Strategy is the merge strategy (deep|shallow|replace|ndjson). Default: deep.
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty"`

	// TimeField is the NDJSON sort key (ndjson strategy only). Records are
	// stably sorted by this field. Default: "_time"; an empty value disables
	// sorting. Records lacking the field sort after those that have it.
	TimeField string `yaml:"timeField,omitempty" json:"timeField,omitempty"`

	// KeyField is the NDJSON de-duplication key (ndjson strategy only). When
	// set, duplicate records (by this field's value) are removed first-wins
	// after sorting. Empty disables de-duplication; records lacking the field
	// are never de-duplicated.
	KeyField string `yaml:"keyField,omitempty" json:"keyField,omitempty"`

	// Limit caps the number of emitted NDJSON records (ndjson strategy only).
	// 0 means unlimited; must be non-negative.
	Limit int `yaml:"limit,omitempty" json:"limit,omitempty"`
}

// SpoolOptions configures optional off-heap spooling of partial responses.
type SpoolOptions struct {
	// Enabled enables off-heap spooling. When false (or when Redis is
	// unavailable) responses are buffered in memory.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Backend is the spool backend (memory|redis). Default: memory.
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"`

	// ThresholdBytes is the body-size threshold (in bytes) above which a
	// response is spooled. Default: DefaultAggregateSpoolThresholdBytes.
	ThresholdBytes int64 `yaml:"thresholdBytes,omitempty" json:"thresholdBytes,omitempty"`

	// RedisRef configures the Redis connection used when Backend is redis.
	RedisRef *AggregateRedisRef `yaml:"redisRef,omitempty" json:"redisRef,omitempty"`

	// TTL is the lifetime of spooled entries. Default: 5m.
	TTL Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

// AggregateRedisRef references the Redis connection used for spooling.
type AggregateRedisRef struct {
	// Address is the standalone Redis address (host:port). Mutually exclusive
	// with Sentinel.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`

	// DB is the Redis database number.
	DB int `yaml:"db,omitempty" json:"db,omitempty"`

	// Password is the Redis password (prefer PasswordVaultPath).
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// PasswordVaultPath is the Vault path resolving the Redis password.
	PasswordVaultPath string `yaml:"passwordVaultPath,omitempty" json:"passwordVaultPath,omitempty"`

	// Sentinel configures a Redis Sentinel connection (HA). Mutually exclusive
	// with Address.
	Sentinel *RedisSentinelConfig `yaml:"sentinel,omitempty" json:"sentinel,omitempty"`
}

// IsEnabled reports whether the aggregate configuration is active.
func (c *AggregateConfig) IsEnabled() bool {
	return c != nil && c.Enabled && len(c.Targets) > 0
}

// GetFailMode returns the effective fail mode (defaulting to all).
func (c *AggregateConfig) GetFailMode() FailMode {
	if c == nil || c.FailMode == "" {
		return FailModeAll
	}
	return c.FailMode
}

// GetMaxParallel returns the effective parallelism bound, applying ENV override
// (ENV has priority over the file/flag-provided value).
func (c *AggregateConfig) GetMaxParallel() int {
	maxParallel := DefaultAggregateMaxParallel
	if c != nil && c.MaxParallel > 0 {
		maxParallel = c.MaxParallel
	}
	if v, ok := envInt(envAggregateMaxParallel); ok && v > 0 {
		maxParallel = v
	}
	return maxParallel
}

// GetSpoolThresholdBytes returns the effective spool threshold, applying ENV
// override (ENV has priority).
func (c *AggregateConfig) GetSpoolThresholdBytes() int64 {
	threshold := int64(DefaultAggregateSpoolThresholdBytes)
	if c != nil && c.Spool != nil && c.Spool.ThresholdBytes > 0 {
		threshold = c.Spool.ThresholdBytes
	}
	if v, ok := envInt64(envAggregateSpoolThreshold); ok && v > 0 {
		threshold = v
	}
	return threshold
}

// ApplyDefaults fills unset fields with sensible defaults. It is safe to call on
// a non-nil receiver only.
func (c *AggregateConfig) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.FailMode == "" {
		c.FailMode = FailModeAll
	}
	if c.MaxParallel <= 0 {
		c.MaxParallel = DefaultAggregateMaxParallel
	}
	c.applyMergeDefaults()
	c.applySpoolDefaults()
	c.applyTargetDefaults()
}

// applyMergeDefaults fills merge-related defaults. An empty strategy with merge
// enabled defaults to deep. For the ndjson strategy an unset TimeField defaults
// to "_time" (sorting only applies to records that actually carry that field;
// records lacking it keep a stable relative order, so the default is safe).
func (c *AggregateConfig) applyMergeDefaults() {
	if c.Merge == nil || !c.Merge.Enabled {
		return
	}
	if c.Merge.Strategy == "" {
		c.Merge.Strategy = MergeStrategyDeep
	}
	if c.Merge.Strategy == MergeStrategyNDJSON && c.Merge.TimeField == "" {
		c.Merge.TimeField = defaultNDJSONTimeField
	}
}

// applySpoolDefaults fills spool-related defaults.
func (c *AggregateConfig) applySpoolDefaults() {
	if c.Spool == nil {
		return
	}
	if c.Spool.Backend == "" {
		c.Spool.Backend = SpoolBackendMemory
	}
	if c.Spool.ThresholdBytes <= 0 {
		c.Spool.ThresholdBytes = DefaultAggregateSpoolThresholdBytes
	}
	if c.Spool.TTL <= 0 {
		c.Spool.TTL = Duration(DefaultCacheTTL)
	}
}

// applyTargetDefaults fills per-target defaults.
func (c *AggregateConfig) applyTargetDefaults() {
	for i := range c.Targets {
		if c.Targets[i].Timeout <= 0 {
			c.Targets[i].Timeout = Duration(DefaultAggregateTargetTimeout)
		}
	}
}

// Validate validates the aggregate configuration and applies defaults.
func (c *AggregateConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	c.ApplyDefaults()

	if len(c.Targets) < MinAggregateTargets {
		return fmt.Errorf("aggregate: at least %d target is required", MinAggregateTargets)
	}

	if err := c.validateFailMode(); err != nil {
		return err
	}

	if err := c.validateTargets(); err != nil {
		return err
	}

	if err := c.validateMerge(); err != nil {
		return err
	}

	return c.validateSpool()
}

// validateFailMode validates the fail-mode and quorum settings.
func (c *AggregateConfig) validateFailMode() error {
	switch c.FailMode {
	case FailModeAll, FailModeAny, FailModeQuorum:
	default:
		return fmt.Errorf("aggregate: invalid failMode %q (must be all, any or quorum)", c.FailMode)
	}
	if c.FailMode == FailModeQuorum && c.QuorumCount > len(c.Targets) {
		return fmt.Errorf("aggregate: quorumCount %d exceeds target count %d", c.QuorumCount, len(c.Targets))
	}
	return nil
}

// validateTargets validates each target and enforces unique names.
func (c *AggregateConfig) validateTargets() error {
	seen := make(map[string]struct{}, len(c.Targets))
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.Name == "" {
			return fmt.Errorf("aggregate: targets[%d].name is required", i)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("aggregate: duplicate target name %q", t.Name)
		}
		seen[t.Name] = struct{}{}

		if t.Destination.Host == "" {
			return fmt.Errorf("aggregate: targets[%d].destination.host is required", i)
		}
		if t.Destination.Port < 1 || t.Destination.Port > 65535 {
			return fmt.Errorf("aggregate: targets[%d].destination.port must be between 1 and 65535", i)
		}
		if t.Retries < 0 {
			return fmt.Errorf("aggregate: targets[%d].retries must be non-negative", i)
		}
		if t.Authentication != nil {
			if err := t.Authentication.Validate(); err != nil {
				return fmt.Errorf("aggregate: targets[%d].authentication: %w", i, err)
			}
		}
		if err := t.TLS.Validate(); err != nil {
			return fmt.Errorf("aggregate: targets[%d].tls: %w", i, err)
		}
	}
	return nil
}

// validateMerge validates merge options.
func (c *AggregateConfig) validateMerge() error {
	if c.Merge == nil || !c.Merge.Enabled {
		return nil
	}
	if c.Merge.Limit < 0 {
		return fmt.Errorf("aggregate: merge.limit must be non-negative")
	}
	switch c.Merge.Strategy {
	case MergeStrategyDeep, MergeStrategyShallow, MergeStrategyReplace, MergeStrategyNDJSON, "":
		return nil
	default:
		return fmt.Errorf(
			"aggregate: invalid merge.strategy %q (must be deep, shallow, replace or ndjson)",
			c.Merge.Strategy,
		)
	}
}

// validateSpool validates spool options.
func (c *AggregateConfig) validateSpool() error {
	if c.Spool == nil || !c.Spool.Enabled {
		return nil
	}
	switch c.Spool.Backend {
	case SpoolBackendMemory:
		return nil
	case SpoolBackendRedis:
		if c.Spool.RedisRef == nil {
			return fmt.Errorf("aggregate: spool.redisRef is required when spool.backend is redis")
		}
		hasAddr := c.Spool.RedisRef.Address != ""
		hasSentinel := c.Spool.RedisRef.Sentinel != nil
		if !hasAddr && !hasSentinel {
			return fmt.Errorf("aggregate: spool.redisRef requires either address or sentinel")
		}
		if hasAddr && hasSentinel {
			return fmt.Errorf("aggregate: spool.redisRef.address and sentinel are mutually exclusive")
		}
		return nil
	default:
		return fmt.Errorf("aggregate: invalid spool.backend %q (must be memory or redis)", c.Spool.Backend)
	}
}

// envInt reads an int from the environment, reporting whether it was present and
// valid.
func envInt(key string) (int, bool) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return v, true
}

// envInt64 reads an int64 from the environment, reporting whether it was present
// and valid.
func envInt64(key string) (int64, bool) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
