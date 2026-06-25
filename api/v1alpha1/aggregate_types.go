// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

// AggregateConfig represents aggregate (fan-out) mirroring configuration.
//
// Distinct from MirrorConfig (single-destination, fire-and-forget shadow
// traffic), AggregateConfig fans a single client request out to multiple
// backends in parallel, optionally merges their responses, and returns a single
// aggregated response. Merge and Redis spooling are both optional.
type AggregateConfig struct {
	// Enabled enables aggregate fan-out for this route.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Targets is the list of backends to fan out to.
	// +kubebuilder:validation:MinItems=1
	Targets []AggregateTarget `json:"targets"`

	// Merge configures optional response merging.
	// +optional
	Merge *MergeOptions `json:"merge,omitempty"`

	// Spool configures optional off-heap (Redis) spooling for large responses.
	// +optional
	Spool *SpoolOptions `json:"spool,omitempty"`

	// FailMode controls partial-failure handling.
	// +kubebuilder:validation:Enum=all;any;quorum
	// +kubebuilder:default=all
	// +optional
	FailMode string `json:"failMode,omitempty"`

	// QuorumCount is the explicit success threshold when FailMode is quorum.
	// When zero, a simple majority is used.
	// +kubebuilder:validation:Minimum=0
	// +optional
	QuorumCount int `json:"quorumCount,omitempty"`

	// MaxParallel bounds the number of concurrent target invocations.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1024
	// +kubebuilder:default=8
	// +optional
	MaxParallel int `json:"maxParallel,omitempty"`

	// PerMessageMerge enables per-message JSON merge for streaming traffic
	// (WS / gRPC streaming). Default: false (passthrough framed interleave).
	// +optional
	PerMessageMerge bool `json:"perMessageMerge,omitempty"`
}

// AggregateTarget describes a single fan-out backend destination.
type AggregateTarget struct {
	// Name is a stable, unique label for this target (used in metrics,
	// tracing and the labeled-envelope output).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Destination is the backend destination (host + port).
	// +kubebuilder:validation:Required
	Destination Destination `json:"destination"`

	// Timeout is the per-target request timeout.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// Retries is the maximum number of retry attempts for transient errors.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	// +optional
	Retries int `json:"retries,omitempty"`

	// TLS configures per-target TLS (including mTLS) for the backend connection.
	// +optional
	TLS *BackendTLSConfig `json:"tls,omitempty"`

	// Authentication configures per-target backend authentication.
	// Sensitive values may reference Vault.
	// +optional
	Authentication *BackendAuthConfig `json:"authentication,omitempty"`
}

// MergeOptions configures optional response merging for aggregate fan-out.
type MergeOptions struct {
	// Enabled enables merging. When false the labeled-envelope output is used.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Strategy is the merge strategy. "ndjson" merges newline-delimited JSON
	// record streams (with optional sort/de-dupe/limit) instead of merging JSON
	// documents.
	// +kubebuilder:validation:Enum=deep;shallow;replace;ndjson
	// +kubebuilder:default=deep
	// +optional
	Strategy string `json:"strategy,omitempty"`

	// TimeField is the NDJSON sort key (ndjson strategy only). Records are
	// stably sorted by this field. Default: "_time". Records lacking the field
	// sort after those that have it.
	// +optional
	TimeField string `json:"timeField,omitempty"`

	// KeyField is the NDJSON de-duplication key (ndjson strategy only). When
	// set, duplicate records are removed first-wins after sorting. Empty
	// disables de-duplication; records lacking the field are never de-duplicated.
	// +optional
	KeyField string `json:"keyField,omitempty"`

	// Limit caps the number of emitted NDJSON records (ndjson strategy only).
	// 0 means unlimited.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Limit int `json:"limit,omitempty"`
}

// SpoolOptions configures optional off-heap spooling of partial responses.
type SpoolOptions struct {
	// Enabled enables off-heap spooling. When false (or when Redis is
	// unavailable) responses are buffered in memory.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Backend is the spool backend.
	// +kubebuilder:validation:Enum=memory;redis
	// +kubebuilder:default=memory
	// +optional
	Backend string `json:"backend,omitempty"`

	// ThresholdBytes is the body-size threshold (in bytes) above which a
	// response is spooled.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ThresholdBytes int64 `json:"thresholdBytes,omitempty"`

	// RedisRef configures the Redis connection used when Backend is redis.
	// +optional
	RedisRef *AggregateRedisRef `json:"redisRef,omitempty"`

	// TTL is the lifetime of spooled entries.
	// +optional
	TTL Duration `json:"ttl,omitempty"`
}

// AggregateRedisRef references the Redis connection used for spooling.
type AggregateRedisRef struct {
	// Address is the standalone Redis address (host:port). Mutually exclusive
	// with Sentinel.
	// +optional
	Address string `json:"address,omitempty"`

	// DB is the Redis database number.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=15
	// +optional
	DB int `json:"db,omitempty"`

	// Password is the Redis password (prefer PasswordVaultPath).
	// +optional
	Password string `json:"password,omitempty"`

	// PasswordVaultPath is the Vault path resolving the Redis password.
	// Format: mount/path.
	// +optional
	PasswordVaultPath string `json:"passwordVaultPath,omitempty"`

	// Sentinel configures a Redis Sentinel connection (HA). Mutually exclusive
	// with Address.
	// +optional
	Sentinel *RedisSentinelSpec `json:"sentinel,omitempty"`
}
