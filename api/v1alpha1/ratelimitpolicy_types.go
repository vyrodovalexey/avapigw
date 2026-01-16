package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// RateLimitPolicy CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=rlp
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// RateLimitPolicy is the Schema for the ratelimitpolicies API.
// RateLimitPolicy defines rate limiting configuration for a target resource.
type RateLimitPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RateLimitPolicySpec   `json:"spec,omitempty"`
	Status RateLimitPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RateLimitPolicyList contains a list of RateLimitPolicy
type RateLimitPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateLimitPolicy `json:"items"`
}

// RateLimitPolicySpec defines the desired state of RateLimitPolicy
type RateLimitPolicySpec struct {
	// TargetRef identifies the target resource to apply rate limiting to.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`

	// Rules defines the rate limiting rules.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Rules []RateLimitRule `json:"rules"`

	// RateLimitResponse defines the response when rate limited.
	// +optional
	RateLimitResponse *RateLimitResponseConfig `json:"rateLimitResponse,omitempty"`

	// Storage defines the storage backend for rate limiting.
	// +optional
	Storage *RateLimitStorageConfig `json:"storage,omitempty"`
}

// RateLimitRule defines a rate limiting rule
type RateLimitRule struct {
	// Name is the name of the rule.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Limit defines the rate limit.
	// +kubebuilder:validation:Required
	Limit RateLimitValue `json:"limit"`

	// Algorithm is the rate limiting algorithm.
	// +kubebuilder:validation:Enum=TokenBucket;SlidingWindow;FixedWindow
	// +kubebuilder:default=TokenBucket
	// +optional
	Algorithm *RateLimitAlgorithm `json:"algorithm,omitempty"`

	// TokenBucket defines token bucket configuration.
	// Used when Algorithm is TokenBucket.
	// +optional
	TokenBucket *TokenBucketConfig `json:"tokenBucket,omitempty"`

	// SlidingWindow defines sliding window configuration.
	// Used when Algorithm is SlidingWindow.
	// +optional
	SlidingWindow *SlidingWindowConfig `json:"slidingWindow,omitempty"`

	// ClientIdentifier defines how to identify clients for rate limiting.
	// +optional
	ClientIdentifier *ClientIdentifierConfig `json:"clientIdentifier,omitempty"`

	// Fallback defines the fallback client identifier if the primary is not available.
	// +optional
	Fallback *ClientIdentifierConfig `json:"fallback,omitempty"`

	// Tiers defines tiered rate limits.
	// +kubebuilder:validation:MaxItems=10
	// +optional
	Tiers []RateLimitTier `json:"tiers,omitempty"`

	// Match defines conditions for when this rule applies.
	// +optional
	Match *RateLimitMatch `json:"match,omitempty"`
}

// RateLimitValue defines a rate limit value
type RateLimitValue struct {
	// Requests is the number of requests allowed.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	Requests int32 `json:"requests"`

	// Unit is the time unit for the rate limit.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Second;Minute;Hour;Day
	Unit RateLimitUnit `json:"unit"`
}

// RateLimitUnit defines the time unit for rate limiting
// +kubebuilder:validation:Enum=Second;Minute;Hour;Day
type RateLimitUnit string

const (
	// RateLimitUnitSecond is per second
	RateLimitUnitSecond RateLimitUnit = "Second"
	// RateLimitUnitMinute is per minute
	RateLimitUnitMinute RateLimitUnit = "Minute"
	// RateLimitUnitHour is per hour
	RateLimitUnitHour RateLimitUnit = "Hour"
	// RateLimitUnitDay is per day
	RateLimitUnitDay RateLimitUnit = "Day"
)

// RateLimitAlgorithm defines the rate limiting algorithm
// +kubebuilder:validation:Enum=TokenBucket;SlidingWindow;FixedWindow
type RateLimitAlgorithm string

const (
	// RateLimitAlgorithmTokenBucket uses token bucket algorithm
	RateLimitAlgorithmTokenBucket RateLimitAlgorithm = "TokenBucket"
	// RateLimitAlgorithmSlidingWindow uses sliding window algorithm
	RateLimitAlgorithmSlidingWindow RateLimitAlgorithm = "SlidingWindow"
	// RateLimitAlgorithmFixedWindow uses fixed window algorithm
	RateLimitAlgorithmFixedWindow RateLimitAlgorithm = "FixedWindow"
)

// TokenBucketConfig defines token bucket configuration
type TokenBucketConfig struct {
	// Tokens is the maximum number of tokens in the bucket.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	Tokens int32 `json:"tokens"`

	// FillInterval is the interval at which tokens are added.
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m))+$`
	// +kubebuilder:default="1s"
	// +optional
	FillInterval *string `json:"fillInterval,omitempty"`

	// TokensPerFill is the number of tokens added per fill interval.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	// +optional
	TokensPerFill *int32 `json:"tokensPerFill,omitempty"`
}

// SlidingWindowConfig defines sliding window configuration
type SlidingWindowConfig struct {
	// WindowSize is the size of the sliding window.
	// +kubebuilder:validation:Pattern=`^([0-9]+(s|m|h))+$`
	// +kubebuilder:default="1m"
	// +optional
	WindowSize *string `json:"windowSize,omitempty"`

	// Precision is the precision of the sliding window.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	// +kubebuilder:default=10
	// +optional
	Precision *int32 `json:"precision,omitempty"`
}

// ClientIdentifierConfig defines how to identify clients
type ClientIdentifierConfig struct {
	// Type is the type of client identifier.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Header;RemoteAddress;JWTClaim;Cookie
	Type ClientIdentifierType `json:"type"`

	// Header is the name of the header to use for identification.
	// Required when Type is Header.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Header *string `json:"header,omitempty"`

	// Claim is the name of the JWT claim to use for identification.
	// Required when Type is JWTClaim.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Claim *string `json:"claim,omitempty"`

	// Cookie is the name of the cookie to use for identification.
	// Required when Type is Cookie.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Cookie *string `json:"cookie,omitempty"`
}

// ClientIdentifierType defines the type of client identifier
// +kubebuilder:validation:Enum=Header;RemoteAddress;JWTClaim;Cookie
type ClientIdentifierType string

const (
	// ClientIdentifierHeader uses a header value
	ClientIdentifierHeader ClientIdentifierType = "Header"
	// ClientIdentifierRemoteAddress uses the remote address
	ClientIdentifierRemoteAddress ClientIdentifierType = "RemoteAddress"
	// ClientIdentifierJWTClaim uses a JWT claim
	ClientIdentifierJWTClaim ClientIdentifierType = "JWTClaim"
	// ClientIdentifierCookie uses a cookie value
	ClientIdentifierCookie ClientIdentifierType = "Cookie"
)

// RateLimitTier defines a tiered rate limit
type RateLimitTier struct {
	// Name is the name of the tier.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Match defines conditions for this tier.
	// +kubebuilder:validation:Required
	Match RateLimitTierMatch `json:"match"`

	// Limit defines the rate limit for this tier.
	// +kubebuilder:validation:Required
	Limit RateLimitValue `json:"limit"`
}

// RateLimitTierMatch defines matching conditions for a tier
type RateLimitTierMatch struct {
	// Headers defines header matching conditions.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Headers []HTTPHeaderMatch `json:"headers,omitempty"`

	// Claims defines JWT claim matching conditions.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Claims []ClaimMatch `json:"claims,omitempty"`
}

// ClaimMatch defines a JWT claim match
type ClaimMatch struct {
	// Name is the name of the claim.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Name string `json:"name"`

	// Value is the value to match.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Value string `json:"value"`
}

// RateLimitMatch defines conditions for when a rate limit rule applies
type RateLimitMatch struct {
	// Paths defines path matching conditions.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Paths []HTTPPathMatch `json:"paths,omitempty"`

	// Methods defines HTTP method matching conditions.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Methods []HTTPMethod `json:"methods,omitempty"`

	// Headers defines header matching conditions.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Headers []HTTPHeaderMatch `json:"headers,omitempty"`
}

// ============================================================================
// Rate Limit Response Configuration
// ============================================================================

// RateLimitResponseConfig defines the response when rate limited
type RateLimitResponseConfig struct {
	// StatusCode is the HTTP status code to return.
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	// +kubebuilder:default=429
	// +optional
	StatusCode *int32 `json:"statusCode,omitempty"`

	// Headers defines headers to include in the response.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Headers []HTTPHeader `json:"headers,omitempty"`

	// Body is the response body.
	// +kubebuilder:validation:MaxLength=4096
	// +optional
	Body *string `json:"body,omitempty"`

	// IncludeRateLimitHeaders indicates whether to include rate limit headers.
	// +kubebuilder:default=true
	// +optional
	IncludeRateLimitHeaders *bool `json:"includeRateLimitHeaders,omitempty"`
}

// ============================================================================
// Rate Limit Storage Configuration
// ============================================================================

// RateLimitStorageConfig defines the storage backend for rate limiting
type RateLimitStorageConfig struct {
	// Type is the type of storage backend.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Memory;Redis
	Type RateLimitStorageType `json:"type"`

	// Redis defines Redis storage configuration.
	// Required when Type is Redis.
	// +optional
	Redis *RedisStorageConfig `json:"redis,omitempty"`
}

// RateLimitStorageType defines the type of storage backend
// +kubebuilder:validation:Enum=Memory;Redis
type RateLimitStorageType string

const (
	// RateLimitStorageMemory uses in-memory storage
	RateLimitStorageMemory RateLimitStorageType = "Memory"
	// RateLimitStorageRedis uses Redis storage
	RateLimitStorageRedis RateLimitStorageType = "Redis"
)

// RedisStorageConfig defines Redis storage configuration
type RedisStorageConfig struct {
	// Address is the Redis server address.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Address string `json:"address"`

	// Database is the Redis database number.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=15
	// +kubebuilder:default=0
	// +optional
	Database *int32 `json:"database,omitempty"`

	// SecretRef references a Secret containing Redis credentials.
	// +optional
	SecretRef *SecretObjectReference `json:"secretRef,omitempty"`

	// TLS defines TLS configuration for Redis connection.
	// +optional
	TLS *RedisTLSConfig `json:"tls,omitempty"`

	// PoolSize is the maximum number of connections in the pool.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	// +kubebuilder:default=10
	// +optional
	PoolSize *int32 `json:"poolSize,omitempty"`

	// Timeout is the timeout for Redis operations.
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s))+$`
	// +kubebuilder:default="5s"
	// +optional
	Timeout *string `json:"timeout,omitempty"`
}

// RedisTLSConfig defines TLS configuration for Redis
type RedisTLSConfig struct {
	// Enabled indicates whether TLS is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// CACertRef references a Secret containing the CA certificate.
	// +optional
	CACertRef *SecretObjectReference `json:"caCertRef,omitempty"`

	// InsecureSkipVerify skips TLS certificate verification.
	// +kubebuilder:default=false
	// +optional
	InsecureSkipVerify *bool `json:"insecureSkipVerify,omitempty"`
}

// ============================================================================
// RateLimitPolicy Status
// ============================================================================

// RateLimitPolicyStatus defines the observed state of RateLimitPolicy
type RateLimitPolicyStatus struct {
	Status `json:",inline"`
}

// GetTargetRef returns the target reference for the policy.
// This implements the PolicyWithTargetRef interface.
func (p *RateLimitPolicy) GetTargetRef() TargetRef {
	return p.Spec.TargetRef
}

// GetPolicies returns the list of RateLimitPolicy items.
// This implements the PolicyList interface for watch handlers.
func (l *RateLimitPolicyList) GetPolicies() []*RateLimitPolicy {
	policies := make([]*RateLimitPolicy, len(l.Items))
	for i := range l.Items {
		policies[i] = &l.Items[i]
	}
	return policies
}

func init() {
	SchemeBuilder.Register(&RateLimitPolicy{}, &RateLimitPolicyList{})
}
