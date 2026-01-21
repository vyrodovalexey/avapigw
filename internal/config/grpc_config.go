// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"time"
)

// Protocol constants for listener configuration.
const (
	ProtocolHTTP  = "HTTP"
	ProtocolHTTPS = "HTTPS"
	ProtocolHTTP2 = "HTTP2"
	ProtocolGRPC  = "GRPC"
)

// GRPCListenerConfig contains gRPC-specific listener configuration.
type GRPCListenerConfig struct {
	// MaxConcurrentStreams limits the number of concurrent streams per connection.
	MaxConcurrentStreams uint32 `yaml:"maxConcurrentStreams,omitempty" json:"maxConcurrentStreams,omitempty"`

	// MaxRecvMsgSize is the maximum message size in bytes the server can receive.
	MaxRecvMsgSize int `yaml:"maxRecvMsgSize,omitempty" json:"maxRecvMsgSize,omitempty"`

	// MaxSendMsgSize is the maximum message size in bytes the server can send.
	MaxSendMsgSize int `yaml:"maxSendMsgSize,omitempty" json:"maxSendMsgSize,omitempty"`

	// Keepalive contains keepalive configuration.
	Keepalive *GRPCKeepaliveConfig `yaml:"keepalive,omitempty" json:"keepalive,omitempty"`

	// Reflection enables gRPC reflection service for service discovery.
	Reflection bool `yaml:"reflection,omitempty" json:"reflection,omitempty"`

	// HealthCheck enables gRPC health check service.
	HealthCheck bool `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`

	// TLS contains TLS configuration for the gRPC server.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// GRPCKeepaliveConfig contains gRPC keepalive configuration.
type GRPCKeepaliveConfig struct {
	// Time is the duration after which if the server doesn't see any activity
	// it pings the client to see if the transport is still alive.
	Time Duration `yaml:"time,omitempty" json:"time,omitempty"`

	// Timeout is the duration the server waits for activity before closing the connection.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// PermitWithoutStream if true, server allows keepalive pings even when there are no active streams.
	PermitWithoutStream bool `yaml:"permitWithoutStream,omitempty" json:"permitWithoutStream,omitempty"`

	// MaxConnectionIdle is the duration a connection can be idle before being closed.
	MaxConnectionIdle Duration `yaml:"maxConnectionIdle,omitempty" json:"maxConnectionIdle,omitempty"`

	// MaxConnectionAge is the maximum duration a connection may exist before being closed.
	MaxConnectionAge Duration `yaml:"maxConnectionAge,omitempty" json:"maxConnectionAge,omitempty"`

	// MaxConnectionAgeGrace is the grace period after MaxConnectionAge before forcibly closing.
	MaxConnectionAgeGrace Duration `yaml:"maxConnectionAgeGrace,omitempty" json:"maxConnectionAgeGrace,omitempty"`
}

// TLSConfig contains TLS configuration.
type TLSConfig struct {
	// Enabled indicates whether TLS is enabled.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// CertFile is the path to the TLS certificate file.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the TLS key file.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate file for client verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// InsecureSkipVerify skips TLS verification (not recommended for production).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`
}

// GRPCRoute represents a gRPC routing rule configuration.
type GRPCRoute struct {
	// Name is the unique name of the route.
	Name string `yaml:"name" json:"name"`

	// Match contains the matching conditions for this route.
	Match []GRPCRouteMatch `yaml:"match,omitempty" json:"match,omitempty"`

	// Route contains the destination(s) for matched requests.
	Route []RouteDestination `yaml:"route,omitempty" json:"route,omitempty"`

	// Timeout is the request timeout for this route.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retries contains retry policy configuration.
	Retries *GRPCRetryPolicy `yaml:"retries,omitempty" json:"retries,omitempty"`

	// Headers contains header manipulation configuration.
	Headers *HeaderManipulation `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Mirror contains traffic mirroring configuration.
	Mirror *MirrorConfig `yaml:"mirror,omitempty" json:"mirror,omitempty"`

	// RateLimit contains route-level rate limiting configuration.
	RateLimit *RateLimitConfig `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Transform contains gRPC-specific transformation configuration.
	Transform *GRPCTransformConfig `yaml:"transform,omitempty" json:"transform,omitempty"`

	// Cache contains caching configuration.
	Cache *CacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`

	// Encoding contains encoding configuration.
	Encoding *EncodingConfig `yaml:"encoding,omitempty" json:"encoding,omitempty"`
}

// GRPCRouteMatch represents matching conditions for a gRPC route.
type GRPCRouteMatch struct {
	// Service matches the gRPC service name.
	Service *StringMatch `yaml:"service,omitempty" json:"service,omitempty"`

	// Method matches the gRPC method name.
	Method *StringMatch `yaml:"method,omitempty" json:"method,omitempty"`

	// Metadata matches gRPC metadata (headers).
	Metadata []MetadataMatch `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// Authority matches the :authority pseudo-header.
	Authority *StringMatch `yaml:"authority,omitempty" json:"authority,omitempty"`

	// WithoutHeaders specifies headers that must NOT be present.
	WithoutHeaders []string `yaml:"withoutHeaders,omitempty" json:"withoutHeaders,omitempty"`
}

// StringMatch represents a string matching configuration.
type StringMatch struct {
	// Exact matches the string exactly.
	Exact string `yaml:"exact,omitempty" json:"exact,omitempty"`

	// Prefix matches strings starting with this prefix.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`

	// Regex matches strings using a regular expression.
	Regex string `yaml:"regex,omitempty" json:"regex,omitempty"`
}

// MatchType returns the type of string match configured.
func (s *StringMatch) MatchType() string {
	if s == nil {
		return ""
	}
	if s.Exact != "" {
		return "exact"
	}
	if s.Prefix != "" {
		return "prefix"
	}
	if s.Regex != "" {
		return "regex"
	}
	return ""
}

// IsEmpty returns true if no match is configured.
func (s *StringMatch) IsEmpty() bool {
	if s == nil {
		return true
	}
	return s.Exact == "" && s.Prefix == "" && s.Regex == ""
}

// IsWildcard returns true if this is a wildcard match.
func (s *StringMatch) IsWildcard() bool {
	if s == nil {
		return false
	}
	return s.Exact == "*" || s.Prefix == "*"
}

// MetadataMatch represents gRPC metadata matching configuration.
type MetadataMatch struct {
	// Name is the metadata key name (case-insensitive for gRPC).
	Name string `yaml:"name" json:"name"`

	// Exact matches the metadata value exactly.
	Exact string `yaml:"exact,omitempty" json:"exact,omitempty"`

	// Prefix matches metadata values starting with this prefix.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`

	// Regex matches metadata values using a regular expression.
	Regex string `yaml:"regex,omitempty" json:"regex,omitempty"`

	// Present matches if the metadata key is present (regardless of value).
	Present *bool `yaml:"present,omitempty" json:"present,omitempty"`

	// Absent matches if the metadata key is NOT present.
	Absent *bool `yaml:"absent,omitempty" json:"absent,omitempty"`
}

// GRPCRetryPolicy represents gRPC retry policy configuration.
type GRPCRetryPolicy struct {
	// Attempts is the maximum number of retry attempts.
	Attempts int `yaml:"attempts" json:"attempts"`

	// PerTryTimeout is the timeout for each retry attempt.
	PerTryTimeout Duration `yaml:"perTryTimeout,omitempty" json:"perTryTimeout,omitempty"`

	// RetryOn is a comma-separated list of gRPC status codes to retry on.
	// Valid values: cancelled, deadline-exceeded, internal, resource-exhausted, unavailable
	RetryOn string `yaml:"retryOn,omitempty" json:"retryOn,omitempty"`

	// BackoffBaseInterval is the base interval for exponential backoff.
	BackoffBaseInterval Duration `yaml:"backoffBaseInterval,omitempty" json:"backoffBaseInterval,omitempty"`

	// BackoffMaxInterval is the maximum interval for exponential backoff.
	BackoffMaxInterval Duration `yaml:"backoffMaxInterval,omitempty" json:"backoffMaxInterval,omitempty"`
}

// GRPCBackend represents a gRPC backend service configuration.
type GRPCBackend struct {
	// Name is the unique name of the backend.
	Name string `yaml:"name" json:"name"`

	// Hosts contains the backend host configurations.
	Hosts []BackendHost `yaml:"hosts" json:"hosts"`

	// HealthCheck contains gRPC health check configuration.
	HealthCheck *GRPCHealthCheckConfig `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	LoadBalancer *LoadBalancer `yaml:"loadBalancer,omitempty" json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for connecting to the backend.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// ConnectionPool contains connection pool configuration.
	ConnectionPool *GRPCConnectionPoolConfig `yaml:"connectionPool,omitempty" json:"connectionPool,omitempty"`
}

// GRPCHealthCheckConfig contains gRPC health check configuration.
type GRPCHealthCheckConfig struct {
	// Enabled indicates whether health checking is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Service is the service name to check. Empty string checks overall health.
	Service string `yaml:"service,omitempty" json:"service,omitempty"`

	// Interval is the health check interval.
	Interval Duration `yaml:"interval,omitempty" json:"interval,omitempty"`

	// Timeout is the health check timeout.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// HealthyThreshold is the number of consecutive successes to mark healthy.
	HealthyThreshold int `yaml:"healthyThreshold,omitempty" json:"healthyThreshold,omitempty"`

	// UnhealthyThreshold is the number of consecutive failures to mark unhealthy.
	UnhealthyThreshold int `yaml:"unhealthyThreshold,omitempty" json:"unhealthyThreshold,omitempty"`
}

// GRPCConnectionPoolConfig contains gRPC connection pool configuration.
type GRPCConnectionPoolConfig struct {
	// MaxIdleConns is the maximum number of idle connections per host.
	MaxIdleConns int `yaml:"maxIdleConns,omitempty" json:"maxIdleConns,omitempty"`

	// MaxConnsPerHost is the maximum number of connections per host.
	MaxConnsPerHost int `yaml:"maxConnsPerHost,omitempty" json:"maxConnsPerHost,omitempty"`

	// IdleConnTimeout is the maximum time a connection can be idle.
	IdleConnTimeout Duration `yaml:"idleConnTimeout,omitempty" json:"idleConnTimeout,omitempty"`
}

// DefaultGRPCListenerConfig returns default gRPC listener configuration.
func DefaultGRPCListenerConfig() *GRPCListenerConfig {
	return &GRPCListenerConfig{
		MaxConcurrentStreams: 100,
		MaxRecvMsgSize:       4 * 1024 * 1024, // 4MB
		MaxSendMsgSize:       4 * 1024 * 1024, // 4MB
		Keepalive: &GRPCKeepaliveConfig{
			Time:                  Duration(30 * time.Second),
			Timeout:               Duration(10 * time.Second),
			PermitWithoutStream:   false,
			MaxConnectionIdle:     Duration(5 * time.Minute),
			MaxConnectionAge:      Duration(30 * time.Minute),
			MaxConnectionAgeGrace: Duration(5 * time.Second),
		},
		Reflection:  false,
		HealthCheck: true,
	}
}

// DefaultGRPCHealthCheckConfig returns default gRPC health check configuration.
func DefaultGRPCHealthCheckConfig() *GRPCHealthCheckConfig {
	return &GRPCHealthCheckConfig{
		Enabled:            true,
		Service:            "",
		Interval:           Duration(10 * time.Second),
		Timeout:            Duration(5 * time.Second),
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}
}

// DefaultGRPCRetryPolicy returns default gRPC retry policy.
func DefaultGRPCRetryPolicy() *GRPCRetryPolicy {
	return &GRPCRetryPolicy{
		Attempts:            3,
		PerTryTimeout:       Duration(10 * time.Second),
		RetryOn:             "unavailable,resource-exhausted",
		BackoffBaseInterval: Duration(100 * time.Millisecond),
		BackoffMaxInterval:  Duration(1 * time.Second),
	}
}

// IsEmpty returns true if the GRPCRouteMatch has no conditions.
func (m *GRPCRouteMatch) IsEmpty() bool {
	if m.Service != nil && !m.Service.IsEmpty() {
		return false
	}
	if m.Method != nil && !m.Method.IsEmpty() {
		return false
	}
	if len(m.Metadata) > 0 {
		return false
	}
	if m.Authority != nil && !m.Authority.IsEmpty() {
		return false
	}
	if len(m.WithoutHeaders) > 0 {
		return false
	}
	return true
}
