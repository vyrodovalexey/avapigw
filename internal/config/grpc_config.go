// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"fmt"
	"time"
)

// Protocol constants for listener configuration.
const (
	ProtocolHTTP  = "HTTP"
	ProtocolHTTPS = "HTTPS"
	ProtocolHTTP2 = "HTTP2"
	ProtocolGRPC  = "GRPC"
)

// TLS mode constants for gRPC listener configuration.
const (
	// TLSModeSimple enables TLS with server certificate only.
	TLSModeSimple = "SIMPLE"

	// TLSModeMutual enables mutual TLS (mTLS) requiring client certificates.
	TLSModeMutual = "MUTUAL"

	// TLSModeOptionalMutual enables TLS with optional client certificate verification.
	TLSModeOptionalMutual = "OPTIONAL_MUTUAL"

	// TLSModeInsecure disables TLS (plaintext, development only).
	TLSModeInsecure = "INSECURE"
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

// TLSConfig contains TLS configuration for gRPC.
type TLSConfig struct {
	// Enabled indicates whether TLS is enabled.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Mode specifies the TLS mode (SIMPLE, MUTUAL, OPTIONAL_MUTUAL, INSECURE).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// CertFile is the path to the TLS certificate file.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the TLS key file.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate file for client verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// MinVersion is the minimum TLS version (TLS12, TLS13).
	MinVersion string `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	MaxVersion string `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// RequireClientCert requires client certificate (for MUTUAL mode).
	RequireClientCert bool `yaml:"requireClientCert,omitempty" json:"requireClientCert,omitempty"`

	// InsecureSkipVerify skips TLS verification (not recommended for production).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// ALPN protocols for negotiation (default: ["h2"]).
	ALPN []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`

	// RequireALPN rejects connections without proper ALPN.
	RequireALPN bool `yaml:"requireALPN,omitempty" json:"requireALPN,omitempty"`

	// AllowedCNs is the list of allowed Common Names for client certs.
	AllowedCNs []string `yaml:"allowedCNs,omitempty" json:"allowedCNs,omitempty"`

	// AllowedSANs is the list of allowed Subject Alternative Names.
	AllowedSANs []string `yaml:"allowedSANs,omitempty" json:"allowedSANs,omitempty"`

	// Vault configures Vault-based certificate management.
	Vault *VaultGRPCTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// VaultGRPCTLSConfig configures Vault-based TLS for gRPC.
type VaultGRPCTLSConfig struct {
	// Enabled enables Vault integration.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// PKIMount is the Vault PKI mount path.
	PKIMount string `yaml:"pkiMount,omitempty" json:"pkiMount,omitempty"`

	// Role is the Vault PKI role name.
	Role string `yaml:"role,omitempty" json:"role,omitempty"`

	// CommonName for certificate requests.
	CommonName string `yaml:"commonName,omitempty" json:"commonName,omitempty"`

	// AltNames for certificate requests.
	AltNames []string `yaml:"altNames,omitempty" json:"altNames,omitempty"`

	// TTL for certificate requests.
	TTL string `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

// Validate validates the TLS configuration.
func (c *TLSConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if err := c.validateMode(); err != nil {
		return err
	}

	if err := c.validateCertificates(); err != nil {
		return err
	}

	if err := c.validateVersions(); err != nil {
		return err
	}

	return c.validateVault()
}

// validateMode validates the TLS mode.
func (c *TLSConfig) validateMode() error {
	if c.Mode == "" {
		return nil
	}

	validModes := map[string]bool{
		TLSModeSimple:         true,
		TLSModeMutual:         true,
		TLSModeOptionalMutual: true,
		TLSModeInsecure:       true,
	}
	if !validModes[c.Mode] {
		return fmt.Errorf("invalid TLS mode: %s", c.Mode)
	}
	return nil
}

// validateCertificates validates certificate configuration.
func (c *TLSConfig) validateCertificates() error {
	// For non-insecure modes, require cert and key (unless Vault is enabled)
	if c.Mode != TLSModeInsecure && c.Mode != "" {
		vaultEnabled := c.Vault != nil && c.Vault.Enabled
		if c.CertFile == "" && !vaultEnabled {
			return fmt.Errorf("certFile is required for TLS mode %s", c.Mode)
		}
		if c.KeyFile == "" && !vaultEnabled {
			return fmt.Errorf("keyFile is required for TLS mode %s", c.Mode)
		}
	}

	// For MUTUAL mode, require CA file
	if c.Mode == TLSModeMutual && c.CAFile == "" {
		return fmt.Errorf("caFile is required for MUTUAL TLS mode")
	}
	return nil
}

// validateVersions validates TLS version configuration.
func (c *TLSConfig) validateVersions() error {
	validVersions := map[string]bool{
		"TLS10": true, "TLS11": true, "TLS12": true, "TLS13": true,
	}

	if c.MinVersion != "" && !validVersions[c.MinVersion] {
		return fmt.Errorf("invalid minVersion: %s", c.MinVersion)
	}
	if c.MaxVersion != "" && !validVersions[c.MaxVersion] {
		return fmt.Errorf("invalid maxVersion: %s", c.MaxVersion)
	}
	return nil
}

// validateVault validates Vault configuration if enabled.
func (c *TLSConfig) validateVault() error {
	if c.Vault != nil && c.Vault.Enabled {
		return c.Vault.Validate()
	}
	return nil
}

// Validate validates the Vault TLS configuration.
func (c *VaultGRPCTLSConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.PKIMount == "" {
		return fmt.Errorf("vault.pkiMount is required")
	}
	if c.Role == "" {
		return fmt.Errorf("vault.role is required")
	}
	if c.CommonName == "" {
		return fmt.Errorf("vault.commonName is required")
	}

	return nil
}

// IsInsecure returns true if insecure mode is enabled.
func (c *TLSConfig) IsInsecure() bool {
	if c == nil {
		return true
	}
	return !c.Enabled || c.Mode == TLSModeInsecure
}

// IsMutual returns true if mutual TLS is required.
func (c *TLSConfig) IsMutual() bool {
	if c == nil {
		return false
	}
	return c.Mode == TLSModeMutual || c.RequireClientCert
}

// IsOptionalMutual returns true if optional mutual TLS is enabled.
func (c *TLSConfig) IsOptionalMutual() bool {
	if c == nil {
		return false
	}
	return c.Mode == TLSModeOptionalMutual
}

// GetEffectiveMode returns the effective TLS mode.
func (c *TLSConfig) GetEffectiveMode() string {
	if c == nil || !c.Enabled {
		return TLSModeInsecure
	}
	if c.Mode == "" {
		return TLSModeSimple
	}
	return c.Mode
}

// GetEffectiveMinVersion returns the effective minimum TLS version.
func (c *TLSConfig) GetEffectiveMinVersion() string {
	if c == nil || c.MinVersion == "" {
		return "TLS12" // Default to TLS 1.2 for gRPC
	}
	return c.MinVersion
}

// GetEffectiveALPN returns the effective ALPN protocols.
func (c *TLSConfig) GetEffectiveALPN() []string {
	if c == nil || len(c.ALPN) == 0 {
		return []string{"h2"} // Default to HTTP/2 for gRPC
	}
	return c.ALPN
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

	// CORS configures CORS for this gRPC route (overrides global).
	CORS *CORSConfig `yaml:"cors,omitempty" json:"cors,omitempty"`

	// Security configures security headers for this gRPC route (overrides global).
	Security *SecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`

	// TLS configures route-level TLS certificate override for this gRPC route.
	// This allows serving different certificates based on SNI for this route.
	TLS *RouteTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Authentication configures route-level authentication.
	Authentication *AuthenticationConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	Authorization *AuthorizationConfig `yaml:"authorization,omitempty" json:"authorization,omitempty"`
}

// HasTLSOverride returns true if the gRPC route has TLS configuration that overrides listener TLS.
func (r *GRPCRoute) HasTLSOverride() bool {
	if r.TLS == nil {
		return false
	}
	hasFiles := r.TLS.CertFile != "" || r.TLS.KeyFile != ""
	hasVault := r.TLS.Vault != nil && r.TLS.Vault.Enabled
	return hasFiles || hasVault
}

// GetEffectiveSNIHosts returns the SNI hosts for this gRPC route.
// Returns nil if no SNI hosts are configured.
func (r *GRPCRoute) GetEffectiveSNIHosts() []string {
	if r.TLS == nil || len(r.TLS.SNIHosts) == 0 {
		return nil
	}
	return r.TLS.SNIHosts
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
	// Valid values: canceled, deadline-exceeded, internal, resource-exhausted, unavailable
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

	// CircuitBreaker configures circuit breaker for this gRPC backend.
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for gRPC backend connections.
	Authentication *BackendAuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`
}

// GRPCHealthCheckConfig contains gRPC health check configuration.
type GRPCHealthCheckConfig struct {
	// Enabled indicates whether health checking is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Service is the service name to check. Empty string checks overall health.
	// Used only when UseHTTP is false (default gRPC health check mode).
	Service string `yaml:"service,omitempty" json:"service,omitempty"`

	// UseHTTP switches health checking from gRPC protocol to HTTP GET.
	// When true, the health checker sends HTTP GET requests to HTTPPath
	// on HTTPPort instead of using grpc.health.v1.Health/Check.
	UseHTTP bool `yaml:"useHTTP,omitempty" json:"useHTTP,omitempty"`

	// HTTPPath is the HTTP path for health checks when UseHTTP is true.
	HTTPPath string `yaml:"httpPath,omitempty" json:"httpPath,omitempty"`

	// HTTPPort is the port for HTTP health checks when UseHTTP is true.
	// If not set, the backend's main port is used.
	HTTPPort int `yaml:"httpPort,omitempty" json:"httpPort,omitempty"`

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

// GRPCBackendToBackend converts a GRPCBackend to a Backend configuration.
// This enables reuse of the shared backend.Registry infrastructure (load balancing,
// health checking, connection management) for gRPC backends.
func GRPCBackendToBackend(gb GRPCBackend) Backend {
	b := Backend{
		Name:           gb.Name,
		Hosts:          gb.Hosts,
		LoadBalancer:   gb.LoadBalancer,
		CircuitBreaker: gb.CircuitBreaker,
		Authentication: gb.Authentication,
	}

	// Convert gRPC health check to internal health check format.
	if gb.HealthCheck != nil && gb.HealthCheck.Enabled {
		if gb.HealthCheck.UseHTTP {
			// Use HTTP health check on a separate monitoring port.
			// This is useful for gRPC backends that require auth on
			// gRPC but expose an unauthenticated HTTP health endpoint.
			httpPath := gb.HealthCheck.HTTPPath
			if httpPath == "" {
				httpPath = "/healthz"
			}
			b.HealthCheck = &HealthCheck{
				Path:               httpPath,
				Interval:           gb.HealthCheck.Interval,
				Timeout:            gb.HealthCheck.Timeout,
				HealthyThreshold:   gb.HealthCheck.HealthyThreshold,
				UnhealthyThreshold: gb.HealthCheck.UnhealthyThreshold,
				UseGRPC:            false,
				Port:               gb.HealthCheck.HTTPPort,
			}
		} else {
			// Default: use native gRPC health checking.
			b.HealthCheck = &HealthCheck{
				Path:               "/grpc.health.v1.Health/Check",
				Interval:           gb.HealthCheck.Interval,
				Timeout:            gb.HealthCheck.Timeout,
				HealthyThreshold:   gb.HealthCheck.HealthyThreshold,
				UnhealthyThreshold: gb.HealthCheck.UnhealthyThreshold,
				UseGRPC:            true,
				GRPCService:        gb.HealthCheck.Service,
			}
		}
	}

	// Convert TLSConfig to BackendTLSConfig
	if gb.TLS != nil {
		b.TLS = &BackendTLSConfig{
			Enabled:            gb.TLS.Enabled,
			Mode:               gb.TLS.Mode,
			CertFile:           gb.TLS.CertFile,
			KeyFile:            gb.TLS.KeyFile,
			CAFile:             gb.TLS.CAFile,
			MinVersion:         gb.TLS.MinVersion,
			MaxVersion:         gb.TLS.MaxVersion,
			CipherSuites:       gb.TLS.CipherSuites,
			InsecureSkipVerify: gb.TLS.InsecureSkipVerify,
		}
		// Convert Vault TLS config if present
		if gb.TLS.Vault != nil && gb.TLS.Vault.Enabled {
			b.TLS.Vault = &VaultBackendTLSConfig{
				Enabled:    gb.TLS.Vault.Enabled,
				PKIMount:   gb.TLS.Vault.PKIMount,
				Role:       gb.TLS.Vault.Role,
				CommonName: gb.TLS.Vault.CommonName,
				AltNames:   gb.TLS.Vault.AltNames,
			}
		}
	}

	return b
}

// GRPCBackendsToBackends converts a slice of GRPCBackend to a slice of Backend.
func GRPCBackendsToBackends(gbs []GRPCBackend) []Backend {
	backends := make([]Backend, 0, len(gbs))
	for _, gb := range gbs {
		backends = append(backends, GRPCBackendToBackend(gb))
	}
	return backends
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
