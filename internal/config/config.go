// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"fmt"
	"time"
)

// GatewayConfig represents the root configuration for the API Gateway.
type GatewayConfig struct {
	APIVersion string      `yaml:"apiVersion" json:"apiVersion"`
	Kind       string      `yaml:"kind" json:"kind"`
	Metadata   Metadata    `yaml:"metadata" json:"metadata"`
	Spec       GatewaySpec `yaml:"spec" json:"spec"`
}

// Metadata contains metadata about the gateway configuration.
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// GatewaySpec contains the main gateway specification.
type GatewaySpec struct {
	Listeners      []Listener            `yaml:"listeners" json:"listeners"`
	Routes         []Route               `yaml:"routes,omitempty" json:"routes,omitempty"`
	Backends       []Backend             `yaml:"backends,omitempty" json:"backends,omitempty"`
	GRPCRoutes     []GRPCRoute           `yaml:"grpcRoutes,omitempty" json:"grpcRoutes,omitempty"`
	GRPCBackends   []GRPCBackend         `yaml:"grpcBackends,omitempty" json:"grpcBackends,omitempty"`
	RateLimit      *RateLimitConfig      `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`
	CORS           *CORSConfig           `yaml:"cors,omitempty" json:"cors,omitempty"`
	Observability  *ObservabilityConfig  `yaml:"observability,omitempty" json:"observability,omitempty"`
	Authentication *AuthenticationConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`
	Authorization  *AuthorizationConfig  `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	Security       *SecurityConfig       `yaml:"security,omitempty" json:"security,omitempty"`
	Audit          *AuditConfig          `yaml:"audit,omitempty" json:"audit,omitempty"`
	// RequestLimits configures request size limits.
	RequestLimits *RequestLimitsConfig `yaml:"requestLimits,omitempty" json:"requestLimits,omitempty"`
	// MaxSessions configures maximum concurrent sessions at the gateway level.
	MaxSessions *MaxSessionsConfig `yaml:"maxSessions,omitempty" json:"maxSessions,omitempty"`
}

// Listener represents a network listener configuration.
type Listener struct {
	Name     string              `yaml:"name" json:"name"`
	Port     int                 `yaml:"port" json:"port"`
	Protocol string              `yaml:"protocol" json:"protocol"`
	Hosts    []string            `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Bind     string              `yaml:"bind,omitempty" json:"bind,omitempty"`
	GRPC     *GRPCListenerConfig `yaml:"grpc,omitempty" json:"grpc,omitempty"`
	TLS      *ListenerTLSConfig  `yaml:"tls,omitempty" json:"tls,omitempty"`
	Timeouts *ListenerTimeouts   `yaml:"timeouts,omitempty" json:"timeouts,omitempty"`
}

// ListenerTimeouts contains timeout configuration for HTTP listeners.
type ListenerTimeouts struct {
	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	ReadTimeout Duration `yaml:"readTimeout,omitempty" json:"readTimeout,omitempty"`

	// ReadHeaderTimeout is the maximum duration for reading request headers.
	ReadHeaderTimeout Duration `yaml:"readHeaderTimeout,omitempty" json:"readHeaderTimeout,omitempty"`

	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout Duration `yaml:"writeTimeout,omitempty" json:"writeTimeout,omitempty"`

	// IdleTimeout is the maximum duration to wait for the next request when keep-alives are enabled.
	IdleTimeout Duration `yaml:"idleTimeout,omitempty" json:"idleTimeout,omitempty"`
}

// DefaultListenerTimeouts returns the default listener timeout configuration.
func DefaultListenerTimeouts() *ListenerTimeouts {
	return &ListenerTimeouts{
		ReadTimeout:       Duration(DefaultReadTimeout),
		ReadHeaderTimeout: Duration(DefaultReadHeaderTimeout),
		WriteTimeout:      Duration(DefaultWriteTimeout),
		IdleTimeout:       Duration(DefaultIdleTimeout),
	}
}

// GetEffectiveReadTimeout returns the effective read timeout.
func (t *ListenerTimeouts) GetEffectiveReadTimeout() time.Duration {
	if t == nil || t.ReadTimeout == 0 {
		return DefaultReadTimeout
	}
	return t.ReadTimeout.Duration()
}

// GetEffectiveReadHeaderTimeout returns the effective read header timeout.
func (t *ListenerTimeouts) GetEffectiveReadHeaderTimeout() time.Duration {
	if t == nil || t.ReadHeaderTimeout == 0 {
		return DefaultReadHeaderTimeout
	}
	return t.ReadHeaderTimeout.Duration()
}

// GetEffectiveWriteTimeout returns the effective write timeout.
func (t *ListenerTimeouts) GetEffectiveWriteTimeout() time.Duration {
	if t == nil || t.WriteTimeout == 0 {
		return DefaultWriteTimeout
	}
	return t.WriteTimeout.Duration()
}

// GetEffectiveIdleTimeout returns the effective idle timeout.
func (t *ListenerTimeouts) GetEffectiveIdleTimeout() time.Duration {
	if t == nil || t.IdleTimeout == 0 {
		return DefaultIdleTimeout
	}
	return t.IdleTimeout.Duration()
}

// ListenerTLSConfig contains TLS configuration for HTTP/HTTPS listeners.
type ListenerTLSConfig struct {
	// Mode specifies the TLS mode (SIMPLE, MUTUAL, OPTIONAL_MUTUAL, PASSTHROUGH, INSECURE).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// MinVersion is the minimum TLS version (TLS12, TLS13).
	MinVersion string `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	MaxVersion string `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// CertFile is the path to the server certificate.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the server private key.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate for client validation.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// RequireClientCert requires client certificate (for MUTUAL mode).
	RequireClientCert bool `yaml:"requireClientCert,omitempty" json:"requireClientCert,omitempty"`

	// InsecureSkipVerify skips certificate verification (dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// ALPN protocols for negotiation.
	ALPN []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`

	// HTTPSRedirect enables automatic HTTP to HTTPS redirect.
	HTTPSRedirect bool `yaml:"httpsRedirect,omitempty" json:"httpsRedirect,omitempty"`

	// HSTS configures HTTP Strict Transport Security.
	HSTS *HSTSConfig `yaml:"hsts,omitempty" json:"hsts,omitempty"`

	// Vault configures Vault-based certificate management.
	Vault *VaultTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// HSTSConfig configures HTTP Strict Transport Security.
type HSTSConfig struct {
	// Enabled enables HSTS header.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// MaxAge is the max-age directive value in seconds.
	MaxAge int `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`

	// IncludeSubDomains includes the includeSubDomains directive.
	IncludeSubDomains bool `yaml:"includeSubDomains,omitempty" json:"includeSubDomains,omitempty"`

	// Preload includes the preload directive.
	Preload bool `yaml:"preload,omitempty" json:"preload,omitempty"`
}

// VaultTLSConfig configures Vault-based TLS for listeners.
type VaultTLSConfig struct {
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

// Route represents a routing rule configuration.
type Route struct {
	Name           string                `yaml:"name" json:"name"`
	Match          []RouteMatch          `yaml:"match,omitempty" json:"match,omitempty"`
	Route          []RouteDestination    `yaml:"route,omitempty" json:"route,omitempty"`
	Timeout        Duration              `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries        *RetryPolicy          `yaml:"retries,omitempty" json:"retries,omitempty"`
	Redirect       *RedirectConfig       `yaml:"redirect,omitempty" json:"redirect,omitempty"`
	Rewrite        *RewriteConfig        `yaml:"rewrite,omitempty" json:"rewrite,omitempty"`
	DirectResponse *DirectResponseConfig `yaml:"directResponse,omitempty" json:"directResponse,omitempty"`
	Headers        *HeaderManipulation   `yaml:"headers,omitempty" json:"headers,omitempty"`
	Mirror         *MirrorConfig         `yaml:"mirror,omitempty" json:"mirror,omitempty"`
	Fault          *FaultInjection       `yaml:"fault,omitempty" json:"fault,omitempty"`
	RateLimit      *RateLimitConfig      `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	Transform      *TransformConfig      `yaml:"transform,omitempty" json:"transform,omitempty"`
	Cache          *CacheConfig          `yaml:"cache,omitempty" json:"cache,omitempty"`
	Encoding       *EncodingConfig       `yaml:"encoding,omitempty" json:"encoding,omitempty"`

	// RequestLimits configures request size limits for this route (overrides global).
	RequestLimits *RequestLimitsConfig `yaml:"requestLimits,omitempty" json:"requestLimits,omitempty"`

	// CORS configures CORS for this route (overrides global).
	CORS *CORSConfig `yaml:"cors,omitempty" json:"cors,omitempty"`

	// Security configures security headers for this route (overrides global).
	Security *SecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this route (overrides global).
	MaxSessions *MaxSessionsConfig `yaml:"maxSessions,omitempty" json:"maxSessions,omitempty"`

	// TLS configures route-level TLS certificate override.
	// This allows serving different certificates based on SNI for this route.
	TLS *RouteTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// RouteTLSConfig contains TLS configuration for a specific route.
// This allows overriding the listener-level TLS certificate for specific routes
// based on SNI (Server Name Indication) matching.
type RouteTLSConfig struct {
	// CertFile is the path to the route-specific certificate file (PEM format).
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the route-specific private key file (PEM format).
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// SNIHosts is the list of SNI hostnames this certificate should be used for.
	// Supports exact matches and wildcard patterns (e.g., "*.example.com").
	SNIHosts []string `yaml:"sniHosts,omitempty" json:"sniHosts,omitempty"`

	// MinVersion is the minimum TLS version for this route (TLS12, TLS13).
	MinVersion string `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version for this route.
	MaxVersion string `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites for this route.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// ClientValidation configures client certificate validation for this route.
	ClientValidation *RouteClientValidationConfig `yaml:"clientValidation,omitempty" json:"clientValidation,omitempty"`

	// Vault configures Vault-based certificate management for this route.
	Vault *VaultTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// RouteClientValidationConfig configures client certificate validation for a route.
type RouteClientValidationConfig struct {
	// Enabled enables client certificate validation for this route.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// CAFile is the path to the CA certificate file for client validation.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// RequireClientCert requires client certificate for this route.
	RequireClientCert bool `yaml:"requireClientCert,omitempty" json:"requireClientCert,omitempty"`

	// AllowedCNs is the list of allowed Common Names for client certificates.
	AllowedCNs []string `yaml:"allowedCNs,omitempty" json:"allowedCNs,omitempty"`

	// AllowedSANs is the list of allowed Subject Alternative Names.
	AllowedSANs []string `yaml:"allowedSANs,omitempty" json:"allowedSANs,omitempty"`
}

// HasTLSOverride returns true if the route has TLS configuration that overrides listener TLS.
func (r *Route) HasTLSOverride() bool {
	if r.TLS == nil {
		return false
	}
	hasFiles := r.TLS.CertFile != "" || r.TLS.KeyFile != ""
	hasVault := r.TLS.Vault != nil && r.TLS.Vault.Enabled
	return hasFiles || hasVault
}

// GetEffectiveSNIHosts returns the SNI hosts for this route.
// Returns nil if no SNI hosts are configured.
func (r *Route) GetEffectiveSNIHosts() []string {
	if r.TLS == nil || len(r.TLS.SNIHosts) == 0 {
		return nil
	}
	return r.TLS.SNIHosts
}

// RouteMatch represents matching conditions for a route.
type RouteMatch struct {
	URI         *URIMatch         `yaml:"uri,omitempty" json:"uri,omitempty"`
	Methods     []string          `yaml:"methods,omitempty" json:"methods,omitempty"`
	Headers     []HeaderMatch     `yaml:"headers,omitempty" json:"headers,omitempty"`
	QueryParams []QueryParamMatch `yaml:"queryParams,omitempty" json:"queryParams,omitempty"`
}

// URIMatch represents URI matching configuration.
type URIMatch struct {
	Exact  string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Regex  string `yaml:"regex,omitempty" json:"regex,omitempty"`
}

// MatchType returns the type of URI match configured.
func (u *URIMatch) MatchType() string {
	if u.Exact != "" {
		return "exact"
	}
	if u.Prefix != "" {
		return "prefix"
	}
	if u.Regex != "" {
		return "regex"
	}
	return ""
}

// IsEmpty returns true if no match is configured.
func (u *URIMatch) IsEmpty() bool {
	return u.Exact == "" && u.Prefix == "" && u.Regex == ""
}

// HeaderMatch represents header matching configuration.
type HeaderMatch struct {
	Name    string `yaml:"name" json:"name"`
	Exact   string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Prefix  string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Regex   string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Present *bool  `yaml:"present,omitempty" json:"present,omitempty"`
	Absent  *bool  `yaml:"absent,omitempty" json:"absent,omitempty"`
}

// QueryParamMatch represents query parameter matching configuration.
type QueryParamMatch struct {
	Name    string `yaml:"name" json:"name"`
	Exact   string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Regex   string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Present *bool  `yaml:"present,omitempty" json:"present,omitempty"`
}

// RouteDestination represents a destination for routing.
type RouteDestination struct {
	Destination Destination `yaml:"destination" json:"destination"`
	Weight      int         `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// Destination represents a backend destination.
type Destination struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

// Backend represents a backend service configuration.
type Backend struct {
	Name         string            `yaml:"name" json:"name"`
	Hosts        []BackendHost     `yaml:"hosts" json:"hosts"`
	HealthCheck  *HealthCheck      `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`
	LoadBalancer *LoadBalancer     `yaml:"loadBalancer,omitempty" json:"loadBalancer,omitempty"`
	TLS          *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaker for this backend.
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for backend connections.
	Authentication *BackendAuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this backend.
	MaxSessions *MaxSessionsConfig `yaml:"maxSessions,omitempty" json:"maxSessions,omitempty"`

	// RateLimit configures rate limiting for this backend.
	RateLimit *RateLimitConfig `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
}

// BackendHost represents a single backend host.
type BackendHost struct {
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	Weight  int    `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// BackendTLSConfig contains TLS configuration for backend connections.
type BackendTLSConfig struct {
	// Enabled enables TLS for backend connections.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Mode specifies the TLS mode (SIMPLE, MUTUAL).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// CAFile is the path to the CA certificate for server verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// CertFile is the path to the client certificate (for mTLS).
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client private key (for mTLS).
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// ServerName overrides the server name for TLS verification.
	ServerName string `yaml:"serverName,omitempty" json:"serverName,omitempty"`

	// InsecureSkipVerify skips server certificate verification (dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// MinVersion is the minimum TLS version (TLS12, TLS13).
	MinVersion string `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	MaxVersion string `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// ALPN protocols for negotiation.
	ALPN []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`

	// Vault configures Vault-based client certificate management.
	Vault *VaultBackendTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// VaultBackendTLSConfig configures Vault-based TLS for backend connections.
type VaultBackendTLSConfig struct {
	// Enabled enables Vault integration for client certificates.
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

// BackendTLSMode constants for backend TLS configuration.
const (
	// BackendTLSModeSimple enables TLS with server certificate verification only.
	BackendTLSModeSimple = "SIMPLE"

	// BackendTLSModeMutual enables mutual TLS (mTLS) with client certificates.
	BackendTLSModeMutual = "MUTUAL"
)

// Validate validates the backend TLS configuration.
func (c *BackendTLSConfig) Validate() error {
	if c == nil {
		return nil
	}

	if err := c.validateMode(); err != nil {
		return err
	}
	if err := c.validateMutualTLS(); err != nil {
		return err
	}
	if err := c.validateVersions(); err != nil {
		return err
	}
	if err := c.validateVault(); err != nil {
		return err
	}

	return nil
}

// validateMode validates the TLS mode.
func (c *BackendTLSConfig) validateMode() error {
	validModes := map[string]bool{
		"": true, BackendTLSModeSimple: true, BackendTLSModeMutual: true, TLSModeInsecure: true,
	}
	if !validModes[c.Mode] {
		return fmt.Errorf("invalid backend TLS mode: %s (must be SIMPLE, MUTUAL, or INSECURE)", c.Mode)
	}
	return nil
}

// validateMutualTLS validates mTLS configuration.
func (c *BackendTLSConfig) validateMutualTLS() error {
	if c.Mode != BackendTLSModeMutual {
		return nil
	}
	vaultEnabled := c.Vault != nil && c.Vault.Enabled
	if c.CertFile == "" && !vaultEnabled {
		return fmt.Errorf("certFile is required for MUTUAL TLS mode (or enable Vault)")
	}
	if c.KeyFile == "" && !vaultEnabled {
		return fmt.Errorf("keyFile is required for MUTUAL TLS mode (or enable Vault)")
	}
	return nil
}

// validateVersions validates TLS version configuration.
func (c *BackendTLSConfig) validateVersions() error {
	validVersions := map[string]bool{
		"": true, "TLS10": true, "TLS11": true, "TLS12": true, "TLS13": true,
	}
	if !validVersions[c.MinVersion] {
		return fmt.Errorf("invalid minVersion: %s", c.MinVersion)
	}
	if !validVersions[c.MaxVersion] {
		return fmt.Errorf("invalid maxVersion: %s", c.MaxVersion)
	}
	return nil
}

// validateVault validates Vault configuration.
func (c *BackendTLSConfig) validateVault() error {
	if c.Vault != nil && c.Vault.Enabled {
		return c.Vault.Validate()
	}
	return nil
}

// Validate validates the Vault backend TLS configuration.
func (c *VaultBackendTLSConfig) Validate() error {
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

// IsEnabled returns true if TLS is enabled for backend connections.
func (c *BackendTLSConfig) IsEnabled() bool {
	return c != nil && c.Enabled
}

// IsMutual returns true if mutual TLS is configured.
func (c *BackendTLSConfig) IsMutual() bool {
	return c != nil && c.Mode == BackendTLSModeMutual
}

// GetEffectiveMode returns the effective TLS mode.
func (c *BackendTLSConfig) GetEffectiveMode() string {
	if c == nil || !c.Enabled {
		return TLSModeInsecure
	}
	if c.Mode == "" {
		return BackendTLSModeSimple
	}
	return c.Mode
}

// GetEffectiveMinVersion returns the effective minimum TLS version.
func (c *BackendTLSConfig) GetEffectiveMinVersion() string {
	if c == nil || c.MinVersion == "" {
		return "TLS12" // Default to TLS 1.2
	}
	return c.MinVersion
}

// HealthCheck represents health check configuration.
type HealthCheck struct {
	Path               string   `yaml:"path" json:"path"`
	Interval           Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout            Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	HealthyThreshold   int      `yaml:"healthyThreshold,omitempty" json:"healthyThreshold,omitempty"`
	UnhealthyThreshold int      `yaml:"unhealthyThreshold,omitempty" json:"unhealthyThreshold,omitempty"`
}

// LoadBalancer represents load balancer configuration.
type LoadBalancer struct {
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
}

// LoadBalancerAlgorithm constants.
const (
	LoadBalancerRoundRobin = "roundRobin"
	LoadBalancerWeighted   = "weighted"
	LoadBalancerLeastConn  = "leastConn"
	LoadBalancerRandom     = "random"
)

// RetryPolicy represents retry configuration.
type RetryPolicy struct {
	Attempts      int      `yaml:"attempts" json:"attempts"`
	PerTryTimeout Duration `yaml:"perTryTimeout,omitempty" json:"perTryTimeout,omitempty"`
	RetryOn       string   `yaml:"retryOn,omitempty" json:"retryOn,omitempty"`
}

// RateLimitConfig represents rate limiting configuration.
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled"`
	RequestsPerSecond int  `yaml:"requestsPerSecond" json:"requestsPerSecond"`
	Burst             int  `yaml:"burst" json:"burst"`
	PerClient         bool `yaml:"perClient,omitempty" json:"perClient,omitempty"`
}

// MaxSessionsConfig configures maximum concurrent sessions.
type MaxSessionsConfig struct {
	// Enabled enables max sessions limiting.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxConcurrent is the maximum number of concurrent sessions.
	MaxConcurrent int `yaml:"maxConcurrent" json:"maxConcurrent"`

	// QueueSize is the size of the waiting queue (0 = reject immediately).
	QueueSize int `yaml:"queueSize,omitempty" json:"queueSize,omitempty"`

	// QueueTimeout is the maximum time to wait in queue.
	QueueTimeout Duration `yaml:"queueTimeout,omitempty" json:"queueTimeout,omitempty"`
}

// GetEffectiveQueueTimeout returns the effective queue timeout.
func (c *MaxSessionsConfig) GetEffectiveQueueTimeout() time.Duration {
	if c == nil || c.QueueTimeout == 0 {
		return DefaultMaxSessionsQueueTimeout
	}
	return c.QueueTimeout.Duration()
}

// RequestLimitsConfig configures request size limits.
type RequestLimitsConfig struct {
	// MaxBodySize is the maximum allowed request body size in bytes.
	// Default is 10MB (10485760 bytes).
	MaxBodySize int64 `yaml:"maxBodySize,omitempty" json:"maxBodySize,omitempty"`

	// MaxHeaderSize is the maximum allowed total header size in bytes.
	// Default is 1MB (1048576 bytes).
	MaxHeaderSize int64 `yaml:"maxHeaderSize,omitempty" json:"maxHeaderSize,omitempty"`
}

// DefaultRequestLimits returns the default request limits configuration.
func DefaultRequestLimits() *RequestLimitsConfig {
	return &RequestLimitsConfig{
		MaxBodySize:   DefaultMaxBodySize,
		MaxHeaderSize: DefaultMaxHeaderSize,
	}
}

// GetEffectiveMaxBodySize returns the effective max body size.
func (c *RequestLimitsConfig) GetEffectiveMaxBodySize() int64 {
	if c == nil || c.MaxBodySize <= 0 {
		return DefaultMaxBodySize
	}
	return c.MaxBodySize
}

// GetEffectiveMaxHeaderSize returns the effective max header size.
func (c *RequestLimitsConfig) GetEffectiveMaxHeaderSize() int64 {
	if c == nil || c.MaxHeaderSize <= 0 {
		return DefaultMaxHeaderSize
	}
	return c.MaxHeaderSize
}

// CircuitBreakerConfig represents circuit breaker configuration.
type CircuitBreakerConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	Threshold        int      `yaml:"threshold" json:"threshold"`
	Timeout          Duration `yaml:"timeout" json:"timeout"`
	HalfOpenRequests int      `yaml:"halfOpenRequests,omitempty" json:"halfOpenRequests,omitempty"`
}

// CORSConfig represents CORS configuration.
type CORSConfig struct {
	AllowOrigins     []string `yaml:"allowOrigins,omitempty" json:"allowOrigins,omitempty"`
	AllowMethods     []string `yaml:"allowMethods,omitempty" json:"allowMethods,omitempty"`
	AllowHeaders     []string `yaml:"allowHeaders,omitempty" json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `yaml:"exposeHeaders,omitempty" json:"exposeHeaders,omitempty"`
	MaxAge           int      `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`
	AllowCredentials bool     `yaml:"allowCredentials,omitempty" json:"allowCredentials,omitempty"`
}

// ObservabilityConfig represents observability configuration.
type ObservabilityConfig struct {
	Metrics *MetricsConfig `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	Tracing *TracingConfig `yaml:"tracing,omitempty" json:"tracing,omitempty"`
	Logging *LoggingConfig `yaml:"logging,omitempty" json:"logging,omitempty"`
}

// MetricsConfig represents metrics configuration.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path,omitempty" json:"path,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
}

// TracingConfig represents tracing configuration.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled" json:"enabled"`
	SamplingRate float64 `yaml:"samplingRate,omitempty" json:"samplingRate,omitempty"`
	OTLPEndpoint string  `yaml:"otlpEndpoint,omitempty" json:"otlpEndpoint,omitempty"`
	ServiceName  string  `yaml:"serviceName,omitempty" json:"serviceName,omitempty"`
}

// LoggingConfig represents logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level,omitempty" json:"level,omitempty"`
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Output string `yaml:"output,omitempty" json:"output,omitempty"`
}

// RedirectConfig represents HTTP redirect configuration.
type RedirectConfig struct {
	URI        string `yaml:"uri,omitempty" json:"uri,omitempty"`
	Code       int    `yaml:"code,omitempty" json:"code,omitempty"`
	Scheme     string `yaml:"scheme,omitempty" json:"scheme,omitempty"`
	Host       string `yaml:"host,omitempty" json:"host,omitempty"`
	Port       int    `yaml:"port,omitempty" json:"port,omitempty"`
	StripQuery bool   `yaml:"stripQuery,omitempty" json:"stripQuery,omitempty"`
}

// RewriteConfig represents URL rewrite configuration.
type RewriteConfig struct {
	URI       string `yaml:"uri,omitempty" json:"uri,omitempty"`
	Authority string `yaml:"authority,omitempty" json:"authority,omitempty"`
}

// DirectResponseConfig represents direct response configuration.
type DirectResponseConfig struct {
	Status  int               `yaml:"status" json:"status"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// HeaderManipulation represents header manipulation configuration.
type HeaderManipulation struct {
	Request  *HeaderOperation `yaml:"request,omitempty" json:"request,omitempty"`
	Response *HeaderOperation `yaml:"response,omitempty" json:"response,omitempty"`
}

// HeaderOperation represents header operations.
type HeaderOperation struct {
	Set    map[string]string `yaml:"set,omitempty" json:"set,omitempty"`
	Add    map[string]string `yaml:"add,omitempty" json:"add,omitempty"`
	Remove []string          `yaml:"remove,omitempty" json:"remove,omitempty"`
}

// FaultInjection represents fault injection configuration.
type FaultInjection struct {
	Delay *FaultDelay `yaml:"delay,omitempty" json:"delay,omitempty"`
	Abort *FaultAbort `yaml:"abort,omitempty" json:"abort,omitempty"`
}

// FaultDelay represents delay fault injection.
type FaultDelay struct {
	FixedDelay Duration `yaml:"fixedDelay" json:"fixedDelay"`
	Percentage float64  `yaml:"percentage,omitempty" json:"percentage,omitempty"`
}

// FaultAbort represents abort fault injection.
type FaultAbort struct {
	HTTPStatus int     `yaml:"httpStatus" json:"httpStatus"`
	Percentage float64 `yaml:"percentage,omitempty" json:"percentage,omitempty"`
}

// MirrorConfig represents traffic mirroring configuration.
type MirrorConfig struct {
	Destination Destination `yaml:"destination" json:"destination"`
	Percentage  float64     `yaml:"percentage,omitempty" json:"percentage,omitempty"`
}

// Duration is a wrapper around time.Duration that supports YAML/JSON marshaling.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	// Remove quotes if present
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// Duration returns the time.Duration value.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: Metadata{
			Name: "default-gateway",
		},
		Spec: GatewaySpec{
			Listeners: []Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
					Hosts:    []string{"*"},
					Bind:     "0.0.0.0",
				},
			},
			Observability: &ObservabilityConfig{
				Metrics: &MetricsConfig{
					Enabled: true,
					Path:    "/metrics",
				},
				Logging: &LoggingConfig{
					Level:  "info",
					Format: "json",
				},
			},
		},
	}
}

// IsEmpty returns true if the RouteMatch has no conditions.
func (rm *RouteMatch) IsEmpty() bool {
	if rm.URI != nil && !rm.URI.IsEmpty() {
		return false
	}
	if len(rm.Methods) > 0 {
		return false
	}
	if len(rm.Headers) > 0 {
		return false
	}
	if len(rm.QueryParams) > 0 {
		return false
	}
	return true
}

// AuthenticationConfig represents authentication configuration.
type AuthenticationConfig struct {
	// Enabled enables authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// JWT configures JWT authentication.
	JWT *JWTAuthConfig `yaml:"jwt,omitempty" json:"jwt,omitempty"`

	// APIKey configures API key authentication.
	APIKey *APIKeyAuthConfig `yaml:"apiKey,omitempty" json:"apiKey,omitempty"`

	// MTLS configures mTLS authentication.
	MTLS *MTLSAuthConfig `yaml:"mtls,omitempty" json:"mtls,omitempty"`

	// OIDC configures OIDC authentication.
	OIDC *OIDCAuthConfig `yaml:"oidc,omitempty" json:"oidc,omitempty"`

	// AllowAnonymous allows anonymous access when no credentials are provided.
	AllowAnonymous bool `yaml:"allowAnonymous,omitempty" json:"allowAnonymous,omitempty"`

	// SkipPaths is a list of paths to skip authentication.
	SkipPaths []string `yaml:"skipPaths,omitempty" json:"skipPaths,omitempty"`
}

// JWTAuthConfig configures JWT authentication.
type JWTAuthConfig struct {
	// Enabled enables JWT authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Issuer is the expected token issuer.
	Issuer string `yaml:"issuer,omitempty" json:"issuer,omitempty"`

	// Audience is the expected token audience.
	Audience []string `yaml:"audience,omitempty" json:"audience,omitempty"`

	// JWKSURL is the URL to fetch JWKS from.
	JWKSURL string `yaml:"jwksUrl,omitempty" json:"jwksUrl,omitempty"`

	// Secret is the secret for HMAC algorithms.
	Secret string `yaml:"secret,omitempty" json:"secret,omitempty"`

	// PublicKey is the public key for RSA/ECDSA algorithms.
	PublicKey string `yaml:"publicKey,omitempty" json:"publicKey,omitempty"`

	// Algorithm is the expected signing algorithm.
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`

	// ClaimMapping maps JWT claims to identity fields.
	ClaimMapping *ClaimMappingConfig `yaml:"claimMapping,omitempty" json:"claimMapping,omitempty"`
}

// ClaimMappingConfig maps JWT claims to identity fields.
type ClaimMappingConfig struct {
	// Roles is the claim containing roles.
	Roles string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// Permissions is the claim containing permissions.
	Permissions string `yaml:"permissions,omitempty" json:"permissions,omitempty"`

	// Groups is the claim containing groups.
	Groups string `yaml:"groups,omitempty" json:"groups,omitempty"`

	// Scopes is the claim containing scopes.
	Scopes string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// Email is the claim containing email.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`

	// Name is the claim containing name.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
}

// APIKeyAuthConfig configures API key authentication.
type APIKeyAuthConfig struct {
	// Enabled enables API key authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Header is the header name for API key.
	Header string `yaml:"header,omitempty" json:"header,omitempty"`

	// Query is the query parameter name for API key.
	Query string `yaml:"query,omitempty" json:"query,omitempty"`

	// HashAlgorithm is the hash algorithm for stored keys.
	HashAlgorithm string `yaml:"hashAlgorithm,omitempty" json:"hashAlgorithm,omitempty"`

	// VaultPath is the Vault path for API keys.
	VaultPath string `yaml:"vaultPath,omitempty" json:"vaultPath,omitempty"`
}

// MTLSAuthConfig configures mTLS authentication.
type MTLSAuthConfig struct {
	// Enabled enables mTLS authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CAFile is the path to the CA certificate.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// ExtractIdentity specifies how to extract identity from certificate.
	ExtractIdentity string `yaml:"extractIdentity,omitempty" json:"extractIdentity,omitempty"`

	// AllowedCNs is a list of allowed common names.
	AllowedCNs []string `yaml:"allowedCNs,omitempty" json:"allowedCNs,omitempty"`

	// AllowedOUs is a list of allowed organizational units.
	AllowedOUs []string `yaml:"allowedOUs,omitempty" json:"allowedOUs,omitempty"`
}

// OIDCAuthConfig configures OIDC authentication.
type OIDCAuthConfig struct {
	// Enabled enables OIDC authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Providers is a list of OIDC providers.
	Providers []OIDCProviderConfig `yaml:"providers,omitempty" json:"providers,omitempty"`
}

// OIDCProviderConfig configures an OIDC provider.
type OIDCProviderConfig struct {
	// Name is the provider name.
	Name string `yaml:"name" json:"name"`

	// IssuerURL is the OIDC issuer URL.
	IssuerURL string `yaml:"issuerUrl" json:"issuerUrl"`

	// ClientID is the OIDC client ID.
	ClientID string `yaml:"clientId" json:"clientId"`

	// ClientSecret is the OIDC client secret.
	ClientSecret string `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`

	// Scopes is the list of scopes to request.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// AuthorizationConfig represents authorization configuration.
type AuthorizationConfig struct {
	// Enabled enables authorization.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// DefaultPolicy is the default policy when no rules match.
	DefaultPolicy string `yaml:"defaultPolicy,omitempty" json:"defaultPolicy,omitempty"`

	// RBAC configures role-based access control.
	RBAC *RBACConfig `yaml:"rbac,omitempty" json:"rbac,omitempty"`

	// ABAC configures attribute-based access control.
	ABAC *ABACConfig `yaml:"abac,omitempty" json:"abac,omitempty"`

	// External configures external authorization.
	External *ExternalAuthzConfig `yaml:"external,omitempty" json:"external,omitempty"`

	// SkipPaths is a list of paths to skip authorization.
	SkipPaths []string `yaml:"skipPaths,omitempty" json:"skipPaths,omitempty"`

	// Cache configures authorization decision caching.
	Cache *AuthzCacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`
}

// RBACConfig configures role-based access control.
type RBACConfig struct {
	// Enabled enables RBAC.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Policies is a list of RBAC policies.
	Policies []RBACPolicyConfig `yaml:"policies,omitempty" json:"policies,omitempty"`

	// RoleHierarchy defines role inheritance.
	RoleHierarchy map[string][]string `yaml:"roleHierarchy,omitempty" json:"roleHierarchy,omitempty"`
}

// RBACPolicyConfig configures an RBAC policy.
type RBACPolicyConfig struct {
	// Name is the policy name.
	Name string `yaml:"name" json:"name"`

	// Roles is a list of roles that match this policy.
	Roles []string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// Resources is a list of resources this policy applies to.
	Resources []string `yaml:"resources,omitempty" json:"resources,omitempty"`

	// Actions is a list of actions this policy allows.
	Actions []string `yaml:"actions,omitempty" json:"actions,omitempty"`

	// Effect is the policy effect (allow or deny).
	Effect string `yaml:"effect,omitempty" json:"effect,omitempty"`

	// Priority is the policy priority.
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`
}

// ABACConfig configures attribute-based access control.
type ABACConfig struct {
	// Enabled enables ABAC.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Policies is a list of ABAC policies.
	Policies []ABACPolicyConfig `yaml:"policies,omitempty" json:"policies,omitempty"`
}

// ABACPolicyConfig configures an ABAC policy.
type ABACPolicyConfig struct {
	// Name is the policy name.
	Name string `yaml:"name" json:"name"`

	// Expression is the CEL expression for the policy.
	Expression string `yaml:"expression" json:"expression"`

	// Resources is a list of resources this policy applies to.
	Resources []string `yaml:"resources,omitempty" json:"resources,omitempty"`

	// Actions is a list of actions this policy applies to.
	Actions []string `yaml:"actions,omitempty" json:"actions,omitempty"`

	// Effect is the policy effect (allow or deny).
	Effect string `yaml:"effect,omitempty" json:"effect,omitempty"`

	// Priority is the policy priority.
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`
}

// ExternalAuthzConfig configures external authorization.
type ExternalAuthzConfig struct {
	// Enabled enables external authorization.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// OPA configures OPA authorization.
	OPA *OPAAuthzConfig `yaml:"opa,omitempty" json:"opa,omitempty"`

	// Timeout is the timeout for external authorization requests.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// FailOpen allows requests when external authorization fails.
	FailOpen bool `yaml:"failOpen,omitempty" json:"failOpen,omitempty"`
}

// OPAAuthzConfig configures OPA authorization.
type OPAAuthzConfig struct {
	// URL is the OPA server URL.
	URL string `yaml:"url" json:"url"`

	// Policy is the OPA policy path.
	Policy string `yaml:"policy,omitempty" json:"policy,omitempty"`

	// Headers are additional headers to send to OPA.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// AuthzCacheConfig configures authorization decision caching.
type AuthzCacheConfig struct {
	// Enabled enables caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache TTL.
	TTL Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of entries.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`

	// Type is the cache type (memory, redis).
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
}

// SecurityConfig represents security configuration.
type SecurityConfig struct {
	// Enabled enables security features.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Headers configures security headers.
	Headers *SecurityHeadersConfig `yaml:"headers,omitempty" json:"headers,omitempty"`

	// HSTS configures HTTP Strict Transport Security.
	HSTS *SecurityHSTSConfig `yaml:"hsts,omitempty" json:"hsts,omitempty"`

	// CSP configures Content Security Policy.
	CSP *CSPConfig `yaml:"csp,omitempty" json:"csp,omitempty"`

	// ReferrerPolicy configures the Referrer-Policy header.
	ReferrerPolicy string `yaml:"referrerPolicy,omitempty" json:"referrerPolicy,omitempty"`
}

// SecurityHeadersConfig configures security headers.
type SecurityHeadersConfig struct {
	// Enabled enables security headers.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// XFrameOptions sets the X-Frame-Options header.
	XFrameOptions string `yaml:"xFrameOptions,omitempty" json:"xFrameOptions,omitempty"`

	// XContentTypeOptions sets the X-Content-Type-Options header.
	XContentTypeOptions string `yaml:"xContentTypeOptions,omitempty" json:"xContentTypeOptions,omitempty"`

	// XXSSProtection sets the X-XSS-Protection header.
	XXSSProtection string `yaml:"xXSSProtection,omitempty" json:"xXSSProtection,omitempty"`

	// CustomHeaders allows setting custom headers.
	CustomHeaders map[string]string `yaml:"customHeaders,omitempty" json:"customHeaders,omitempty"`
}

// SecurityHSTSConfig configures HTTP Strict Transport Security.
type SecurityHSTSConfig struct {
	// Enabled enables HSTS.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxAge is the max-age directive value in seconds.
	MaxAge int `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`

	// IncludeSubDomains includes the includeSubDomains directive.
	IncludeSubDomains bool `yaml:"includeSubDomains,omitempty" json:"includeSubDomains,omitempty"`

	// Preload includes the preload directive.
	Preload bool `yaml:"preload,omitempty" json:"preload,omitempty"`
}

// CSPConfig configures Content Security Policy.
type CSPConfig struct {
	// Enabled enables CSP.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Policy is the full CSP policy string.
	Policy string `yaml:"policy,omitempty" json:"policy,omitempty"`

	// ReportOnly sets the header to Content-Security-Policy-Report-Only.
	ReportOnly bool `yaml:"reportOnly,omitempty" json:"reportOnly,omitempty"`

	// ReportURI is the URI to report CSP violations.
	ReportURI string `yaml:"reportUri,omitempty" json:"reportUri,omitempty"`
}

// AuditConfig represents audit logging configuration.
type AuditConfig struct {
	// Enabled enables audit logging.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Level is the minimum audit level to log.
	Level string `yaml:"level,omitempty" json:"level,omitempty"`

	// Output specifies the output destination (stdout, stderr, file path).
	Output string `yaml:"output,omitempty" json:"output,omitempty"`

	// Format specifies the output format (json, text).
	Format string `yaml:"format,omitempty" json:"format,omitempty"`

	// Events configures which events to audit.
	Events *AuditEventsConfig `yaml:"events,omitempty" json:"events,omitempty"`

	// SkipPaths specifies paths to skip auditing.
	SkipPaths []string `yaml:"skipPaths,omitempty" json:"skipPaths,omitempty"`

	// RedactFields specifies fields to redact from logs.
	RedactFields []string `yaml:"redactFields,omitempty" json:"redactFields,omitempty"`
}

// AuditEventsConfig configures which events to audit.
type AuditEventsConfig struct {
	// Authentication enables authentication event auditing.
	Authentication bool `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// Authorization enables authorization event auditing.
	Authorization bool `yaml:"authorization,omitempty" json:"authorization,omitempty"`

	// Request enables request event auditing.
	Request bool `yaml:"request,omitempty" json:"request,omitempty"`

	// Response enables response event auditing.
	Response bool `yaml:"response,omitempty" json:"response,omitempty"`

	// Configuration enables configuration change auditing.
	Configuration bool `yaml:"configuration,omitempty" json:"configuration,omitempty"`

	// Security enables security event auditing.
	Security bool `yaml:"security,omitempty" json:"security,omitempty"`
}

// BackendAuthConfig configures authentication for backend connections.
type BackendAuthConfig struct {
	// Type specifies the authentication type (jwt, basic, mtls).
	Type string `yaml:"type" json:"type"`

	// JWT configures JWT authentication for backend.
	JWT *BackendJWTAuthConfig `yaml:"jwt,omitempty" json:"jwt,omitempty"`

	// Basic configures Basic authentication for backend.
	Basic *BackendBasicAuthConfig `yaml:"basic,omitempty" json:"basic,omitempty"`

	// MTLS configures mTLS authentication for backend.
	MTLS *BackendMTLSAuthConfig `yaml:"mtls,omitempty" json:"mtls,omitempty"`
}

// BackendJWTAuthConfig configures JWT authentication for backend connections.
type BackendJWTAuthConfig struct {
	// Enabled enables JWT authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TokenSource specifies where to get the token (static, vault, oidc).
	TokenSource string `yaml:"tokenSource" json:"tokenSource"`

	// StaticToken is a static JWT token (for development only).
	StaticToken string `yaml:"staticToken,omitempty" json:"staticToken,omitempty"`

	// VaultPath is the Vault path for JWT token.
	VaultPath string `yaml:"vaultPath,omitempty" json:"vaultPath,omitempty"`

	// OIDC configures OIDC token acquisition.
	OIDC *BackendOIDCConfig `yaml:"oidc,omitempty" json:"oidc,omitempty"`

	// HeaderName is the header name for the token (default: Authorization).
	HeaderName string `yaml:"headerName,omitempty" json:"headerName,omitempty"`

	// HeaderPrefix is the prefix for the token (default: Bearer).
	HeaderPrefix string `yaml:"headerPrefix,omitempty" json:"headerPrefix,omitempty"`
}

// BackendOIDCConfig configures OIDC token acquisition for backend auth.
type BackendOIDCConfig struct {
	// IssuerURL is the OIDC issuer URL.
	IssuerURL string `yaml:"issuerUrl" json:"issuerUrl"`

	// ClientID is the OIDC client ID.
	ClientID string `yaml:"clientId" json:"clientId"`

	// ClientSecret is the OIDC client secret.
	ClientSecret string `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`

	// ClientSecretVaultPath is the Vault path for client secret.
	ClientSecretVaultPath string `yaml:"clientSecretVaultPath,omitempty" json:"clientSecretVaultPath,omitempty"`

	// Scopes are the scopes to request.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// TokenCacheTTL is the TTL for cached tokens.
	TokenCacheTTL Duration `yaml:"tokenCacheTTL,omitempty" json:"tokenCacheTTL,omitempty"`
}

// BackendBasicAuthConfig configures Basic authentication for backend connections.
type BackendBasicAuthConfig struct {
	// Enabled enables Basic authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Username is the username for Basic auth.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Password is the password for Basic auth.
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// VaultPath is the Vault path for credentials.
	VaultPath string `yaml:"vaultPath,omitempty" json:"vaultPath,omitempty"`

	// UsernameKey is the key in Vault for username (default: username).
	UsernameKey string `yaml:"usernameKey,omitempty" json:"usernameKey,omitempty"`

	// PasswordKey is the key in Vault for password (default: password).
	PasswordKey string `yaml:"passwordKey,omitempty" json:"passwordKey,omitempty"`
}

// BackendMTLSAuthConfig configures mTLS authentication for backend connections.
type BackendMTLSAuthConfig struct {
	// Enabled enables mTLS authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CertFile is the path to the client certificate.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client private key.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate for server verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// Vault configures Vault-based certificate management.
	Vault *VaultBackendTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// Validate validates the backend authentication configuration.
func (c *BackendAuthConfig) Validate() error {
	if c == nil {
		return nil
	}

	validTypes := map[string]bool{"": true, "jwt": true, "basic": true, "mtls": true}
	if !validTypes[c.Type] {
		return fmt.Errorf("invalid backend auth type: %s (must be jwt, basic, or mtls)", c.Type)
	}

	if c.JWT != nil && c.JWT.Enabled {
		if err := c.JWT.Validate(); err != nil {
			return fmt.Errorf("jwt auth config: %w", err)
		}
	}

	if c.Basic != nil && c.Basic.Enabled {
		if err := c.Basic.Validate(); err != nil {
			return fmt.Errorf("basic auth config: %w", err)
		}
	}

	if c.MTLS != nil && c.MTLS.Enabled {
		if err := c.MTLS.Validate(); err != nil {
			return fmt.Errorf("mtls auth config: %w", err)
		}
	}

	return nil
}

// Validate validates the JWT authentication configuration.
func (c *BackendJWTAuthConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	validSources := map[string]bool{"static": true, "vault": true, "oidc": true}
	if !validSources[c.TokenSource] {
		return fmt.Errorf("invalid token source: %s (must be static, vault, or oidc)", c.TokenSource)
	}

	switch c.TokenSource {
	case "static":
		if c.StaticToken == "" {
			return fmt.Errorf("staticToken is required for static token source")
		}
	case "vault":
		if c.VaultPath == "" {
			return fmt.Errorf("vaultPath is required for vault token source")
		}
	case "oidc":
		if c.OIDC == nil {
			return fmt.Errorf("oidc config is required for oidc token source")
		}
		if err := c.OIDC.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the OIDC configuration.
func (c *BackendOIDCConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.IssuerURL == "" {
		return fmt.Errorf("issuerUrl is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("clientId is required")
	}
	if c.ClientSecret == "" && c.ClientSecretVaultPath == "" {
		return fmt.Errorf("either clientSecret or clientSecretVaultPath is required")
	}

	return nil
}

// Validate validates the Basic authentication configuration.
func (c *BackendBasicAuthConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	hasStatic := c.Username != "" && c.Password != ""
	hasVault := c.VaultPath != ""

	if !hasStatic && !hasVault {
		return fmt.Errorf("either username/password or vaultPath is required")
	}

	return nil
}

// Validate validates the mTLS authentication configuration.
func (c *BackendMTLSAuthConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	hasFiles := c.CertFile != "" && c.KeyFile != ""
	hasVault := c.Vault != nil && c.Vault.Enabled

	if !hasFiles && !hasVault {
		return fmt.Errorf("either certFile/keyFile or vault config is required")
	}

	if hasVault {
		if err := c.Vault.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// GetEffectiveHeaderName returns the effective header name for JWT.
func (c *BackendJWTAuthConfig) GetEffectiveHeaderName() string {
	if c == nil || c.HeaderName == "" {
		return "Authorization"
	}
	return c.HeaderName
}

// GetEffectiveHeaderPrefix returns the effective header prefix for JWT.
func (c *BackendJWTAuthConfig) GetEffectiveHeaderPrefix() string {
	if c == nil || c.HeaderPrefix == "" {
		return "Bearer"
	}
	return c.HeaderPrefix
}

// GetEffectiveUsernameKey returns the effective username key for Vault.
func (c *BackendBasicAuthConfig) GetEffectiveUsernameKey() string {
	if c == nil || c.UsernameKey == "" {
		return "username"
	}
	return c.UsernameKey
}

// GetEffectivePasswordKey returns the effective password key for Vault.
func (c *BackendBasicAuthConfig) GetEffectivePasswordKey() string {
	if c == nil || c.PasswordKey == "" {
		return "password"
	}
	return c.PasswordKey
}
