package config

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

	// Authentication configures route-level authentication.
	Authentication *AuthenticationConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	Authorization *AuthorizationConfig `yaml:"authorization,omitempty" json:"authorization,omitempty"`

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

// RetryPolicy represents retry configuration.
type RetryPolicy struct {
	Attempts      int      `yaml:"attempts" json:"attempts"`
	PerTryTimeout Duration `yaml:"perTryTimeout,omitempty" json:"perTryTimeout,omitempty"`
	RetryOn       string   `yaml:"retryOn,omitempty" json:"retryOn,omitempty"`
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
