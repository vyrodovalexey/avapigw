package config

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

	// Redis contains Redis-specific configuration for authorization cache.
	// Only used when Type is "redis".
	Redis *RedisCacheConfig `yaml:"redis,omitempty" json:"redis,omitempty"`
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
