// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Duration is a string representation of a duration (e.g., "30s", "5m", "1h").
// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$`
type Duration string

// ConditionType represents the type of condition.
type ConditionType string

// Condition types for CRD status.
const (
	// ConditionReady indicates the resource is ready.
	ConditionReady ConditionType = "Ready"

	// ConditionValid indicates the resource configuration is valid.
	ConditionValid ConditionType = "Valid"

	// ConditionHealthy indicates the resource is healthy (for backends).
	ConditionHealthy ConditionType = "Healthy"
)

// ConditionReason represents the reason for a condition.
type ConditionReason string

// Condition reasons.
const (
	ReasonReconciled       ConditionReason = "Reconciled"
	ReasonReconcileFailed  ConditionReason = "ReconcileFailed"
	ReasonValidationPassed ConditionReason = "ValidationPassed"
	ReasonValidationFailed ConditionReason = "ValidationFailed"
	ReasonHealthCheckOK    ConditionReason = "HealthCheckOK"
	ReasonHealthCheckFail  ConditionReason = "HealthCheckFailed"
	ReasonApplied          ConditionReason = "Applied"
	ReasonApplyFailed      ConditionReason = "ApplyFailed"
	ReasonDeleted          ConditionReason = "Deleted"
	ReasonDeleteFailed     ConditionReason = "DeleteFailed"
)

// Condition represents a condition of a resource.
type Condition struct {
	// Type of condition.
	Type ConditionType `json:"type"`

	// Status of the condition (True, False, Unknown).
	Status metav1.ConditionStatus `json:"status"`

	// Reason for the condition's last transition.
	Reason ConditionReason `json:"reason"`

	// Message is a human-readable message indicating details about the transition.
	// +optional
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the last time the condition transitioned from one status to another.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// ObservedGeneration represents the .metadata.generation that the condition was set based upon.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// AppliedGateway represents a gateway where the configuration has been applied.
type AppliedGateway struct {
	// Name of the gateway.
	Name string `json:"name"`

	// Namespace of the gateway.
	Namespace string `json:"namespace"`

	// LastApplied is the timestamp when the configuration was last applied.
	LastApplied metav1.Time `json:"lastApplied"`
}

// StringMatch represents a string matching configuration.
type StringMatch struct {
	// Exact matches the string exactly.
	// +optional
	Exact string `json:"exact,omitempty"`

	// Prefix matches strings starting with this prefix.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Regex matches strings using a regular expression.
	// +optional
	Regex string `json:"regex,omitempty"`
}

// HeaderMatch represents header matching configuration.
type HeaderMatch struct {
	// Name is the header name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Exact matches the header value exactly.
	// +optional
	Exact string `json:"exact,omitempty"`

	// Prefix matches header values starting with this prefix.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Regex matches header values using a regular expression.
	// +optional
	Regex string `json:"regex,omitempty"`

	// Present matches if the header is present (regardless of value).
	// +optional
	Present *bool `json:"present,omitempty"`

	// Absent matches if the header is NOT present.
	// +optional
	Absent *bool `json:"absent,omitempty"`
}

// Destination represents a backend destination.
type Destination struct {
	// Host is the backend host (service name or IP).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// Port is the backend port.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int `json:"port"`
}

// RouteDestination represents a destination with weight for routing.
type RouteDestination struct {
	// Destination is the backend destination.
	// +kubebuilder:validation:Required
	Destination Destination `json:"destination"`

	// Weight is the traffic weight for this destination (0-100).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	// +optional
	Weight int `json:"weight,omitempty"`
}

// RetryPolicy represents retry configuration.
type RetryPolicy struct {
	// Attempts is the maximum number of retry attempts.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=3
	Attempts int `json:"attempts"`

	// PerTryTimeout is the timeout for each retry attempt.
	// +optional
	PerTryTimeout Duration `json:"perTryTimeout,omitempty"`

	// RetryOn is a comma-separated list of conditions to retry on.
	// For HTTP: 5xx, reset, connect-failure, retriable-4xx, refused-stream, etc.
	// For gRPC: canceled, deadline-exceeded, internal, resource-exhausted, unavailable.
	// +optional
	RetryOn string `json:"retryOn,omitempty"`
}

// GRPCRetryPolicy represents gRPC-specific retry configuration.
type GRPCRetryPolicy struct {
	// Attempts is the maximum number of retry attempts.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=3
	Attempts int `json:"attempts"`

	// PerTryTimeout is the timeout for each retry attempt.
	// +optional
	PerTryTimeout Duration `json:"perTryTimeout,omitempty"`

	// RetryOn is a comma-separated list of gRPC status codes to retry on.
	// Valid values: canceled, deadline-exceeded, internal, resource-exhausted, unavailable.
	// +optional
	RetryOn string `json:"retryOn,omitempty"`

	// BackoffBaseInterval is the base interval for exponential backoff.
	// +optional
	BackoffBaseInterval Duration `json:"backoffBaseInterval,omitempty"`

	// BackoffMaxInterval is the maximum interval for exponential backoff.
	// +optional
	BackoffMaxInterval Duration `json:"backoffMaxInterval,omitempty"`
}

// HeaderOperation represents header operations.
type HeaderOperation struct {
	// Set replaces header values.
	// +optional
	Set map[string]string `json:"set,omitempty"`

	// Add appends header values.
	// +optional
	Add map[string]string `json:"add,omitempty"`

	// Remove removes headers.
	// +optional
	Remove []string `json:"remove,omitempty"`
}

// HeaderManipulation represents header manipulation configuration.
type HeaderManipulation struct {
	// Request contains request header operations.
	// +optional
	Request *HeaderOperation `json:"request,omitempty"`

	// Response contains response header operations.
	// +optional
	Response *HeaderOperation `json:"response,omitempty"`
}

// RateLimitConfig represents rate limiting configuration.
type RateLimitConfig struct {
	// Enabled enables rate limiting.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// RequestsPerSecond is the maximum requests per second.
	// +kubebuilder:validation:Minimum=1
	RequestsPerSecond int `json:"requestsPerSecond"`

	// Burst is the maximum burst size.
	// +kubebuilder:validation:Minimum=1
	Burst int `json:"burst"`

	// PerClient enables per-client rate limiting.
	// +optional
	PerClient bool `json:"perClient,omitempty"`
}

// CORSConfig represents CORS configuration.
type CORSConfig struct {
	// AllowOrigins is the list of allowed origins.
	// +optional
	AllowOrigins []string `json:"allowOrigins,omitempty"`

	// AllowMethods is the list of allowed HTTP methods.
	// +optional
	AllowMethods []string `json:"allowMethods,omitempty"`

	// AllowHeaders is the list of allowed headers.
	// +optional
	AllowHeaders []string `json:"allowHeaders,omitempty"`

	// ExposeHeaders is the list of headers to expose.
	// +optional
	ExposeHeaders []string `json:"exposeHeaders,omitempty"`

	// MaxAge is the maximum age for preflight cache in seconds.
	// +optional
	MaxAge int `json:"maxAge,omitempty"`

	// AllowCredentials allows credentials.
	// +optional
	AllowCredentials bool `json:"allowCredentials,omitempty"`
}

// SecurityHeadersConfig represents security headers configuration.
type SecurityHeadersConfig struct {
	// Enabled enables security headers.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// XFrameOptions sets the X-Frame-Options header.
	// +optional
	XFrameOptions string `json:"xFrameOptions,omitempty"`

	// XContentTypeOptions sets the X-Content-Type-Options header.
	// +optional
	XContentTypeOptions string `json:"xContentTypeOptions,omitempty"`

	// XXSSProtection sets the X-XSS-Protection header.
	// +optional
	XXSSProtection string `json:"xXSSProtection,omitempty"`

	// ContentSecurityPolicy sets the Content-Security-Policy header.
	// +optional
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty"`

	// StrictTransportSecurity sets the Strict-Transport-Security header.
	// +optional
	StrictTransportSecurity string `json:"strictTransportSecurity,omitempty"`
}

// SecurityConfig represents security configuration.
type SecurityConfig struct {
	// Enabled enables security features.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Headers configures security headers.
	// +optional
	Headers *SecurityHeadersConfig `json:"headers,omitempty"`
}

// MaxSessionsConfig configures maximum concurrent sessions.
type MaxSessionsConfig struct {
	// Enabled enables max sessions limiting.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// MaxConcurrent is the maximum number of concurrent sessions.
	// +kubebuilder:validation:Minimum=1
	MaxConcurrent int `json:"maxConcurrent"`

	// QueueSize is the size of the waiting queue (0 = reject immediately).
	// +optional
	QueueSize int `json:"queueSize,omitempty"`

	// QueueTimeout is the maximum time to wait in queue.
	// +optional
	QueueTimeout Duration `json:"queueTimeout,omitempty"`
}

// RequestLimitsConfig configures request size limits.
type RequestLimitsConfig struct {
	// MaxBodySize is the maximum allowed request body size in bytes.
	// +optional
	MaxBodySize int64 `json:"maxBodySize,omitempty"`

	// MaxHeaderSize is the maximum allowed total header size in bytes.
	// +optional
	MaxHeaderSize int64 `json:"maxHeaderSize,omitempty"`
}

// VaultTLSConfig configures Vault-based TLS certificate management.
type VaultTLSConfig struct {
	// Enabled enables Vault integration.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// PKIMount is the Vault PKI mount path.
	// +optional
	PKIMount string `json:"pkiMount,omitempty"`

	// Role is the Vault PKI role name.
	// +optional
	Role string `json:"role,omitempty"`

	// CommonName for certificate requests.
	// +optional
	CommonName string `json:"commonName,omitempty"`

	// AltNames for certificate requests.
	// +optional
	AltNames []string `json:"altNames,omitempty"`

	// TTL for certificate requests.
	// +optional
	TTL string `json:"ttl,omitempty"`
}

// ClientValidationConfig configures client certificate validation.
type ClientValidationConfig struct {
	// Enabled enables client certificate validation.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// CAFile is the path to the CA certificate file for client validation.
	// +optional
	CAFile string `json:"caFile,omitempty"`

	// RequireClientCert requires client certificate.
	// +optional
	RequireClientCert bool `json:"requireClientCert,omitempty"`

	// AllowedCNs is the list of allowed Common Names for client certificates.
	// +optional
	AllowedCNs []string `json:"allowedCNs,omitempty"`

	// AllowedSANs is the list of allowed Subject Alternative Names.
	// +optional
	AllowedSANs []string `json:"allowedSANs,omitempty"`
}

// RouteTLSConfig contains TLS configuration for a specific route.
type RouteTLSConfig struct {
	// CertFile is the path to the route-specific certificate file (PEM format).
	// +optional
	CertFile string `json:"certFile,omitempty"`

	// KeyFile is the path to the route-specific private key file (PEM format).
	// +optional
	KeyFile string `json:"keyFile,omitempty"`

	// SNIHosts is the list of SNI hostnames this certificate should be used for.
	// +optional
	SNIHosts []string `json:"sniHosts,omitempty"`

	// MinVersion is the minimum TLS version (TLS12, TLS13).
	// +kubebuilder:validation:Enum=TLS12;TLS13
	// +optional
	MinVersion string `json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	// +kubebuilder:validation:Enum=TLS12;TLS13
	// +optional
	MaxVersion string `json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	// +optional
	CipherSuites []string `json:"cipherSuites,omitempty"`

	// ClientValidation configures client certificate validation.
	// +optional
	ClientValidation *ClientValidationConfig `json:"clientValidation,omitempty"`

	// Vault configures Vault-based certificate management.
	// +optional
	Vault *VaultTLSConfig `json:"vault,omitempty"`
}

// MirrorConfig represents traffic mirroring configuration.
type MirrorConfig struct {
	// Destination is the mirror destination.
	// +kubebuilder:validation:Required
	Destination Destination `json:"destination"`

	// Percentage is the percentage of traffic to mirror (0-100).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	// +optional
	Percentage int `json:"percentage,omitempty"`
}

// CircuitBreakerConfig represents circuit breaker configuration.
type CircuitBreakerConfig struct {
	// Enabled enables circuit breaker.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Threshold is the number of failures before opening the circuit.
	// +kubebuilder:validation:Minimum=1
	Threshold int `json:"threshold"`

	// Timeout is the time to wait before attempting to close the circuit.
	// +kubebuilder:validation:Required
	Timeout Duration `json:"timeout"`

	// HalfOpenRequests is the number of requests to allow in half-open state.
	// +optional
	HalfOpenRequests int `json:"halfOpenRequests,omitempty"`
}

// LoadBalancerAlgorithm represents load balancer algorithm.
// +kubebuilder:validation:Enum=roundRobin;weighted;leastConn;random
type LoadBalancerAlgorithm string

// Load balancer algorithm constants.
const (
	LoadBalancerRoundRobin LoadBalancerAlgorithm = "roundRobin"
	LoadBalancerWeighted   LoadBalancerAlgorithm = "weighted"
	LoadBalancerLeastConn  LoadBalancerAlgorithm = "leastConn"
	LoadBalancerRandom     LoadBalancerAlgorithm = "random"
)

// LoadBalancerConfig represents load balancer configuration.
type LoadBalancerConfig struct {
	// Algorithm is the load balancing algorithm.
	// +kubebuilder:default=roundRobin
	Algorithm LoadBalancerAlgorithm `json:"algorithm,omitempty"`
}

// AuthenticationConfig represents route-level authentication configuration.
type AuthenticationConfig struct {
	// Enabled enables authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// JWT configures JWT authentication.
	// +optional
	JWT *JWTAuthConfig `json:"jwt,omitempty"`

	// APIKey configures API key authentication.
	// +optional
	APIKey *APIKeyAuthConfig `json:"apiKey,omitempty"`

	// MTLS configures mTLS authentication.
	// +optional
	MTLS *MTLSAuthConfig `json:"mtls,omitempty"`

	// OIDC configures OIDC authentication.
	// +optional
	OIDC *OIDCAuthConfig `json:"oidc,omitempty"`

	// AllowAnonymous allows anonymous access when no credentials are provided.
	// +optional
	AllowAnonymous bool `json:"allowAnonymous,omitempty"`

	// SkipPaths is a list of paths to skip authentication.
	// +optional
	SkipPaths []string `json:"skipPaths,omitempty"`
}

// JWTAuthConfig configures JWT authentication.
type JWTAuthConfig struct {
	// Enabled enables JWT authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Issuer is the expected token issuer.
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// Audience is the expected token audience.
	// +optional
	Audience []string `json:"audience,omitempty"`

	// JWKSURL is the URL to fetch JWKS from.
	// +optional
	JWKSURL string `json:"jwksUrl,omitempty"`

	// Secret is the secret for HMAC algorithms.
	// +optional
	Secret string `json:"secret,omitempty"`

	// PublicKey is the public key for RSA/ECDSA algorithms.
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// Algorithm is the expected signing algorithm.
	// +kubebuilder:validation:Enum=HS256;HS384;HS512;RS256;RS384;RS512;ES256;ES384;ES512
	// +optional
	Algorithm string `json:"algorithm,omitempty"`

	// ClaimMapping maps JWT claims to identity fields.
	// +optional
	ClaimMapping *ClaimMappingConfig `json:"claimMapping,omitempty"`
}

// ClaimMappingConfig maps JWT claims to identity fields.
type ClaimMappingConfig struct {
	// Roles is the claim containing roles.
	// +optional
	Roles string `json:"roles,omitempty"`

	// Permissions is the claim containing permissions.
	// +optional
	Permissions string `json:"permissions,omitempty"`

	// Groups is the claim containing groups.
	// +optional
	Groups string `json:"groups,omitempty"`

	// Scopes is the claim containing scopes.
	// +optional
	Scopes string `json:"scopes,omitempty"`

	// Email is the claim containing email.
	// +optional
	Email string `json:"email,omitempty"`

	// Name is the claim containing name.
	// +optional
	Name string `json:"name,omitempty"`
}

// APIKeyAuthConfig configures API key authentication.
type APIKeyAuthConfig struct {
	// Enabled enables API key authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Header is the header name for API key.
	// +kubebuilder:default=X-API-Key
	// +optional
	Header string `json:"header,omitempty"`

	// Query is the query parameter name for API key.
	// +optional
	Query string `json:"query,omitempty"`

	// HashAlgorithm is the hash algorithm for stored keys.
	// +kubebuilder:validation:Enum=sha256;sha512;bcrypt
	// +optional
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`

	// VaultPath is the Vault path for API keys.
	// +optional
	VaultPath string `json:"vaultPath,omitempty"`
}

// MTLSAuthConfig configures mTLS authentication.
type MTLSAuthConfig struct {
	// Enabled enables mTLS authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// CAFile is the path to the CA certificate.
	// +optional
	CAFile string `json:"caFile,omitempty"`

	// ExtractIdentity specifies how to extract identity from certificate.
	// +kubebuilder:validation:Enum=cn;san;ou
	// +optional
	ExtractIdentity string `json:"extractIdentity,omitempty"`

	// AllowedCNs is a list of allowed common names.
	// +optional
	AllowedCNs []string `json:"allowedCNs,omitempty"`

	// AllowedOUs is a list of allowed organizational units.
	// +optional
	AllowedOUs []string `json:"allowedOUs,omitempty"`
}

// OIDCAuthConfig configures OIDC authentication.
type OIDCAuthConfig struct {
	// Enabled enables OIDC authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Providers is a list of OIDC providers.
	// +optional
	Providers []OIDCProviderConfig `json:"providers,omitempty"`
}

// OIDCProviderConfig configures an OIDC provider.
type OIDCProviderConfig struct {
	// Name is the provider name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// IssuerURL is the OIDC issuer URL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	IssuerURL string `json:"issuerUrl"`

	// ClientID is the OIDC client ID.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ClientID string `json:"clientId"`

	// ClientSecret is the OIDC client secret.
	// +optional
	ClientSecret string `json:"clientSecret,omitempty"`

	// ClientSecretRef references a Kubernetes secret containing the client secret.
	// +optional
	ClientSecretRef *SecretKeySelector `json:"clientSecretRef,omitempty"`

	// Scopes is the list of scopes to request.
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// AuthorizationConfig represents route-level authorization configuration.
type AuthorizationConfig struct {
	// Enabled enables authorization.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// DefaultPolicy is the default policy when no rules match.
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=deny
	// +optional
	DefaultPolicy string `json:"defaultPolicy,omitempty"`

	// RBAC configures role-based access control.
	// +optional
	RBAC *RBACConfig `json:"rbac,omitempty"`

	// ABAC configures attribute-based access control.
	// +optional
	ABAC *ABACConfig `json:"abac,omitempty"`

	// External configures external authorization.
	// +optional
	External *ExternalAuthzConfig `json:"external,omitempty"`

	// SkipPaths is a list of paths to skip authorization.
	// +optional
	SkipPaths []string `json:"skipPaths,omitempty"`

	// Cache configures authorization decision caching.
	// +optional
	Cache *AuthzCacheConfig `json:"cache,omitempty"`
}

// RBACConfig configures role-based access control.
type RBACConfig struct {
	// Enabled enables RBAC.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Policies is a list of RBAC policies.
	// +optional
	Policies []RBACPolicyConfig `json:"policies,omitempty"`

	// RoleHierarchy defines role inheritance.
	// +optional
	RoleHierarchy map[string][]string `json:"roleHierarchy,omitempty"`
}

// RBACPolicyConfig configures an RBAC policy.
type RBACPolicyConfig struct {
	// Name is the policy name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Roles is a list of roles that match this policy.
	// +optional
	Roles []string `json:"roles,omitempty"`

	// Resources is a list of resources this policy applies to.
	// +optional
	Resources []string `json:"resources,omitempty"`

	// Actions is a list of actions this policy allows.
	// +optional
	Actions []string `json:"actions,omitempty"`

	// Effect is the policy effect (allow or deny).
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=allow
	// +optional
	Effect string `json:"effect,omitempty"`

	// Priority is the policy priority.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Priority int `json:"priority,omitempty"`
}

// ABACConfig configures attribute-based access control.
type ABACConfig struct {
	// Enabled enables ABAC.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Policies is a list of ABAC policies.
	// +optional
	Policies []ABACPolicyConfig `json:"policies,omitempty"`
}

// ABACPolicyConfig configures an ABAC policy.
type ABACPolicyConfig struct {
	// Name is the policy name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Expression is the CEL expression for the policy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Expression string `json:"expression"`

	// Resources is a list of resources this policy applies to.
	// +optional
	Resources []string `json:"resources,omitempty"`

	// Actions is a list of actions this policy applies to.
	// +optional
	Actions []string `json:"actions,omitempty"`

	// Effect is the policy effect (allow or deny).
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=allow
	// +optional
	Effect string `json:"effect,omitempty"`

	// Priority is the policy priority.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Priority int `json:"priority,omitempty"`
}

// ExternalAuthzConfig configures external authorization.
type ExternalAuthzConfig struct {
	// Enabled enables external authorization.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// OPA configures OPA authorization.
	// +optional
	OPA *OPAAuthzConfig `json:"opa,omitempty"`

	// Timeout is the timeout for external authorization requests.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// FailOpen allows requests when external authorization fails.
	// +optional
	FailOpen bool `json:"failOpen,omitempty"`
}

// OPAAuthzConfig configures OPA authorization.
type OPAAuthzConfig struct {
	// URL is the OPA server URL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`

	// Policy is the OPA policy path.
	// +optional
	Policy string `json:"policy,omitempty"`

	// Headers are additional headers to send to OPA.
	// +optional
	Headers map[string]string `json:"headers,omitempty"`
}

// AuthzCacheConfig configures authorization decision caching.
type AuthzCacheConfig struct {
	// Enabled enables caching.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// TTL is the cache TTL.
	// +optional
	TTL Duration `json:"ttl,omitempty"`

	// MaxSize is the maximum number of entries.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxSize int `json:"maxSize,omitempty"`

	// Type is the cache type (memory, redis).
	// +kubebuilder:validation:Enum=memory;redis
	// +kubebuilder:default=memory
	// +optional
	Type string `json:"type,omitempty"`
}

// BackendTransformConfig represents backend transformation configuration.
type BackendTransformConfig struct {
	// Request contains request transformation configuration.
	// +optional
	Request *BackendRequestTransform `json:"request,omitempty"`

	// Response contains response transformation configuration.
	// +optional
	Response *BackendResponseTransform `json:"response,omitempty"`
}

// BackendRequestTransform represents backend request transformation.
type BackendRequestTransform struct {
	// Template is a Go template for transforming the request body.
	// +optional
	Template string `json:"template,omitempty"`

	// Headers contains header manipulation.
	// +optional
	Headers *HeaderOperation `json:"headers,omitempty"`
}

// BackendResponseTransform represents backend response transformation.
type BackendResponseTransform struct {
	// AllowFields is the list of fields to allow in the response.
	// +optional
	AllowFields []string `json:"allowFields,omitempty"`

	// DenyFields is the list of fields to deny in the response.
	// +optional
	DenyFields []string `json:"denyFields,omitempty"`

	// FieldMappings maps field names.
	// +optional
	FieldMappings map[string]string `json:"fieldMappings,omitempty"`

	// Headers contains header manipulation.
	// +optional
	Headers *HeaderOperation `json:"headers,omitempty"`
}

// BackendCacheConfig represents backend caching configuration.
type BackendCacheConfig struct {
	// Enabled enables caching.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// TTL is the cache time-to-live.
	// +optional
	TTL Duration `json:"ttl,omitempty"`

	// KeyComponents are the components used to generate the cache key.
	// +optional
	KeyComponents []string `json:"keyComponents,omitempty"`

	// StaleWhileRevalidate allows serving stale content while revalidating.
	// +optional
	StaleWhileRevalidate Duration `json:"staleWhileRevalidate,omitempty"`

	// Type is the cache type (memory, redis).
	// +kubebuilder:validation:Enum=memory;redis
	// +kubebuilder:default=memory
	// +optional
	Type string `json:"type,omitempty"`
}

// BackendEncodingConfig represents backend encoding configuration.
type BackendEncodingConfig struct {
	// Request contains request encoding configuration.
	// +optional
	Request *BackendEncodingSettings `json:"request,omitempty"`

	// Response contains response encoding configuration.
	// +optional
	Response *BackendEncodingSettings `json:"response,omitempty"`
}

// BackendEncodingSettings represents encoding settings for backends.
type BackendEncodingSettings struct {
	// ContentType is the content type.
	// +optional
	ContentType string `json:"contentType,omitempty"`

	// Compression specifies compression algorithm.
	// +kubebuilder:validation:Enum=gzip;deflate;br;none
	// +optional
	Compression string `json:"compression,omitempty"`
}

// GRPCBackendTransformConfig represents gRPC backend transformation configuration.
type GRPCBackendTransformConfig struct {
	// FieldMask contains field mask configuration.
	// +optional
	FieldMask *GRPCFieldMaskConfig `json:"fieldMask,omitempty"`

	// Metadata contains metadata manipulation configuration.
	// +optional
	Metadata *GRPCMetadataManipulation `json:"metadata,omitempty"`
}

// GRPCFieldMaskConfig represents field mask configuration for gRPC backends.
type GRPCFieldMaskConfig struct {
	// Paths is the list of field paths to include.
	// +optional
	Paths []string `json:"paths,omitempty"`
}

// GRPCMetadataManipulation represents metadata manipulation configuration for gRPC backends.
type GRPCMetadataManipulation struct {
	// Static contains static metadata values.
	// +optional
	Static map[string]string `json:"static,omitempty"`

	// Dynamic contains dynamic metadata values (templates).
	// +optional
	Dynamic map[string]string `json:"dynamic,omitempty"`
}
