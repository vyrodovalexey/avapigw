// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackendSpec defines the desired state of Backend.
type BackendSpec struct {
	// Hosts contains the backend host configurations.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Hosts []BackendHost `json:"hosts"`

	// HealthCheck contains health check configuration.
	// +optional
	HealthCheck *HealthCheckConfig `json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	// +optional
	LoadBalancer *LoadBalancerConfig `json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for backend connections.
	// +optional
	TLS *BackendTLSConfig `json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaker for this backend.
	// +optional
	CircuitBreaker *CircuitBreakerConfig `json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for backend connections.
	// +optional
	Authentication *BackendAuthConfig `json:"authentication,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this backend.
	// +optional
	MaxSessions *MaxSessionsConfig `json:"maxSessions,omitempty"`

	// RateLimit configures rate limiting for this backend.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// RequestLimits configures request size limits for this backend.
	// +optional
	RequestLimits *RequestLimitsConfig `json:"requestLimits,omitempty"`

	// Transform contains transformation configuration for this backend.
	// +optional
	Transform *BackendTransformConfig `json:"transform,omitempty"`

	// Cache contains caching configuration for this backend.
	// +optional
	Cache *BackendCacheConfig `json:"cache,omitempty"`

	// Encoding contains encoding configuration for this backend.
	// +optional
	Encoding *BackendEncodingConfig `json:"encoding,omitempty"`
}

// BackendHost represents a single backend host.
type BackendHost struct {
	// Address is the backend host address (IP or hostname).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`

	// Port is the backend port.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int `json:"port"`

	// Weight is the traffic weight for this host (0-100).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=1
	// +optional
	Weight int `json:"weight,omitempty"`
}

// HealthCheckConfig represents health check configuration.
type HealthCheckConfig struct {
	// Path is the health check path.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`

	// Interval is the health check interval.
	// +optional
	Interval Duration `json:"interval,omitempty"`

	// Timeout is the health check timeout.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// HealthyThreshold is the number of consecutive successes to mark healthy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=2
	// +optional
	HealthyThreshold int `json:"healthyThreshold,omitempty"`

	// UnhealthyThreshold is the number of consecutive failures to mark unhealthy.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	// +optional
	UnhealthyThreshold int `json:"unhealthyThreshold,omitempty"`
}

// BackendTLSConfig contains TLS configuration for backend connections.
type BackendTLSConfig struct {
	// Enabled enables TLS for backend connections.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Mode specifies the TLS mode (SIMPLE, MUTUAL).
	// +kubebuilder:validation:Enum=SIMPLE;MUTUAL;INSECURE
	// +kubebuilder:default=SIMPLE
	// +optional
	Mode string `json:"mode,omitempty"`

	// CAFile is the path to the CA certificate for server verification.
	// +optional
	CAFile string `json:"caFile,omitempty"`

	// CertFile is the path to the client certificate (for mTLS).
	// +optional
	CertFile string `json:"certFile,omitempty"`

	// KeyFile is the path to the client private key (for mTLS).
	// +optional
	KeyFile string `json:"keyFile,omitempty"`

	// ServerName overrides the server name for TLS verification.
	// +optional
	ServerName string `json:"serverName,omitempty"`

	// InsecureSkipVerify skips server certificate verification (dev only).
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

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

	// ALPN protocols for negotiation.
	// +optional
	ALPN []string `json:"alpn,omitempty"`

	// Vault configures Vault-based client certificate management.
	// +optional
	Vault *VaultBackendTLSConfig `json:"vault,omitempty"`
}

// VaultBackendTLSConfig configures Vault-based TLS for backend connections.
type VaultBackendTLSConfig struct {
	// Enabled enables Vault integration for client certificates.
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

// BackendAuthConfig configures authentication for backend connections.
type BackendAuthConfig struct {
	// Type specifies the authentication type (jwt, basic, mtls).
	// +kubebuilder:validation:Enum=jwt;basic;mtls
	// +kubebuilder:validation:Required
	Type string `json:"type"`

	// JWT configures JWT authentication for backend.
	// +optional
	JWT *BackendJWTAuthConfig `json:"jwt,omitempty"`

	// Basic configures Basic authentication for backend.
	// +optional
	Basic *BackendBasicAuthConfig `json:"basic,omitempty"`

	// MTLS configures mTLS authentication for backend.
	// +optional
	MTLS *BackendMTLSAuthConfig `json:"mtls,omitempty"`
}

// BackendJWTAuthConfig configures JWT authentication for backend connections.
type BackendJWTAuthConfig struct {
	// Enabled enables JWT authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// TokenSource specifies where to get the token (static, vault, oidc).
	// +kubebuilder:validation:Enum=static;vault;oidc
	// +kubebuilder:validation:Required
	TokenSource string `json:"tokenSource"`

	// StaticToken is a static JWT token (for development only).
	// +optional
	StaticToken string `json:"staticToken,omitempty"`

	// VaultPath is the Vault path for JWT token.
	// +optional
	VaultPath string `json:"vaultPath,omitempty"`

	// OIDC configures OIDC token acquisition.
	// +optional
	OIDC *BackendOIDCConfig `json:"oidc,omitempty"`

	// HeaderName is the header name for the token (default: Authorization).
	// +kubebuilder:default=Authorization
	// +optional
	HeaderName string `json:"headerName,omitempty"`

	// HeaderPrefix is the prefix for the token (default: Bearer).
	// +kubebuilder:default=Bearer
	// +optional
	HeaderPrefix string `json:"headerPrefix,omitempty"`
}

// BackendOIDCConfig configures OIDC token acquisition for backend auth.
type BackendOIDCConfig struct {
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

	// Scopes are the scopes to request.
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// TokenCacheTTL is the TTL for cached tokens.
	// +optional
	TokenCacheTTL Duration `json:"tokenCacheTTL,omitempty"`
}

// SecretKeySelector selects a key from a Kubernetes secret.
type SecretKeySelector struct {
	// Name is the name of the secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key is the key in the secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// BackendBasicAuthConfig configures Basic authentication for backend connections.
type BackendBasicAuthConfig struct {
	// Enabled enables Basic authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Username is the username for Basic auth.
	// +optional
	Username string `json:"username,omitempty"`

	// Password is the password for Basic auth.
	// +optional
	Password string `json:"password,omitempty"`

	// VaultPath is the Vault path for credentials.
	// +optional
	VaultPath string `json:"vaultPath,omitempty"`

	// UsernameKey is the key in Vault for username (default: username).
	// +kubebuilder:default=username
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`

	// PasswordKey is the key in Vault for password (default: password).
	// +kubebuilder:default=password
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// BackendMTLSAuthConfig configures mTLS authentication for backend connections.
type BackendMTLSAuthConfig struct {
	// Enabled enables mTLS authentication.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// CertFile is the path to the client certificate.
	// +optional
	CertFile string `json:"certFile,omitempty"`

	// KeyFile is the path to the client private key.
	// +optional
	KeyFile string `json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate for server verification.
	// +optional
	CAFile string `json:"caFile,omitempty"`

	// Vault configures Vault-based certificate management.
	// +optional
	Vault *VaultBackendTLSConfig `json:"vault,omitempty"`
}

// BackendStatus defines the observed state of Backend.
type BackendStatus struct {
	// Conditions represent the latest available observations of the Backend's state.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// HealthyHosts is the number of healthy hosts.
	// +optional
	HealthyHosts int `json:"healthyHosts,omitempty"`

	// TotalHosts is the total number of hosts.
	// +optional
	TotalHosts int `json:"totalHosts,omitempty"`

	// LastHealthCheck is the timestamp of the last health check.
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=be
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Healthy",type="string",JSONPath=".status.conditions[?(@.type=='Healthy')].status"
// +kubebuilder:printcolumn:name="Hosts",type="string",JSONPath=".status.healthyHosts"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Backend is the Schema for the backends API.
type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BackendList contains a list of Backend.
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Backend{}, &BackendList{})
}
