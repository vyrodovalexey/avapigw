// Package config provides configuration management for the API Gateway.
package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// LocalConfig represents the local YAML configuration for the API Gateway.
// This configuration can define routes, backends, rate limits, and auth policies
// that are loaded from a local YAML file.
type LocalConfig struct {
	// Gateway defines the gateway configuration including listeners
	Gateway GatewayConfig `yaml:"gateway"`

	// Routes defines the routing rules for the gateway
	Routes []LocalRoute `yaml:"routes"`

	// Backends defines the backend services
	Backends []LocalBackend `yaml:"backends"`

	// RateLimits defines rate limiting policies
	RateLimits []LocalRateLimit `yaml:"rateLimits"`

	// AuthPolicies defines authentication and authorization policies
	AuthPolicies []LocalAuthPolicy `yaml:"authPolicies"`
}

// GatewayConfig defines the gateway-level configuration.
type GatewayConfig struct {
	// Name is the unique identifier for this gateway
	Name string `yaml:"name"`

	// Listeners defines the network listeners for the gateway
	Listeners []ListenerConfig `yaml:"listeners"`
}

// ListenerConfig defines a network listener configuration.
type ListenerConfig struct {
	// Name is the unique identifier for this listener
	Name string `yaml:"name"`

	// Port is the port number to listen on
	Port int `yaml:"port"`

	// Protocol is the protocol to use (HTTP, HTTPS, TCP, TLS)
	Protocol string `yaml:"protocol"`

	// Hostname is the optional hostname to match (for virtual hosting)
	Hostname string `yaml:"hostname,omitempty"`

	// TLS contains TLS configuration if protocol is HTTPS or TLS
	TLS *ListenerTLSConfig `yaml:"tls,omitempty"`
}

// ListenerTLSConfig defines TLS configuration for a listener.
type ListenerTLSConfig struct {
	// Mode is the TLS mode (terminate, passthrough)
	Mode string `yaml:"mode,omitempty"`

	// CertificateRef references a certificate
	CertificateRef *CertificateRef `yaml:"certificateRef,omitempty"`

	// MinVersion is the minimum TLS version (1.2, 1.3)
	MinVersion string `yaml:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version (1.2, 1.3)
	MaxVersion string `yaml:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites
	CipherSuites []string `yaml:"cipherSuites,omitempty"`
}

// CertificateRef references a TLS certificate.
type CertificateRef struct {
	// Name is the name of the certificate
	Name string `yaml:"name"`

	// Namespace is the namespace of the certificate (for Kubernetes)
	Namespace string `yaml:"namespace,omitempty"`

	// Kind is the kind of the certificate resource
	Kind string `yaml:"kind,omitempty"`
}

// LocalRoute defines a routing rule.
type LocalRoute struct {
	// Name is the unique identifier for this route
	Name string `yaml:"name"`

	// Hostnames is the list of hostnames to match
	Hostnames []string `yaml:"hostnames"`

	// PathMatch defines how to match the request path
	PathMatch PathMatchConfig `yaml:"pathMatch"`

	// Methods is the list of HTTP methods to match (optional)
	Methods []string `yaml:"methods,omitempty"`

	// Headers defines header matching rules (optional)
	Headers []HeaderMatchConfig `yaml:"headers,omitempty"`

	// QueryParams defines query parameter matching rules (optional)
	QueryParams []QueryParamMatchConfig `yaml:"queryParams,omitempty"`

	// BackendRefs defines the backend services to route to
	BackendRefs []BackendRefConfig `yaml:"backendRefs"`

	// Filters defines request/response filters to apply
	Filters []FilterConfig `yaml:"filters,omitempty"`

	// RateLimitRef references a rate limit policy
	RateLimitRef string `yaml:"rateLimitRef,omitempty"`

	// AuthPolicyRef references an auth policy
	AuthPolicyRef string `yaml:"authPolicyRef,omitempty"`

	// Timeout is the request timeout for this route
	Timeout time.Duration `yaml:"timeout,omitempty"`

	// Retries defines retry configuration for this route
	Retries *RetryConfig `yaml:"retries,omitempty"`
}

// PathMatchConfig defines path matching configuration.
type PathMatchConfig struct {
	// Type is the type of path match (Exact, PathPrefix, RegularExpression)
	Type string `yaml:"type"`

	// Value is the path value to match
	Value string `yaml:"value"`
}

// HeaderMatchConfig defines header matching configuration.
type HeaderMatchConfig struct {
	// Name is the header name to match
	Name string `yaml:"name"`

	// Type is the type of match (Exact, RegularExpression)
	Type string `yaml:"type,omitempty"`

	// Value is the header value to match
	Value string `yaml:"value"`
}

// QueryParamMatchConfig defines query parameter matching configuration.
type QueryParamMatchConfig struct {
	// Name is the query parameter name to match
	Name string `yaml:"name"`

	// Type is the type of match (Exact, RegularExpression)
	Type string `yaml:"type,omitempty"`

	// Value is the query parameter value to match
	Value string `yaml:"value"`
}

// BackendRefConfig references a backend service.
type BackendRefConfig struct {
	// Name is the name of the backend
	Name string `yaml:"name"`

	// Weight is the traffic weight for this backend (for load balancing)
	Weight int `yaml:"weight,omitempty"`

	// Port is the port to use (overrides backend default)
	Port int `yaml:"port,omitempty"`
}

// FilterConfig defines a request/response filter.
type FilterConfig struct {
	// Type is the filter type (RequestHeaderModifier, ResponseHeaderModifier, URLRewrite, RequestRedirect)
	Type string `yaml:"type"`

	// RequestHeaderModifier modifies request headers
	RequestHeaderModifier *HeaderModifierConfig `yaml:"requestHeaderModifier,omitempty"`

	// ResponseHeaderModifier modifies response headers
	ResponseHeaderModifier *HeaderModifierConfig `yaml:"responseHeaderModifier,omitempty"`

	// URLRewrite rewrites the request URL
	URLRewrite *URLRewriteConfig `yaml:"urlRewrite,omitempty"`

	// RequestRedirect redirects the request
	RequestRedirect *RequestRedirectConfig `yaml:"requestRedirect,omitempty"`
}

// HeaderModifierConfig defines header modification configuration.
type HeaderModifierConfig struct {
	// Set sets headers (overwrites existing)
	Set []HeaderConfig `yaml:"set,omitempty"`

	// Add adds headers (appends to existing)
	Add []HeaderConfig `yaml:"add,omitempty"`

	// Remove removes headers
	Remove []string `yaml:"remove,omitempty"`
}

// HeaderConfig defines a header name-value pair.
type HeaderConfig struct {
	// Name is the header name
	Name string `yaml:"name"`

	// Value is the header value
	Value string `yaml:"value"`
}

// URLRewriteConfig defines URL rewrite configuration.
type URLRewriteConfig struct {
	// Hostname is the new hostname
	Hostname string `yaml:"hostname,omitempty"`

	// Path is the path rewrite configuration
	Path *PathRewriteConfig `yaml:"path,omitempty"`
}

// PathRewriteConfig defines path rewrite configuration.
type PathRewriteConfig struct {
	// Type is the rewrite type (ReplacePrefixMatch, ReplaceFullPath)
	Type string `yaml:"type"`

	// ReplacePrefixMatch is the new prefix
	ReplacePrefixMatch string `yaml:"replacePrefixMatch,omitempty"`

	// ReplaceFullPath is the new full path
	ReplaceFullPath string `yaml:"replaceFullPath,omitempty"`
}

// RequestRedirectConfig defines request redirect configuration.
type RequestRedirectConfig struct {
	// Scheme is the redirect scheme (http, https)
	Scheme string `yaml:"scheme,omitempty"`

	// Hostname is the redirect hostname
	Hostname string `yaml:"hostname,omitempty"`

	// Port is the redirect port
	Port int `yaml:"port,omitempty"`

	// Path is the redirect path configuration
	Path *PathRewriteConfig `yaml:"path,omitempty"`

	// StatusCode is the HTTP status code for the redirect (301, 302, etc.)
	StatusCode int `yaml:"statusCode,omitempty"`
}

// RetryConfig defines retry configuration.
type RetryConfig struct {
	// NumRetries is the number of retries
	NumRetries int `yaml:"numRetries"`

	// RetryOn is the conditions to retry on
	RetryOn []string `yaml:"retryOn,omitempty"`

	// PerTryTimeout is the timeout per retry attempt
	PerTryTimeout time.Duration `yaml:"perTryTimeout,omitempty"`

	// BackoffBaseInterval is the base interval for exponential backoff
	BackoffBaseInterval time.Duration `yaml:"backoffBaseInterval,omitempty"`

	// BackoffMaxInterval is the maximum interval for exponential backoff
	BackoffMaxInterval time.Duration `yaml:"backoffMaxInterval,omitempty"`
}

// LocalBackend defines a backend service.
type LocalBackend struct {
	// Name is the unique identifier for this backend
	Name string `yaml:"name"`

	// Endpoints defines the backend endpoints
	Endpoints []EndpointConfig `yaml:"endpoints"`

	// Protocol is the protocol to use (HTTP, HTTPS, gRPC, TCP)
	Protocol string `yaml:"protocol"`

	// LoadBalancer defines the load balancing configuration
	LoadBalancer *LoadBalancerConfig `yaml:"loadBalancer,omitempty"`

	// HealthCheck defines health check configuration
	HealthCheck *HealthCheckConfig `yaml:"healthCheck,omitempty"`

	// CircuitBreaker defines circuit breaker configuration
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty"`

	// TLS defines TLS configuration for backend connections
	TLS *BackendTLSConfig `yaml:"tls,omitempty"`

	// ConnectionPool defines connection pool configuration
	ConnectionPool *ConnectionPoolConfig `yaml:"connectionPool,omitempty"`
}

// EndpointConfig defines a backend endpoint.
type EndpointConfig struct {
	// Address is the endpoint address (hostname or IP)
	Address string `yaml:"address"`

	// Port is the endpoint port
	Port int `yaml:"port"`

	// Weight is the traffic weight for this endpoint
	Weight int `yaml:"weight,omitempty"`
}

// LoadBalancerConfig defines load balancing configuration.
type LoadBalancerConfig struct {
	// Algorithm is the load balancing algorithm (RoundRobin, LeastConnections, Random, ConsistentHash)
	Algorithm string `yaml:"algorithm"`

	// ConsistentHash defines consistent hash configuration
	ConsistentHash *ConsistentHashConfig `yaml:"consistentHash,omitempty"`
}

// ConsistentHashConfig defines consistent hash configuration.
type ConsistentHashConfig struct {
	// Header is the header to use for hashing
	Header string `yaml:"header,omitempty"`

	// Cookie is the cookie to use for hashing
	Cookie string `yaml:"cookie,omitempty"`

	// SourceIP uses source IP for hashing
	SourceIP bool `yaml:"sourceIP,omitempty"`
}

// HealthCheckConfig defines health check configuration.
type HealthCheckConfig struct {
	// Interval is the health check interval
	Interval time.Duration `yaml:"interval"`

	// Timeout is the health check timeout
	Timeout time.Duration `yaml:"timeout"`

	// UnhealthyThreshold is the number of failures before marking unhealthy
	UnhealthyThreshold int `yaml:"unhealthyThreshold"`

	// HealthyThreshold is the number of successes before marking healthy
	HealthyThreshold int `yaml:"healthyThreshold"`

	// HTTP defines HTTP health check configuration
	HTTP *HTTPHealthCheckConfig `yaml:"http,omitempty"`

	// TCP defines TCP health check configuration
	TCP *TCPHealthCheckConfig `yaml:"tcp,omitempty"`

	// GRPC defines gRPC health check configuration
	GRPC *GRPCHealthCheckConfig `yaml:"grpc,omitempty"`
}

// HTTPHealthCheckConfig defines HTTP health check configuration.
type HTTPHealthCheckConfig struct {
	// Path is the health check path
	Path string `yaml:"path"`

	// Method is the HTTP method (GET, HEAD)
	Method string `yaml:"method,omitempty"`

	// ExpectedStatuses is the list of expected status codes
	ExpectedStatuses []int `yaml:"expectedStatuses,omitempty"`
}

// TCPHealthCheckConfig defines TCP health check configuration.
type TCPHealthCheckConfig struct {
	// Send is the data to send
	Send string `yaml:"send,omitempty"`

	// Receive is the expected response
	Receive string `yaml:"receive,omitempty"`
}

// GRPCHealthCheckConfig defines gRPC health check configuration.
type GRPCHealthCheckConfig struct {
	// Service is the gRPC service name
	Service string `yaml:"service,omitempty"`
}

// CircuitBreakerConfig defines circuit breaker configuration.
type CircuitBreakerConfig struct {
	// MaxConnections is the maximum number of connections
	MaxConnections int `yaml:"maxConnections,omitempty"`

	// MaxPendingRequests is the maximum number of pending requests
	MaxPendingRequests int `yaml:"maxPendingRequests,omitempty"`

	// MaxRequests is the maximum number of requests
	MaxRequests int `yaml:"maxRequests,omitempty"`

	// MaxRetries is the maximum number of retries
	MaxRetries int `yaml:"maxRetries,omitempty"`

	// ConsecutiveErrors is the number of consecutive errors before opening
	ConsecutiveErrors int `yaml:"consecutiveErrors,omitempty"`

	// Interval is the time window for counting errors
	Interval time.Duration `yaml:"interval,omitempty"`

	// BaseEjectionTime is the base ejection time
	BaseEjectionTime time.Duration `yaml:"baseEjectionTime,omitempty"`

	// MaxEjectionPercent is the maximum percentage of hosts to eject
	MaxEjectionPercent int `yaml:"maxEjectionPercent,omitempty"`
}

// BackendTLSConfig defines TLS configuration for backend connections.
type BackendTLSConfig struct {
	// Mode is the TLS mode (disable, simple, mutual)
	Mode string `yaml:"mode,omitempty"`

	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty"`

	// CACertificate is the CA certificate for verification
	CACertificate string `yaml:"caCertificate,omitempty"`

	// ClientCertificate is the client certificate for mutual TLS
	ClientCertificate string `yaml:"clientCertificate,omitempty"`

	// ClientKey is the client key for mutual TLS
	ClientKey string `yaml:"clientKey,omitempty"`

	// SNI is the Server Name Indication
	SNI string `yaml:"sni,omitempty"`
}

// ConnectionPoolConfig defines connection pool configuration.
type ConnectionPoolConfig struct {
	// HTTP defines HTTP connection pool configuration
	HTTP *HTTPConnectionPoolConfig `yaml:"http,omitempty"`

	// TCP defines TCP connection pool configuration
	TCP *TCPConnectionPoolConfig `yaml:"tcp,omitempty"`
}

// HTTPConnectionPoolConfig defines HTTP connection pool configuration.
type HTTPConnectionPoolConfig struct {
	// MaxRequestsPerConnection is the maximum requests per connection
	MaxRequestsPerConnection int `yaml:"maxRequestsPerConnection,omitempty"`

	// MaxRetries is the maximum number of retries
	MaxRetries int `yaml:"maxRetries,omitempty"`

	// IdleTimeout is the idle connection timeout
	IdleTimeout time.Duration `yaml:"idleTimeout,omitempty"`

	// H2UpgradePolicy is the HTTP/2 upgrade policy
	H2UpgradePolicy string `yaml:"h2UpgradePolicy,omitempty"`
}

// TCPConnectionPoolConfig defines TCP connection pool configuration.
type TCPConnectionPoolConfig struct {
	// MaxConnections is the maximum number of connections
	MaxConnections int `yaml:"maxConnections,omitempty"`

	// ConnectTimeout is the connection timeout
	ConnectTimeout time.Duration `yaml:"connectTimeout,omitempty"`
}

// LocalRateLimit defines a rate limiting policy.
type LocalRateLimit struct {
	// Name is the unique identifier for this rate limit policy
	Name string `yaml:"name"`

	// Algorithm is the rate limiting algorithm (token_bucket, sliding_window, fixed_window)
	Algorithm string `yaml:"algorithm"`

	// Requests is the number of requests allowed per window
	Requests int `yaml:"requests"`

	// Window is the time window for rate limiting
	Window time.Duration `yaml:"window"`

	// Burst is the burst size (for token bucket)
	Burst int `yaml:"burst,omitempty"`

	// Key defines how to identify rate limit keys
	Key *RateLimitKeyConfig `yaml:"key,omitempty"`

	// ResponseHeaders defines headers to add to rate limited responses
	ResponseHeaders *RateLimitResponseHeaders `yaml:"responseHeaders,omitempty"`
}

// RateLimitKeyConfig defines how to identify rate limit keys.
type RateLimitKeyConfig struct {
	// Type is the key type (IP, Header, User)
	Type string `yaml:"type"`

	// Header is the header name (when type is Header)
	Header string `yaml:"header,omitempty"`

	// Claim is the JWT claim name (when type is User)
	Claim string `yaml:"claim,omitempty"`
}

// RateLimitResponseHeaders defines headers to add to rate limited responses.
type RateLimitResponseHeaders struct {
	// RateLimitLimit is the header name for the limit
	RateLimitLimit string `yaml:"rateLimitLimit,omitempty"`

	// RateLimitRemaining is the header name for remaining requests
	RateLimitRemaining string `yaml:"rateLimitRemaining,omitempty"`

	// RateLimitReset is the header name for reset time
	RateLimitReset string `yaml:"rateLimitReset,omitempty"`
}

// LocalAuthPolicy defines an authentication and authorization policy.
type LocalAuthPolicy struct {
	// Name is the unique identifier for this auth policy
	Name string `yaml:"name"`

	// JWT defines JWT authentication configuration
	JWT *JWTAuthConfig `yaml:"jwt,omitempty"`

	// APIKey defines API key authentication configuration
	APIKey *APIKeyAuthConfig `yaml:"apiKey,omitempty"`

	// BasicAuth defines basic authentication configuration
	BasicAuth *BasicAuthConfig `yaml:"basicAuth,omitempty"`

	// OAuth2 defines OAuth2 authentication configuration
	OAuth2 *OAuth2AuthConfig `yaml:"oauth2,omitempty"`

	// Rules defines authorization rules
	Rules []AuthRuleConfig `yaml:"rules,omitempty"`
}

// JWTAuthConfig defines JWT authentication configuration.
type JWTAuthConfig struct {
	// Issuer is the expected JWT issuer
	Issuer string `yaml:"issuer,omitempty"`

	// Audiences is the list of expected audiences
	Audiences []string `yaml:"audiences,omitempty"`

	// JWKSURL is the URL to fetch JWKS from
	JWKSURL string `yaml:"jwksUrl,omitempty"`

	// Algorithms is the list of allowed algorithms
	Algorithms []string `yaml:"algorithms,omitempty"`

	// TokenSource defines where to extract the token from
	TokenSource *TokenSourceConfig `yaml:"tokenSource,omitempty"`

	// ClaimsToHeaders maps JWT claims to request headers
	ClaimsToHeaders []ClaimToHeaderConfig `yaml:"claimsToHeaders,omitempty"`
}

// TokenSourceConfig defines where to extract the token from.
type TokenSourceConfig struct {
	// Header is the header name
	Header string `yaml:"header,omitempty"`

	// Prefix is the token prefix (e.g., "Bearer ")
	Prefix string `yaml:"prefix,omitempty"`

	// Cookie is the cookie name
	Cookie string `yaml:"cookie,omitempty"`

	// Query is the query parameter name
	Query string `yaml:"query,omitempty"`
}

// ClaimToHeaderConfig maps a JWT claim to a request header.
type ClaimToHeaderConfig struct {
	// Claim is the JWT claim name
	Claim string `yaml:"claim"`

	// Header is the request header name
	Header string `yaml:"header"`
}

// APIKeyAuthConfig defines API key authentication configuration.
type APIKeyAuthConfig struct {
	// Header is the header name for the API key
	Header string `yaml:"header,omitempty"`

	// Query is the query parameter name for the API key
	Query string `yaml:"query,omitempty"`

	// Keys is the list of valid API keys (for local validation)
	Keys []APIKeyConfig `yaml:"keys,omitempty"`

	// VaultPath is the Vault path for API keys
	VaultPath string `yaml:"vaultPath,omitempty"`
}

// APIKeyConfig defines an API key.
type APIKeyConfig struct {
	// Name is the key name/identifier
	Name string `yaml:"name"`

	// Key is the API key value (should be stored securely)
	Key string `yaml:"key,omitempty"`

	// Roles is the list of roles for this key
	Roles []string `yaml:"roles,omitempty"`
}

// BasicAuthConfig defines basic authentication configuration.
type BasicAuthConfig struct {
	// Realm is the authentication realm
	Realm string `yaml:"realm,omitempty"`

	// Users is the list of users (for local validation)
	Users []BasicAuthUserConfig `yaml:"users,omitempty"`

	// VaultPath is the Vault path for credentials
	VaultPath string `yaml:"vaultPath,omitempty"`
}

// BasicAuthUserConfig defines a basic auth user.
type BasicAuthUserConfig struct {
	// Username is the username
	Username string `yaml:"username"`

	// PasswordHash is the bcrypt hash of the password
	PasswordHash string `yaml:"passwordHash,omitempty"`

	// Roles is the list of roles for this user
	Roles []string `yaml:"roles,omitempty"`
}

// OAuth2AuthConfig defines OAuth2 authentication configuration.
type OAuth2AuthConfig struct {
	// TokenEndpoint is the OAuth2 token endpoint
	TokenEndpoint string `yaml:"tokenEndpoint,omitempty"`

	// IntrospectionEndpoint is the token introspection endpoint
	IntrospectionEndpoint string `yaml:"introspectionEndpoint,omitempty"`

	// ClientID is the OAuth2 client ID
	ClientID string `yaml:"clientId,omitempty"`

	// ClientSecret is the OAuth2 client secret (should be stored securely)
	ClientSecret string `yaml:"clientSecret,omitempty"`

	// VaultPath is the Vault path for OAuth2 credentials
	VaultPath string `yaml:"vaultPath,omitempty"`

	// Scopes is the list of required scopes
	Scopes []string `yaml:"scopes,omitempty"`
}

// AuthRuleConfig defines an authorization rule.
type AuthRuleConfig struct {
	// Paths is the list of paths this rule applies to
	Paths []string `yaml:"paths,omitempty"`

	// Methods is the list of HTTP methods this rule applies to
	Methods []string `yaml:"methods,omitempty"`

	// Roles is the list of required roles
	Roles []string `yaml:"roles,omitempty"`

	// Claims defines required JWT claims
	Claims map[string]string `yaml:"claims,omitempty"`

	// Allow specifies if the rule allows or denies access
	Allow bool `yaml:"allow"`
}

// Validate validates the LocalConfig and returns an error if invalid.
func (c *LocalConfig) Validate() error {
	// Validate gateway configuration
	if err := c.Gateway.Validate(); err != nil {
		return fmt.Errorf("gateway validation failed: %w", err)
	}

	// Validate routes
	routeNames := make(map[string]bool)
	for i, route := range c.Routes {
		if err := route.Validate(); err != nil {
			return fmt.Errorf("route[%d] validation failed: %w", i, err)
		}
		if routeNames[route.Name] {
			return fmt.Errorf("duplicate route name: %s", route.Name)
		}
		routeNames[route.Name] = true
	}

	// Validate backends
	backendNames := make(map[string]bool)
	for i, backend := range c.Backends {
		if err := backend.Validate(); err != nil {
			return fmt.Errorf("backend[%d] validation failed: %w", i, err)
		}
		if backendNames[backend.Name] {
			return fmt.Errorf("duplicate backend name: %s", backend.Name)
		}
		backendNames[backend.Name] = true
	}

	// Validate rate limits
	rateLimitNames := make(map[string]bool)
	for i, rateLimit := range c.RateLimits {
		if err := rateLimit.Validate(); err != nil {
			return fmt.Errorf("rateLimit[%d] validation failed: %w", i, err)
		}
		if rateLimitNames[rateLimit.Name] {
			return fmt.Errorf("duplicate rate limit name: %s", rateLimit.Name)
		}
		rateLimitNames[rateLimit.Name] = true
	}

	// Validate auth policies
	authPolicyNames := make(map[string]bool)
	for i, authPolicy := range c.AuthPolicies {
		if err := authPolicy.Validate(); err != nil {
			return fmt.Errorf("authPolicy[%d] validation failed: %w", i, err)
		}
		if authPolicyNames[authPolicy.Name] {
			return fmt.Errorf("duplicate auth policy name: %s", authPolicy.Name)
		}
		authPolicyNames[authPolicy.Name] = true
	}

	// Validate references
	for _, route := range c.Routes {
		// Validate backend references
		for _, backendRef := range route.BackendRefs {
			if !backendNames[backendRef.Name] {
				return fmt.Errorf("route %s references unknown backend: %s", route.Name, backendRef.Name)
			}
		}

		// Validate rate limit reference
		if route.RateLimitRef != "" && !rateLimitNames[route.RateLimitRef] {
			return fmt.Errorf("route %s references unknown rate limit: %s", route.Name, route.RateLimitRef)
		}

		// Validate auth policy reference
		if route.AuthPolicyRef != "" && !authPolicyNames[route.AuthPolicyRef] {
			return fmt.Errorf("route %s references unknown auth policy: %s", route.Name, route.AuthPolicyRef)
		}
	}

	return nil
}

// Validate validates the GatewayConfig.
func (g *GatewayConfig) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("gateway name is required")
	}

	listenerNames := make(map[string]bool)
	listenerPorts := make(map[int]bool)

	for i, listener := range g.Listeners {
		if err := listener.Validate(); err != nil {
			return fmt.Errorf("listener[%d] validation failed: %w", i, err)
		}
		if listenerNames[listener.Name] {
			return fmt.Errorf("duplicate listener name: %s", listener.Name)
		}
		listenerNames[listener.Name] = true

		if listenerPorts[listener.Port] {
			return fmt.Errorf("duplicate listener port: %d", listener.Port)
		}
		listenerPorts[listener.Port] = true
	}

	return nil
}

// Validate validates the ListenerConfig.
func (l *ListenerConfig) Validate() error {
	if l.Name == "" {
		return fmt.Errorf("listener name is required")
	}

	if l.Port < 1 || l.Port > 65535 {
		return fmt.Errorf("listener port must be between 1 and 65535, got %d", l.Port)
	}

	validProtocols := map[string]bool{
		"HTTP":  true,
		"HTTPS": true,
		"TCP":   true,
		"TLS":   true,
		"GRPC":  true,
		"GRPCS": true,
	}
	if !validProtocols[strings.ToUpper(l.Protocol)] {
		return fmt.Errorf("invalid listener protocol: %s", l.Protocol)
	}

	// TLS configuration is required for HTTPS and TLS protocols
	if (strings.ToUpper(l.Protocol) == "HTTPS" || strings.ToUpper(l.Protocol) == "TLS" || strings.ToUpper(l.Protocol) == "GRPCS") && l.TLS == nil {
		return fmt.Errorf("TLS configuration is required for %s protocol", l.Protocol)
	}

	if l.TLS != nil {
		if err := l.TLS.Validate(); err != nil {
			return fmt.Errorf("TLS validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the ListenerTLSConfig.
func (t *ListenerTLSConfig) Validate() error {
	validModes := map[string]bool{
		"":            true,
		"terminate":   true,
		"passthrough": true,
	}
	if !validModes[strings.ToLower(t.Mode)] {
		return fmt.Errorf("invalid TLS mode: %s", t.Mode)
	}

	validVersions := map[string]bool{
		"":    true,
		"1.2": true,
		"1.3": true,
	}
	if !validVersions[t.MinVersion] {
		return fmt.Errorf("invalid TLS min version: %s", t.MinVersion)
	}
	if !validVersions[t.MaxVersion] {
		return fmt.Errorf("invalid TLS max version: %s", t.MaxVersion)
	}

	return nil
}

// Validate validates the LocalRoute.
func (r *LocalRoute) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("route name is required")
	}

	if err := r.PathMatch.Validate(); err != nil {
		return fmt.Errorf("pathMatch validation failed: %w", err)
	}

	if len(r.BackendRefs) == 0 {
		return fmt.Errorf("at least one backend reference is required")
	}

	for i, backendRef := range r.BackendRefs {
		if err := backendRef.Validate(); err != nil {
			return fmt.Errorf("backendRef[%d] validation failed: %w", i, err)
		}
	}

	for i, filter := range r.Filters {
		if err := filter.Validate(); err != nil {
			return fmt.Errorf("filter[%d] validation failed: %w", i, err)
		}
	}

	// Validate HTTP methods
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
		"CONNECT": true,
		"TRACE":   true,
	}
	for _, method := range r.Methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	if r.Retries != nil {
		if err := r.Retries.Validate(); err != nil {
			return fmt.Errorf("retries validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the PathMatchConfig.
func (p *PathMatchConfig) Validate() error {
	validTypes := map[string]bool{
		"Exact":             true,
		"PathPrefix":        true,
		"RegularExpression": true,
	}
	if !validTypes[p.Type] {
		return fmt.Errorf("invalid path match type: %s", p.Type)
	}

	if p.Value == "" {
		return fmt.Errorf("path match value is required")
	}

	// Validate regex if type is RegularExpression
	if p.Type == "RegularExpression" {
		if _, err := regexp.Compile(p.Value); err != nil {
			return fmt.Errorf("invalid regular expression: %w", err)
		}
	}

	return nil
}

// Validate validates the BackendRefConfig.
func (b *BackendRefConfig) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("backend reference name is required")
	}

	if b.Weight < 0 {
		return fmt.Errorf("backend weight must be non-negative")
	}

	if b.Port != 0 && (b.Port < 1 || b.Port > 65535) {
		return fmt.Errorf("backend port must be between 1 and 65535, got %d", b.Port)
	}

	return nil
}

// Validate validates the FilterConfig.
func (f *FilterConfig) Validate() error {
	validTypes := map[string]bool{
		"RequestHeaderModifier":  true,
		"ResponseHeaderModifier": true,
		"URLRewrite":             true,
		"RequestRedirect":        true,
	}
	if !validTypes[f.Type] {
		return fmt.Errorf("invalid filter type: %s", f.Type)
	}

	return nil
}

// Validate validates the RetryConfig.
func (r *RetryConfig) Validate() error {
	if r.NumRetries < 0 {
		return fmt.Errorf("numRetries must be non-negative")
	}

	if r.PerTryTimeout < 0 {
		return fmt.Errorf("perTryTimeout must be non-negative")
	}

	if r.BackoffBaseInterval < 0 {
		return fmt.Errorf("backoffBaseInterval must be non-negative")
	}

	if r.BackoffMaxInterval < 0 {
		return fmt.Errorf("backoffMaxInterval must be non-negative")
	}

	return nil
}

// Validate validates the LocalBackend.
func (b *LocalBackend) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("backend name is required")
	}

	if len(b.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint is required")
	}

	for i, endpoint := range b.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return fmt.Errorf("endpoint[%d] validation failed: %w", i, err)
		}
	}

	validProtocols := map[string]bool{
		"HTTP":  true,
		"HTTPS": true,
		"GRPC":  true,
		"GRPCS": true,
		"TCP":   true,
		"TLS":   true,
	}
	if !validProtocols[strings.ToUpper(b.Protocol)] {
		return fmt.Errorf("invalid backend protocol: %s", b.Protocol)
	}

	if b.LoadBalancer != nil {
		if err := b.LoadBalancer.Validate(); err != nil {
			return fmt.Errorf("loadBalancer validation failed: %w", err)
		}
	}

	if b.HealthCheck != nil {
		if err := b.HealthCheck.Validate(); err != nil {
			return fmt.Errorf("healthCheck validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the EndpointConfig.
func (e *EndpointConfig) Validate() error {
	if e.Address == "" {
		return fmt.Errorf("endpoint address is required")
	}

	if e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("endpoint port must be between 1 and 65535, got %d", e.Port)
	}

	if e.Weight < 0 {
		return fmt.Errorf("endpoint weight must be non-negative")
	}

	return nil
}

// Validate validates the LoadBalancerConfig.
func (l *LoadBalancerConfig) Validate() error {
	validAlgorithms := map[string]bool{
		"RoundRobin":       true,
		"LeastConnections": true,
		"Random":           true,
		"ConsistentHash":   true,
	}
	if !validAlgorithms[l.Algorithm] {
		return fmt.Errorf("invalid load balancer algorithm: %s", l.Algorithm)
	}

	if l.Algorithm == "ConsistentHash" && l.ConsistentHash == nil {
		return fmt.Errorf("consistentHash configuration is required for ConsistentHash algorithm")
	}

	return nil
}

// Validate validates the HealthCheckConfig.
func (h *HealthCheckConfig) Validate() error {
	if h.Interval <= 0 {
		return fmt.Errorf("health check interval must be positive")
	}

	if h.Timeout <= 0 {
		return fmt.Errorf("health check timeout must be positive")
	}

	if h.UnhealthyThreshold <= 0 {
		return fmt.Errorf("unhealthy threshold must be positive")
	}

	if h.HealthyThreshold <= 0 {
		return fmt.Errorf("healthy threshold must be positive")
	}

	// At least one health check type must be configured
	if h.HTTP == nil && h.TCP == nil && h.GRPC == nil {
		return fmt.Errorf("at least one health check type (HTTP, TCP, or GRPC) must be configured")
	}

	return nil
}

// Validate validates the LocalRateLimit.
func (r *LocalRateLimit) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rate limit name is required")
	}

	validAlgorithms := map[string]bool{
		"token_bucket":   true,
		"sliding_window": true,
		"fixed_window":   true,
	}
	if !validAlgorithms[r.Algorithm] {
		return fmt.Errorf("invalid rate limit algorithm: %s", r.Algorithm)
	}

	if r.Requests <= 0 {
		return fmt.Errorf("rate limit requests must be positive")
	}

	if r.Window <= 0 {
		return fmt.Errorf("rate limit window must be positive")
	}

	if r.Burst < 0 {
		return fmt.Errorf("rate limit burst must be non-negative")
	}

	if r.Key != nil {
		if err := r.Key.Validate(); err != nil {
			return fmt.Errorf("rate limit key validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the RateLimitKeyConfig.
func (k *RateLimitKeyConfig) Validate() error {
	validTypes := map[string]bool{
		"IP":     true,
		"Header": true,
		"User":   true,
	}
	if !validTypes[k.Type] {
		return fmt.Errorf("invalid rate limit key type: %s", k.Type)
	}

	if k.Type == "Header" && k.Header == "" {
		return fmt.Errorf("header name is required for Header key type")
	}

	if k.Type == "User" && k.Claim == "" {
		return fmt.Errorf("claim name is required for User key type")
	}

	return nil
}

// Validate validates the LocalAuthPolicy.
func (a *LocalAuthPolicy) Validate() error {
	if a.Name == "" {
		return fmt.Errorf("auth policy name is required")
	}

	// At least one auth method must be configured
	if a.JWT == nil && a.APIKey == nil && a.BasicAuth == nil && a.OAuth2 == nil {
		return fmt.Errorf("at least one authentication method must be configured")
	}

	if a.JWT != nil {
		if err := a.JWT.Validate(); err != nil {
			return fmt.Errorf("JWT validation failed: %w", err)
		}
	}

	if a.APIKey != nil {
		if err := a.APIKey.Validate(); err != nil {
			return fmt.Errorf("API key validation failed: %w", err)
		}
	}

	if a.BasicAuth != nil {
		if err := a.BasicAuth.Validate(); err != nil {
			return fmt.Errorf("basic auth validation failed: %w", err)
		}
	}

	if a.OAuth2 != nil {
		if err := a.OAuth2.Validate(); err != nil {
			return fmt.Errorf("OAuth2 validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the JWTAuthConfig.
func (j *JWTAuthConfig) Validate() error {
	if j.JWKSURL == "" && j.Issuer == "" {
		return fmt.Errorf("either JWKS URL or issuer is required")
	}

	return nil
}

// Validate validates the APIKeyAuthConfig.
func (a *APIKeyAuthConfig) Validate() error {
	if a.Header == "" && a.Query == "" {
		return fmt.Errorf("either header or query parameter must be specified for API key")
	}

	return nil
}

// Validate validates the BasicAuthConfig.
func (b *BasicAuthConfig) Validate() error {
	// No specific validation required
	return nil
}

// Validate validates the OAuth2AuthConfig.
func (o *OAuth2AuthConfig) Validate() error {
	if o.TokenEndpoint == "" && o.IntrospectionEndpoint == "" {
		return fmt.Errorf("either token endpoint or introspection endpoint is required")
	}

	return nil
}
