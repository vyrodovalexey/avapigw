// Package config provides configuration types and loading for the API Gateway.
package config

// Protocol constant for GraphQL listener configuration.
const (
	ProtocolGraphQL = "GRAPHQL"
)

// GraphQLRoute represents a GraphQL routing rule configuration.
type GraphQLRoute struct {
	// Name is the unique name of the route.
	Name string `yaml:"name" json:"name"`

	// Match contains the matching conditions for this route.
	Match []GraphQLRouteMatch `yaml:"match,omitempty" json:"match,omitempty"`

	// Route contains the destination(s) for matched requests.
	Route []RouteDestination `yaml:"route,omitempty" json:"route,omitempty"`

	// Timeout is the request timeout for this route.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retries contains retry policy configuration.
	Retries *RetryPolicy `yaml:"retries,omitempty" json:"retries,omitempty"`

	// Headers contains header manipulation configuration.
	Headers *HeaderManipulation `yaml:"headers,omitempty" json:"headers,omitempty"`

	// RateLimit contains route-level rate limiting configuration.
	RateLimit *RateLimitConfig `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Cache contains caching configuration.
	Cache *CacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`

	// CORS configures CORS for this GraphQL route (overrides global).
	CORS *CORSConfig `yaml:"cors,omitempty" json:"cors,omitempty"`

	// Security configures security headers for this GraphQL route (overrides global).
	Security *SecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`

	// TLS configures route-level TLS certificate override for this GraphQL route.
	TLS *RouteTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Authentication configures route-level authentication.
	Authentication *AuthenticationConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	Authorization *AuthorizationConfig `yaml:"authorization,omitempty" json:"authorization,omitempty"`

	// DepthLimit is the maximum query depth allowed.
	DepthLimit int `yaml:"depthLimit,omitempty" json:"depthLimit,omitempty"`

	// ComplexityLimit is the maximum query complexity allowed.
	ComplexityLimit int `yaml:"complexityLimit,omitempty" json:"complexityLimit,omitempty"`

	// IntrospectionEnabled controls whether introspection queries are allowed.
	IntrospectionEnabled *bool `yaml:"introspectionEnabled,omitempty" json:"introspectionEnabled,omitempty"`

	// AllowedOperations restricts which operation types are allowed (query, mutation, subscription).
	AllowedOperations []string `yaml:"allowedOperations,omitempty" json:"allowedOperations,omitempty"`
}

// HasTLSOverride returns true if the GraphQL route has TLS configuration that overrides listener TLS.
func (r *GraphQLRoute) HasTLSOverride() bool {
	if r.TLS == nil {
		return false
	}
	hasFiles := r.TLS.CertFile != "" || r.TLS.KeyFile != ""
	hasVault := r.TLS.Vault != nil && r.TLS.Vault.Enabled
	return hasFiles || hasVault
}

// GetEffectiveSNIHosts returns the SNI hosts for this GraphQL route.
// Returns nil if no SNI hosts are configured.
func (r *GraphQLRoute) GetEffectiveSNIHosts() []string {
	if r.TLS == nil || len(r.TLS.SNIHosts) == 0 {
		return nil
	}
	return r.TLS.SNIHosts
}

// GraphQLRouteMatch represents matching conditions for a GraphQL route.
type GraphQLRouteMatch struct {
	// Path matches the HTTP path for the GraphQL endpoint.
	Path *StringMatch `yaml:"path,omitempty" json:"path,omitempty"`

	// OperationType matches the GraphQL operation type (query, mutation, subscription).
	OperationType string `yaml:"operationType,omitempty" json:"operationType,omitempty"`

	// OperationName matches the GraphQL operation name.
	OperationName *StringMatch `yaml:"operationName,omitempty" json:"operationName,omitempty"`

	// Headers matches HTTP headers.
	Headers []HeaderMatchConfig `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// HeaderMatchConfig represents header matching configuration for GraphQL routes.
type HeaderMatchConfig struct {
	// Name is the header name.
	Name string `yaml:"name" json:"name"`

	// Exact matches the header value exactly.
	Exact string `yaml:"exact,omitempty" json:"exact,omitempty"`

	// Prefix matches header values starting with this prefix.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`

	// Regex matches header values using a regular expression.
	Regex string `yaml:"regex,omitempty" json:"regex,omitempty"`
}

// IsEmpty returns true if the GraphQLRouteMatch has no conditions.
func (m *GraphQLRouteMatch) IsEmpty() bool {
	if m.Path != nil && !m.Path.IsEmpty() {
		return false
	}
	if m.OperationType != "" {
		return false
	}
	if m.OperationName != nil && !m.OperationName.IsEmpty() {
		return false
	}
	if len(m.Headers) > 0 {
		return false
	}
	return true
}

// GraphQLBackend represents a GraphQL backend service configuration.
type GraphQLBackend struct {
	// Name is the unique name of the backend.
	Name string `yaml:"name" json:"name"`

	// Hosts contains the backend host configurations.
	Hosts []BackendHost `yaml:"hosts" json:"hosts"`

	// HealthCheck contains health check configuration.
	HealthCheck *HealthCheck `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	LoadBalancer *LoadBalancer `yaml:"loadBalancer,omitempty" json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for connecting to the backend.
	TLS *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaker for this GraphQL backend.
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// Authentication configures authentication for GraphQL backend connections.
	Authentication *BackendAuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`
}

// GraphQLBackendToBackend converts a GraphQLBackend to a Backend configuration.
// This enables reuse of the shared backend.Registry infrastructure (load balancing,
// health checking, connection management) for GraphQL backends.
func GraphQLBackendToBackend(gb GraphQLBackend) Backend {
	b := Backend{
		Name:           gb.Name,
		Hosts:          gb.Hosts,
		HealthCheck:    gb.HealthCheck,
		LoadBalancer:   gb.LoadBalancer,
		TLS:            gb.TLS,
		CircuitBreaker: gb.CircuitBreaker,
		Authentication: gb.Authentication,
	}

	return b
}

// GraphQLBackendsToBackends converts a slice of GraphQLBackend to a slice of Backend.
func GraphQLBackendsToBackends(gbs []GraphQLBackend) []Backend {
	backends := make([]Backend, 0, len(gbs))
	for _, gb := range gbs {
		backends = append(backends, GraphQLBackendToBackend(gb))
	}
	return backends
}
