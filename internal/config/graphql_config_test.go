package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// Protocol Constant Tests
// ============================================================================

func TestProtocolGraphQLConstant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "GRAPHQL", ProtocolGraphQL)
}

// ============================================================================
// GraphQLRoute Tests
// ============================================================================

func TestGraphQLRoute_HasTLSOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    GraphQLRoute
		expected bool
	}{
		{
			name:     "nil TLS config",
			route:    GraphQLRoute{Name: "test"},
			expected: false,
		},
		{
			name: "empty TLS config",
			route: GraphQLRoute{
				Name: "test",
				TLS:  &RouteTLSConfig{},
			},
			expected: false,
		},
		{
			name: "TLS with cert file only",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with key file only",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					KeyFile: "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with both cert and key files",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with Vault disabled",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					Vault: &VaultTLSConfig{
						Enabled: false,
					},
				},
			},
			expected: false,
		},
		{
			name: "TLS with Vault enabled",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					Vault: &VaultTLSConfig{
						Enabled:    true,
						PKIMount:   "pki",
						Role:       "my-role",
						CommonName: "example.com",
					},
				},
			},
			expected: true,
		},
		{
			name: "TLS with SNI hosts only (no cert)",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					SNIHosts: []string{"api.example.com"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.route.HasTLSOverride())
		})
	}
}

func TestGraphQLRoute_GetEffectiveSNIHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    GraphQLRoute
		expected []string
	}{
		{
			name:     "nil TLS config",
			route:    GraphQLRoute{Name: "test"},
			expected: nil,
		},
		{
			name: "empty TLS config",
			route: GraphQLRoute{
				Name: "test",
				TLS:  &RouteTLSConfig{},
			},
			expected: nil,
		},
		{
			name: "TLS with empty SNI hosts",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{},
				},
			},
			expected: nil,
		},
		{
			name: "TLS with single SNI host",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"graphql.example.com"},
				},
			},
			expected: []string{"graphql.example.com"},
		},
		{
			name: "TLS with multiple SNI hosts",
			route: GraphQLRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"graphql.example.com", "api.example.com", "*.example.com"},
				},
			},
			expected: []string{"graphql.example.com", "api.example.com", "*.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.route.GetEffectiveSNIHosts()
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGraphQLRouteMatch_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    GraphQLRouteMatch
		expected bool
	}{
		{
			name:     "empty match",
			match:    GraphQLRouteMatch{},
			expected: true,
		},
		{
			name: "with path",
			match: GraphQLRouteMatch{
				Path: &StringMatch{Exact: "/graphql"},
			},
			expected: false,
		},
		{
			name: "with operation type",
			match: GraphQLRouteMatch{
				OperationType: "query",
			},
			expected: false,
		},
		{
			name: "with operation name",
			match: GraphQLRouteMatch{
				OperationName: &StringMatch{Exact: "GetUser"},
			},
			expected: false,
		},
		{
			name: "with headers",
			match: GraphQLRouteMatch{
				Headers: []HeaderMatchConfig{{Name: "x-custom"}},
			},
			expected: false,
		},
		{
			name: "with empty path",
			match: GraphQLRouteMatch{
				Path: &StringMatch{},
			},
			expected: true,
		},
		{
			name: "with empty operation name",
			match: GraphQLRouteMatch{
				OperationName: &StringMatch{},
			},
			expected: true,
		},
		{
			name: "with nil path and empty operation type",
			match: GraphQLRouteMatch{
				Path:          nil,
				OperationType: "",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.match.IsEmpty())
		})
	}
}

// ============================================================================
// GraphQLRoute YAML/JSON Round-Trip Tests
// ============================================================================

func TestGraphQLRoute_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	introspectionEnabled := true
	original := GraphQLRoute{
		Name: "test-graphql-route",
		Match: []GraphQLRouteMatch{
			{
				Path:          &StringMatch{Exact: "/graphql"},
				OperationType: "query",
				OperationName: &StringMatch{Prefix: "Get"},
				Headers: []HeaderMatchConfig{
					{Name: "x-custom", Exact: "value"},
				},
			},
		},
		Route: []RouteDestination{
			{
				Destination: Destination{Host: "graphql-backend", Port: 8080},
				Weight:      100,
			},
		},
		Timeout:              Duration(30 * time.Second),
		DepthLimit:           10,
		ComplexityLimit:      100,
		IntrospectionEnabled: &introspectionEnabled,
		AllowedOperations:    []string{"query", "mutation"},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GraphQLRoute
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Name, restored.Name)
	assert.Len(t, restored.Match, 1)
	assert.Len(t, restored.Route, 1)
	assert.Equal(t, original.Timeout, restored.Timeout)
	assert.Equal(t, original.DepthLimit, restored.DepthLimit)
	assert.Equal(t, original.ComplexityLimit, restored.ComplexityLimit)
	require.NotNil(t, restored.IntrospectionEnabled)
	assert.True(t, *restored.IntrospectionEnabled)
	assert.Equal(t, original.AllowedOperations, restored.AllowedOperations)
}

func TestGraphQLRoute_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := GraphQLRoute{
		Name: "json-graphql-route",
		Match: []GraphQLRouteMatch{
			{
				Path:          &StringMatch{Prefix: "/graphql"},
				OperationType: "mutation",
			},
		},
		Route: []RouteDestination{
			{
				Destination: Destination{Host: "backend", Port: 4000},
				Weight:      100,
			},
		},
		DepthLimit:      5,
		ComplexityLimit: 50,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GraphQLRoute
	err = json.Unmarshal(jsonData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Name, restored.Name)
	assert.Len(t, restored.Match, 1)
	assert.Equal(t, original.DepthLimit, restored.DepthLimit)
	assert.Equal(t, original.ComplexityLimit, restored.ComplexityLimit)
}

func TestGraphQLRoute_FullConfig(t *testing.T) {
	t.Parallel()

	introspectionEnabled := false
	route := GraphQLRoute{
		Name: "full-graphql-route",
		Match: []GraphQLRouteMatch{
			{
				Path:          &StringMatch{Exact: "/graphql"},
				OperationType: "query",
				OperationName: &StringMatch{Exact: "GetUser"},
				Headers: []HeaderMatchConfig{
					{Name: "Authorization", Prefix: "Bearer "},
					{Name: "X-Tenant", Regex: "^[a-z]+$"},
				},
			},
		},
		Route: []RouteDestination{
			{
				Destination: Destination{Host: "graphql-backend", Port: 4000},
				Weight:      100,
			},
		},
		Timeout: Duration(30 * time.Second),
		Retries: &RetryPolicy{
			Attempts: 3,
		},
		Headers: &HeaderManipulation{
			Request: &HeaderOperation{
				Set: map[string]string{"x-gateway": "avapigw"},
			},
		},
		RateLimit: &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     Duration(5 * time.Minute),
		},
		CORS: &CORSConfig{
			AllowOrigins: []string{"https://example.com"},
		},
		Security: &SecurityConfig{
			Enabled: true,
		},
		TLS: &RouteTLSConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		Authentication: &AuthenticationConfig{
			Enabled: true,
		},
		Authorization: &AuthorizationConfig{
			Enabled: true,
		},
		DepthLimit:           10,
		ComplexityLimit:      100,
		IntrospectionEnabled: &introspectionEnabled,
		AllowedOperations:    []string{"query", "mutation", "subscription"},
	}

	assert.Equal(t, "full-graphql-route", route.Name)
	assert.Len(t, route.Match, 1)
	assert.Len(t, route.Route, 1)
	assert.NotNil(t, route.Retries)
	assert.NotNil(t, route.Headers)
	assert.NotNil(t, route.RateLimit)
	assert.NotNil(t, route.Cache)
	assert.NotNil(t, route.CORS)
	assert.NotNil(t, route.Security)
	assert.NotNil(t, route.TLS)
	assert.NotNil(t, route.Authentication)
	assert.NotNil(t, route.Authorization)
	assert.Equal(t, 10, route.DepthLimit)
	assert.Equal(t, 100, route.ComplexityLimit)
	assert.False(t, *route.IntrospectionEnabled)
	assert.Len(t, route.AllowedOperations, 3)
}

// ============================================================================
// HeaderMatchConfig Tests
// ============================================================================

func TestHeaderMatchConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config HeaderMatchConfig
	}{
		{
			name:   "exact match",
			config: HeaderMatchConfig{Name: "x-custom", Exact: "value"},
		},
		{
			name:   "prefix match",
			config: HeaderMatchConfig{Name: "Authorization", Prefix: "Bearer "},
		},
		{
			name:   "regex match",
			config: HeaderMatchConfig{Name: "x-tenant", Regex: "^[a-z]+$"},
		},
		{
			name:   "name only",
			config: HeaderMatchConfig{Name: "x-present"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotEmpty(t, tt.config.Name)
		})
	}
}

// ============================================================================
// GraphQLBackend Tests
// ============================================================================

func TestGraphQLBackend_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := GraphQLBackend{
		Name: "graphql-service",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 4000, Weight: 50},
			{Address: "10.0.0.2", Port: 4000, Weight: 50},
		},
		HealthCheck: &HealthCheck{
			Path:               "/health",
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
		LoadBalancer: &LoadBalancer{
			Algorithm: LoadBalancerRoundRobin,
		},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GraphQLBackend
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Name, restored.Name)
	assert.Len(t, restored.Hosts, 2)
	assert.NotNil(t, restored.HealthCheck)
	assert.NotNil(t, restored.LoadBalancer)
}

// ============================================================================
// GraphQLBackendToBackend Tests
// ============================================================================

func TestGraphQLBackendToBackend_BasicConversion(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name: "graphql-service",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 4000, Weight: 50},
			{Address: "10.0.0.2", Port: 4000, Weight: 50},
		},
	}

	b := GraphQLBackendToBackend(gb)

	assert.Equal(t, "graphql-service", b.Name)
	assert.Len(t, b.Hosts, 2)
	assert.Equal(t, "10.0.0.1", b.Hosts[0].Address)
	assert.Equal(t, 4000, b.Hosts[0].Port)
	assert.Equal(t, 50, b.Hosts[0].Weight)
	assert.Nil(t, b.HealthCheck)
	assert.Nil(t, b.TLS)
	assert.Nil(t, b.LoadBalancer)
	assert.Nil(t, b.CircuitBreaker)
	assert.Nil(t, b.Authentication)
}

func TestGraphQLBackendToBackend_WithHealthCheck(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		HealthCheck: &HealthCheck{
			Path:               "/health",
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	b := GraphQLBackendToBackend(gb)

	require.NotNil(t, b.HealthCheck)
	assert.Equal(t, "/health", b.HealthCheck.Path)
	assert.Equal(t, Duration(10*time.Second), b.HealthCheck.Interval)
	assert.Equal(t, Duration(5*time.Second), b.HealthCheck.Timeout)
	assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
	assert.Equal(t, 3, b.HealthCheck.UnhealthyThreshold)
}

func TestGraphQLBackendToBackend_WithNilHealthCheck(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:        "svc",
		Hosts:       []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		HealthCheck: nil,
	}

	b := GraphQLBackendToBackend(gb)

	assert.Nil(t, b.HealthCheck)
}

func TestGraphQLBackendToBackend_WithTLSConfig(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		TLS: &BackendTLSConfig{
			Enabled:            true,
			Mode:               "SIMPLE",
			CertFile:           "/path/to/cert.pem",
			KeyFile:            "/path/to/key.pem",
			CAFile:             "/path/to/ca.pem",
			InsecureSkipVerify: false,
		},
	}

	b := GraphQLBackendToBackend(gb)

	require.NotNil(t, b.TLS)
	assert.True(t, b.TLS.Enabled)
	assert.Equal(t, "SIMPLE", b.TLS.Mode)
	assert.Equal(t, "/path/to/cert.pem", b.TLS.CertFile)
	assert.Equal(t, "/path/to/key.pem", b.TLS.KeyFile)
	assert.Equal(t, "/path/to/ca.pem", b.TLS.CAFile)
	assert.False(t, b.TLS.InsecureSkipVerify)
}

func TestGraphQLBackendToBackend_NilTLS(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		TLS:   nil,
	}

	b := GraphQLBackendToBackend(gb)

	assert.Nil(t, b.TLS)
}

func TestGraphQLBackendToBackend_WithLoadBalancer(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		LoadBalancer: &LoadBalancer{
			Algorithm: LoadBalancerRoundRobin,
		},
	}

	b := GraphQLBackendToBackend(gb)

	require.NotNil(t, b.LoadBalancer)
	assert.Equal(t, LoadBalancerRoundRobin, b.LoadBalancer.Algorithm)
}

func TestGraphQLBackendToBackend_WithCircuitBreaker(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
		},
	}

	b := GraphQLBackendToBackend(gb)

	require.NotNil(t, b.CircuitBreaker)
	assert.True(t, b.CircuitBreaker.Enabled)
	assert.Equal(t, 5, b.CircuitBreaker.Threshold)
}

func TestGraphQLBackendToBackend_WithAuthentication(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
			JWT: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "test-token",
			},
		},
	}

	b := GraphQLBackendToBackend(gb)

	require.NotNil(t, b.Authentication)
	assert.Equal(t, "jwt", b.Authentication.Type)
	require.NotNil(t, b.Authentication.JWT)
	assert.True(t, b.Authentication.JWT.Enabled)
}

func TestGraphQLBackendToBackend_FullConfig(t *testing.T) {
	t.Parallel()

	gb := GraphQLBackend{
		Name: "full-svc",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 4000, Weight: 50},
			{Address: "10.0.0.2", Port: 4000, Weight: 50},
		},
		HealthCheck: &HealthCheck{
			Path:     "/health",
			Interval: Duration(10 * time.Second),
			Timeout:  Duration(5 * time.Second),
		},
		LoadBalancer: &LoadBalancer{
			Algorithm: LoadBalancerRoundRobin,
		},
		TLS: &BackendTLSConfig{
			Enabled: true,
			Mode:    "SIMPLE",
		},
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
		},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
		},
	}

	b := GraphQLBackendToBackend(gb)

	assert.Equal(t, "full-svc", b.Name)
	assert.Len(t, b.Hosts, 2)
	assert.NotNil(t, b.HealthCheck)
	assert.NotNil(t, b.LoadBalancer)
	assert.NotNil(t, b.TLS)
	assert.NotNil(t, b.CircuitBreaker)
	assert.NotNil(t, b.Authentication)
}

// ============================================================================
// GraphQLBackendsToBackends Tests
// ============================================================================

func TestGraphQLBackendsToBackends_EmptySlice(t *testing.T) {
	t.Parallel()

	result := GraphQLBackendsToBackends([]GraphQLBackend{})

	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestGraphQLBackendsToBackends_NilSlice(t *testing.T) {
	t.Parallel()

	result := GraphQLBackendsToBackends(nil)

	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestGraphQLBackendsToBackends_MultipleBackends(t *testing.T) {
	t.Parallel()

	gbs := []GraphQLBackend{
		{
			Name:  "svc-1",
			Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000}},
		},
		{
			Name:  "svc-2",
			Hosts: []BackendHost{{Address: "10.0.0.2", Port: 4001}},
			HealthCheck: &HealthCheck{
				Path:     "/health",
				Interval: Duration(5 * time.Second),
				Timeout:  Duration(2 * time.Second),
			},
		},
		{
			Name:  "svc-3",
			Hosts: []BackendHost{{Address: "10.0.0.3", Port: 4002}},
			TLS: &BackendTLSConfig{
				Enabled: true,
				Mode:    "SIMPLE",
			},
		},
	}

	result := GraphQLBackendsToBackends(gbs)

	require.Len(t, result, 3)
	assert.Equal(t, "svc-1", result[0].Name)
	assert.Equal(t, "svc-2", result[1].Name)
	assert.Equal(t, "svc-3", result[2].Name)

	// Verify svc-1 has no health check
	assert.Nil(t, result[0].HealthCheck)

	// Verify svc-2 has health check
	require.NotNil(t, result[1].HealthCheck)
	assert.Equal(t, "/health", result[1].HealthCheck.Path)

	// Verify svc-3 has TLS
	require.NotNil(t, result[2].TLS)
	assert.True(t, result[2].TLS.Enabled)
}

func TestGraphQLBackendsToBackends_SingleBackend(t *testing.T) {
	t.Parallel()

	gbs := []GraphQLBackend{
		{
			Name:  "single-svc",
			Hosts: []BackendHost{{Address: "10.0.0.1", Port: 4000, Weight: 100}},
		},
	}

	result := GraphQLBackendsToBackends(gbs)

	require.Len(t, result, 1)
	assert.Equal(t, "single-svc", result[0].Name)
	assert.Len(t, result[0].Hosts, 1)
	assert.Equal(t, 100, result[0].Hosts[0].Weight)
}

// ============================================================================
// GatewaySpec GraphQL Fields Tests
// ============================================================================

func TestGatewaySpec_GraphQLFields(t *testing.T) {
	t.Parallel()

	spec := GatewaySpec{
		GraphQLRoutes: []GraphQLRoute{
			{
				Name: "graphql-route-1",
				Match: []GraphQLRouteMatch{
					{
						Path:          &StringMatch{Exact: "/graphql"},
						OperationType: "query",
					},
				},
				Route: []RouteDestination{
					{
						Destination: Destination{Host: "graphql-backend", Port: 4000},
						Weight:      100,
					},
				},
			},
		},
		GraphQLBackends: []GraphQLBackend{
			{
				Name: "graphql-backend",
				Hosts: []BackendHost{
					{Address: "10.0.0.1", Port: 4000},
				},
			},
		},
	}

	assert.Len(t, spec.GraphQLRoutes, 1)
	assert.Equal(t, "graphql-route-1", spec.GraphQLRoutes[0].Name)
	assert.Len(t, spec.GraphQLBackends, 1)
	assert.Equal(t, "graphql-backend", spec.GraphQLBackends[0].Name)
}

func TestGatewaySpec_GraphQLFields_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := GatewaySpec{
		Listeners: []Listener{
			{Name: "http", Port: 8080, Protocol: "HTTP"},
		},
		GraphQLRoutes: []GraphQLRoute{
			{
				Name:       "gql-route",
				DepthLimit: 10,
			},
		},
		GraphQLBackends: []GraphQLBackend{
			{
				Name:  "gql-backend",
				Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
			},
		},
	}

	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	var restored GatewaySpec
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	assert.Len(t, restored.GraphQLRoutes, 1)
	assert.Equal(t, "gql-route", restored.GraphQLRoutes[0].Name)
	assert.Equal(t, 10, restored.GraphQLRoutes[0].DepthLimit)
	assert.Len(t, restored.GraphQLBackends, 1)
	assert.Equal(t, "gql-backend", restored.GraphQLBackends[0].Name)
}
