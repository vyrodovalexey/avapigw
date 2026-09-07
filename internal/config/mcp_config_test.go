package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Protocol Constant Tests
// ============================================================================

func TestProtocolMCPConstant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "MCP", ProtocolMCP)
}

// ============================================================================
// MCPConfig.SetDefaults Tests
// ============================================================================

func TestMCPConfig_SetDefaults(t *testing.T) {
	t.Parallel()

	c := &MCPConfig{}
	c.SetDefaults()

	assert.Equal(t, DefaultMCPPath, c.Path)
	assert.Equal(t, DefaultMCPNamespaceSep, c.NamespaceSep)
	assert.Equal(t, DefaultMCPMaxBodySize, c.MaxBodySize)
	assert.Equal(t, DefaultMCPMaxSSEEventSize, c.MaxSSEEventSize)
	assert.Equal(t, DefaultMCPMaxResponseSize, c.MaxResponseSize)
	assert.Equal(t, DefaultMCPMaxContentBlocks, c.MaxContentBlocks)
	assert.Equal(t, DefaultMCPMaxConcurrentStreamsPerPrincipal, c.MaxConcurrentStreamsPerPrincipal)
	assert.Equal(t, DefaultMCPMaxConcurrentUpstreamConns, c.MaxConcurrentUpstreamConns)
	assert.Equal(t, MCPTrustPolicyStrip, c.TrustPolicy)
	assert.Equal(t, DefaultMCPMaxSchemaDepth, c.MaxSchemaDepth)
	assert.Equal(t, DefaultMCPMaxSubschemas, c.MaxSubschemas)
}

func TestMCPConfig_SetDefaults_NilReceiver(t *testing.T) {
	t.Parallel()

	var c *MCPConfig
	assert.NotPanics(t, func() { c.SetDefaults() })
}

func TestMCPConfig_SetDefaults_DoesNotOverrideExisting(t *testing.T) {
	t.Parallel()

	c := &MCPConfig{
		Path:                             "/custom",
		NamespaceSep:                     "_",
		MaxBodySize:                      100,
		MaxSSEEventSize:                  200,
		MaxResponseSize:                  300,
		MaxContentBlocks:                 10,
		MaxConcurrentStreamsPerPrincipal: 5,
		MaxConcurrentUpstreamConns:       7,
		TrustPolicy:                      MCPTrustPolicyFlag,
		MaxSchemaDepth:                   3,
		MaxSubschemas:                    9,
	}
	c.SetDefaults()

	assert.Equal(t, "/custom", c.Path)
	assert.Equal(t, "_", c.NamespaceSep)
	assert.Equal(t, int64(100), c.MaxBodySize)
	assert.Equal(t, int64(200), c.MaxSSEEventSize)
	assert.Equal(t, int64(300), c.MaxResponseSize)
	assert.Equal(t, 10, c.MaxContentBlocks)
	assert.Equal(t, 5, c.MaxConcurrentStreamsPerPrincipal)
	assert.Equal(t, 7, c.MaxConcurrentUpstreamConns)
	assert.Equal(t, MCPTrustPolicyFlag, c.TrustPolicy)
	assert.Equal(t, 3, c.MaxSchemaDepth)
	assert.Equal(t, 9, c.MaxSubschemas)
}

// ============================================================================
// MCPConfig GetEffective* Tests
// ============================================================================

func TestMCPConfig_GetEffectivePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *MCPConfig
		expected string
	}{
		{name: "nil config", cfg: nil, expected: DefaultMCPPath},
		{name: "empty path", cfg: &MCPConfig{}, expected: DefaultMCPPath},
		{name: "custom path", cfg: &MCPConfig{Path: "/rpc"}, expected: "/rpc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectivePath())
		})
	}
}

func TestMCPConfig_GetEffectiveNamespaceSep(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *MCPConfig
		expected string
	}{
		{name: "nil config", cfg: nil, expected: DefaultMCPNamespaceSep},
		{name: "empty sep", cfg: &MCPConfig{}, expected: DefaultMCPNamespaceSep},
		{name: "custom sep", cfg: &MCPConfig{NamespaceSep: "_"}, expected: "_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveNamespaceSep())
		})
	}
}

func TestMCPConfig_GetEffectiveTrustPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *MCPConfig
		expected string
	}{
		{name: "nil config", cfg: nil, expected: MCPTrustPolicyStrip},
		{name: "empty policy", cfg: &MCPConfig{}, expected: MCPTrustPolicyStrip},
		{name: "flag policy", cfg: &MCPConfig{TrustPolicy: MCPTrustPolicyFlag}, expected: MCPTrustPolicyFlag},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveTrustPolicy())
		})
	}
}

func TestMCPConfig_GetEffectiveEraCacheTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *MCPConfig
		expected Duration
	}{
		{name: "nil config", cfg: nil, expected: Duration(DefaultMCPEraCacheTTL)},
		{name: "zero TTL", cfg: &MCPConfig{}, expected: Duration(DefaultMCPEraCacheTTL)},
		{name: "negative TTL", cfg: &MCPConfig{EraCacheTTL: Duration(-1)}, expected: Duration(DefaultMCPEraCacheTTL)},
		{name: "custom TTL", cfg: &MCPConfig{EraCacheTTL: Duration(time.Minute)}, expected: Duration(time.Minute)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveEraCacheTTL())
		})
	}
}

func TestMCPConfig_GetEffectiveHeldRequestDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *MCPConfig
		expected Duration
	}{
		{name: "nil config", cfg: nil, expected: Duration(DefaultMCPHeldRequestDeadline)},
		{name: "zero deadline", cfg: &MCPConfig{}, expected: Duration(DefaultMCPHeldRequestDeadline)},
		{
			name:     "negative deadline",
			cfg:      &MCPConfig{HeldRequestDeadline: Duration(-1)},
			expected: Duration(DefaultMCPHeldRequestDeadline),
		},
		{
			name:     "custom deadline",
			cfg:      &MCPConfig{HeldRequestDeadline: Duration(time.Minute)},
			expected: Duration(time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveHeldRequestDeadline())
		})
	}
}

// ============================================================================
// MCPOAuthResourceServer Tests
// ============================================================================

func TestMCPOAuthResourceServer_GetEffectiveResource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		srv      *MCPOAuthResourceServer
		expected string
	}{
		{name: "nil server", srv: nil, expected: ""},
		{name: "empty canonical URI", srv: &MCPOAuthResourceServer{}, expected: ""},
		{
			name:     "with canonical URI",
			srv:      &MCPOAuthResourceServer{CanonicalURI: "https://hub.example.com"},
			expected: "https://hub.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.srv.GetEffectiveResource())
		})
	}
}

// ============================================================================
// MCPRouteMatch.IsEmpty Tests
// ============================================================================

func TestMCPRouteMatch_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    MCPRouteMatch
		expected bool
	}{
		{name: "empty match", match: MCPRouteMatch{}, expected: true},
		{name: "with path", match: MCPRouteMatch{Path: &StringMatch{Exact: "/mcp"}}, expected: false},
		{name: "with method", match: MCPRouteMatch{Method: "tools/call"}, expected: false},
		{name: "with name", match: MCPRouteMatch{Name: &StringMatch{Exact: "weather"}}, expected: false},
		{name: "with headers", match: MCPRouteMatch{Headers: []HeaderMatchConfig{{Name: "x-a"}}}, expected: false},
		{name: "with empty path", match: MCPRouteMatch{Path: &StringMatch{}}, expected: true},
		{name: "with empty name", match: MCPRouteMatch{Name: &StringMatch{}}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.match.IsEmpty())
		})
	}
}

// ============================================================================
// MCPRoute Tests
// ============================================================================

func TestMCPRoute_HasTLSOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    MCPRoute
		expected bool
	}{
		{name: "nil TLS", route: MCPRoute{Name: "r"}, expected: false},
		{name: "empty TLS", route: MCPRoute{Name: "r", TLS: &RouteTLSConfig{}}, expected: false},
		{
			name:     "cert file only",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{CertFile: "/c.pem"}},
			expected: true,
		},
		{
			name:     "key file only",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{KeyFile: "/k.pem"}},
			expected: true,
		},
		{
			name:     "vault disabled",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{Vault: &VaultTLSConfig{Enabled: false}}},
			expected: false,
		},
		{
			name:     "vault enabled",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{Vault: &VaultTLSConfig{Enabled: true}}},
			expected: true,
		},
		{
			name:     "sni only",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{SNIHosts: []string{"a.example.com"}}},
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

func TestMCPRoute_GetEffectiveSNIHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    MCPRoute
		expected []string
	}{
		{name: "nil TLS", route: MCPRoute{Name: "r"}, expected: nil},
		{name: "empty TLS", route: MCPRoute{Name: "r", TLS: &RouteTLSConfig{}}, expected: nil},
		{
			name:     "empty SNI",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{SNIHosts: []string{}}},
			expected: nil,
		},
		{
			name:     "with SNI hosts",
			route:    MCPRoute{Name: "r", TLS: &RouteTLSConfig{SNIHosts: []string{"a.example.com", "b.example.com"}}},
			expected: []string{"a.example.com", "b.example.com"},
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

func TestMCPRoute_ToMiddlewareRoute(t *testing.T) {
	t.Parallel()

	route := MCPRoute{
		Name:           "mcp-route",
		Timeout:        Duration(30 * time.Second),
		Retries:        &RetryPolicy{Attempts: 3},
		Headers:        &HeaderManipulation{Request: &HeaderOperation{Set: map[string]string{"x-a": "b"}}},
		RateLimit:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100},
		Cache:          &CacheConfig{Enabled: true, TTL: Duration(time.Minute)},
		CORS:           &CORSConfig{AllowOrigins: []string{"https://example.com"}},
		Security:       &SecurityConfig{Enabled: true},
		TLS:            &RouteTLSConfig{CertFile: "/c.pem", KeyFile: "/k.pem"},
		Authentication: &AuthenticationConfig{Enabled: true},
		Authorization:  &AuthorizationConfig{Enabled: true},
		// Routing-only fields that MUST NOT be projected.
		Match:     []MCPRouteMatch{{Method: "tools/call"}},
		Upstreams: []string{"backend-1"},
		ScopeMap:  map[string][]string{"tools/call": {"scope:a"}},
	}

	mr := route.ToMiddlewareRoute()
	require.NotNil(t, mr)

	// Middleware fields are projected.
	assert.Equal(t, "mcp-route", mr.Name)
	assert.Equal(t, route.Timeout, mr.Timeout)
	assert.Equal(t, route.Retries, mr.Retries)
	assert.Equal(t, route.Headers, mr.Headers)
	assert.Equal(t, route.RateLimit, mr.RateLimit)
	assert.Equal(t, route.Cache, mr.Cache)
	assert.Equal(t, route.CORS, mr.CORS)
	assert.Equal(t, route.Security, mr.Security)
	assert.Equal(t, route.TLS, mr.TLS)
	assert.Equal(t, route.Authentication, mr.Authentication)
	assert.Equal(t, route.Authorization, mr.Authorization)

	// Routing-only fields are absent.
	assert.Nil(t, mr.Match)
	assert.Nil(t, mr.Route)
}

// ============================================================================
// MCPBackend GetEffective* / SetDefaults Tests
// ============================================================================

func TestMCPBackend_GetEffectiveTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		backend  *MCPBackend
		expected string
	}{
		{name: "nil backend", backend: nil, expected: MCPBackendTransportStreamableHTTP},
		{name: "empty transport", backend: &MCPBackend{}, expected: MCPBackendTransportStreamableHTTP},
		{
			name:     "custom transport",
			backend:  &MCPBackend{Transport: MCPBackendTransportStreamableHTTP},
			expected: MCPBackendTransportStreamableHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.backend.GetEffectiveTransport())
		})
	}
}

func TestMCPBackend_GetEffectiveNamespacePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		backend  *MCPBackend
		expected string
	}{
		{name: "nil backend", backend: nil, expected: ""},
		{name: "empty prefix uses name", backend: &MCPBackend{Name: "svc"}, expected: "svc"},
		{
			name:     "custom prefix",
			backend:  &MCPBackend{Name: "svc", NamespacePrefix: "custom"},
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.backend.GetEffectiveNamespacePrefix())
		})
	}
}

func TestMCPBackend_GetEffectivePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		backend  *MCPBackend
		expected string
	}{
		{name: "nil backend", backend: nil, expected: DefaultMCPUpstreamPath},
		{name: "empty path", backend: &MCPBackend{}, expected: DefaultMCPUpstreamPath},
		{name: "custom path", backend: &MCPBackend{Path: "/v2/mcp"}, expected: "/v2/mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.backend.GetEffectivePath())
		})
	}
}

func TestMCPBackend_SetDefaults(t *testing.T) {
	t.Parallel()

	b := &MCPBackend{Name: "svc"}
	b.SetDefaults()

	assert.Equal(t, MCPBackendTransportStreamableHTTP, b.Transport)
	assert.Equal(t, "svc", b.NamespacePrefix)
	assert.Equal(t, DefaultMCPUpstreamPath, b.Path)
}

func TestMCPBackend_SetDefaults_NilReceiver(t *testing.T) {
	t.Parallel()

	var b *MCPBackend
	assert.NotPanics(t, func() { b.SetDefaults() })
}

func TestMCPBackend_SetDefaults_DoesNotOverrideExisting(t *testing.T) {
	t.Parallel()

	b := &MCPBackend{
		Name:            "svc",
		Transport:       MCPBackendTransportStreamableHTTP,
		NamespacePrefix: "pfx",
		Path:            "/custom",
	}
	b.SetDefaults()

	assert.Equal(t, "pfx", b.NamespacePrefix)
	assert.Equal(t, "/custom", b.Path)
}

// ============================================================================
// MCPBackendToBackend Tests
// ============================================================================

func TestMCPBackendToBackend_BasicConversion(t *testing.T) {
	t.Parallel()

	mb := MCPBackend{
		Name: "mcp-svc",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 9000, Weight: 50},
			{Address: "10.0.0.2", Port: 9000, Weight: 50},
		},
	}

	b := MCPBackendToBackend(mb)

	assert.Equal(t, "mcp-svc", b.Name)
	assert.Len(t, b.Hosts, 2)
	assert.Equal(t, "10.0.0.1", b.Hosts[0].Address)
	assert.Equal(t, 9000, b.Hosts[0].Port)
	assert.Nil(t, b.HealthCheck)
	assert.Nil(t, b.TLS)
	assert.Nil(t, b.LoadBalancer)
	assert.Nil(t, b.CircuitBreaker)
	assert.Nil(t, b.Authentication)
	assert.Nil(t, b.RateLimit)
}

func TestMCPBackendToBackend_MapsCredentialToAuthentication(t *testing.T) {
	t.Parallel()

	mb := MCPBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 9000}},
		Credential: &BackendAuthConfig{
			Type: "jwt",
			JWT: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "tok",
			},
		},
	}

	b := MCPBackendToBackend(mb)

	require.NotNil(t, b.Authentication)
	assert.Equal(t, "jwt", b.Authentication.Type)
	require.NotNil(t, b.Authentication.JWT)
	assert.True(t, b.Authentication.JWT.Enabled)
}

func TestMCPBackendToBackend_FullConfig(t *testing.T) {
	t.Parallel()

	mb := MCPBackend{
		Name: "full-svc",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 9000, Weight: 50},
			{Address: "10.0.0.2", Port: 9000, Weight: 50},
		},
		HealthCheck: &HealthCheck{
			Path:               "/health",
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
		LoadBalancer:   &LoadBalancer{Algorithm: LoadBalancerRoundRobin},
		TLS:            &BackendTLSConfig{Enabled: true, Mode: "SIMPLE"},
		CircuitBreaker: &CircuitBreakerConfig{Enabled: true, Threshold: 5},
		Credential:     &BackendAuthConfig{Type: "jwt"},
		RateLimit:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100},
	}

	b := MCPBackendToBackend(mb)

	assert.Equal(t, "full-svc", b.Name)
	assert.Len(t, b.Hosts, 2)
	require.NotNil(t, b.HealthCheck)
	assert.Equal(t, "/health", b.HealthCheck.Path)
	assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
	require.NotNil(t, b.LoadBalancer)
	assert.Equal(t, LoadBalancerRoundRobin, b.LoadBalancer.Algorithm)
	require.NotNil(t, b.TLS)
	assert.True(t, b.TLS.Enabled)
	require.NotNil(t, b.CircuitBreaker)
	assert.Equal(t, 5, b.CircuitBreaker.Threshold)
	require.NotNil(t, b.Authentication)
	require.NotNil(t, b.RateLimit)
	assert.Equal(t, 100, b.RateLimit.RequestsPerSecond)
}

// ============================================================================
// MCPBackendsToBackends Tests
// ============================================================================

func TestMCPBackendsToBackends_EmptySlice(t *testing.T) {
	t.Parallel()

	result := MCPBackendsToBackends([]MCPBackend{})
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestMCPBackendsToBackends_NilSlice(t *testing.T) {
	t.Parallel()

	result := MCPBackendsToBackends(nil)
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestMCPBackendsToBackends_MultipleBackends(t *testing.T) {
	t.Parallel()

	mbs := []MCPBackend{
		{Name: "svc-1", Hosts: []BackendHost{{Address: "10.0.0.1", Port: 9000}}},
		{
			Name:        "svc-2",
			Hosts:       []BackendHost{{Address: "10.0.0.2", Port: 9001}},
			HealthCheck: &HealthCheck{Path: "/health", Interval: Duration(5 * time.Second)},
		},
		{
			Name:  "svc-3",
			Hosts: []BackendHost{{Address: "10.0.0.3", Port: 9002}},
			TLS:   &BackendTLSConfig{Enabled: true, Mode: "SIMPLE"},
		},
	}

	result := MCPBackendsToBackends(mbs)

	require.Len(t, result, 3)
	assert.Equal(t, "svc-1", result[0].Name)
	assert.Nil(t, result[0].HealthCheck)
	require.NotNil(t, result[1].HealthCheck)
	assert.Equal(t, "/health", result[1].HealthCheck.Path)
	require.NotNil(t, result[2].TLS)
	assert.True(t, result[2].TLS.Enabled)
}

// ============================================================================
// MCPUpstream alias Tests
// ============================================================================

func TestMCPUpstreamAlias(t *testing.T) {
	t.Parallel()

	var up MCPUpstream = MCPBackend{Name: "svc"}
	assert.Equal(t, "svc", up.Name)
}

// ============================================================================
// MCPTimeouts / MCPTTLClamp / MCPSharedKey struct Tests
// ============================================================================

func TestMCPTimeouts_Fields(t *testing.T) {
	t.Parallel()

	timeouts := MCPTimeouts{
		PerMethod: map[string]Duration{"tools/call": Duration(10 * time.Second)},
		PerTool:   map[string]Duration{"weather": Duration(20 * time.Second)},
		Default:   Duration(5 * time.Second),
	}

	assert.Equal(t, Duration(10*time.Second), timeouts.PerMethod["tools/call"])
	assert.Equal(t, Duration(20*time.Second), timeouts.PerTool["weather"])
	assert.Equal(t, Duration(5*time.Second), timeouts.Default)
}

func TestMCPTTLClamp_Fields(t *testing.T) {
	t.Parallel()

	clamp := MCPTTLClamp{Min: Duration(time.Second), Max: Duration(time.Minute)}
	assert.Equal(t, Duration(time.Second), clamp.Min)
	assert.Equal(t, Duration(time.Minute), clamp.Max)
}

func TestMCPSharedKey_Fields(t *testing.T) {
	t.Parallel()

	key := MCPSharedKey{
		Source:     MCPKeySourceInline,
		Value:      "base64key",
		VaultMount: "kv",
		VaultPath:  "secret/mcp",
		VaultField: "key",
	}
	assert.Equal(t, MCPKeySourceInline, key.Source)
	assert.Equal(t, "base64key", key.Value)
	assert.Equal(t, "kv", key.VaultMount)
	assert.Equal(t, "secret/mcp", key.VaultPath)
	assert.Equal(t, "key", key.VaultField)
}
