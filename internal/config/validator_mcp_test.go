package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mcpBaseSpec returns a minimal valid spec with one MCP backend and one MCP
// route that references it. Individual tests mutate the returned spec to
// exercise a specific validation branch.
func mcpBaseSpec() GatewaySpec {
	return GatewaySpec{
		Listeners: []Listener{
			{Name: "http", Port: 8080, Protocol: "HTTP"},
		},
		MCPBackends: []MCPBackend{
			{
				Name:  "mcp-backend",
				Hosts: []BackendHost{{Address: "10.0.0.1", Port: 9000}},
			},
		},
		MCPRoutes: []MCPRoute{
			{
				Name:      "mcp-route",
				Upstreams: []string{"mcp-backend"},
				Match: []MCPRouteMatch{
					{Method: "tools/call", Name: &StringMatch{Exact: "weather"}},
				},
			},
		},
	}
}

func mcpConfigFrom(spec GatewaySpec) *GatewayConfig {
	return &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "test"},
		Spec:       spec,
	}
}

// validateMCP runs only the MCP validation functions against a spec and
// returns the resulting errors, avoiding coupling to unrelated validation.
func validateMCP(spec GatewaySpec) ValidationErrors {
	v := NewValidator()
	v.validateMCPRoutes(spec.MCPRoutes, spec.MCPBackends)
	v.validateMCPBackends(spec.MCPBackends)
	return v.errors
}

// ============================================================================
// Valid config passes
// ============================================================================

func TestValidateMCP_ValidConfig(t *testing.T) {
	t.Parallel()

	err := ValidateConfig(mcpConfigFrom(mcpBaseSpec()))
	assert.NoError(t, err)
}

func TestValidateMCP_ValidWithFullBackend(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Transport = MCPBackendTransportStreamableHTTP
	spec.MCPBackends[0].Era = MCPEraModern
	spec.MCPBackends[0].TrustLevel = MCPTrustTrusted
	spec.MCPBackends[0].Separator = "_"
	spec.MCPBackends[0].NamespacePrefix = "svc"

	errs := validateMCP(spec)
	assert.False(t, errs.HasErrors(), errs.Error())
}

// ============================================================================
// Route validation
// ============================================================================

func TestValidateMCPRoutes_MissingName(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].Name = ""

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "route name is required")
}

func TestValidateMCPRoutes_DuplicateName(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes = append(spec.MCPRoutes, MCPRoute{
		Name:      "mcp-route",
		Upstreams: []string{"mcp-backend"},
	})

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "duplicate MCP route name")
}

func TestValidateMCPRoutes_NoUpstreams(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].Upstreams = nil

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "at least one upstream is required")
}

func TestValidateMCPRoutes_UnknownUpstream(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].Upstreams = []string{"does-not-exist"}

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "references unknown MCP upstream")
}

func TestValidateMCPRoutes_NegativeTimeout(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].Timeout = Duration(-1)

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "timeout cannot be negative")
}

func TestValidateMCPRoutes_OptionSubConfigs(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].Retries = &RetryPolicy{Attempts: 3}
	spec.MCPRoutes[0].RateLimit = &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 200}
	spec.MCPRoutes[0].Cache = &CacheConfig{Enabled: true, TTL: Duration(60_000_000_000)}
	spec.MCPRoutes[0].TLS = &RouteTLSConfig{CertFile: "/c.pem", KeyFile: "/k.pem"}

	errs := validateMCP(spec)
	assert.False(t, errs.HasErrors(), errs.Error())
}

func TestValidateMCPBackends_CredentialInvalid(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Credential = &BackendAuthConfig{Type: "not-a-valid-type"}

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "invalid backend auth type")
}

func TestValidateMCPRoutes_MatchSubConfigs(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].Match = []MCPRouteMatch{
		{
			Path:    &StringMatch{Exact: "/mcp"},
			Name:    &StringMatch{Prefix: "w"},
			Headers: []HeaderMatchConfig{{Name: "x-tenant", Exact: "acme"}},
		},
	}

	errs := validateMCP(spec)
	assert.False(t, errs.HasErrors(), errs.Error())
}

// ============================================================================
// Backend validation
// ============================================================================

func TestValidateMCPBackends_MissingName(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Name = ""

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "backend name is required")
}

func TestValidateMCPBackends_DuplicateName(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends = append(spec.MCPBackends, MCPBackend{
		Name:  "mcp-backend",
		Hosts: []BackendHost{{Address: "10.0.0.9", Port: 9000}},
	})

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "duplicate MCP backend name")
}

func TestValidateMCPBackends_NoHosts(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Hosts = nil

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "at least one host is required")
}

func TestValidateMCPBackends_InvalidTransport(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Transport = "websocket"

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "invalid transport")
}

func TestValidateMCPBackends_InvalidEra(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Era = "ancient"

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "invalid era")
}

func TestValidateMCPBackends_InvalidTrustLevel(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].TrustLevel = "sortof"

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "invalid trust level")
}

func TestValidateMCPBackends_BadSeparatorAlphabet(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Separator = "/"

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "outside the allowed alphabet")
}

func TestValidateMCPBackends_NamespacePrefixBudgetExceeded(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	// prefix >= 128 characters leaves no room within the name budget.
	longPrefix := ""
	for i := 0; i < 130; i++ {
		longPrefix += "a"
	}
	spec.MCPBackends[0].NamespacePrefix = longPrefix

	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "leaves no room within")
}

func TestValidateMCPBackends_SubConfigs(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].HealthCheck = &HealthCheck{
		Path:               "/health",
		Interval:           Duration(10_000_000_000),
		Timeout:            Duration(5_000_000_000),
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}
	spec.MCPBackends[0].LoadBalancer = &LoadBalancer{Algorithm: LoadBalancerRoundRobin}
	spec.MCPBackends[0].CircuitBreaker = &CircuitBreakerConfig{
		Enabled:   true,
		Threshold: 5,
		Timeout:   Duration(5_000_000_000),
	}
	spec.MCPBackends[0].RateLimit = &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 200}

	errs := validateMCP(spec)
	assert.False(t, errs.HasErrors(), errs.Error())
}

// ============================================================================
// Vault TLS scan (vault_config.go) — MCP routes/backends
// ============================================================================

func TestRoutesRequireVaultTLS_MCPRoute(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].TLS = &RouteTLSConfig{
		Vault: &VaultTLSConfig{Enabled: true, PKIMount: "pki", Role: "r", CommonName: "cn"},
	}

	assert.True(t, spec.routesRequireVaultTLS())
	assert.True(t, spec.RequiresVaultTLS())
}

func TestRoutesRequireVaultTLS_MCPRoute_Disabled(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPRoutes[0].TLS = &RouteTLSConfig{Vault: &VaultTLSConfig{Enabled: false}}

	assert.False(t, spec.routesRequireVaultTLS())
}

func TestBackendsRequireVaultTLS_MCPBackend_TLS(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].TLS = &BackendTLSConfig{
		Vault: &VaultBackendTLSConfig{Enabled: true, PKIMount: "pki", Role: "r", CommonName: "cn"},
	}

	assert.True(t, spec.backendsRequireVaultTLS())
	assert.True(t, spec.RequiresVaultTLS())
}

func TestBackendsRequireVaultTLS_MCPBackend_Credential(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	spec.MCPBackends[0].Credential = &BackendAuthConfig{
		Type: "mtls",
		MTLS: &BackendMTLSAuthConfig{
			Enabled: true,
			Vault:   &VaultBackendTLSConfig{Enabled: true, PKIMount: "pki", Role: "r", CommonName: "cn"},
		},
	}

	assert.True(t, spec.backendsRequireVaultTLS())
}

func TestBackendsRequireVaultTLS_MCPBackend_None(t *testing.T) {
	t.Parallel()

	spec := mcpBaseSpec()
	assert.False(t, spec.backendsRequireVaultTLS())
}
