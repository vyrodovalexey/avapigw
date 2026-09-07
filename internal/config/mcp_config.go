// Package config provides configuration types and loading for the API Gateway.
package config

// Protocol constant for MCP (Model Context Protocol) hub listener configuration.
const (
	// ProtocolMCP identifies a listener/route operating in MCP hub mode.
	ProtocolMCP = "MCP"
)

// MCP hub defaults. These mirror the recommendations in the MCP-Hub
// requirements (specifications/mcp-hub-req.md) and are applied by
// MCPConfig.SetDefaults / MCPBackend.SetDefaults so downstream consumers
// always observe an effective configuration.
const (
	// DefaultMCPPath is the default downstream MCP endpoint path (HUB-101).
	DefaultMCPPath = "/mcp"

	// DefaultMCPUpstreamPath is the default upstream MCP endpoint path used
	// when an MCPBackend does not pin its own path.
	DefaultMCPUpstreamPath = "/mcp"

	// DefaultMCPNamespaceSep is the default namespacing separator. It is
	// drawn from the recommended tool-name alphabet (A-Za-z0-9_.-) so the
	// produced namespaced names stay within HUB-162 constraints.
	DefaultMCPNamespaceSep = "."

	// DefaultMCPMaxBodySize is the default maximum downstream request body
	// size in bytes (HUB-405). Default: 4 MiB.
	DefaultMCPMaxBodySize int64 = 4 * 1024 * 1024

	// DefaultMCPMaxSSEEventSize is the default maximum size of a single SSE
	// event the hub will emit or relay in bytes (HUB-405). Default: 1 MiB.
	DefaultMCPMaxSSEEventSize int64 = 1 * 1024 * 1024

	// DefaultMCPMaxResponseSize is the default maximum total response size in
	// bytes (HUB-405). Default: 16 MiB.
	DefaultMCPMaxResponseSize int64 = 16 * 1024 * 1024

	// DefaultMCPMaxContentBlocks is the default maximum number of content
	// blocks in a single result (HUB-405).
	DefaultMCPMaxContentBlocks = 256

	// DefaultMCPMaxConcurrentStreamsPerPrincipal bounds concurrent streams
	// per authenticated principal (HUB-405).
	DefaultMCPMaxConcurrentStreamsPerPrincipal = 256

	// DefaultMCPMaxConcurrentUpstreamConns bounds concurrent upstream
	// connections (HUB-405).
	DefaultMCPMaxConcurrentUpstreamConns = 512

	// DefaultMCPMaxNameLen is the maximum namespaced primitive name length
	// mandated by HUB-162.
	DefaultMCPMaxNameLen = 128
)

// MCPBackendTransportStreamableHTTP is the only upstream transport supported
// in this iteration (HTTP/HTTPS Streamable HTTP).
const MCPBackendTransportStreamableHTTP = "streamable-http"

// MCP upstream era constants (HUB-724 pinning, HUB-721/723 detection).
const (
	// MCPEraModern selects the modern (stateless, per-request metadata) era.
	MCPEraModern = "modern"

	// MCPEraLegacy selects the legacy (initialize handshake, sessions) era.
	MCPEraLegacy = "legacy"
)

// MCP upstream trust level constants (HUB-401).
const (
	// MCPTrustTrusted marks an upstream whose annotations/descriptions are
	// trusted and forwarded unmodified.
	MCPTrustTrusted = "trusted"

	// MCPTrustUntrusted marks an upstream whose annotations/descriptions are
	// treated as untrusted content and may be stripped or flagged.
	MCPTrustUntrusted = "untrusted"
)

// MCPConfig contains MCP-hub-specific gateway configuration such as the
// endpoint path, request/response size limits and the origin allowlist
// enforced on the downstream endpoint (HUB-101, HUB-106, HUB-405).
type MCPConfig struct {
	// Path is the downstream MCP endpoint path. Default: /mcp (HUB-101).
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// MaxBodySize is the maximum allowed downstream request body size in
	// bytes (HUB-405).
	MaxBodySize int64 `yaml:"maxBodySize,omitempty" json:"maxBodySize,omitempty"`

	// MaxSSEEventSize is the maximum size of a single SSE event in bytes
	// (HUB-405).
	MaxSSEEventSize int64 `yaml:"maxSSEEventSize,omitempty" json:"maxSSEEventSize,omitempty"`

	// AllowedOrigins is the origin allowlist enforced on incoming
	// connections. When empty, every origin is accepted (HUB-106).
	AllowedOrigins []string `yaml:"allowedOrigins,omitempty" json:"allowedOrigins,omitempty"`

	// NamespaceSep is the separator used when namespacing upstream primitive
	// names. It MUST be a subset of A-Za-z0-9_.- (HUB-162).
	NamespaceSep string `yaml:"namespaceSep,omitempty" json:"namespaceSep,omitempty"`

	// MaxContentBlocks bounds the number of content blocks per result
	// (HUB-405).
	MaxContentBlocks int `yaml:"maxContentBlocks,omitempty" json:"maxContentBlocks,omitempty"`

	// MaxResponseSize bounds the total response size in bytes (HUB-405).
	MaxResponseSize int64 `yaml:"maxResponseSize,omitempty" json:"maxResponseSize,omitempty"`

	// MaxConcurrentStreamsPerPrincipal bounds concurrent streams per
	// authenticated principal (HUB-405).
	//nolint:lll // struct tag requires full yaml/json names
	MaxConcurrentStreamsPerPrincipal int `yaml:"maxConcurrentStreamsPerPrincipal,omitempty" json:"maxConcurrentStreamsPerPrincipal,omitempty"`

	// MaxConcurrentUpstreamConns bounds concurrent upstream connections
	// (HUB-405).
	//nolint:lll // struct tag requires full yaml/json names
	MaxConcurrentUpstreamConns int `yaml:"maxConcurrentUpstreamConns,omitempty" json:"maxConcurrentUpstreamConns,omitempty"`

	// SubscriptionKeepAlive is the interval between SSE keep-alive comment
	// lines on idle subscription streams (HUB-225). Default ≤30s.
	SubscriptionKeepAlive Duration `yaml:"subscriptionKeepAlive,omitempty" json:"subscriptionKeepAlive,omitempty"`

	// MRTRMaxRounds is the maximum number of input_required rounds for a
	// single logical operation (HUB-208).
	MRTRMaxRounds int `yaml:"mrtrMaxRounds,omitempty" json:"mrtrMaxRounds,omitempty"`

	// MRTRBudget is the total wall-clock budget for a single MRTR operation
	// (HUB-208).
	MRTRBudget Duration `yaml:"mrtrBudget,omitempty" json:"mrtrBudget,omitempty"`

	// CacheTTLMin is the lower clamp applied to aggregated cache TTLs
	// (HUB-182).
	CacheTTLMin Duration `yaml:"cacheTTLMin,omitempty" json:"cacheTTLMin,omitempty"`

	// CacheTTLMax is the upper clamp applied to aggregated cache TTLs
	// (HUB-182).
	CacheTTLMax Duration `yaml:"cacheTTLMax,omitempty" json:"cacheTTLMax,omitempty"`

	// OAuthResourceServer configures the hub's OAuth 2.1 resource-server
	// surface: the RFC 9728 protected-resource metadata and token audience
	// validation (HUB-301/302). When nil the well-known endpoint is not
	// served and MCP authorization is opt-in per route.
	//nolint:lll // struct tag requires full yaml/json names
	OAuthResourceServer *MCPOAuthResourceServer `yaml:"oauthResourceServer,omitempty" json:"oauthResourceServer,omitempty"`

	// SharedKey configures the shared AEAD key source used by the cursor
	// codec and MRTR envelope sealer so multi-replica deployments verify
	// each other's tokens (HUB-166/207). When nil a per-process key is
	// generated (single-replica dev only) with a WARN.
	SharedKey *MCPSharedKey `yaml:"sharedKey,omitempty" json:"sharedKey,omitempty"`

	// NonceStoreRedis configures the Redis (standalone or Sentinel) backend
	// used to enforce single-use MRTR envelope nonces ACROSS replicas
	// (HUB-207/209/501). It reuses the same connection shape as the rate
	// limiter so a deployment can point both at the same Sentinel cluster.
	// When nil single-use is enforced with a bounded in-memory store (correct
	// only within a single replica).
	//nolint:lll // struct tag requires full yaml/json names
	NonceStoreRedis *RateLimitRedisConfig `yaml:"nonceStoreRedis,omitempty" json:"nonceStoreRedis,omitempty"`

	// TrustPolicy configures how untrusted-upstream descriptions/annotations
	// are handled (HUB-401): "strip" or "flag". Default: strip.
	TrustPolicy string `yaml:"trustPolicy,omitempty" json:"trustPolicy,omitempty"`

	// DriftRequireReapproval, when true, excludes a changed tool definition
	// from discovery until it is re-approved (HUB-402). Default: false
	// (drift is logged + metered but definitions still served).
	//nolint:lll // struct tag requires full yaml/json names
	DriftRequireReapproval bool `yaml:"driftRequireReapproval,omitempty" json:"driftRequireReapproval,omitempty"`

	// MaxSchemaDepth bounds the nesting depth of a tool input/output schema
	// the hub will accept (HUB-404). Default: DefaultMCPMaxSchemaDepth.
	MaxSchemaDepth int `yaml:"maxSchemaDepth,omitempty" json:"maxSchemaDepth,omitempty"`

	// MaxSubschemas bounds the number of subschema nodes in a tool schema
	// (HUB-404). Default: DefaultMCPMaxSubschemas.
	MaxSubschemas int `yaml:"maxSubschemas,omitempty" json:"maxSubschemas,omitempty"`

	// SchemaValidationBudget bounds the wall-clock time a single schema
	// validation may take (HUB-404). Default: DefaultMCPSchemaBudget.
	//nolint:lll // struct tag requires full yaml/json names
	SchemaValidationBudget Duration `yaml:"schemaValidationBudget,omitempty" json:"schemaValidationBudget,omitempty"`

	// DryRun enables shadow mode: routing/policy/schema validation resolve a
	// request WITHOUT invoking the upstream, returning a synthetic result
	// (HUB-507). A per-request Mcp-Dry-Run: true header also enables it.
	DryRun bool `yaml:"dryRun,omitempty" json:"dryRun,omitempty"`

	// HealthCheckInterval is the period between per-upstream MCP health
	// probes (T-60). Zero disables periodic probing.
	//nolint:lll // struct tag requires full yaml/json names
	HealthCheckInterval Duration `yaml:"healthCheckInterval,omitempty" json:"healthCheckInterval,omitempty"`

	// EraCacheTTL bounds how long a per-upstream era determination is trusted
	// before it is re-probed (HUB-723). Zero uses DefaultMCPEraCacheTTL.
	EraCacheTTL Duration `yaml:"eraCacheTTL,omitempty" json:"eraCacheTTL,omitempty"`

	// LegacySessionIdleTimeout bounds how long a pooled legacy upstream
	// session may stay idle before it is eligible for teardown (HUB-702).
	// Zero uses DefaultMCPLegacySessionIdleTimeout.
	//nolint:lll // struct tag requires full yaml/json names
	LegacySessionIdleTimeout Duration `yaml:"legacySessionIdleTimeout,omitempty" json:"legacySessionIdleTimeout,omitempty"`

	// HeldRequestDeadline bounds how long a held legacy server-initiated
	// request awaits the downstream client's inputResponses before it expires
	// (HUB-705). Zero uses DefaultMCPHeldRequestDeadline.
	//nolint:lll // struct tag requires full yaml/json names
	HeldRequestDeadline Duration `yaml:"heldRequestDeadline,omitempty" json:"heldRequestDeadline,omitempty"`
}

// MCP dual-era bridging defaults (HUB-701..707, HUB-721..724). These mirror the
// era package defaults so a config that omits them observes the same effective
// behavior.
const (
	// DefaultMCPEraCacheTTL is the default per-upstream era-cache TTL (HUB-723).
	DefaultMCPEraCacheTTL = 30 * 60 * 1_000_000_000 // 30m in nanoseconds

	// DefaultMCPLegacySessionIdleTimeout is the default idle timeout before a
	// pooled legacy session is eligible for teardown (HUB-702).
	DefaultMCPLegacySessionIdleTimeout = 5 * 60 * 1_000_000_000 // 5m

	// DefaultMCPHeldRequestDeadline is the default held-request deadline
	// (HUB-705).
	DefaultMCPHeldRequestDeadline = 2 * 60 * 1_000_000_000 // 2m
)

// GetEffectiveEraCacheTTL returns the configured era-cache TTL or the default
// (HUB-723).
func (c *MCPConfig) GetEffectiveEraCacheTTL() Duration {
	if c == nil || c.EraCacheTTL <= 0 {
		return Duration(DefaultMCPEraCacheTTL)
	}
	return c.EraCacheTTL
}

// GetEffectiveHeldRequestDeadline returns the configured held-request deadline
// or the default (HUB-705).
func (c *MCPConfig) GetEffectiveHeldRequestDeadline() Duration {
	if c == nil || c.HeldRequestDeadline <= 0 {
		return Duration(DefaultMCPHeldRequestDeadline)
	}
	return c.HeldRequestDeadline
}

// MCP trust-policy constants (HUB-401).
const (
	// MCPTrustPolicyStrip removes untrusted descriptions/annotations.
	MCPTrustPolicyStrip = "strip"
	// MCPTrustPolicyFlag annotates untrusted content with a warning marker
	// instead of removing it.
	MCPTrustPolicyFlag = "flag"
)

// Schema validation cost bound defaults (HUB-404).
const (
	// DefaultMCPMaxSchemaDepth bounds tool schema nesting depth.
	DefaultMCPMaxSchemaDepth = 32
	// DefaultMCPMaxSubschemas bounds the number of subschema nodes.
	DefaultMCPMaxSubschemas = 2048
)

// MCPSharedKeySource enumerates the supported shared-key sources.
const (
	// MCPKeySourceInline reads a base64-encoded 32-byte key from Value.
	MCPKeySourceInline = "inline"
	// MCPKeySourceVaultKV reads the key from a Vault KV secret.
	MCPKeySourceVaultKV = "vaultKV"
	// MCPKeySourceVaultTransit derives the key via Vault Transit.
	MCPKeySourceVaultTransit = "vaultTransit"
)

// MCPSharedKey configures the shared AEAD key source for the cursor codec and
// MRTR envelope sealer (HUB-166/207).
type MCPSharedKey struct {
	// Source selects the key source: "inline", "vaultKV" or "vaultTransit".
	Source string `yaml:"source,omitempty" json:"source,omitempty"`

	// Value is the base64-encoded 32-byte key when Source is "inline".
	Value string `yaml:"value,omitempty" json:"value,omitempty"`

	// VaultMount is the Vault mount for the KV or Transit source.
	VaultMount string `yaml:"vaultMount,omitempty" json:"vaultMount,omitempty"`

	// VaultPath is the KV secret path (Source "vaultKV") or the Transit key
	// name (Source "vaultTransit").
	VaultPath string `yaml:"vaultPath,omitempty" json:"vaultPath,omitempty"`

	// VaultField is the KV field holding the base64 key (Source "vaultKV").
	// Default: "key".
	VaultField string `yaml:"vaultField,omitempty" json:"vaultField,omitempty"`
}

// GetEffectiveTrustPolicy returns the configured trust policy or the default
// (strip) when unset.
func (c *MCPConfig) GetEffectiveTrustPolicy() string {
	if c == nil || c.TrustPolicy == "" {
		return MCPTrustPolicyStrip
	}
	return c.TrustPolicy
}

// MCPOAuthResourceServer configures the hub as an OAuth 2.1 resource server
// (HUB-301/302). It carries the hub's canonical resource URI, the trusted
// authorization servers and the scopes advertised in the RFC 9728
// protected-resource metadata.
type MCPOAuthResourceServer struct {
	// CanonicalURI is the hub's canonical resource identifier. Presented
	// tokens MUST carry this value in their audience (RFC 8707, HUB-302).
	// It is also published as the "resource" field of the RFC 9728 metadata.
	CanonicalURI string `yaml:"canonicalURI,omitempty" json:"canonicalURI,omitempty"`

	// AuthorizationServers lists the issuer URLs of the authorization
	// servers trusted to mint tokens for the hub (RFC 9728
	// authorization_servers).
	AuthorizationServers []string `yaml:"authorizationServers,omitempty" json:"authorizationServers,omitempty"`

	// ScopesSupported lists the scopes advertised in the protected-resource
	// metadata (RFC 9728 scopes_supported).
	ScopesSupported []string `yaml:"scopesSupported,omitempty" json:"scopesSupported,omitempty"`

	// OIDCProvider names the configured OIDC provider used to validate token
	// signatures and issuers before the audience check is applied. When
	// empty, bearer tokens are accepted only structurally (audience is still
	// enforced) — signature validation requires a provider.
	OIDCProvider string `yaml:"oidcProvider,omitempty" json:"oidcProvider,omitempty"`

	// PolicyMode enables the deny-by-default policy engine (HUB-310). When
	// false, only scope enforcement applies.
	PolicyMode bool `yaml:"policyMode,omitempty" json:"policyMode,omitempty"`
}

// GetEffectiveResource returns the hub's canonical resource URI.
func (o *MCPOAuthResourceServer) GetEffectiveResource() string {
	if o == nil {
		return ""
	}
	return o.CanonicalURI
}

// GetEffectivePath returns the configured downstream MCP path or the default
// when unset.
func (c *MCPConfig) GetEffectivePath() string {
	if c == nil || c.Path == "" {
		return DefaultMCPPath
	}
	return c.Path
}

// GetEffectiveNamespaceSep returns the configured namespacing separator or
// the default when unset.
func (c *MCPConfig) GetEffectiveNamespaceSep() string {
	if c == nil || c.NamespaceSep == "" {
		return DefaultMCPNamespaceSep
	}
	return c.NamespaceSep
}

// SetDefaults applies sensible defaults to unset MCPConfig fields, mirroring
// how the codebase applies defaults elsewhere (e.g. GetEffective* helpers).
// It is safe to call on a nil receiver, in which case it is a no-op.
func (c *MCPConfig) SetDefaults() {
	if c == nil {
		// Nil MCPConfig means MCP mode is disabled; nothing to default.
		return
	}
	if c.Path == "" {
		c.Path = DefaultMCPPath
	}
	if c.NamespaceSep == "" {
		c.NamespaceSep = DefaultMCPNamespaceSep
	}
	if c.MaxBodySize == 0 {
		c.MaxBodySize = DefaultMCPMaxBodySize
	}
	if c.MaxSSEEventSize == 0 {
		c.MaxSSEEventSize = DefaultMCPMaxSSEEventSize
	}
	if c.MaxResponseSize == 0 {
		c.MaxResponseSize = DefaultMCPMaxResponseSize
	}
	if c.MaxContentBlocks == 0 {
		c.MaxContentBlocks = DefaultMCPMaxContentBlocks
	}
	if c.MaxConcurrentStreamsPerPrincipal == 0 {
		c.MaxConcurrentStreamsPerPrincipal = DefaultMCPMaxConcurrentStreamsPerPrincipal
	}
	if c.MaxConcurrentUpstreamConns == 0 {
		c.MaxConcurrentUpstreamConns = DefaultMCPMaxConcurrentUpstreamConns
	}
	if c.TrustPolicy == "" {
		c.TrustPolicy = MCPTrustPolicyStrip
	}
	if c.MaxSchemaDepth == 0 {
		c.MaxSchemaDepth = DefaultMCPMaxSchemaDepth
	}
	if c.MaxSubschemas == 0 {
		c.MaxSubschemas = DefaultMCPMaxSubschemas
	}
}

// MCPRouteMatch represents matching conditions for an MCP route. Matches are
// derivable from mirrored headers alone (HUB-148): Method mirrors Mcp-Method
// and Name mirrors Mcp-Name.
type MCPRouteMatch struct {
	// Path matches the HTTP path for the MCP endpoint.
	Path *StringMatch `yaml:"path,omitempty" json:"path,omitempty"`

	// Method matches the MCP method (mirrored into the Mcp-Method header).
	Method string `yaml:"method,omitempty" json:"method,omitempty"`

	// Name matches the MCP primitive name (mirrored into the Mcp-Name
	// header) for tools/call, resources/read and prompts/get.
	Name *StringMatch `yaml:"name,omitempty" json:"name,omitempty"`

	// Headers matches HTTP headers.
	Headers []HeaderMatchConfig `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// IsEmpty returns true if the MCPRouteMatch has no conditions.
func (m *MCPRouteMatch) IsEmpty() bool {
	if m.Path != nil && !m.Path.IsEmpty() {
		return false
	}
	if m.Method != "" {
		return false
	}
	if m.Name != nil && !m.Name.IsEmpty() {
		return false
	}
	if len(m.Headers) > 0 {
		return false
	}
	return true
}

// MCPUpstreamRef references an MCPBackend with an optional traffic weight.
// It mirrors config.RouteDestination.Weight so MCP weighted routing follows
// the same 0-100 / sum-to-100 semantics as APIRoute destinations.
type MCPUpstreamRef struct {
	// Name is the referenced MCPBackend name.
	Name string `yaml:"name" json:"name"`

	// Weight is the relative traffic weight (0-100). Zero-weight refs receive
	// no traffic when any sibling has a positive weight (0% canary); when all
	// weights are zero, selection is uniform.
	Weight int `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// MCPRoute represents an MCP routing rule configuration. It mirrors
// GraphQLRoute: routing-specific fields live here while cross-cutting
// middleware is projected onto a Route view via ToMiddlewareRoute.
type MCPRoute struct {
	// Name is the unique name of the route.
	Name string `yaml:"name" json:"name"`

	// Match contains the matching conditions for this route.
	Match []MCPRouteMatch `yaml:"match,omitempty" json:"match,omitempty"`

	// Upstreams lists the MCPBackend names this route fans out to (legacy,
	// equal weight). Mutually exclusive with WeightedUpstreams.
	Upstreams []string `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`

	// WeightedUpstreams lists MCPBackend references with traffic weights for
	// single-upstream selection (canary / A-B). Mutually exclusive with
	// Upstreams. Aggregation and subscription fan-out still cover ALL
	// referenced upstreams regardless of weight.
	WeightedUpstreams []MCPUpstreamRef `yaml:"weightedUpstreams,omitempty" json:"weightedUpstreams,omitempty"`

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

	// CORS configures CORS for this MCP route (overrides global).
	CORS *CORSConfig `yaml:"cors,omitempty" json:"cors,omitempty"`

	// Security configures security headers for this MCP route (overrides global).
	Security *SecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`

	// TLS configures route-level TLS certificate override for this MCP route.
	TLS *RouteTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Authentication configures route-level authentication.
	Authentication *AuthenticationConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	Authorization *AuthorizationConfig `yaml:"authorization,omitempty" json:"authorization,omitempty"`

	// ScopeMap maps a primitive or method to the OAuth scopes required to
	// invoke it (HUB-305/306).
	ScopeMap map[string][]string `yaml:"scopeMap,omitempty" json:"scopeMap,omitempty"`
}

// UpstreamRefs returns the route's upstream references in configured order as
// the single source of truth for selection. When WeightedUpstreams is set it
// is returned as-is; otherwise the legacy Upstreams list is mapped to
// zero-weight refs (equal-weight semantics). Setting both fields is a
// validation error handled by the validator/webhook, not silent precedence.
func (r *MCPRoute) UpstreamRefs() []MCPUpstreamRef {
	if len(r.WeightedUpstreams) > 0 {
		return r.WeightedUpstreams
	}
	refs := make([]MCPUpstreamRef, len(r.Upstreams))
	for i, name := range r.Upstreams {
		refs[i] = MCPUpstreamRef{Name: name}
	}
	return refs
}

// UpstreamNames returns ALL referenced upstream names in configured order,
// regardless of weight. Aggregation and subscription fan-out use this so a
// zero-weight upstream is never dropped from server/discover, */list or
// subscriptions/listen.
func (r *MCPRoute) UpstreamNames() []string {
	refs := r.UpstreamRefs()
	names := make([]string, len(refs))
	for i := range refs {
		names[i] = refs[i].Name
	}
	return names
}

// HasTLSOverride returns true if the MCP route has TLS configuration that
// overrides listener TLS.
func (r *MCPRoute) HasTLSOverride() bool {
	if r.TLS == nil {
		return false
	}
	hasFiles := r.TLS.CertFile != "" || r.TLS.KeyFile != ""
	hasVault := r.TLS.Vault != nil && r.TLS.Vault.Enabled
	return hasFiles || hasVault
}

// GetEffectiveSNIHosts returns the SNI hosts for this MCP route.
// Returns nil if no SNI hosts are configured.
func (r *MCPRoute) GetEffectiveSNIHosts() []string {
	if r.TLS == nil || len(r.TLS.SNIHosts) == 0 {
		return nil
	}
	return r.TLS.SNIHosts
}

// ToMiddlewareRoute projects the MCP route's cross-cutting middleware
// configuration (authentication, authorization, rate limiting, CORS,
// security headers, caching, header manipulation, TLS) onto a Route view so
// the shared per-route middleware machinery (gateway.RouteMiddlewareManager)
// serves MCP routes with exactly the same middleware chain semantics as HTTP
// routes. Routing-only fields (Match, Upstreams, WeightedUpstreams, ScopeMap)
// are intentionally NOT projected: routing stays in the MCP router, and the
// view is consumed
// for middleware construction only. Mirrors GraphQLRoute.ToMiddlewareRoute.
func (r *MCPRoute) ToMiddlewareRoute() *Route {
	return &Route{
		Name:           r.Name,
		Timeout:        r.Timeout,
		Retries:        r.Retries,
		Headers:        r.Headers,
		RateLimit:      r.RateLimit,
		Cache:          r.Cache,
		CORS:           r.CORS,
		Security:       r.Security,
		TLS:            r.TLS,
		Authentication: r.Authentication,
		Authorization:  r.Authorization,
	}
}

// MCPTimeouts configures per-method and per-tool timeouts for an upstream
// (HUB-243).
type MCPTimeouts struct {
	// PerMethod maps an MCP method name to its timeout.
	PerMethod map[string]Duration `yaml:"perMethod,omitempty" json:"perMethod,omitempty"`

	// PerTool maps a de-namespaced tool name to its timeout.
	PerTool map[string]Duration `yaml:"perTool,omitempty" json:"perTool,omitempty"`

	// Default is the fallback timeout when no per-method/per-tool override
	// applies.
	Default Duration `yaml:"default,omitempty" json:"default,omitempty"`
}

// MCPTTLClamp clamps aggregated cache TTLs to a configured range (HUB-182).
type MCPTTLClamp struct {
	// Min is the lower clamp for cache TTLs.
	Min Duration `yaml:"min,omitempty" json:"min,omitempty"`

	// Max is the upper clamp for cache TTLs.
	Max Duration `yaml:"max,omitempty" json:"max,omitempty"`
}

// MCPBackend represents an MCP upstream server configuration. It mirrors the
// MCPUpstream CRD (HUB-503) and reuses the shared backend infrastructure via
// MCPBackendToBackend.
type MCPBackend struct {
	// Name is the unique name of the upstream.
	Name string `yaml:"name" json:"name"`

	// Hosts contains the upstream host configurations.
	Hosts []BackendHost `yaml:"hosts" json:"hosts"`

	// Transport selects the upstream transport. Only "streamable-http" is
	// supported in this iteration.
	Transport string `yaml:"transport,omitempty" json:"transport,omitempty"`

	// Era pins the protocol era: "modern", "legacy" or "" (auto-detect).
	Era string `yaml:"era,omitempty" json:"era,omitempty"`

	// PinnedVersion pins a specific protocol version, bypassing probing
	// (HUB-724).
	PinnedVersion string `yaml:"pinnedVersion,omitempty" json:"pinnedVersion,omitempty"`

	// NamespacePrefix is the prefix applied when namespacing this upstream's
	// primitives (HUB-162). Defaults to Name when unset.
	NamespacePrefix string `yaml:"namespacePrefix,omitempty" json:"namespacePrefix,omitempty"`

	// Separator overrides the global namespacing separator for this upstream
	// (HUB-162). Must be a subset of A-Za-z0-9_.-.
	Separator string `yaml:"separator,omitempty" json:"separator,omitempty"`

	// Allow restricts which primitives are exposed from this upstream
	// (HUB-503 allow list). Empty means allow all (subject to Deny).
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`

	// Deny excludes primitives from this upstream (HUB-503 deny list).
	Deny []string `yaml:"deny,omitempty" json:"deny,omitempty"`

	// TrustLevel marks the upstream as "trusted" or "untrusted" (HUB-401).
	TrustLevel string `yaml:"trustLevel,omitempty" json:"trustLevel,omitempty"`

	// HealthCheck contains health check configuration.
	HealthCheck *HealthCheck `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`

	// LoadBalancer contains load balancer configuration.
	LoadBalancer *LoadBalancer `yaml:"loadBalancer,omitempty" json:"loadBalancer,omitempty"`

	// TLS contains TLS configuration for connecting to the upstream
	// (including Vault PKI mTLS, HUB-309).
	TLS *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CircuitBreaker configures circuit breaking for this upstream (HUB-504).
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// Credential configures the independent upstream credential source; the
	// downstream client token is never forwarded (HUB-303/304).
	Credential *BackendAuthConfig `yaml:"credential,omitempty" json:"credential,omitempty"`

	// Timeouts configures per-method/per-tool timeouts (HUB-243).
	Timeouts *MCPTimeouts `yaml:"timeouts,omitempty" json:"timeouts,omitempty"`

	// CacheTTLClamp clamps aggregated cache TTLs for this upstream (HUB-182).
	CacheTTLClamp *MCPTTLClamp `yaml:"cacheTTLClamp,omitempty" json:"cacheTTLClamp,omitempty"`

	// RateLimit configures rate limiting for this upstream.
	RateLimit *RateLimitConfig `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Path is the upstream MCP endpoint path. Default: /mcp.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// MCPUpstream is an alias for MCPBackend, matching the MCPUpstream CRD
// terminology used in the requirements (HUB-503).
type MCPUpstream = MCPBackend

// GetEffectiveTransport returns the configured transport or the default
// streamable-http transport when unset.
func (b *MCPBackend) GetEffectiveTransport() string {
	if b == nil || b.Transport == "" {
		return MCPBackendTransportStreamableHTTP
	}
	return b.Transport
}

// GetEffectiveNamespacePrefix returns the configured namespace prefix or the
// upstream Name when unset (HUB-162).
func (b *MCPBackend) GetEffectiveNamespacePrefix() string {
	if b == nil {
		return ""
	}
	if b.NamespacePrefix == "" {
		return b.Name
	}
	return b.NamespacePrefix
}

// GetEffectivePath returns the configured upstream MCP path or the default
// when unset.
func (b *MCPBackend) GetEffectivePath() string {
	if b == nil || b.Path == "" {
		return DefaultMCPUpstreamPath
	}
	return b.Path
}

// SetDefaults applies sensible defaults to unset MCPBackend fields. It is
// safe to call on a nil receiver, in which case it is a no-op.
func (b *MCPBackend) SetDefaults() {
	if b == nil {
		// Nil upstream has nothing to default.
		return
	}
	if b.Transport == "" {
		b.Transport = MCPBackendTransportStreamableHTTP
	}
	if b.NamespacePrefix == "" {
		b.NamespacePrefix = b.Name
	}
	if b.Path == "" {
		b.Path = DefaultMCPUpstreamPath
	}
}

// MCPBackendToBackend converts an MCPBackend to a Backend configuration so
// MCP upstreams reuse the shared backend.Registry infrastructure (load
// balancing, health checking, connection management, TLS/mTLS and per-backend
// authentication). Mirrors GraphQLBackendToBackend. The upstream Credential
// maps to Backend.Authentication (HUB-303/304).
func MCPBackendToBackend(b MCPBackend) Backend {
	return Backend{
		Name:           b.Name,
		Hosts:          b.Hosts,
		HealthCheck:    b.HealthCheck,
		LoadBalancer:   b.LoadBalancer,
		TLS:            b.TLS,
		CircuitBreaker: b.CircuitBreaker,
		Authentication: b.Credential,
		RateLimit:      b.RateLimit,
	}
}

// MCPBackendsToBackends converts a slice of MCPBackend to a slice of Backend.
func MCPBackendsToBackends(bs []MCPBackend) []Backend {
	backends := make([]Backend, 0, len(bs))
	for _, b := range bs {
		backends = append(backends, MCPBackendToBackend(b))
	}
	return backends
}
