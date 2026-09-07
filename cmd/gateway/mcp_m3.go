package main

import (
	"crypto/rand"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	mcpcache "github.com/vyrodovalexey/avapigw/internal/mcp/cache"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mcpCacheRouteName is the CacheFactory route key used for the shared MCP
// result cache instance.
const mcpCacheRouteName = "__mcp_result_cache__"

// mcpM3Options builds the additive M3 MCPHandler options: the discovery
// aggregator (with an integrity-protected pagination cursor codec), the result
// cache, and the OAuth 2.1 authorizer. A component that cannot be constructed
// is simply omitted, keeping the M2 pass-through behavior intact.
func mcpM3Options(
	cfg *config.GatewayConfig,
	mcpRegistry *backend.Registry,
	mapper namespace.Mapper,
	hub mcpproxy.HubClient,
	cacheFactory *gateway.CacheFactory,
	sealer envelope.Sealer,
	logger observability.Logger,
) []gateway.MCPHandlerOption {
	var opts []gateway.MCPHandlerOption

	if agg, resolver := buildMCPAggregator(cfg, mcpRegistry, mapper, hub, sealer, logger); agg != nil {
		opts = append(opts, gateway.WithMCPHandlerAggregator(agg))
		// Register the resolver so hot reloads refresh its upstream map in
		// lock-step with the handler's own map (G-1).
		if resolver != nil {
			opts = append(opts, gateway.WithMCPHandlerUpstreamResolver(resolver))
		}
	}
	if c := buildMCPCache(cfg, cacheFactory, logger); c != nil {
		opts = append(opts, gateway.WithMCPHandlerCache(c))
	}
	if a := buildMCPAuthorizer(cfg, logger); a != nil {
		opts = append(opts, gateway.WithMCPHandlerAuthorizer(a))
	}
	return opts
}

// buildMCPAggregator constructs the discovery aggregator with an AEAD
// pagination cursor codec (HUB-166) plus the M5 security-hardening components
// (trust policy, drift detection, bounded schema validation — HUB-401/402/404).
// The cursor codec uses the shared sealer when configured so cursors verify
// across replicas; otherwise a per-process key is generated (single-replica).
func buildMCPAggregator(
	cfg *config.GatewayConfig,
	mcpRegistry *backend.Registry,
	mapper namespace.Mapper,
	hub mcpproxy.HubClient,
	sealer envelope.Sealer,
	logger observability.Logger,
) (discovery.Aggregator, *gateway.MCPUpstreamResolver) {
	cursors := buildMCPCursorCodec(sealer, logger)
	if cursors == nil {
		return nil, nil
	}
	resolver := gateway.NewMCPUpstreamResolver(mcpRegistry, mcpUpstreamMap(cfg.Spec.MCPBackends))
	agg, err := discovery.NewDefaultAggregator(hub, resolver, mapper, cursors,
		discovery.WithAggregatorLogger(logger),
		discovery.WithAggregatorMetrics(mcpmetrics.GetMetrics()),
		discovery.WithAggregatorTrustPolicy(mcpTrustPolicy(cfg)),
		discovery.WithAggregatorSchemaLimits(mcpSchemaLimits(cfg)),
		discovery.WithAggregatorDriftStore(mcpDriftStore(cfg)),
		// HUB-124: the aggregator MUST construct a fresh _meta for every
		// forwarded discovery/list request, carrying the hub's own clientInfo
		// and its brokerable capability set. Mirror the tools/call path.
		discovery.WithAggregatorClientInfo(hubInfo()),
		discovery.WithAggregatorBrokerableCapabilities(gateway.BrokerableCapabilities()),
	)
	if err != nil {
		logger.Error("failed to build MCP aggregator; discovery aggregation disabled",
			observability.Error(err))
		return nil, nil
	}
	return agg, resolver
}

// buildMCPCursorCodec builds the pagination cursor codec over the shared sealer
// when provided, else over a freshly generated per-process key (HUB-166). A
// per-process key breaks cross-replica pagination continuity.
func buildMCPCursorCodec(sealer envelope.Sealer, logger observability.Logger) *discovery.CursorCodec {
	if sealer == nil {
		var err error
		sealer, err = newProcessSealer()
		if err != nil {
			logger.Error("failed to build MCP cursor sealer; discovery aggregation disabled",
				observability.Error(err))
			return nil
		}
	}
	cursors, err := discovery.NewCursorCodec(sealer)
	if err != nil {
		logger.Error("failed to build MCP cursor codec; discovery aggregation disabled",
			observability.Error(err))
		return nil
	}
	return cursors
}

// newProcessSealer builds an AEAD sealer over a fresh per-process key (the
// single-replica fallback). Options let callers wire the cross-replica nonce
// store / consume TTL onto the fallback sealer (HUB-207).
func newProcessSealer(opts ...envelope.SealerOption) (envelope.Sealer, error) {
	key := make([]byte, envelope.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return envelope.NewAEADSealer(key, opts...)
}

// buildMCPCache constructs the MCP result cache over a CacheFactory-managed
// cache instance, applying the configured TTL clamps (HUB-182).
func buildMCPCache(
	cfg *config.GatewayConfig,
	cacheFactory *gateway.CacheFactory,
	logger observability.Logger,
) *mcpcache.ResultCache {
	if cacheFactory == nil {
		return nil
	}
	backendCache, err := cacheFactory.GetOrCreate(mcpCacheRouteName, config.DefaultCacheConfig())
	if err != nil {
		logger.Warn("failed to create MCP result cache; caching disabled",
			observability.Error(err))
		return nil
	}
	c, err := mcpcache.New(backendCache, mcpCacheConfig(cfg),
		mcpcache.WithLogger(logger),
		mcpcache.WithMetrics(mcpmetrics.GetMetrics()),
	)
	if err != nil {
		logger.Warn("failed to build MCP result cache; caching disabled",
			observability.Error(err))
		return nil
	}
	return c
}

// mcpCacheConfig maps the MCP cache TTL clamps from configuration.
func mcpCacheConfig(cfg *config.GatewayConfig) mcpcache.Config {
	out := mcpcache.Config{}
	if cfg.Spec.MCP != nil {
		out.TTLMin = time.Duration(cfg.Spec.MCP.CacheTTLMin)
		out.TTLMax = time.Duration(cfg.Spec.MCP.CacheTTLMax)
	}
	return out
}

// buildMCPAuthorizer constructs the MCP OAuth 2.1 authorizer when the MCP
// OAuthResourceServer block is configured (HUB-301/302/305/310). When the block
// is absent the authorizer is nil and MCP authorization stays disabled
// (additive/opt-in).
func buildMCPAuthorizer(
	cfg *config.GatewayConfig,
	logger observability.Logger,
) *mcpauthz.Authorizer {
	rs := mcpOAuthConfig(cfg)
	if rs == nil {
		return nil
	}
	validator := buildMCPTokenValidator(cfg, rs, logger)
	authzCfg := mcpauthz.Config{
		CanonicalURI:        rs.CanonicalURI,
		ResourceMetadataURL: rs.CanonicalURI + mcpauthz.WellKnownPath,
		PolicyMode:          rs.PolicyMode,
	}
	return mcpauthz.NewAuthorizer(validator, authzCfg, mcpauthz.WithLogger(logger))
}

// mcpOAuthConfig returns the configured OAuth resource-server block, or nil.
func mcpOAuthConfig(cfg *config.GatewayConfig) *config.MCPOAuthResourceServer {
	if cfg == nil || cfg.Spec.MCP == nil {
		return nil
	}
	return cfg.Spec.MCP.OAuthResourceServer
}

// buildMCPTokenValidator wraps the configured OIDC provider as a
// TokenValidator so token signatures/issuers are validated by the shared OIDC
// stack (HUB-302 layers the audience check on top). Returns nil when no
// provider is configured — audience validation still applies but signature
// validation requires a provider.
func buildMCPTokenValidator(
	cfg *config.GatewayConfig,
	rs *config.MCPOAuthResourceServer,
	logger observability.Logger,
) mcpauthz.TokenValidator {
	if rs.OIDCProvider == "" {
		return nil
	}
	authCfg, err := auth.ConvertFromGatewayConfig(cfg.Spec.Authentication)
	if err != nil || authCfg == nil || authCfg.OIDC == nil {
		logger.Warn("MCP OAuth: no OIDC configuration; token signature validation disabled")
		return nil
	}
	providerCfg := authCfg.OIDC.GetProvider(rs.OIDCProvider)
	if providerCfg == nil {
		logger.Warn("MCP OAuth: OIDC provider not found; token signature validation disabled",
			observability.String("provider", rs.OIDCProvider))
		return nil
	}
	provider, err := oidc.NewProvider(providerCfg, authCfg.OIDC, oidc.WithProviderLogger(logger))
	if err != nil {
		logger.Warn("MCP OAuth: failed to build OIDC provider; token signature validation disabled",
			observability.Error(err))
		return nil
	}
	return mcpauthz.NewOIDCValidator(provider)
}
