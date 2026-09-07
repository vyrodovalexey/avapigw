package main

import (
	"context"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// mcpEnabled reports whether the configuration enables the MCP hub: either an
// explicit MCP config block or at least one MCP route.
func mcpEnabled(cfg *config.GatewayConfig) bool {
	return cfg != nil && (cfg.Spec.MCP != nil || len(cfg.Spec.MCPRoutes) > 0)
}

// initMCPBackendRegistry creates and loads a dedicated backend registry for
// MCP upstreams. A separate registry (mirroring initGRPCBackendRegistry) keeps
// MCP upstreams isolated from the HTTP data-plane registry so their lifecycle
// (start/stop/reload) and endpoint index never interfere with proxied HTTP
// backends. The MCPBackend configs are projected onto Backend via
// config.MCPBackendsToBackends so they reuse the shared backend infrastructure
// (load balancing, health checking, TLS/mTLS, per-upstream credentials).
func initMCPBackendRegistry(
	mcpBackends []config.MCPBackend,
	logger observability.Logger,
	metrics *observability.Metrics,
	vaultClient vault.Client,
) *backend.Registry {
	opts := []backend.RegistryOption{backend.WithRegistryMetrics(metrics)}
	if vaultClient != nil {
		opts = append(opts, backend.WithRegistryVaultClient(vaultClient))
	}
	reg := backend.NewRegistry(logger, opts...)
	if err := reg.LoadFromConfig(config.MCPBackendsToBackends(mcpBackends)); err != nil {
		fatalWithSync(logger, "failed to load MCP backends", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}
	return reg
}

// initMCPHandler builds the MCP endpoint handler wired with the per-route
// middleware manager, the hub client, the namespace mapper and the MCP
// metrics. It returns nil when MCP is not enabled. The backend registry passed
// here is the dedicated MCP upstream registry.
func initMCPHandler(
	cfg *config.GatewayConfig,
	mcpRegistry *backend.Registry,
	routeMiddlewareMgr *gateway.RouteMiddlewareManager,
	cacheFactory *gateway.CacheFactory,
	logger observability.Logger,
	vaultClient vault.Client,
	auditLogger audit.Logger,
) *gateway.MCPHandler {
	if !mcpEnabled(cfg) {
		return nil
	}

	sep := ""
	if cfg.Spec.MCP != nil {
		sep = cfg.Spec.MCP.GetEffectiveNamespaceSep()
	}
	mapper, err := namespace.NewDefaultMapper(sep)
	if err != nil {
		logger.Error("failed to build MCP namespace mapper; MCP endpoint disabled",
			observability.Error(err),
		)
		return nil
	}

	hub := mcpproxy.NewHTTPHubClient(
		mcpproxy.WithHubClientLogger(logger),
		mcpproxy.WithHubClientMaxResponseSize(mcpMaxResponseSize(cfg)),
		mcpproxy.WithHubClientMaxSSEEventSize(mcpMaxSSEEventSize(cfg)),
	)

	// Build the cross-replica single-use nonce store (HUB-207/209/501). When
	// configured it is injected into the MRTR sealer so a replayed retry is
	// rejected by any replica; otherwise a bounded in-memory store is used.
	nonces := buildMCPNonceStore(context.Background(), cfg, vaultClient, logger)

	// Build the shared AEAD sealer once so the cursor codec and MRTR envelope
	// verify each other's tokens across replicas (HUB-166/207). A nil sealer
	// falls back to per-process keys in the M3/M4 builders (single-replica dev).
	sealer := buildMCPSharedSealer(cfg, vaultClient, nonces, logger)

	// M3: attach discovery aggregation, result caching and authorization when
	// the configuration enables them. Each is additive — a nil component keeps
	// the M2 pass-through behavior.
	m3 := mcpM3Options(cfg, mcpRegistry, mapper, hub, cacheFactory, sealer, logger)
	// M4: attach the MRTR coordinator (HUB-201..209). The subscription manager
	// is attached after construction (it depends on the handler).
	m4 := mcpM4Options(cfg, sealer, nonces, logger)
	// M5: audit, dry-run/shadow mode and concurrency limits (HUB-405/507/408).
	m5 := mcpM5Options(cfg, auditLogger)
	opts := make([]gateway.MCPHandlerOption, 0, 9+len(m3)+len(m4)+len(m5))
	opts = append(opts,
		gateway.WithMCPHandlerLogger(logger),
		gateway.WithMCPHandlerBackendRegistry(mcpRegistry),
		gateway.WithMCPHandlerHub(hub),
		gateway.WithMCPHandlerMapper(mapper),
		gateway.WithMCPHandlerMetrics(mcpmetrics.GetMetrics()),
		gateway.WithMCPHandlerRouteMiddleware(routeMiddlewareMgr),
		gateway.WithMCPHandlerConfig(cfg.Spec.MCPRoutes, mcpUpstreamMap(cfg.Spec.MCPBackends), cfg.Spec.MCP),
		gateway.WithMCPHandlerClientInfo(hubInfo()),
		gateway.WithMCPHandlerServerInfo(hubInfo()),
	)
	opts = append(opts, m3...)
	opts = append(opts, m4...)
	opts = append(opts, m5...)

	handler, err := gateway.NewMCPHandler(opts...)
	if err != nil {
		logger.Error("failed to build MCP handler; MCP endpoint disabled",
			observability.Error(err),
		)
		return nil
	}
	// M4: attach the subscription manager now that the handler exists
	// (HUB-221..229). Additive — a construction failure leaves subscriptions
	// disabled.
	attachMCPSubscriptions(cfg, handler, mapper, logger)
	// M5: attach the per-upstream health checker (T-60). Additive — disabled
	// when no HealthCheckInterval is configured.
	attachMCPHealthChecker(cfg, handler, mcpRegistry, hub, logger)
	// M6: attach HTTP dual-era bridging (HUB-701..707/721..724). Additive —
	// disabled when every upstream is pinned modern. It wraps the modern hub
	// client with an era-aware wrapper so legacy upstreams are bridged.
	attachMCPEraBridging(cfg, handler, hub, mcpEraCache(cacheFactory, logger), sealer, logger)

	logger.Info("MCP endpoint composed into global middleware chain",
		observability.String("path", gateway.MCPPathFromConfig(cfg)),
		observability.Int("routes", len(cfg.Spec.MCPRoutes)),
		observability.Int("upstreams", len(cfg.Spec.MCPBackends)),
	)
	return handler
}

// hubInfo returns the hub's participant identity used as clientInfo (upstream)
// and serverInfo (downstream results).
func hubInfo() meta.Info {
	return meta.Info{Name: "avapigw-mcp-hub", Version: version}
}

// mcpUpstreamMap builds a name-keyed map of MCP upstream configs, applying
// defaults so consumers observe an effective configuration.
func mcpUpstreamMap(backends []config.MCPBackend) map[string]config.MCPBackend {
	m := make(map[string]config.MCPBackend, len(backends))
	for i := range backends {
		b := backends[i]
		b.SetDefaults()
		m[b.Name] = b
	}
	return m
}

// mcpMaxResponseSize resolves the configured maximum upstream response size or
// the default (HUB-405).
func mcpMaxResponseSize(cfg *config.GatewayConfig) int64 {
	if cfg != nil && cfg.Spec.MCP != nil && cfg.Spec.MCP.MaxResponseSize > 0 {
		return cfg.Spec.MCP.MaxResponseSize
	}
	return config.DefaultMCPMaxResponseSize
}

// mcpMaxSSEEventSize resolves the configured maximum SSE event size or the
// default (HUB-405).
func mcpMaxSSEEventSize(cfg *config.GatewayConfig) int64 {
	if cfg != nil && cfg.Spec.MCP != nil && cfg.Spec.MCP.MaxSSEEventSize > 0 {
		return cfg.Spec.MCP.MaxSSEEventSize
	}
	return config.DefaultMCPMaxSSEEventSize
}

// initMCPSubsystem builds the dedicated MCP upstream registry, the MCP handler
// and composes the MCP path dispatcher around next. It returns the registry
// (nil signals a fatal load failure to the caller), the handler (nil when MCP
// is disabled) and the composed chain root. Extracting this keeps
// initApplication within its statement budget.
func initMCPSubsystem(
	cfg *config.GatewayConfig,
	next http.Handler,
	routeMiddlewareMgr *gateway.RouteMiddlewareManager,
	cacheFactory *gateway.CacheFactory,
	logger observability.Logger,
	metrics *observability.Metrics,
	vaultClient vault.Client,
	auditLogger audit.Logger,
) (*backend.Registry, *gateway.MCPHandler, http.Handler) {
	mcpBackendRegistry := initMCPBackendRegistry(cfg.Spec.MCPBackends, logger, metrics, vaultClient)
	if mcpBackendRegistry == nil {
		return nil, nil, next
	}
	mcpHandler := initMCPHandler(
		cfg, mcpBackendRegistry, routeMiddlewareMgr, cacheFactory, logger, vaultClient, auditLogger,
	)
	chainRoot := composeMCPDispatcher(cfg, mcpHandler, next)
	return mcpBackendRegistry, mcpHandler, chainRoot
}

// composeMCPDispatcher wraps next (the GraphQL dispatcher / reverse proxy) with
// the MCP path dispatcher when the MCP handler is enabled. When MCP is
// disabled it returns next unchanged so behavior is unchanged (additive). When
// an OAuth resource-server block is configured, the RFC 9728 well-known
// protected-resource metadata endpoint is registered on the dispatcher
// (HUB-301).
func composeMCPDispatcher(cfg *config.GatewayConfig, handler *gateway.MCPHandler, next http.Handler) http.Handler {
	if handler == nil {
		return next
	}
	dispatcher := gateway.NewMCPPathDispatcher(
		gateway.MCPPathFromConfig(cfg), mcpDispatchHandler(handler), next,
	)
	if wk := buildMCPWellKnownHandler(cfg); wk != nil {
		dispatcher = dispatcher.WithWellKnown(mcpauthz.WellKnownPath, wk)
	}
	return dispatcher
}

// buildMCPWellKnownHandler builds the RFC 9728 protected-resource metadata
// handler from the configured OAuth resource-server block (HUB-301). Returns
// nil when no block is configured.
func buildMCPWellKnownHandler(cfg *config.GatewayConfig) http.Handler {
	rs := mcpOAuthConfig(cfg)
	if rs == nil {
		return nil
	}
	handler, err := mcpauthz.NewResourceMetadataHandler(
		rs.CanonicalURI, rs.AuthorizationServers, rs.ScopesSupported,
	)
	if err != nil {
		return nil
	}
	return handler
}

// mcpDispatchHandler converts the concrete MCP handler into the dispatcher's
// http.Handler dependency, preserving nil-ness so the dispatcher's nil check
// is not defeated by a typed-nil pointer inside a non-nil interface.
func mcpDispatchHandler(h *gateway.MCPHandler) http.Handler {
	if h == nil {
		return nil
	}
	return h
}

// registerMCPMetrics registers the MCP metrics singleton with the gateway's
// custom Prometheus registry so the avapigw_mcp_* series appear on /metrics.
func registerMCPMetrics(metrics *observability.Metrics) {
	mcpmetrics.GetMetrics().Register(metrics.Registry())
}
