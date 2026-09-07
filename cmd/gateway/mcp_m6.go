package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/era"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/mcp/security"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// attachMCPEraBridging wires the HTTP dual-era bridging components onto the MCP
// handler (Milestone M6, HUB-701..707/721..724). It is additive: when no legacy
// upstream is configured it is a no-op and the modern-only path is unchanged.
// It builds the era cache/determiner, the legacy session pool, the
// server-initiated-request bridge and the held-request store, then installs an
// era-aware wrapper around the handler's modern hub client so brokered calls
// route by era.
func attachMCPEraBridging(
	cfg *config.GatewayConfig,
	handler *gateway.MCPHandler,
	innerHub mcpproxy.HubClient,
	mcpCache cache.Cache,
	sealer envelope.Sealer,
	logger observability.Logger,
) {
	if handler == nil || !mcpEraEnabled(cfg) {
		return
	}
	metrics := mcpmetrics.GetMetrics()
	mc := cfg.Spec.MCP

	determiner := era.NewDeterminer(
		era.NewEraCache(era.WithEraCacheTTL(time.Duration(mc.GetEffectiveEraCacheTTL()))),
		metrics,
	)

	sealer = ensureEraSealer(sealer, logger)
	held := era.NewHeldRequestStore(mcpCache)
	bridge, err := era.NewServerInitiatedBridge(sealer, held,
		era.WithBridgeLogger(logger),
		era.WithBridgeMetrics(metrics),
		era.WithBridgeDeadline(time.Duration(mc.GetEffectiveHeldRequestDeadline())),
	)
	if err != nil {
		logger.Error("failed to build MCP server-initiated bridge; era bridging disabled",
			observability.Error(err))
		return
	}

	pool, err := era.NewSessionPool(
		era.NewHTTPLegacyTransport(handler, mcpMaxResponseSize(cfg)),
		handler, // MCPHandler satisfies era.SessionFactory
		era.WithPoolLogger(logger),
		era.WithPoolMetrics(metrics),
	)
	if err != nil {
		logger.Error("failed to build MCP legacy session pool; era bridging disabled",
			observability.Error(err))
		return
	}

	prober := era.NewHTTPProber(newModernProbeFunc(handler, innerHub), logger)
	wrapper, err := era.NewEraAwareHubClient(
		innerHub, determiner, pool, prober, handler,
		era.WithClientLogger(logger),
		era.WithClientBridge(bridge),
	)
	if err != nil {
		logger.Error("failed to build era-aware hub client; era bridging disabled",
			observability.Error(err))
		return
	}

	handler.SetHub(wrapper)
	gateway.WithMCPHandlerEra(pool, bridge)(handler)
	logger.Info("MCP HTTP dual-era bridging enabled",
		observability.Int("upstreams", len(cfg.Spec.MCPBackends)))
}

// mcpEraCache returns the shared cache backend used for held-request storage
// (HUB-705), reusing the MCP result-cache instance. A nil factory or a creation
// failure yields nil so the held-request store falls back to in-memory.
func mcpEraCache(cacheFactory *gateway.CacheFactory, logger observability.Logger) cache.Cache {
	if cacheFactory == nil {
		return nil
	}
	backendCache, err := cacheFactory.GetOrCreate(mcpCacheRouteName, config.DefaultCacheConfig())
	if err != nil {
		logger.Warn("failed to obtain MCP era cache backend; using in-memory held store",
			observability.Error(err))
		return nil
	}
	return backendCache
}

// mcpEraEnabled reports whether any configured MCP upstream may be legacy, so
// era bridging is worth wiring. An upstream explicitly pinned to "modern" never
// needs the legacy path; anything else (auto-detect, "legacy", or a pinned
// version) does.
func mcpEraEnabled(cfg *config.GatewayConfig) bool {
	if cfg == nil || cfg.Spec.MCP == nil {
		return false
	}
	for i := range cfg.Spec.MCPBackends {
		b := cfg.Spec.MCPBackends[i]
		if b.Era != config.MCPEraModern {
			return true
		}
	}
	return false
}

// ensureEraSealer returns sealer, or a freshly generated per-process AEAD sealer
// when nil so the held-request envelope always has a key (single-replica dev).
// A dummy key is generated at init time rather than hard-coded.
func ensureEraSealer(sealer envelope.Sealer, logger observability.Logger) envelope.Sealer {
	if sealer != nil {
		return sealer
	}
	key, err := security.GenerateKey()
	if err != nil {
		logger.Error("failed to generate per-process era sealer key", observability.Error(err))
		return nil
	}
	s, err := envelope.NewAEADSealer(key)
	if err != nil {
		logger.Error("failed to build per-process era sealer", observability.Error(err))
		return nil
	}
	logger.Warn("MCP era bridging using a per-process key; held-request tokens " +
		"will NOT verify across replicas")
	return s
}

// newModernProbeFunc returns the modern era-detection probe (HUB-721): it issues
// a minimal modern initialize-shaped request through the inner hub client and
// returns the parsed response (or an *UpstreamError on a 4xx) so the prober can
// classify the era.
func newModernProbeFunc(
	resolver era.BackendResolver, innerHub mcpproxy.HubClient,
) era.ModernProbeFunc {
	return func(ctx context.Context, upstreamID string) (*jsonrpc.Response, error) {
		sb, path, ok := resolver.ResolveBackend(upstreamID)
		if !ok {
			return nil, era.ErrNoPendingCall // upstream unknown; treated as legacy fallback
		}
		req := buildModernProbeRequest()
		return innerHub.Call(ctx, sb, path, req, nil)
	}
}

// buildModernProbeRequest builds a minimal modern-shaped probe request carrying
// a supported protocol version and empty client capabilities in `_meta`
// (HUB-721). A modern upstream answers or returns a modern JSON-RPC error; a
// legacy upstream rejects it non-modernly.
func buildModernProbeRequest() *jsonrpc.Request {
	metaObj := map[string]any{
		protocol.MetaProtocolVersion:    protocol.LatestVersion,
		protocol.MetaClientCapabilities: map[string]any{},
	}
	params, _ := json.Marshal(map[string]any{"_meta": metaObj})
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      json.RawMessage(`"era-probe"`),
		Method:  protocol.MethodToolsList,
		Params:  params,
	}
}
