package main

import (
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpmrtr "github.com/vyrodovalexey/avapigw/internal/mcp/mrtr"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	mcpsub "github.com/vyrodovalexey/avapigw/internal/mcp/subscription"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mcpM4Options builds the additive M4 MCPHandler option for the MRTR
// coordinator (HUB-201..209). The subscription manager depends on the handler
// itself, so it is attached after construction via attachMCPSubscriptions. The
// coordinator is omitted when it cannot be constructed, keeping M3 behavior.
func mcpM4Options(
	cfg *config.GatewayConfig,
	sealer envelope.Sealer,
	nonces envelope.NonceStore,
	logger observability.Logger,
) []gateway.MCPHandlerOption {
	var opts []gateway.MCPHandlerOption
	if coord := buildMCPCoordinator(cfg, sealer, nonces, logger); coord != nil {
		opts = append(opts, gateway.WithMCPHandlerMRTRCoordinator(coord))
	}
	return opts
}

// attachMCPSubscriptions constructs the subscription manager over the handler's
// own upstream streamer and cache-invalidation hook and attaches it (HUB-221..
// 229). It is additive: on failure subscriptions/listen returns method-not-found.
func attachMCPSubscriptions(
	cfg *config.GatewayConfig,
	handler *gateway.MCPHandler,
	mapper namespace.Mapper,
	logger observability.Logger,
) {
	if mgr := buildMCPSubscriptionManager(cfg, handler, mapper, logger); mgr != nil {
		handler.AttachSubscriptionManager(mgr)
	}
}

// buildMCPCoordinator constructs the MRTR coordinator over the shared AEAD
// sealer when configured so MRTR retries verify on any replica (HUB-207).
// Without a shared sealer a per-process key is generated (single-replica dev).
// Returns nil on any failure so MRTR degrades to pass-through.
func buildMCPCoordinator(
	cfg *config.GatewayConfig, sealer envelope.Sealer, nonces envelope.NonceStore,
	logger observability.Logger,
) *mcpmrtr.Coordinator {
	if sealer == nil {
		var err error
		sealer, err = newProcessSealer(mcpNonceSealerOptions(cfg, nonces)...)
		if err != nil {
			logger.Error("failed to build MRTR sealer; MRTR disabled", observability.Error(err))
			return nil
		}
	}
	coord, err := mcpmrtr.NewCoordinator(sealer, mcpMRTRConfig(cfg),
		mcpmrtr.WithLogger(logger),
		mcpmrtr.WithMetrics(mcpmetrics.GetMetrics()),
	)
	if err != nil {
		logger.Error("failed to build MRTR coordinator; MRTR disabled", observability.Error(err))
		return nil
	}
	return coord
}

// mcpMRTRConfig maps the MRTR round/budget limits from configuration (HUB-208).
func mcpMRTRConfig(cfg *config.GatewayConfig) mcpmrtr.Config {
	out := mcpmrtr.Config{}
	if cfg.Spec.MCP != nil {
		out.MaxRounds = cfg.Spec.MCP.MRTRMaxRounds
		out.Budget = time.Duration(cfg.Spec.MCP.MRTRBudget)
	}
	return out
}

// buildMCPSubscriptionManager constructs the subscription manager over the
// handler's own upstream streamer (which resolves and streams via the hub
// client) and cache-invalidation hook (HUB-185/221..229). Returns nil on any
// failure so subscriptions degrade to method-not-found.
func buildMCPSubscriptionManager(
	cfg *config.GatewayConfig,
	handler *gateway.MCPHandler,
	mapper namespace.Mapper,
	logger observability.Logger,
) *mcpsub.Manager {
	streamer := handler.NewUpstreamStreamer()
	mgr, err := mcpsub.NewManager(streamer, mapper, mcpSubscriptionConfig(cfg),
		mcpsub.WithLogger(logger),
		mcpsub.WithMetrics(mcpmetrics.GetMetrics()),
		mcpsub.WithInvalidator(handler),
	)
	if err != nil {
		logger.Error("failed to build MCP subscription manager; subscriptions disabled",
			observability.Error(err))
		return nil
	}
	return mgr
}

// mcpSubscriptionConfig maps the keep-alive and debounce windows from
// configuration (HUB-225/229).
func mcpSubscriptionConfig(cfg *config.GatewayConfig) mcpsub.Config {
	out := mcpsub.Config{}
	if cfg.Spec.MCP != nil {
		out.KeepAlive = time.Duration(cfg.Spec.MCP.SubscriptionKeepAlive)
	}
	return out
}
