package main

import (
	"context"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/mcp/security"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// mcpM5Options builds the additive M5 MCPHandler options: the tools/call audit
// logger (HUB-408), shadow/dry-run mode (HUB-507) and the concurrency limits
// (HUB-405). Each is gated by configuration so absence keeps prior behavior.
func mcpM5Options(cfg *config.GatewayConfig, auditLogger audit.Logger) []gateway.MCPHandlerOption {
	var opts []gateway.MCPHandlerOption
	if auditLogger != nil {
		opts = append(opts, gateway.WithMCPHandlerAuditLogger(auditLogger))
	}
	if cfg != nil && cfg.Spec.MCP != nil {
		mc := cfg.Spec.MCP
		if mc.DryRun {
			opts = append(opts, gateway.WithMCPHandlerDryRun(true))
		}
		opts = append(opts, gateway.WithMCPHandlerLimits(
			mc.MaxConcurrentStreamsPerPrincipal, mc.MaxConcurrentUpstreamConns,
		))
	}
	return opts
}

// sharedKeyLoadTimeout bounds the Vault call that loads the shared AEAD key at
// startup so a slow/unreachable Vault cannot stall boot indefinitely.
const sharedKeyLoadTimeout = 10 * time.Second

// buildMCPSharedSealer resolves the shared AEAD key from the configured source
// and returns a Sealer shared by the cursor codec and MRTR coordinator
// (HUB-166/207). When no shared key is configured it returns nil so the M3/M4
// builders fall back to a per-process key with a WARN (single-replica dev).
func buildMCPSharedSealer(
	cfg *config.GatewayConfig,
	vaultClient vault.Client,
	nonces envelope.NonceStore,
	logger observability.Logger,
) envelope.Sealer {
	keyCfg := mcpSharedKeyConfig(cfg)
	if keyCfg == nil {
		logger.Warn("MCP shared key not configured; using per-process keys " +
			"(cursor/MRTR tokens will NOT verify across replicas)")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedKeyLoadTimeout)
	defer cancel()
	key, err := security.LoadSharedKey(ctx, keyCfg, vaultClient)
	if err != nil {
		logger.Error("failed to load MCP shared key; falling back to per-process keys",
			observability.Error(err))
		return nil
	}
	sealer, err := envelope.NewAEADSealer(key, mcpNonceSealerOptions(cfg, nonces)...)
	if err != nil {
		logger.Error("failed to build MCP shared sealer; falling back to per-process keys",
			observability.Error(err))
		return nil
	}
	logger.Info("MCP shared AEAD key loaded",
		observability.String("source", keyCfg.Source))
	return sealer
}

// mcpNonceSealerOptions returns the AEADSealer options that wire the
// cross-replica single-use nonce store and align the consume TTL with the MRTR
// envelope TTL (HUB-207/209). A nil store leaves the bounded in-memory default.
func mcpNonceSealerOptions(cfg *config.GatewayConfig, nonces envelope.NonceStore) []envelope.SealerOption {
	opts := []envelope.SealerOption{envelope.WithConsumeTTL(mcpEnvelopeTTL(cfg))}
	if nonces != nil {
		opts = append(opts, envelope.WithNonceStore(nonces))
	}
	return opts
}

// mcpEnvelopeTTL resolves the MRTR envelope TTL used as the single-use nonce
// retention window. It mirrors the coordinator default when unconfigured.
func mcpEnvelopeTTL(cfg *config.GatewayConfig) time.Duration {
	if cfg != nil && cfg.Spec.MCP != nil && cfg.Spec.MCP.MRTRBudget > 0 {
		return time.Duration(cfg.Spec.MCP.MRTRBudget)
	}
	return envelope.DefaultNonceTTL
}

// mcpSharedKeyConfig returns the configured shared-key block, or nil.
func mcpSharedKeyConfig(cfg *config.GatewayConfig) *config.MCPSharedKey {
	if cfg == nil || cfg.Spec.MCP == nil {
		return nil
	}
	return cfg.Spec.MCP.SharedKey
}

// mcpSchemaLimits maps the schema cost bounds from configuration (HUB-404).
func mcpSchemaLimits(cfg *config.GatewayConfig) security.SchemaLimits {
	if cfg == nil || cfg.Spec.MCP == nil {
		return security.SchemaLimits{
			MaxDepth: config.DefaultMCPMaxSchemaDepth,
			MaxNodes: config.DefaultMCPMaxSubschemas,
		}
	}
	mc := cfg.Spec.MCP
	depth := mc.MaxSchemaDepth
	if depth == 0 {
		depth = config.DefaultMCPMaxSchemaDepth
	}
	nodes := mc.MaxSubschemas
	if nodes == 0 {
		nodes = config.DefaultMCPMaxSubschemas
	}
	return security.SchemaLimits{
		MaxDepth: depth,
		MaxNodes: nodes,
		Budget:   time.Duration(mc.SchemaValidationBudget),
	}
}

// mcpTrustPolicy returns the configured untrusted-upstream trust policy
// (HUB-401).
func mcpTrustPolicy(cfg *config.GatewayConfig) string {
	if cfg == nil || cfg.Spec.MCP == nil {
		return config.MCPTrustPolicyStrip
	}
	return cfg.Spec.MCP.GetEffectiveTrustPolicy()
}

// mcpDriftStore builds the tool-definition drift detector (HUB-402), honoring
// the require-re-approval flag.
func mcpDriftStore(cfg *config.GatewayConfig) *security.DriftStore {
	require := false
	if cfg != nil && cfg.Spec.MCP != nil {
		require = cfg.Spec.MCP.DriftRequireReapproval
	}
	return security.NewDriftStore(require)
}

// attachMCPHealthChecker builds and starts the per-upstream MCP health checker
// (T-60). It is additive: with no HealthCheckInterval configured it is a no-op.
// The checker is stopped by the handler's Close during drain.
func attachMCPHealthChecker(
	cfg *config.GatewayConfig,
	handler *gateway.MCPHandler,
	mcpRegistry *backend.Registry,
	hub mcpproxy.HubClient,
	logger observability.Logger,
) {
	if cfg == nil || cfg.Spec.MCP == nil {
		return
	}
	interval := time.Duration(cfg.Spec.MCP.HealthCheckInterval)
	if interval <= 0 {
		return
	}
	resolver := gateway.NewMCPUpstreamResolver(mcpRegistry, mcpUpstreamMap(cfg.Spec.MCPBackends))
	ids := make([]string, 0, len(cfg.Spec.MCPBackends))
	for i := range cfg.Spec.MCPBackends {
		ids = append(ids, cfg.Spec.MCPBackends[i].Name)
	}
	hc := gateway.NewMCPHealthChecker(hub, resolver, ids, interval, logger)
	handler.AttachHealthChecker(context.Background(), hc)
}
