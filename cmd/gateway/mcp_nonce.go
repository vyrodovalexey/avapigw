package main

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/redisclient"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// nonceRedisConnectTimeout bounds the initial Redis connectivity check for the
// MRTR nonce store so a slow/unreachable Sentinel cannot stall boot. The
// underlying client already applies exponential backoff with jitter across
// attempts (redisclient.New → pingWithRetry).
const nonceRedisConnectTimeout = 15 * time.Second

// buildMCPNonceStore builds the cross-replica single-use MRTR nonce store
// (HUB-207/209/501). It connects to the configured Redis (standalone or
// Sentinel), reusing the shared redisclient (exponential-backoff connect,
// Vault-resolved passwords, TLS). It returns nil when no Redis is configured or
// the connection cannot be established, so the sealer falls back to the bounded
// in-memory store (single-replica correctness only).
func buildMCPNonceStore(
	ctx context.Context,
	cfg *config.GatewayConfig,
	vaultClient vault.Client,
	logger observability.Logger,
) envelope.NonceStore {
	rc := mcpNonceRedisConfig(cfg)
	if rc == nil || rc.IsEmpty() {
		return nil
	}

	connectCtx, cancel := context.WithTimeout(ctx, nonceRedisConnectTimeout)
	defer cancel()

	opts := []redisclient.Option{redisclient.WithPingMode(redisclient.PingBestEffort)}
	if vaultClient != nil {
		opts = append(opts, redisclient.WithVaultClient(vaultClient))
	}
	client, err := redisclient.New(connectCtx, redisclient.FromRateLimitRedisConfig(rc), logger, opts...)
	if err != nil {
		logger.Error("failed to connect MCP nonce-store Redis; single-use nonces will "+
			"NOT be enforced across replicas (in-memory fallback)", observability.Error(err))
		return nil
	}

	store, err := envelope.NewRedisNonceStore(newRedisSetNX(client))
	if err != nil {
		logger.Error("failed to build MCP Redis nonce store; using in-memory fallback",
			observability.Error(err))
		return nil
	}
	logger.Info("MCP MRTR single-use nonces enforced via Redis (cross-replica)")
	return store
}

// mcpNonceRedisConfig returns the configured nonce-store Redis block, or nil.
func mcpNonceRedisConfig(cfg *config.GatewayConfig) *config.RateLimitRedisConfig {
	if cfg == nil || cfg.Spec.MCP == nil {
		return nil
	}
	return cfg.Spec.MCP.NonceStoreRedis
}

// redisSetNX adapts a go-redis UniversalClient to envelope.NonceSetNXer using
// an atomic SET NX EX, so a replayed MRTR retry is rejected by any replica
// sharing the cluster (HUB-207/209/501).
type redisSetNX struct {
	client redis.UniversalClient
}

// newRedisSetNX wraps the client as an envelope.NonceSetNXer.
func newRedisSetNX(client redis.UniversalClient) *redisSetNX {
	return &redisSetNX{client: client}
}

// SetNX performs SET key value NX EX ttl, returning true when the key was
// newly created (first, valid Consume) and false when it already existed (a
// replayed retry).
func (r *redisSetNX) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, ttl).Result()
}
