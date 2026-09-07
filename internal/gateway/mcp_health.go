package gateway

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mcpHealthProbeTimeout bounds a single upstream health probe.
const mcpHealthProbeTimeout = 5 * time.Second

// mcpHealthResolver resolves an upstream id to its ServiceBackend and config
// for probing. It is satisfied by MCPUpstreamResolver.
type mcpHealthResolver interface {
	Resolve(upstreamID string) (*backend.ServiceBackend, config.MCPBackend, bool)
}

// MCPHealthChecker periodically probes each configured MCP upstream via
// server/discover and publishes a per-upstream health gauge plus a degraded
// flag consumed by discovery (T-60 / HUB-167). It is additive: when disabled
// (interval <= 0) it never starts.
type MCPHealthChecker struct {
	hub      mcpproxy.HubClient
	resolver mcpHealthResolver
	metrics  *mcpmetrics.Metrics
	logger   observability.Logger
	interval time.Duration

	mu        sync.RWMutex
	upstreams []string
	healthy   map[string]bool

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewMCPHealthChecker constructs a health checker over the hub client and
// upstream resolver. A non-positive interval disables periodic probing.
func NewMCPHealthChecker(
	hub mcpproxy.HubClient,
	resolver mcpHealthResolver,
	upstreams []string,
	interval time.Duration,
	logger observability.Logger,
) *MCPHealthChecker {
	return &MCPHealthChecker{
		hub:       hub,
		resolver:  resolver,
		metrics:   mcpmetrics.GetMetrics(),
		logger:    logger,
		interval:  interval,
		upstreams: append([]string(nil), upstreams...),
		healthy:   make(map[string]bool),
		stopCh:    make(chan struct{}),
	}
}

// Start launches the periodic probe loop until ctx is canceled or Stop is
// called. It is a no-op when probing is disabled. The caller owns the returned
// goroutine's lifetime via ctx/Stop.
func (c *MCPHealthChecker) Start(ctx context.Context) {
	if c == nil || c.interval <= 0 {
		return
	}
	go c.loop(ctx)
}

// Stop halts the probe loop. Safe to call multiple times.
func (c *MCPHealthChecker) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// IsHealthy reports the last-probed health of an upstream. An unprobed upstream
// is optimistically reported healthy so discovery is not degraded before the
// first probe completes.
func (c *MCPHealthChecker) IsHealthy(upstreamID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.healthy[upstreamID]
	return !ok || h
}

// loop runs the probe cycle on the configured interval.
func (c *MCPHealthChecker) loop(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.probeAll(ctx) // probe once immediately so the gauge is populated
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.probeAll(ctx)
		}
	}
}

// probeAll probes every configured upstream, updating the gauge and cache.
func (c *MCPHealthChecker) probeAll(ctx context.Context) {
	c.mu.RLock()
	ups := append([]string(nil), c.upstreams...)
	c.mu.RUnlock()
	for _, id := range ups {
		c.probeOne(ctx, id)
	}
}

// probeOne probes a single upstream via server/discover, updating its health.
func (c *MCPHealthChecker) probeOne(ctx context.Context, id string) {
	healthy := c.doProbe(ctx, id)
	c.mu.Lock()
	c.healthy[id] = healthy
	c.mu.Unlock()
	c.metrics.SetUpstreamHealthy(id, healthy)
	if !healthy {
		c.logger.Warn("mcp health: upstream probe failed",
			observability.String("upstream", id))
	}
}

// doProbe performs the actual server/discover round-trip and reports whether
// the upstream answered successfully within the probe timeout.
func (c *MCPHealthChecker) doProbe(ctx context.Context, id string) bool {
	sb, cfg, ok := c.resolver.Resolve(id)
	if !ok {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, mcpHealthProbeTimeout)
	defer cancel()

	req := &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      json.RawMessage(`"health"`),
		Method:  protocol.MethodServerDiscover,
	}
	hdrs := headers.DeriveUpstreamHeaders(protocol.MethodServerDiscover, "", nil, nil)
	resp, err := c.hub.Call(probeCtx, sb, cfg.GetEffectivePath(), req, hdrs)
	if err != nil {
		return false
	}
	return resp != nil && resp.Error == nil
}
