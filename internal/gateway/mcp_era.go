package gateway

import (
	"encoding/json"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/mcp/era"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// ResolveBackend resolves an upstream id to its ServiceBackend and upstream MCP
// path (era.BackendResolver). It reuses the handler's registry and upstream
// config so the legacy transport shares the modern infrastructure (HUB-701).
func (h *MCPHandler) ResolveBackend(upstreamID string) (sb *backend.ServiceBackend, path string, ok bool) {
	h.mu.RLock()
	upstream, exists := h.upstreams[upstreamID]
	h.mu.RUnlock()
	if !exists {
		return nil, "", false
	}
	if h.backendRegistry == nil {
		return nil, "", false
	}
	b, found := h.backendRegistry.Get(upstream.Name)
	if !found {
		return nil, "", false
	}
	svc, isSvc := b.(*backend.ServiceBackend)
	if !isSvc {
		return nil, "", false
	}
	return svc, upstream.GetEffectivePath(), true
}

// UpstreamEraInfo returns the per-upstream era configuration used to resolve the
// era (era.UpstreamInfoProvider): the configured era pin and pinned version
// (HUB-724) and the origin used as the era-cache key (HUB-723).
func (h *MCPHandler) UpstreamEraInfo(upstreamID string) (info era.UpstreamEraInfo, ok bool) {
	h.mu.RLock()
	upstream, exists := h.upstreams[upstreamID]
	h.mu.RUnlock()
	if !exists {
		return era.UpstreamEraInfo{}, false
	}
	return era.UpstreamEraInfo{
		ID:            upstreamID,
		Origin:        era.Origin(upstreamID),
		ConfiguredEra: upstream.Era,
		PinnedVersion: upstream.PinnedVersion,
	}, true
}

// InitParams returns the legacy initialize parameters for an upstream
// (era.SessionFactory). The hub advertises its own clientInfo so the upstream
// never observes the downstream client identity (HUB-702). The negotiated
// protocol version is the upstream's pinned version when set, else the hub's
// first interop version.
func (h *MCPHandler) InitParams(upstreamID string) era.InitializeParams {
	h.mu.RLock()
	upstream := h.upstreams[upstreamID]
	h.mu.RUnlock()

	version := upstream.PinnedVersion
	if version == "" {
		version = defaultLegacyInteropVersion()
	}
	clientInfo, _ := json.Marshal(h.hubClientInfo)
	return era.InitializeParams{
		ProtocolVersion: version,
		ClientInfoJSON:  clientInfo,
	}
}

// ServerRequestHandler returns the bridge handler that converts a legacy
// server-initiated request into an input_required result (era.SessionFactory,
// HUB-704), or nil when no bridge is wired.
func (h *MCPHandler) ServerRequestHandler(_ string) era.ServerRequestFunc {
	h.mu.RLock()
	bridge := h.eraBridge
	h.mu.RUnlock()
	if bridge == nil {
		return nil
	}
	return bridge.HandleServerRequest
}

// defaultLegacyInteropVersion returns the newest interop (legacy) protocol
// version the hub bridges to, used as the default negotiated version for an
// unpinned legacy upstream.
func defaultLegacyInteropVersion() string {
	if len(protocol.InteropVersions) > 0 {
		return protocol.InteropVersions[0]
	}
	return ""
}
