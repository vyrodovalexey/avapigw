package era

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ModernProbeFunc performs the modern probe request against an upstream and
// returns the parsed response or an error. It is satisfied by a closure over
// the modern HubClient bound to a resolved backend, so the prober does not need
// the backend registry directly.
type ModernProbeFunc func(ctx context.Context, upstreamID string) (*jsonrpc.Response, error)

// HTTPProber implements the HTTP era-detection probe (HUB-721): it attempts a
// modern request first and inspects the body of a 400 before falling back. A
// recognized modern JSON-RPC error (e.g. -32022 UnsupportedProtocolVersion, or a
// -32602 with a modern shape) means the upstream IS modern and the hub retries
// with a supported version rather than falling back to legacy.
type HTTPProber struct {
	probe  ModernProbeFunc
	logger observability.Logger
}

// NewHTTPProber constructs an HTTP era prober over the modern probe function.
func NewHTTPProber(probe ModernProbeFunc, logger observability.Logger) *HTTPProber {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &HTTPProber{probe: probe, logger: logger}
}

// Probe determines the era of an HTTP upstream (HUB-721). It runs the modern
// probe; a successful (or modern-error) outcome classifies the upstream as
// modern, while a non-modern 400/transport failure falls back to legacy.
func (p *HTTPProber) Probe(ctx context.Context, upstreamID, origin string) (Era, error) {
	_ = origin // origin is the cache key; the probe targets upstreamID's backend.
	resp, err := p.probe(ctx, upstreamID)
	if err != nil {
		return p.classifyProbeError(upstreamID, err), nil
	}
	// A response (success or JSON-RPC error) came back in the modern shape:
	// the upstream speaks modern. A modern protocol-version error still means
	// modern — the hub retries with a supported version on the real call.
	if resp != nil {
		return EraModern, nil
	}
	return EraLegacy, nil
}

// classifyProbeError inspects a probe transport/HTTP error to decide the era
// (HUB-721). A 400 whose body carries a recognized modern JSON-RPC error means
// the upstream is modern; any other 400 or transport error falls back to legacy.
func (p *HTTPProber) classifyProbeError(upstreamID string, err error) Era {
	var upErr *mcpproxy.UpstreamError
	if !errors.As(err, &upErr) {
		// Transport-level failure (connection refused, timeout, ...): the hub
		// cannot conclude modern, so it falls back to the legacy handshake.
		p.logger.Debug("era: modern probe transport error; assuming legacy",
			observability.String("upstream", upstreamID), observability.Error(err))
		return EraLegacy
	}
	if upErr.StatusCode == http.StatusBadRequest && isModernErrorBody(upErr.Body) {
		return EraModern
	}
	return EraLegacy
}

// isModernErrorBody reports whether a 400 response body carries a recognized
// modern JSON-RPC error (HUB-721): a JSON-RPC error object whose code is a
// modern MCP code (e.g. -32022 UnsupportedProtocolVersion) or -32602
// InvalidParams with a modern-shaped error envelope.
func isModernErrorBody(body string) bool {
	if body == "" {
		return false
	}
	var resp jsonrpc.Response
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return false
	}
	if resp.JSONRPC != jsonrpc.Version || resp.Error == nil {
		return false
	}
	return isModernErrorCode(resp.Error.Code)
}

// isModernErrorCode reports whether a JSON-RPC error code indicates a modern
// upstream (HUB-721).
func isModernErrorCode(code int) bool {
	switch code {
	case protocol.UnsupportedProtocolVersion, protocol.InvalidParams,
		protocol.MissingRequiredClientCapability, protocol.HeaderMismatch:
		return true
	default:
		return false
	}
}
