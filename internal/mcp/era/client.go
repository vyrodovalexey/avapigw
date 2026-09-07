package era

import (
	"context"
	"errors"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// UpstreamEraInfo carries the per-upstream era configuration needed to resolve
// the era: the configured era pin and pinned protocol version (HUB-724) and the
// origin used as the era-cache key (HUB-723).
type UpstreamEraInfo struct {
	// ID is the upstream id (used to key the session pool and metrics).
	ID string
	// Origin is the stable origin used as the era-cache key (HUB-723). For an
	// HTTP upstream the upstream id is a sufficient stable origin.
	Origin string
	// ConfiguredEra is the MCPBackend.Era pin ("modern"/"legacy"/"").
	ConfiguredEra string
	// PinnedVersion is the MCPBackend.PinnedVersion (HUB-724).
	PinnedVersion string
}

// UpstreamInfoProvider resolves an upstream id to its era configuration. It is
// satisfied by the gateway MCP handler.
type UpstreamInfoProvider interface {
	// UpstreamEraInfo returns the era configuration for upstreamID, or
	// ok=false when the upstream is unknown.
	UpstreamEraInfo(upstreamID string) (info UpstreamEraInfo, ok bool)
}

// EraAwareHubClient decorates an existing modern HubClient with legacy-era
// bridging (HUB-701..707, HUB-721..724). For a modern upstream it delegates
// verbatim to the wrapped client so modern-only deployments are unchanged. For
// a legacy upstream it routes through the pooled legacy session and normalizes
// the result into the modern shape (HUB-706).
type EraAwareHubClient struct {
	inner      mcpproxy.HubClient
	determiner *Determiner
	pool       *SessionPool
	prober     Prober
	info       UpstreamInfoProvider
	bridge     *ServerInitiatedBridge
	logger     observability.Logger
}

// ClientOption configures an EraAwareHubClient.
type ClientOption func(*EraAwareHubClient)

// WithClientLogger sets the wrapper logger.
func WithClientLogger(l observability.Logger) ClientOption {
	return func(c *EraAwareHubClient) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithClientBridge wires the server-initiated-request bridge so a legacy call
// that triggers a server-initiated request is resolved as an input_required
// result (HUB-704). A nil bridge disables that correlation (the legacy call
// then only observes a direct upstream response).
func WithClientBridge(b *ServerInitiatedBridge) ClientOption {
	return func(c *EraAwareHubClient) {
		c.bridge = b
	}
}

// NewEraAwareHubClient wraps inner with era-aware legacy handling. inner is the
// existing modern HubClient; determiner resolves upstream eras; pool owns legacy
// sessions; prober performs live era probes; info supplies per-upstream era
// configuration. A nil inner is rejected.
func NewEraAwareHubClient(
	inner mcpproxy.HubClient,
	determiner *Determiner,
	pool *SessionPool,
	prober Prober,
	info UpstreamInfoProvider,
	opts ...ClientOption,
) (*EraAwareHubClient, error) {
	if inner == nil {
		return nil, errors.New("era: nil inner hub client")
	}
	if determiner == nil {
		return nil, errors.New("era: nil determiner")
	}
	if pool == nil {
		return nil, errors.New("era: nil session pool")
	}
	if info == nil {
		return nil, errors.New("era: nil upstream info provider")
	}
	c := &EraAwareHubClient{
		inner:      inner,
		determiner: determiner,
		pool:       pool,
		prober:     prober,
		info:       info,
		logger:     observability.NopLogger(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Call routes a single JSON-RPC request by era. A modern (or era-undeterminable)
// upstream delegates to the wrapped client; a legacy upstream is served via the
// pooled session and its result normalized to the modern shape (HUB-706). The
// upstream id is derived from the backend name so the wrapper can resolve era
// configuration without changing the HubClient contract.
func (c *EraAwareHubClient) Call(
	ctx context.Context,
	up *backend.ServiceBackend,
	upstreamPath string,
	req *jsonrpc.Request,
	upstreamHeaders http.Header,
) (*jsonrpc.Response, error) {
	if up == nil {
		return nil, mcpproxy.ErrNilUpstream
	}
	era := c.resolveEra(ctx, up.Name())
	if era != EraLegacy {
		return c.inner.Call(ctx, up, upstreamPath, req, upstreamHeaders)
	}
	return c.callLegacy(ctx, up.Name(), req)
}

// Stream routes a streaming request by era. A modern upstream delegates to the
// wrapped client's SSE relay; a legacy upstream serves the request via the
// pooled session and relays the single normalized response as one event
// (subscription fan-out for legacy upstreams is handled by
// LegacySubscriptionAdapter, not this path).
func (c *EraAwareHubClient) Stream(
	ctx context.Context,
	up *backend.ServiceBackend,
	upstreamPath string,
	req *jsonrpc.Request,
	upstreamHeaders http.Header,
	handler mcpproxy.SSEEventHandler,
) error {
	if up == nil {
		return mcpproxy.ErrNilUpstream
	}
	era := c.resolveEra(ctx, up.Name())
	if era != EraLegacy {
		return c.inner.Stream(ctx, up, upstreamPath, req, upstreamHeaders, handler)
	}
	resp, err := c.callLegacy(ctx, up.Name(), req)
	if err != nil {
		return err
	}
	body, err := jsonrpc.Encode(resp)
	if err != nil {
		return err
	}
	return handler(mcpproxy.SSEEvent{Event: eventNameMessage, Data: body})
}

// resolveEra determines the era for an upstream, defaulting to modern on any
// resolution failure so an undeterminable upstream keeps the modern path
// (additive). A cache-assumption failure is handled at the call site by
// invalidating and re-probing.
func (c *EraAwareHubClient) resolveEra(ctx context.Context, upstreamID string) Era {
	info, ok := c.info.UpstreamEraInfo(upstreamID)
	if !ok {
		return EraModern
	}
	era, err := c.determiner.Determine(
		ctx, info.ID, info.Origin, info.ConfiguredEra, info.PinnedVersion, c.prober,
	)
	if err != nil {
		c.logger.Debug("era: determination failed; defaulting to modern",
			observability.String("upstream", upstreamID), observability.Error(err))
		return EraModern
	}
	return era
}

// callLegacy serves a JSON-RPC request through the pooled legacy session and
// normalizes the result into the modern shape (HUB-706). Session loss is
// recovered transparently by the session's own retry path (HUB-702). When a
// bridge is wired the call is correlated so a server-initiated request the
// upstream issues while the call is open is delivered as an input_required
// result (HUB-704).
func (c *EraAwareHubClient) callLegacy(
	ctx context.Context, upstreamID string, req *jsonrpc.Request,
) (*jsonrpc.Response, error) {
	sess, err := c.pool.Acquire(ctx, upstreamID)
	if err != nil {
		return nil, err
	}
	if c.bridge == nil {
		resp, postErr := sess.PostRequest(ctx, req)
		if postErr != nil {
			return nil, postErr
		}
		return TranslateLegacyResult(resp)
	}
	return c.callLegacyCorrelated(ctx, upstreamID, sess, req)
}

// callLegacyCorrelated registers an in-flight call with the bridge, posts the
// request, and returns whichever outcome resolves first: a direct upstream
// response (translated to the modern shape, HUB-706) or an input_required
// result synthesized from a server-initiated request (HUB-704). The pending
// registration is always released.
func (c *EraAwareHubClient) callLegacyCorrelated(
	ctx context.Context, upstreamID string, sess *LegacySession, req *jsonrpc.Request,
) (*jsonrpc.Response, error) {
	pc, release := c.bridge.Begin(upstreamID)
	defer release()

	resp, err := sess.PostRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp != nil {
		// The upstream answered directly; resolve the pending call so a racing
		// server-initiated frame does not strand it, then return the modern
		// result.
		c.bridge.ResolveResponse(upstreamID, resp)
	}
	outcome, err := c.bridge.Await(ctx, pc)
	if err != nil {
		return nil, err
	}
	return outcomeToResponse(req, outcome)
}

// outcomeToResponse converts a bridge outcome into a JSON-RPC response: a
// terminal response is normalized to the modern shape; an input_required
// outcome is wrapped as the result of req's id (HUB-704).
func outcomeToResponse(req *jsonrpc.Request, o PendingOutcome) (*jsonrpc.Response, error) {
	if o.Response != nil {
		return TranslateLegacyResult(o.Response)
	}
	return &jsonrpc.Response{
		JSONRPC: jsonrpc.Version,
		ID:      req.ID,
		Result:  o.InputRequired,
	}, nil
}

// Origin returns the era-cache origin for an upstream (the upstream id is a
// sufficient stable origin for HTTP upstreams, HUB-723).
func Origin(upstreamID string) string { return upstreamID }
