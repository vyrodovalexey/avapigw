package era

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpmrtr "github.com/vyrodovalexey/avapigw/internal/mcp/mrtr"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ErrNoPendingCall indicates a server-initiated request arrived with no
// downstream call awaiting it. The upstream request is dropped (the hub cannot
// synthesize a client it does not have).
var ErrNoPendingCall = errors.New("era: no pending downstream call for server-initiated request")

// PendingOutcome is the resolution of a pending legacy downstream call: either
// a terminal JSON-RPC response from the upstream, or an input_required result
// synthesized from a server-initiated request (HUB-704).
type PendingOutcome struct {
	// Response is a terminal upstream JSON-RPC response (nil when InputRequired).
	Response *jsonrpc.Response
	// InputRequired carries the enveloped input_required result body when the
	// upstream instead issued a server-initiated request.
	InputRequired json.RawMessage
}

// PendingCall is one in-flight legacy downstream call awaiting an SSE outcome:
// either a terminal upstream response or a server-initiated request converted to
// an input_required result (HUB-704).
type PendingCall struct {
	outcome chan PendingOutcome
	once    sync.Once
}

// resolve delivers an outcome exactly once so a late duplicate SSE frame cannot
// double-resolve a call.
func (p *PendingCall) resolve(o PendingOutcome) {
	p.once.Do(func() { p.outcome <- o })
}

// ServerInitiatedBridge converts legacy server-initiated requests arriving on
// an upstream SSE stream into input_required results toward the downstream
// client (HUB-704), and correlates them with the in-flight downstream call. It
// holds the open upstream request in a HeldRequestStore keyed by the sealed
// envelope id (HUB-705), enforcing single-use on the retry (HUB-209).
type ServerInitiatedBridge struct {
	sealer   envelope.Sealer
	held     HeldRequestStore
	metrics  *mcpmetrics.Metrics
	logger   observability.Logger
	deadline time.Duration
	now      func() time.Time

	mu      sync.Mutex
	pending map[string]*PendingCall
}

// BridgeOption configures a ServerInitiatedBridge.
type BridgeOption func(*ServerInitiatedBridge)

// WithBridgeLogger sets the bridge logger.
func WithBridgeLogger(l observability.Logger) BridgeOption {
	return func(b *ServerInitiatedBridge) {
		if l != nil {
			b.logger = l
		}
	}
}

// WithBridgeMetrics sets the bridge metrics recorder.
func WithBridgeMetrics(m *mcpmetrics.Metrics) BridgeOption {
	return func(b *ServerInitiatedBridge) {
		if m != nil {
			b.metrics = m
		}
	}
}

// WithBridgeDeadline sets the held-request deadline (HUB-705). A non-positive
// value falls back to DefaultHeldRequestDeadline.
func WithBridgeDeadline(d time.Duration) BridgeOption {
	return func(b *ServerInitiatedBridge) {
		if d > 0 {
			b.deadline = d
		}
	}
}

// WithBridgeClock overrides the time source (test seam).
func WithBridgeClock(now func() time.Time) BridgeOption {
	return func(b *ServerInitiatedBridge) {
		if now != nil {
			b.now = now
		}
	}
}

// NewServerInitiatedBridge constructs the bridge over a sealer and held-request
// store. A nil held store falls back to an in-memory store.
func NewServerInitiatedBridge(
	sealer envelope.Sealer, held HeldRequestStore, opts ...BridgeOption,
) (*ServerInitiatedBridge, error) {
	if sealer == nil {
		return nil, errors.New("era: nil envelope sealer")
	}
	if held == nil {
		held = NewMemoryHeldStore()
	}
	b := &ServerInitiatedBridge{
		sealer:   sealer,
		held:     held,
		metrics:  mcpmetrics.GetMetrics(),
		logger:   observability.NopLogger(),
		deadline: DefaultHeldRequestDeadline,
		now:      time.Now,
		pending:  make(map[string]*PendingCall),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
}

// pendingKey correlates a server-initiated request with an in-flight downstream
// call. Legacy upstreams issue at most one outstanding server-initiated request
// per session at a time, so the upstream id is a sufficient key for the current
// call; it is scoped per upstream to avoid cross-upstream collisions.
func pendingKey(upstreamID string) string {
	return upstreamID
}

// Begin registers an in-flight downstream call for an upstream so a subsequent
// server-initiated SSE request can be correlated to it (HUB-704). It returns
// the pending call and a release func the caller MUST defer to avoid leaking
// the registration.
func (b *ServerInitiatedBridge) Begin(upstreamID string) (call *PendingCall, release func()) {
	key := pendingKey(upstreamID)
	pc := &PendingCall{outcome: make(chan PendingOutcome, 1)}
	b.mu.Lock()
	b.pending[key] = pc
	b.mu.Unlock()
	return pc, func() {
		b.mu.Lock()
		if b.pending[key] == pc {
			delete(b.pending, key)
		}
		b.mu.Unlock()
	}
}

// Await blocks until the pending call is resolved by a terminal response or an
// input_required conversion, or ctx is canceled.
func (b *ServerInitiatedBridge) Await(ctx context.Context, pc *PendingCall) (PendingOutcome, error) {
	select {
	case <-ctx.Done():
		return PendingOutcome{}, fmt.Errorf("era: await server-initiated outcome: %w", ctx.Err())
	case o := <-pc.outcome:
		return o, nil
	}
}

// ResolveResponse delivers a terminal upstream response to the pending call for
// an upstream (used when the upstream answers the original request directly
// over SSE rather than issuing a server-initiated request).
func (b *ServerInitiatedBridge) ResolveResponse(upstreamID string, resp *jsonrpc.Response) {
	if pc := b.take(upstreamID); pc != nil {
		pc.resolve(PendingOutcome{Response: resp})
	}
}

// take removes and returns the pending call for an upstream, or nil.
func (b *ServerInitiatedBridge) take(upstreamID string) *PendingCall {
	key := pendingKey(upstreamID)
	b.mu.Lock()
	pc := b.pending[key]
	delete(b.pending, key)
	b.mu.Unlock()
	return pc
}

// HandleServerRequest is the ServerRequestFunc installed on the pooled legacy
// session (HUB-704). It seals an MRTR envelope binding the held upstream
// request, stores the held state keyed by the envelope id (HUB-705), builds the
// input_required result and resolves the correlated downstream call. When no
// downstream call is pending the upstream request is dropped.
func (b *ServerInitiatedBridge) HandleServerRequest(
	ctx context.Context, upstreamID string, req *jsonrpc.Request,
) error {
	pc := b.take(upstreamID)
	if pc == nil {
		return ErrNoPendingCall
	}

	held := &HeldRequest{
		UpstreamID:        upstreamID,
		UpstreamRequestID: req.ID,
		Method:            req.Method,
		CreatedAt:         b.now(),
	}
	token, err := b.sealHeld(ctx, upstreamID, held)
	if err != nil {
		return err
	}

	result, err := buildLegacyInputRequired(token, req)
	if err != nil {
		return err
	}
	b.metrics.IncHeldRequests(upstreamID)
	pc.resolve(PendingOutcome{InputRequired: result})
	return nil
}

// sealHeld seals an MRTR envelope carrying the held request id and stores the
// held state under that id (HUB-705). The envelope Nonce is the single-use id.
func (b *ServerInitiatedBridge) sealHeld(
	ctx context.Context, upstreamID string, held *HeldRequest,
) (string, error) {
	env := &envelope.Envelope{
		UpstreamID:    upstreamID,
		Primitive:     held.Method,
		IssuedAt:      b.now(),
		TTL:           b.deadline,
		OperationID:   newHeldID(),
		RetriedMethod: held.Method,
	}
	token, err := b.sealer.Seal(ctx, env)
	if err != nil {
		return "", fmt.Errorf("era: seal held envelope: %w", err)
	}
	if err := b.held.Put(ctx, env.OperationID, held, b.deadline); err != nil {
		return "", fmt.Errorf("era: store held request: %w", err)
	}
	return token, nil
}

// ResumeHeld consumes the held request for the token presented on a downstream
// retry and returns it (single-use, HUB-209). An expired/absent/consumed held
// request yields a deterministic error (HUB-705). The caller delivers the
// client's inputResponses as the JSON-RPC response to held.UpstreamRequestID.
func (b *ServerInitiatedBridge) ResumeHeld(ctx context.Context, token string) (*HeldRequest, error) {
	env, err := b.sealer.Open(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHeldNotFound, err)
	}
	held, err := b.held.Consume(ctx, env.OperationID)
	if err != nil {
		if errors.Is(err, ErrHeldNotFound) {
			b.metrics.RecordHeldRequestExpired(env.UpstreamID)
		}
		return nil, err
	}
	// Enforce single-use of the envelope nonce as well, closing any window a
	// duplicate token replay could exploit (HUB-209).
	if err := b.sealer.Consume(ctx, env.Nonce); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHeldConsumed, err)
	}
	b.metrics.DecHeldRequests(env.UpstreamID)
	return held, nil
}

// DeliverInputResponse builds the JSON-RPC response that answers the original
// upstream server-initiated request with the client's inputResponses (HUB-704).
func DeliverInputResponse(held *HeldRequest, inputResponses json.RawMessage) (*jsonrpc.Request, error) {
	// The client's inputResponses become the result of the upstream's
	// server-initiated request. It is delivered as a JSON-RPC response on the
	// legacy session (POST) addressed to the held request id.
	resp := &jsonrpc.Response{
		JSONRPC: jsonrpc.Version,
		ID:      rawOrNull(held.UpstreamRequestID),
		Result:  inputResponses,
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("era: encode input response: %w", err)
	}
	// Legacy upstreams accept the client's answer as a POSTed JSON-RPC message;
	// it is wrapped as a raw message the transport writes to the session.
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		Method:  "",
		Params:  raw,
	}, nil
}

// buildLegacyInputRequired assembles the downstream input_required result body
// for a legacy server-initiated request (HUB-704). The upstream's request
// params are preserved verbatim as the single input request keyed by its type,
// mirroring the modern inputRequests shape (HUB-205).
func buildLegacyInputRequired(token string, req *jsonrpc.Request) (json.RawMessage, error) {
	inputType := inputTypeForMethod(req.Method)
	entry := map[string]json.RawMessage{
		"type": mustJSONString(inputType),
	}
	if len(req.Params) > 0 {
		entry["params"] = req.Params
	}
	entryRaw, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("era: encode input request: %w", err)
	}
	body := map[string]any{
		mcpmrtr.FieldResultType:   protocol.ResultInputRequired,
		mcpmrtr.FieldRequestState: token,
		mcpmrtr.FieldInputRequests: map[string]json.RawMessage{
			inputType: entryRaw,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("era: encode legacy input_required: %w", err)
	}
	return raw, nil
}

// inputTypeForMethod maps a legacy server-initiated method to the modern input
// request type the downstream client answers (HUB-704/206).
func inputTypeForMethod(method string) string {
	switch method {
	case LegacyMethodSamplingCreate:
		return mcpmrtr.CapSampling
	case LegacyMethodElicitationCreate:
		return mcpmrtr.CapElicitation
	case LegacyMethodRootsList:
		return mcpmrtr.CapRoots
	default:
		return "unknown"
	}
}

// rawOrNull returns raw or a JSON null when raw is empty.
func rawOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// newHeldID mints a random 128-bit id used to key held request state (HUB-705).
// A random id is collision-free across concurrent held requests and replicas.
func newHeldID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failure is fatal-grade; fall back to a time token so the
		// held request still gets a (locally unique) id rather than panicking.
		return fmt.Sprintf("held-%d", time.Now().UnixNano())
	}
	return "held-" + hex.EncodeToString(buf[:])
}
