// Package mrtr implements the hub's Multi Round-Trip Request coordination
// (HUB-201..209). In revision 2026-07-28 there are no server→client requests:
// an upstream that needs sampling, elicitation or roots input returns an
// InputRequiredResult (resultType "input_required") that the client answers by
// retrying the original request with inputResponses and an opaque requestState.
//
// The hub is a protocol-aware intermediary: it never lets a client's opaque
// requestState route or authorize a retry by itself (HUB-204). Instead it wraps
// the upstream requestState in an AEAD-protected envelope carrying the upstream
// id, de-namespaced primitive name, a digest of the salient parameters, the
// authenticated principal, an issue time and a TTL, plus the original upstream
// state (HUB-202). On retry it unwraps and verifies the envelope (integrity,
// principal, method+params, expiry, single-use) before forwarding the
// upstream's ORIGINAL state verbatim (HUB-202/203/209).
package mrtr

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Result-field constants used in an InputRequiredResult body.
const (
	// FieldResultType is the result discriminator key.
	FieldResultType = "resultType"
	// FieldRequestState carries the opaque MRTR state.
	FieldRequestState = "requestState"
	// FieldInputRequests carries the upstream-assigned input requests.
	FieldInputRequests = "inputRequests"
	// FieldInputResponses carries the client's answers on retry.
	FieldInputResponses = "inputResponses"
	// fieldType is the type discriminator within an input request entry.
	fieldType = "type"
)

// Client-capability / input-request type names the hub must broker (HUB-206).
const (
	// CapSampling names the sampling capability / input-request type.
	CapSampling = "sampling"
	// CapElicitation names the elicitation capability / input-request type.
	CapElicitation = "elicitation"
	// CapRoots names the roots capability / input-request type.
	CapRoots = "roots"
)

// mrtrMethods is the set of methods for which the hub relays input_required
// downstream (HUB-201). No other method may carry it.
var mrtrMethods = map[string]bool{
	protocol.MethodToolsCall:     true,
	protocol.MethodResourcesRead: true,
	protocol.MethodPromptsGet:    true,
}

// IsMRTRMethod reports whether a method may carry an input_required result
// (HUB-201).
func IsMRTRMethod(method string) bool {
	return mrtrMethods[method]
}

// Sentinel errors returned by the coordinator.
var (
	// ErrRoundLimit indicates the operation exceeded the configured maximum
	// round count (HUB-208).
	ErrRoundLimit = errors.New("mrtr: maximum round count exceeded")
	// ErrBudgetExceeded indicates the operation exceeded its wall-clock
	// budget (HUB-208).
	ErrBudgetExceeded = errors.New("mrtr: wall-clock budget exceeded")
	// ErrMissingCapability indicates the upstream requested an input type the
	// downstream client did not declare and the hub cannot satisfy (HUB-206).
	ErrMissingCapability = errors.New("mrtr: missing required client capability")
	// ErrInvalidRetryState indicates the presented requestState failed
	// verification (HUB-203).
	ErrInvalidRetryState = errors.New("mrtr: invalid retry state")
)

// CapabilityError carries the set of client capabilities missing to satisfy an
// upstream input request, so the handler can report -32021 with data.missing
// (HUB-206).
type CapabilityError struct {
	// Missing lists the capability names the client did not declare.
	Missing []string
}

// Error implements the error interface.
func (e *CapabilityError) Error() string {
	return fmt.Sprintf("mrtr: missing required client capabilities: %v", e.Missing)
}

// Config bounds a single logical MRTR operation (HUB-208).
type Config struct {
	// MaxRounds is the maximum number of input_required rounds. Zero uses
	// DefaultMaxRounds.
	MaxRounds int
	// Budget is the total wall-clock budget for the operation. Zero uses
	// DefaultBudget.
	Budget time.Duration
	// EnvelopeTTL bounds an issued envelope's validity. Zero uses
	// DefaultEnvelopeTTL.
	EnvelopeTTL time.Duration
}

// MRTR defaults.
const (
	// DefaultMaxRounds bounds input_required rounds when unconfigured.
	DefaultMaxRounds = 8
	// DefaultBudget bounds the operation wall-clock when unconfigured.
	DefaultBudget = 5 * time.Minute
	// DefaultEnvelopeTTL bounds envelope validity when unconfigured.
	DefaultEnvelopeTTL = 5 * time.Minute
)

// withDefaults returns a copy of the config with zero fields defaulted.
func (c Config) withDefaults() Config {
	if c.MaxRounds <= 0 {
		c.MaxRounds = DefaultMaxRounds
	}
	if c.Budget <= 0 {
		c.Budget = DefaultBudget
	}
	if c.EnvelopeTTL <= 0 {
		c.EnvelopeTTL = DefaultEnvelopeTTL
	}
	return c
}

// Coordinator processes MRTR initial calls and retries, sealing/verifying the
// AEAD envelope and enforcing round/budget limits. It is safe for concurrent
// use: the sealer serializes single-use bookkeeping internally.
type Coordinator struct {
	sealer  envelope.Sealer
	cfg     Config
	metrics *mcpmetrics.Metrics
	logger  observability.Logger
	now     func() time.Time
}

// Option configures a Coordinator.
type Option func(*Coordinator)

// WithMetrics sets the metrics recorder.
func WithMetrics(m *mcpmetrics.Metrics) Option {
	return func(c *Coordinator) {
		if m != nil {
			c.metrics = m
		}
	}
}

// WithLogger sets the coordinator logger.
func WithLogger(l observability.Logger) Option {
	return func(c *Coordinator) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithClock overrides the time source (test seam).
func WithClock(now func() time.Time) Option {
	return func(c *Coordinator) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCoordinator constructs a Coordinator over the given sealer and config.
func NewCoordinator(sealer envelope.Sealer, cfg Config, opts ...Option) (*Coordinator, error) {
	if sealer == nil {
		return nil, errors.New("mrtr: nil sealer")
	}
	c := &Coordinator{
		sealer:  sealer,
		cfg:     cfg.withDefaults(),
		metrics: mcpmetrics.GetMetrics(),
		logger:  observability.NopLogger(),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// CallContext carries the routing/authorization context of a request needed to
// seal and verify an MRTR envelope.
type CallContext struct {
	// UpstreamID is the upstream that owns the operation.
	UpstreamID string
	// Method is the JSON-RPC method (must be an MRTR method).
	Method string
	// DenamespacedName is the de-namespaced primitive name.
	DenamespacedName string
	// Principal is the authenticated principal (HUB-203). Empty when
	// authorization is not configured.
	Principal string
	// SalientParams is the JSON of the parameters whose digest binds the
	// envelope to the request (HUB-202/203).
	SalientParams json.RawMessage
	// ClientCapabilities is the set of input types the downstream client
	// declared (sampling/elicitation/roots) — drives HUB-206.
	ClientCapabilities map[string]bool
}

// RetryState is the verified result of unwrapping a retry envelope. It carries
// the upstream's ORIGINAL requestState (forwarded verbatim, HUB-202) and the
// operation id linking MRTR rounds/spans, plus the sealed round counter and
// operation-start so the next round is bounded server-side (HUB-208).
type RetryState struct {
	// UpstreamState is the original upstream requestState.
	UpstreamState json.RawMessage
	// OperationID links MRTR rounds and spans.
	OperationID string
	// Round is the sealed 1-based round number of the envelope being
	// retried; the resulting round is Round+1 (HUB-208).
	Round int
	// OperationStart is the sealed wall-clock start of the logical MRTR
	// operation, carried forward so the total budget spans all rounds
	// (HUB-208).
	OperationStart time.Time
}

// InspectResult classifies an upstream response for the MRTR path.
type InspectResult struct {
	// InputRequired is true when the response is an input_required result.
	InputRequired bool
	// RequestState is the upstream's opaque requestState (present only when
	// InputRequired).
	RequestState json.RawMessage
	// InputRequests are the upstream-assigned input requests (present only
	// when InputRequired), preserved verbatim (HUB-205).
	InputRequests map[string]json.RawMessage
}

// Inspect classifies an upstream response: it reports whether the result is an
// input_required result and, if so, extracts the requestState and inputRequests
// verbatim (HUB-205). A response for a non-MRTR method never yields
// InputRequired even if the body carries the discriminator (HUB-201).
func (c *Coordinator) Inspect(method string, resp *jsonrpc.Response) (InspectResult, error) {
	if !isInspectable(resp) {
		return InspectResult{}, nil
	}
	var body struct {
		ResultType    string                     `json:"resultType"`
		RequestState  json.RawMessage            `json:"requestState"`
		InputRequests map[string]json.RawMessage `json:"inputRequests"`
	}
	if err := json.Unmarshal(resp.Result, &body); err != nil {
		return InspectResult{}, fmt.Errorf("mrtr: decode result: %w", err)
	}
	if body.ResultType != protocol.ResultInputRequired {
		return InspectResult{}, nil
	}
	if !IsMRTRMethod(method) {
		// HUB-201: never relay input_required for a non-MRTR method.
		return InspectResult{}, fmt.Errorf("%w: method %q", ErrInvalidRetryState, method)
	}
	return InspectResult{
		InputRequired: true,
		RequestState:  body.RequestState,
		InputRequests: body.InputRequests,
	}, nil
}

// isInspectable reports whether a response carries a result body worth
// inspecting for an input_required discriminator: a successful, non-empty
// result. An error response or an empty result is never input_required.
func isInspectable(resp *jsonrpc.Response) bool {
	if resp == nil || len(resp.Result) == 0 {
		return false
	}
	return resp.Error == nil
}

// checkCapabilities enforces HUB-206: every upstream input request type must be
// one the downstream client declared. Types the hub itself can satisfy are out
// of scope here (roots-from-config is deferred). It returns a *CapabilityError
// listing the missing capabilities when any are undeclared.
func checkCapabilities(inputRequests map[string]json.RawMessage, clientCaps map[string]bool) error {
	missing := map[string]bool{}
	for _, raw := range inputRequests {
		typ := inputRequestType(raw)
		if typ == "" {
			continue
		}
		if !clientCaps[typ] {
			missing[typ] = true
		}
	}
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for name := range missing {
		names = append(names, name)
	}
	sort.Strings(names)
	return &CapabilityError{Missing: names}
}

// inputRequestType extracts the "type" discriminator from an input-request
// entry, or "" when absent.
func inputRequestType(raw json.RawMessage) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	v, ok := obj[fieldType]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

// BuildDownstream seals an MRTR envelope for an upstream input_required result
// and returns the downstream result body with the hub's envelope substituted
// for the upstream requestState (HUB-202). It first enforces capability
// discipline (HUB-206), then the round-count and wall-clock budget bounds
// SERVER-SIDE (HUB-208), and records the MRTR round metric. round is the
// 1-based round index sealed into the envelope so the next retry is round+1;
// operationStart is the sealed operation start (zero for the first round, in
// which case now() is used). operationID links the rounds (empty for the first
// round, in which case a fresh id is minted).
func (c *Coordinator) BuildDownstream(
	ctx context.Context, cc CallContext, ins InspectResult, round int, operationID string,
	operationStart time.Time,
) (json.RawMessage, error) {
	if err := checkCapabilities(ins.InputRequests, cc.ClientCapabilities); err != nil {
		return nil, err
	}
	now := c.now()
	if operationStart.IsZero() {
		operationStart = now
	}
	if err := c.enforceBounds(round, operationStart, now, cc); err != nil {
		return nil, err
	}
	if operationID == "" {
		operationID = newOperationID()
	}

	env := &envelope.Envelope{
		UpstreamID:     cc.UpstreamID,
		Primitive:      cc.DenamespacedName,
		ParamDigest:    paramDigest(cc.SalientParams),
		Principal:      cc.Principal,
		IssuedAt:       now,
		TTL:            c.cfg.EnvelopeTTL,
		OperationID:    operationID,
		UpstreamState:  ins.RequestState,
		RetriedMethod:  cc.Method,
		Round:          round,
		OperationStart: operationStart,
	}
	token, err := c.sealer.Seal(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("mrtr: seal envelope: %w", err)
	}

	c.metrics.RecordMRTRRound(cc.UpstreamID, cc.Method)

	return buildInputRequiredResult(token, ins.InputRequests)
}

// enforceBounds enforces the configured maximum round count and total
// wall-clock budget for a logical MRTR operation SERVER-SIDE (HUB-208). It
// records the reject as an auth failure so operators can observe abusive or
// runaway MRTR flows.
func (c *Coordinator) enforceBounds(round int, operationStart, now time.Time, cc CallContext) error {
	if round > c.cfg.MaxRounds {
		c.logger.Warn("mrtr: round limit exceeded",
			observability.String("upstream", cc.UpstreamID),
			observability.String("method", cc.Method),
			observability.Int("round", round),
			observability.Int("maxRounds", c.cfg.MaxRounds))
		c.metrics.RecordAuthFailure(cc.Method, mcpmetrics.AuthClassRetryState)
		return ErrRoundLimit
	}
	if now.Sub(operationStart) > c.cfg.Budget {
		c.logger.Warn("mrtr: wall-clock budget exceeded",
			observability.String("upstream", cc.UpstreamID),
			observability.String("method", cc.Method),
			observability.Duration("elapsed", now.Sub(operationStart)),
			observability.Duration("budget", c.cfg.Budget))
		c.metrics.RecordAuthFailure(cc.Method, mcpmetrics.AuthClassRetryState)
		return ErrBudgetExceeded
	}
	return nil
}

// buildInputRequiredResult assembles the downstream input_required body with
// the hub envelope as requestState and the upstream inputRequests preserved
// verbatim (HUB-205).
func buildInputRequiredResult(
	token string, inputRequests map[string]json.RawMessage,
) (json.RawMessage, error) {
	body := map[string]any{
		FieldResultType:    protocol.ResultInputRequired,
		FieldRequestState:  token,
		FieldInputRequests: inputRequests,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("mrtr: encode input_required: %w", err)
	}
	return raw, nil
}

// IsRetry reports whether request params carry an MRTR retry (requestState +
// inputResponses). Both fields are required for a retry; a lone requestState is
// treated as untrusted noise and ignored (HUB-204).
func IsRetry(params map[string]any) bool {
	_, hasState := params[FieldRequestState]
	_, hasResponses := params[FieldInputResponses]
	return hasState && hasResponses
}

// VerifyRetry unwraps and verifies the retry envelope (HUB-203/209) and returns
// the upstream's ORIGINAL state to forward verbatim (HUB-202). It enforces
// integrity, principal match, method+params match, expiry and single-use. The
// presented requestState/inputResponses are treated as untrusted: only the
// verified envelope influences routing/authorization (HUB-204).
func (c *Coordinator) VerifyRetry(
	ctx context.Context, token string, cc CallContext,
) (*RetryState, error) {
	env, err := c.sealer.Open(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRetryState, err)
	}
	if err := envelope.VerifyRetry(env, cc.Principal, cc.Method, paramDigest(cc.SalientParams)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRetryState, err)
	}
	// Cross-upstream retries must land on the sealed upstream (HUB-204).
	if cc.UpstreamID != "" && env.UpstreamID != cc.UpstreamID {
		return nil, fmt.Errorf("%w: upstream mismatch", ErrInvalidRetryState)
	}
	// Enforce the wall-clock budget across rounds using the sealed operation
	// start (HUB-208). The round-count bound is enforced on the next
	// BuildDownstream with Round+1.
	if !env.OperationStart.IsZero() && c.now().Sub(env.OperationStart) > c.cfg.Budget {
		c.metrics.RecordAuthFailure(cc.Method, mcpmetrics.AuthClassRetryState)
		return nil, fmt.Errorf("%w: %w", ErrInvalidRetryState, ErrBudgetExceeded)
	}
	// Single-use enforcement (HUB-209): consume the nonce under the store's
	// atomicity guarantee so there is no time-of-check/time-of-use window and,
	// with a shared store, a replay against any replica is rejected (HUB-207).
	if err := c.sealer.Consume(ctx, env.Nonce); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRetryState, err)
	}
	return &RetryState{
		UpstreamState:  env.UpstreamState,
		OperationID:    env.OperationID,
		Round:          env.Round,
		OperationStart: env.OperationStart,
	}, nil
}

// SealedUpstreamID opens a retry token WITHOUT consuming it, returning the
// sealed upstream id so the handler can route the retry to the correct upstream
// before it knows the de-namespaced context. Verification and single-use
// consumption still happen in VerifyRetry (HUB-203/204/209).
func (c *Coordinator) SealedUpstreamID(ctx context.Context, token string) (string, error) {
	env, err := c.sealer.Open(ctx, token)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRetryState, err)
	}
	return env.UpstreamID, nil
}

// paramDigest computes a stable digest of the salient request parameters used
// to bind the envelope to the request (HUB-202/203).
func paramDigest(params json.RawMessage) []byte {
	sum := sha256.Sum256(params)
	return sum[:]
}

// newOperationID mints a random operation id linking MRTR rounds and spans
// (HUB-506). A random 128-bit token is collision-free across concurrent
// operations, unlike a time-seeded id.
func newOperationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal-grade; fall back to a time token so
		// correlation still functions rather than panicking on the hot path.
		return fmt.Sprintf("op-%d", time.Now().UnixNano())
	}
	return "op-" + hex.EncodeToString(b[:])
}
