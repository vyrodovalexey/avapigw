package mrtr

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

func newSealer(t *testing.T) *envelope.AEADSealer {
	t.Helper()
	key := make([]byte, envelope.KeySize)
	for i := range key {
		key[i] = byte(i + 3)
	}
	s, err := envelope.NewAEADSealer(key)
	require.NoError(t, err)
	return s
}

func newCoord(t *testing.T, cfg Config, opts ...Option) *Coordinator {
	t.Helper()
	c, err := NewCoordinator(newSealer(t), cfg, opts...)
	require.NoError(t, err)
	return c
}

func TestNewCoordinatorNilSealer(t *testing.T) {
	t.Parallel()
	_, err := NewCoordinator(nil, Config{})
	assert.Error(t, err)
}

func TestConfigWithDefaults(t *testing.T) {
	t.Parallel()
	c := Config{}.withDefaults()
	assert.Equal(t, DefaultMaxRounds, c.MaxRounds)
	assert.Equal(t, DefaultBudget, c.Budget)
	assert.Equal(t, DefaultEnvelopeTTL, c.EnvelopeTTL)
}

func TestIsMRTRMethod(t *testing.T) {
	t.Parallel()
	assert.True(t, IsMRTRMethod(protocol.MethodToolsCall))
	assert.True(t, IsMRTRMethod(protocol.MethodResourcesRead))
	assert.True(t, IsMRTRMethod(protocol.MethodPromptsGet))
	assert.False(t, IsMRTRMethod(protocol.MethodToolsList))
	assert.False(t, IsMRTRMethod("server/discover"))
}

func TestIsRetry(t *testing.T) {
	t.Parallel()
	assert.True(t, IsRetry(map[string]any{"requestState": "s", "inputResponses": []any{}}))
	assert.False(t, IsRetry(map[string]any{"requestState": "s"}), "lone requestState is ignored")
	assert.False(t, IsRetry(map[string]any{"inputResponses": []any{}}))
	assert.False(t, IsRetry(map[string]any{}))
}

func TestInspectInputRequired(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	result := `{"resultType":"input_required","requestState":"up-state","inputRequests":{"r1":{"type":"sampling"}}}`
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(result)}

	ins, err := c.Inspect(protocol.MethodToolsCall, resp)
	require.NoError(t, err)
	assert.True(t, ins.InputRequired)
	assert.JSONEq(t, `"up-state"`, string(ins.RequestState))
	assert.Contains(t, ins.InputRequests, "r1")
}

func TestInspectNonInputRequired(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"resultType":"complete"}`)}
	ins, err := c.Inspect(protocol.MethodToolsCall, resp)
	require.NoError(t, err)
	assert.False(t, ins.InputRequired)
}

func TestInspectNonMRTRMethodRejected(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"resultType":"input_required"}`)}
	_, err := c.Inspect(protocol.MethodToolsList, resp)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestInspectNotInspectable(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	// nil response.
	ins, err := c.Inspect(protocol.MethodToolsCall, nil)
	require.NoError(t, err)
	assert.False(t, ins.InputRequired)
	// error response.
	ins, err = c.Inspect(protocol.MethodToolsCall, &jsonrpc.Response{Error: &jsonrpc.Error{Code: -1}})
	require.NoError(t, err)
	assert.False(t, ins.InputRequired)
	// empty result.
	ins, err = c.Inspect(protocol.MethodToolsCall, &jsonrpc.Response{JSONRPC: jsonrpc.Version})
	require.NoError(t, err)
	assert.False(t, ins.InputRequired)
}

func TestInspectDecodeError(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`not-json`)}
	_, err := c.Inspect(protocol.MethodToolsCall, resp)
	assert.Error(t, err)
}

func mrtrCallContext() CallContext {
	return CallContext{
		UpstreamID:         "up1",
		Method:             protocol.MethodToolsCall,
		DenamespacedName:   "echo",
		Principal:          "alice",
		SalientParams:      json.RawMessage(`{"a":1}`),
		ClientCapabilities: map[string]bool{"sampling": true, "elicitation": true, "roots": true},
	}
}

func inputRequired() InspectResult {
	return InspectResult{
		InputRequired: true,
		RequestState:  json.RawMessage(`"upstream-state"`),
		InputRequests: map[string]json.RawMessage{"r1": json.RawMessage(`{"type":"sampling"}`)},
	}
}

func TestBuildDownstreamAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()

	body, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 1, "", time.Time{})
	require.NoError(t, err)

	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &obj))
	var rt string
	require.NoError(t, json.Unmarshal(obj[FieldResultType], &rt))
	assert.Equal(t, protocol.ResultInputRequired, rt)
	// inputRequests preserved verbatim.
	assert.Contains(t, obj, FieldInputRequests)

	var token string
	require.NoError(t, json.Unmarshal(obj[FieldRequestState], &token))
	require.NotEmpty(t, token)

	// Verify the retry: same principal/method/params.
	rs, err := c.VerifyRetry(context.Background(), token, cc)
	require.NoError(t, err)
	assert.JSONEq(t, `"upstream-state"`, string(rs.UpstreamState))
	assert.NotEmpty(t, rs.OperationID)
}

// errSealer is a Sealer whose Seal always fails, to drive the BuildDownstream
// seal-error wrap (line 374).
type errSealer struct{}

func (errSealer) Seal(context.Context, *envelope.Envelope) (string, error) {
	return "", assertSealErr
}
func (errSealer) Open(context.Context, string) (*envelope.Envelope, error) {
	return nil, assertSealErr
}
func (errSealer) Consume(context.Context, []byte) error { return nil }

var assertSealErr = errorsNew("seal boom")

// errorsNew avoids importing errors solely for a sentinel.
func errorsNew(msg string) error { return &simpleErr{msg} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

func TestBuildDownstreamSealError(t *testing.T) {
	t.Parallel()
	c, err := NewCoordinator(errSealer{}, Config{})
	require.NoError(t, err)

	_, err = c.BuildDownstream(context.Background(), mrtrCallContext(), inputRequired(), 1, "", time.Time{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mrtr: seal envelope")
}

// TestWithMetricsAndLoggerNilGuards proves nil options are no-ops: the
// coordinator keeps its defaults.
func TestWithMetricsAndLoggerNilGuards(t *testing.T) {
	t.Parallel()
	c, err := NewCoordinator(newSealer(t), Config{}, WithMetrics(nil), WithLogger(nil))
	require.NoError(t, err)
	assert.NotNil(t, c.metrics, "nil metrics option must not clear the default")
	assert.NotNil(t, c.logger, "nil logger option must not clear the default")
}

func TestBuildDownstreamMissingCapability(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	cc.ClientCapabilities = map[string]bool{} // client declared nothing

	_, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 1, "", time.Time{})
	var capErr *CapabilityError
	require.ErrorAs(t, err, &capErr)
	assert.Equal(t, []string{"sampling"}, capErr.Missing)
	assert.Contains(t, capErr.Error(), "sampling")
}

func TestBuildDownstreamRoundLimit(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{MaxRounds: 2})
	cc := mrtrCallContext()
	_, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 3, "op-1", time.Now())
	assert.ErrorIs(t, err, ErrRoundLimit)
}

// TestBuildDownstreamBudgetExceeded proves the wall-clock budget is enforced
// SERVER-SIDE using the sealed operation start (HUB-208).
func TestBuildDownstreamBudgetExceeded(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{Budget: time.Minute})
	cc := mrtrCallContext()
	// Operation started well beyond the budget ago.
	started := time.Now().Add(-2 * time.Minute)
	_, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 2, "op-1", started)
	assert.ErrorIs(t, err, ErrBudgetExceeded)
}

// TestBuildDownstreamSealsRoundAndStart proves the round counter and operation
// start are sealed into the envelope and recovered on VerifyRetry, so the
// server — not the client — controls MRTR progress (HUB-208).
func TestBuildDownstreamSealsRoundAndStart(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	start := time.Now().Add(-30 * time.Second).Truncate(time.Second)

	body, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 3, "op-fixed", start)
	require.NoError(t, err)
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &obj))
	var token string
	require.NoError(t, json.Unmarshal(obj[FieldRequestState], &token))

	rs, err := c.VerifyRetry(context.Background(), token, cc)
	require.NoError(t, err)
	assert.Equal(t, 3, rs.Round)
	assert.True(t, rs.OperationStart.Equal(start), "sealed operation start must round-trip")
}

// TestVerifyRetryBudgetExceeded proves a retry whose sealed operation start is
// older than the budget is rejected even before the nonce is consumed
// (HUB-208).
func TestVerifyRetryBudgetExceeded(t *testing.T) {
	t.Parallel()
	// Seal with a start far in the past by fixing the clock during seal.
	oldStart := time.Now().Add(-10 * time.Minute)
	sealClock := func() time.Time { return oldStart }
	c := newCoord(t, Config{Budget: time.Minute, EnvelopeTTL: time.Hour}, WithClock(sealClock))
	cc := mrtrCallContext()
	body, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 1, "op-b", oldStart)
	require.NoError(t, err)
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &obj))
	var token string
	require.NoError(t, json.Unmarshal(obj[FieldRequestState], &token))

	// Verify with the real (now much later) clock so the budget is exceeded.
	c2, err := NewCoordinator(c.sealer, Config{Budget: time.Minute, EnvelopeTTL: time.Hour})
	require.NoError(t, err)
	_, err = c2.VerifyRetry(context.Background(), token, cc)
	assert.ErrorIs(t, err, ErrBudgetExceeded)
}

func TestBuildDownstreamPreservesOperationID(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	body, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 2, "op-fixed", time.Now())
	require.NoError(t, err)
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &obj))
	var token string
	require.NoError(t, json.Unmarshal(obj[FieldRequestState], &token))
	rs, err := c.VerifyRetry(context.Background(), token, cc)
	require.NoError(t, err)
	assert.Equal(t, "op-fixed", rs.OperationID)
}

func sealedToken(t *testing.T, c *Coordinator, cc CallContext) string {
	t.Helper()
	body, err := c.BuildDownstream(context.Background(), cc, inputRequired(), 1, "op-x", time.Now())
	require.NoError(t, err)
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &obj))
	var token string
	require.NoError(t, json.Unmarshal(obj[FieldRequestState], &token))
	return token
}

func TestVerifyRetryTampered(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)
	tampered := "ZZZZ" + token[4:]
	_, err := c.VerifyRetry(context.Background(), tampered, cc)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestVerifyRetryCrossPrincipal(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	other := cc
	other.Principal = "mallory"
	_, err := c.VerifyRetry(context.Background(), token, other)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestVerifyRetryCrossParams(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	other := cc
	other.SalientParams = json.RawMessage(`{"a":2}`)
	_, err := c.VerifyRetry(context.Background(), token, other)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestVerifyRetryCrossUpstream(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	other := cc
	other.UpstreamID = "up2"
	_, err := c.VerifyRetry(context.Background(), token, other)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestVerifyRetryExpired(t *testing.T) {
	t.Parallel()
	// Seal in the past with a short TTL so it is expired at verify time.
	past := time.Now().Add(-time.Hour)
	c := newCoord(t, Config{EnvelopeTTL: time.Second}, WithClock(func() time.Time { return past }))
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	_, err := c.VerifyRetry(context.Background(), token, cc)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestVerifyRetrySingleUse(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	_, err := c.VerifyRetry(context.Background(), token, cc)
	require.NoError(t, err)
	// Second use of the same token/nonce must fail (HUB-209).
	_, err = c.VerifyRetry(context.Background(), token, cc)
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestVerifyRetryEmptyUpstreamMatchesAny(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	other := cc
	other.UpstreamID = "" // an empty ctx upstream skips the mismatch check
	rs, err := c.VerifyRetry(context.Background(), token, other)
	require.NoError(t, err)
	assert.NotNil(t, rs)
}

func TestSealedUpstreamID(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	cc := mrtrCallContext()
	token := sealedToken(t, c, cc)

	id, err := c.SealedUpstreamID(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "up1", id)

	// Opening it did not consume the nonce: verify still works afterwards.
	_, err = c.VerifyRetry(context.Background(), token, cc)
	require.NoError(t, err)
}

func TestSealedUpstreamIDInvalidToken(t *testing.T) {
	t.Parallel()
	c := newCoord(t, Config{})
	_, err := c.SealedUpstreamID(context.Background(), "garbage")
	assert.ErrorIs(t, err, ErrInvalidRetryState)
}

func TestCheckCapabilitiesMultipleMissing(t *testing.T) {
	t.Parallel()
	reqs := map[string]json.RawMessage{
		"a": json.RawMessage(`{"type":"sampling"}`),
		"b": json.RawMessage(`{"type":"roots"}`),
		"c": json.RawMessage(`{"type":"elicitation"}`),
	}
	err := checkCapabilities(reqs, map[string]bool{"sampling": true})
	var capErr *CapabilityError
	require.ErrorAs(t, err, &capErr)
	// Sorted, deduplicated.
	assert.Equal(t, []string{"elicitation", "roots"}, capErr.Missing)
}

func TestCheckCapabilitiesNoTypeIgnored(t *testing.T) {
	t.Parallel()
	reqs := map[string]json.RawMessage{"a": json.RawMessage(`{"notatype":1}`)}
	assert.NoError(t, checkCapabilities(reqs, map[string]bool{}))
}

func TestInputRequestType(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "sampling", inputRequestType(json.RawMessage(`{"type":"sampling"}`)))
	assert.Equal(t, "", inputRequestType(json.RawMessage(`{"other":1}`)))
	assert.Equal(t, "", inputRequestType(json.RawMessage(`not-json`)))
	assert.Equal(t, "", inputRequestType(json.RawMessage(`{"type":123}`)))
}

func TestWithLoggerAndMetricsOptions(t *testing.T) {
	t.Parallel()
	// Nil options are ignored without panicking.
	c := newCoord(t, Config{}, WithLogger(nil), WithMetrics(nil), WithClock(nil))
	require.NotNil(t, c)
}

func TestNewOperationIDUnique(t *testing.T) {
	t.Parallel()
	a := newOperationID()
	b := newOperationID()
	assert.NotEqual(t, a, b)
	assert.Contains(t, a, "op-")
}
