package era

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpmrtr "github.com/vyrodovalexey/avapigw/internal/mcp/mrtr"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fixedClock returns a deterministic-but-valid clock: it freezes at the moment
// of construction so envelope IssuedAt is not in the distant past (the real
// AEADSealer.Open enforces TTL against wall-clock time).
func fixedClock() func() time.Time {
	t := time.Now()
	return func() time.Time { return t }
}

func TestNewServerInitiatedBridgeNilSealer(t *testing.T) {
	t.Parallel()
	_, err := NewServerInitiatedBridge(nil, nil)
	if err == nil || err.Error() != "era: nil envelope sealer" {
		t.Fatalf("want nil sealer error, got %v", err)
	}
}

func TestNewServerInitiatedBridgeNilHeld(t *testing.T) {
	t.Parallel()
	b, err := NewServerInitiatedBridge(realSealer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.held == nil {
		t.Fatal("expected mem store fallback")
	}
}

func TestBridgeOptions(t *testing.T) {
	t.Parallel()
	clock := fixedClock()
	b, err := NewServerInitiatedBridge(realSealer(), nil,
		WithBridgeLogger(nil),
		WithBridgeLogger(observability.NopLogger()),
		WithBridgeMetrics(nil),
		WithBridgeMetrics(mcpmetrics.GetMetrics()),
		WithBridgeDeadline(0),
		WithBridgeDeadline(5*time.Minute),
		WithBridgeClock(nil),
		WithBridgeClock(clock),
	)
	if err != nil {
		t.Fatal(err)
	}
	if b.deadline != 5*time.Minute {
		t.Fatalf("deadline = %v want 5m", b.deadline)
	}
	if !b.now().Equal(clock()) {
		t.Fatal("clock not applied")
	}
}

func TestBridgeBeginRelease(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	pc, release := b.Begin("u1")
	if pc == nil {
		t.Fatal("nil pending call")
	}
	b.mu.Lock()
	if _, ok := b.pending[pendingKey("u1")]; !ok {
		b.mu.Unlock()
		t.Fatal("pending not registered")
	}
	b.mu.Unlock()
	release()
	b.mu.Lock()
	if _, ok := b.pending[pendingKey("u1")]; ok {
		b.mu.Unlock()
		t.Fatal("pending not released")
	}
	b.mu.Unlock()
	// Second release is a no-op.
	release()
}

func TestBridgeAwaitReceivesOutcome(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	pc, release := b.Begin("u1")
	defer release()
	want := PendingOutcome{Response: &jsonrpc.Response{JSONRPC: jsonrpc.Version}}
	go pc.resolve(want)
	got, err := b.Await(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Response == nil {
		t.Fatal("expected response outcome")
	}
}

func TestBridgeAwaitCtxCanceled(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	pc, release := b.Begin("u1")
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.Await(ctx, pc)
	if err == nil {
		t.Fatal("expected canceled error")
	}
}

func TestPendingCallResolveIdempotent(t *testing.T) {
	t.Parallel()
	pc := &PendingCall{outcome: make(chan PendingOutcome, 1)}
	pc.resolve(PendingOutcome{InputRequired: json.RawMessage("1")})
	pc.resolve(PendingOutcome{InputRequired: json.RawMessage("2")})
	o := <-pc.outcome
	if string(o.InputRequired) != "1" {
		t.Fatalf("expected first resolve to win, got %q", o.InputRequired)
	}
}

func TestResolveResponseWithPending(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	pc, release := b.Begin("u1")
	defer release()
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, ID: json.RawMessage("1")}
	b.ResolveResponse("u1", resp)
	o, err := b.Await(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	if o.Response != resp {
		t.Fatal("expected the delivered response")
	}
}

func TestResolveResponseNoPending(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	// No panic, no-op.
	b.ResolveResponse("u1", &jsonrpc.Response{})
}

func TestHandleServerRequestNoPending(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	err := b.HandleServerRequest(context.Background(), "u1",
		&jsonrpc.Request{ID: json.RawMessage("1"), Method: "sampling/createMessage"})
	if !errors.Is(err, ErrNoPendingCall) {
		t.Fatalf("want ErrNoPendingCall, got %v", err)
	}
}

func TestHandleServerRequestHappyPath(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil, WithBridgeClock(fixedClock()))
	pc, release := b.Begin("u1")
	defer release()
	req := &jsonrpc.Request{
		ID:     json.RawMessage("1"),
		Method: "sampling/createMessage",
		Params: json.RawMessage(`{"a":1}`),
	}
	if err := b.HandleServerRequest(context.Background(), "u1", req); err != nil {
		t.Fatal(err)
	}
	o, err := b.Await(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.InputRequired) == 0 {
		t.Fatal("expected input_required body")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(o.InputRequired, &body); err != nil {
		t.Fatal(err)
	}
	var rt string
	_ = json.Unmarshal(body[mcpmrtr.FieldResultType], &rt)
	if rt != protocol.ResultInputRequired {
		t.Fatalf("resultType = %q", rt)
	}
	var token string
	_ = json.Unmarshal(body[mcpmrtr.FieldRequestState], &token)
	if token == "" {
		t.Fatal("empty requestState token")
	}
	if _, ok := body[mcpmrtr.FieldInputRequests]; !ok {
		t.Fatal("missing inputRequests")
	}
}

func TestSealHeldSealError(t *testing.T) {
	t.Parallel()
	sealer := &fakeSealer{sealFn: func(context.Context, *envelope.Envelope) (string, error) {
		return "", errors.New("seal boom")
	}}
	b, _ := NewServerInitiatedBridge(sealer, nil)
	pc, release := b.Begin("u1")
	defer release()
	_ = pc
	err := b.HandleServerRequest(context.Background(), "u1",
		&jsonrpc.Request{ID: json.RawMessage("1"), Method: "sampling/createMessage"})
	if err == nil || !contains(err.Error(), "seal held envelope") {
		t.Fatalf("want seal error, got %v", err)
	}
}

// failingHeldStore fails on Put.
type failingHeldStore struct{ HeldRequestStore }

func (f failingHeldStore) Put(context.Context, string, *HeldRequest, time.Duration) error {
	return errors.New("put boom")
}

func TestSealHeldPutError(t *testing.T) {
	t.Parallel()
	store := failingHeldStore{HeldRequestStore: NewMemoryHeldStore()}
	b, _ := NewServerInitiatedBridge(realSealer(), store)
	b.Begin("u1")
	err := b.HandleServerRequest(context.Background(), "u1",
		&jsonrpc.Request{ID: json.RawMessage("1"), Method: "sampling/createMessage"})
	if err == nil || !contains(err.Error(), "store held request") {
		t.Fatalf("want store held request error, got %v", err)
	}
}

func TestResumeHeldHappyPath(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil, WithBridgeClock(fixedClock()))
	pc, release := b.Begin("u1")
	defer release()
	req := &jsonrpc.Request{ID: json.RawMessage("5"), Method: "sampling/createMessage"}
	if err := b.HandleServerRequest(context.Background(), "u1", req); err != nil {
		t.Fatal(err)
	}
	o, _ := b.Await(context.Background(), pc)
	token := extractToken(t, o.InputRequired)
	held, err := b.ResumeHeld(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if held.UpstreamID != "u1" {
		t.Fatalf("upstream = %q", held.UpstreamID)
	}
}

func TestResumeHeldBadToken(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil)
	_, err := b.ResumeHeld(context.Background(), "garbage-token")
	if !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("want ErrHeldNotFound, got %v", err)
	}
}

func TestResumeHeldConsumedTwice(t *testing.T) {
	t.Parallel()
	b, _ := NewServerInitiatedBridge(realSealer(), nil, WithBridgeClock(fixedClock()))
	pc, release := b.Begin("u1")
	defer release()
	req := &jsonrpc.Request{ID: json.RawMessage("5"), Method: "sampling/createMessage"}
	_ = b.HandleServerRequest(context.Background(), "u1", req)
	o, _ := b.Await(context.Background(), pc)
	token := extractToken(t, o.InputRequired)
	if _, err := b.ResumeHeld(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	// Second resume: held store now empty → ErrHeldNotFound.
	if _, err := b.ResumeHeld(context.Background(), token); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("second resume err = %v want ErrHeldNotFound", err)
	}
}

func TestResumeHeldNonceConsumeError(t *testing.T) {
	t.Parallel()
	// Real seal/open, held store OK, but Consume errors → ErrHeldConsumed.
	real := realSealer()
	sealer := &fakeSealer{
		sealFn:    real.Seal,
		openFn:    real.Open,
		consumeFn: func(context.Context, []byte) error { return errors.New("consumed") },
	}
	b, _ := NewServerInitiatedBridge(sealer, nil, WithBridgeClock(fixedClock()))
	pc, release := b.Begin("u1")
	defer release()
	req := &jsonrpc.Request{ID: json.RawMessage("5"), Method: "sampling/createMessage"}
	_ = b.HandleServerRequest(context.Background(), "u1", req)
	o, _ := b.Await(context.Background(), pc)
	token := extractToken(t, o.InputRequired)
	if _, err := b.ResumeHeld(context.Background(), token); !errors.Is(err, ErrHeldConsumed) {
		t.Fatalf("want ErrHeldConsumed, got %v", err)
	}
}

func TestResumeHeldExpired(t *testing.T) {
	t.Parallel()
	// Open OK but held store Consume returns ErrHeldNotFound.
	real := realSealer()
	sealer := &fakeSealer{sealFn: real.Seal, openFn: real.Open}
	b, _ := NewServerInitiatedBridge(sealer, NewMemoryHeldStore(), WithBridgeClock(fixedClock()))
	pc, release := b.Begin("u1")
	defer release()
	req := &jsonrpc.Request{ID: json.RawMessage("5"), Method: "sampling/createMessage"}
	_ = b.HandleServerRequest(context.Background(), "u1", req)
	o, _ := b.Await(context.Background(), pc)
	token := extractToken(t, o.InputRequired)
	// Consume the held entry directly so ResumeHeld's Consume misses.
	env, _ := real.Open(context.Background(), token)
	_, _ = b.held.Consume(context.Background(), env.OperationID)
	if _, err := b.ResumeHeld(context.Background(), token); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("want ErrHeldNotFound, got %v", err)
	}
}

func TestDeliverInputResponse(t *testing.T) {
	t.Parallel()
	held := &HeldRequest{UpstreamRequestID: json.RawMessage("5")}
	inputResponses := json.RawMessage(`{"ok":true}`)
	req, err := DeliverInputResponse(held, inputResponses)
	if err != nil {
		t.Fatal(err)
	}
	var resp jsonrpc.Response
	if err := json.Unmarshal(req.Params, &resp); err != nil {
		t.Fatal(err)
	}
	if string(resp.ID) != "5" {
		t.Fatalf("id = %q", string(resp.ID))
	}
	if string(resp.Result) != `{"ok":true}` {
		t.Fatalf("result = %q", string(resp.Result))
	}

	// Empty UpstreamRequestID → null id.
	held2 := &HeldRequest{}
	req2, err := DeliverInputResponse(held2, inputResponses)
	if err != nil {
		t.Fatal(err)
	}
	var resp2 jsonrpc.Response
	_ = json.Unmarshal(req2.Params, &resp2)
	if string(resp2.ID) != "null" {
		t.Fatalf("empty id should be null, got %q", string(resp2.ID))
	}
}

func TestBuildLegacyInputRequired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method   string
		wantType string
	}{
		{LegacyMethodSamplingCreate, mcpmrtr.CapSampling},
		{LegacyMethodElicitationCreate, mcpmrtr.CapElicitation},
		{LegacyMethodRootsList, mcpmrtr.CapRoots},
		{"tools/list", "unknown"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			raw, err := buildLegacyInputRequired("tok", &jsonrpc.Request{Method: tt.method, Params: json.RawMessage(`{"a":1}`)})
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			_ = json.Unmarshal(raw, &body)
			var reqs map[string]json.RawMessage
			_ = json.Unmarshal(body[mcpmrtr.FieldInputRequests], &reqs)
			entryRaw, ok := reqs[tt.wantType]
			if !ok {
				t.Fatalf("missing input request for type %q", tt.wantType)
			}
			var entry map[string]json.RawMessage
			_ = json.Unmarshal(entryRaw, &entry)
			if _, ok := entry["params"]; !ok {
				t.Fatal("expected params in entry")
			}
		})
	}
}

func TestBuildLegacyInputRequiredNoParams(t *testing.T) {
	t.Parallel()
	raw, err := buildLegacyInputRequired("tok", &jsonrpc.Request{Method: LegacyMethodSamplingCreate})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	_ = json.Unmarshal(raw, &body)
	var reqs map[string]json.RawMessage
	_ = json.Unmarshal(body[mcpmrtr.FieldInputRequests], &reqs)
	var entry map[string]json.RawMessage
	_ = json.Unmarshal(reqs[mcpmrtr.CapSampling], &entry)
	if _, ok := entry["params"]; ok {
		t.Fatal("no params should be present when req.Params is empty")
	}
}

var heldIDRe = regexp.MustCompile(`^held-[0-9a-f]{32}$`)

func TestNewHeldID(t *testing.T) {
	t.Parallel()
	a := newHeldID()
	b := newHeldID()
	if !heldIDRe.MatchString(a) {
		t.Fatalf("bad held id format: %q", a)
	}
	if a == b {
		t.Fatal("held ids should be unique")
	}
}

func extractToken(t *testing.T, inputRequired json.RawMessage) string {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(inputRequired, &body); err != nil {
		t.Fatal(err)
	}
	var token string
	if err := json.Unmarshal(body[mcpmrtr.FieldRequestState], &token); err != nil {
		t.Fatal(err)
	}
	return token
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return len(sub) == 0
}
