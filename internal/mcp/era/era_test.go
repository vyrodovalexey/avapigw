package era

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

func TestPin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		era     string
		version string
		want    Era
	}{
		{"modern pin", "modern", "", EraModern},
		{"legacy pin", "legacy", "", EraLegacy},
		{"version pin implies legacy", "", "2025-06-18", EraLegacy},
		{"unpinned", "", "", EraUnknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Pin(tc.era, tc.version); got != tc.want {
				t.Fatalf("Pin(%q,%q)=%v want %v", tc.era, tc.version, got, tc.want)
			}
		})
	}
}

func TestEraCacheGetSetInvalidateExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	c := NewEraCache(WithEraCacheTTL(time.Minute), WithEraCacheClock(func() time.Time { return now }))

	if _, ok := c.Get("o1"); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Set("o1", EraLegacy)
	if got, ok := c.Get("o1"); !ok || got != EraLegacy {
		t.Fatalf("Get after Set = %v,%v", got, ok)
	}
	// Expire.
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("o1"); ok {
		t.Fatal("expected miss after TTL expiry")
	}
	now = time.Unix(0, 0)
	c.Set("o1", EraModern)
	c.Invalidate("o1")
	if _, ok := c.Get("o1"); ok {
		t.Fatal("expected miss after Invalidate")
	}
}

type stubProber struct {
	era  Era
	err  error
	hits int
}

func (s *stubProber) Probe(_ context.Context, _, _ string) (Era, error) {
	s.hits++
	return s.era, s.err
}

func TestDeterminePinBypassesProbe(t *testing.T) {
	t.Parallel()
	d := NewDeterminer(NewEraCache(), nil)
	p := &stubProber{era: EraModern}
	got, err := d.Determine(context.Background(), "u1", "u1", "legacy", "", p)
	if err != nil || got != EraLegacy {
		t.Fatalf("Determine pinned = %v,%v", got, err)
	}
	if p.hits != 0 {
		t.Fatalf("prober called %d times for pinned upstream", p.hits)
	}
}

func TestDetermineProbesThenCaches(t *testing.T) {
	t.Parallel()
	d := NewDeterminer(NewEraCache(), nil)
	p := &stubProber{era: EraLegacy}
	for i := 0; i < 3; i++ {
		got, err := d.Determine(context.Background(), "u1", "u1", "", "", p)
		if err != nil || got != EraLegacy {
			t.Fatalf("Determine = %v,%v", got, err)
		}
	}
	if p.hits != 1 {
		t.Fatalf("prober called %d times; want 1 (cached after first)", p.hits)
	}
	d.Invalidate("u1")
	if _, err := d.Determine(context.Background(), "u1", "u1", "", "", p); err != nil {
		t.Fatal(err)
	}
	if p.hits != 2 {
		t.Fatalf("prober called %d times after invalidate; want 2", p.hits)
	}
}

func TestTranslateLegacyResultRemapsNotFound(t *testing.T) {
	t.Parallel()
	resp := &jsonrpc.Response{
		JSONRPC: jsonrpc.Version,
		Error:   &jsonrpc.Error{Code: legacyResourceNotFound, Message: "not found"},
	}
	out, err := TranslateLegacyResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error.Code != protocol.InvalidParams {
		t.Fatalf("code = %d want %d", out.Error.Code, protocol.InvalidParams)
	}
}

func TestTranslateLegacyResultInjectsResultType(t *testing.T) {
	t.Parallel()
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{"x":1}`)}
	out, err := TranslateLegacyResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out.Result, &obj); err != nil {
		t.Fatal(err)
	}
	var rt string
	if err := json.Unmarshal(obj[resultTypeField], &rt); err != nil {
		t.Fatal(err)
	}
	if rt != protocol.ResultComplete {
		t.Fatalf("resultType = %q want %q", rt, protocol.ResultComplete)
	}
}

func TestTranslateLegacyResultPreservesExistingResultType(t *testing.T) {
	t.Parallel()
	resp := &jsonrpc.Response{
		JSONRPC: jsonrpc.Version,
		Result:  json.RawMessage(`{"resultType":"input_required"}`),
	}
	out, err := TranslateLegacyResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]string
	if err := json.Unmarshal(out.Result, &obj); err != nil {
		t.Fatal(err)
	}
	if obj[resultTypeField] != protocol.ResultInputRequired {
		t.Fatalf("resultType overwritten: %q", obj[resultTypeField])
	}
}

func TestMemoryHeldStoreSingleUse(t *testing.T) {
	t.Parallel()
	s := NewMemoryHeldStore()
	ctx := context.Background()
	req := &HeldRequest{UpstreamID: "u1", Method: "sampling/createMessage"}
	if err := s.Put(ctx, "id1", req, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := s.Consume(ctx, "id1")
	if err != nil || got.UpstreamID != "u1" {
		t.Fatalf("first Consume = %v,%v", got, err)
	}
	if _, err := s.Consume(ctx, "id1"); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("second Consume err = %v want ErrHeldNotFound", err)
	}
}

func TestMemoryHeldStoreExpiry(t *testing.T) {
	t.Parallel()
	ms := &memoryHeldStore{now: func() time.Time { return time.Unix(100, 0) }, entries: map[string]memoryHeldEntry{}}
	_ = ms.Put(context.Background(), "id1", &HeldRequest{UpstreamID: "u1"}, time.Second)
	ms.now = func() time.Time { return time.Unix(200, 0) }
	if _, err := ms.Consume(context.Background(), "id1"); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("expired Consume err = %v want ErrHeldNotFound", err)
	}
}

func TestShouldDropDownstream(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"logging/setLevel", "ping", "notifications/roots/list_changed"} {
		if !shouldDropDownstream(m) {
			t.Fatalf("method %q should be dropped downstream (HUB-707)", m)
		}
	}
	if shouldDropDownstream("notifications/resources/updated") {
		t.Fatal("resources/updated must be relayed downstream")
	}
}

func TestIsModernErrorBody(t *testing.T) {
	t.Parallel()
	modern := `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"bad version"}}`
	if !isModernErrorBody(modern) {
		t.Fatal("expected modern error body to be recognized (HUB-721)")
	}
	legacy := `{"error":"session required"}`
	if isModernErrorBody(legacy) {
		t.Fatal("legacy body must not be recognized as modern")
	}
}
