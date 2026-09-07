package era

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
)

// ---------------------------------------------------------------------------
// era.go residual
// ---------------------------------------------------------------------------

func TestMetricLabel(t *testing.T) {
	t.Parallel()
	if got := EraLegacy.metricLabel(); got != mcpmetrics.EraLegacy {
		t.Fatalf("EraLegacy.metricLabel()=%q want %q", got, mcpmetrics.EraLegacy)
	}
	if got := EraModern.metricLabel(); got != mcpmetrics.EraModern {
		t.Fatalf("EraModern.metricLabel()=%q want %q", got, mcpmetrics.EraModern)
	}
}

func TestNewDeterminerNilArgs(t *testing.T) {
	t.Parallel()
	d := NewDeterminer(nil, nil)
	if d == nil {
		t.Fatal("nil determiner")
	}
	p := &stubProber{era: EraModern}
	got, err := d.Determine(context.Background(), "u1", "u1", "", "", p)
	if err != nil || got != EraModern {
		t.Fatalf("Determine = %v,%v", got, err)
	}
}

func TestDetermineProbeError(t *testing.T) {
	t.Parallel()
	d := NewDeterminer(NewEraCache(), nil)
	p := &stubProber{err: errors.New("probe failed")}
	got, err := d.Determine(context.Background(), "u1", "u1", "", "", p)
	if err == nil {
		t.Fatal("expected error from probe")
	}
	if got != EraUnknown {
		t.Fatalf("era = %v want EraUnknown", got)
	}
}

// ---------------------------------------------------------------------------
// translate.go quick wins
// ---------------------------------------------------------------------------

func TestTranslateLegacyResultNil(t *testing.T) {
	t.Parallel()
	out, err := TranslateLegacyResult(nil)
	if out != nil || err != nil {
		t.Fatalf("TranslateLegacyResult(nil) = %v,%v", out, err)
	}
}

func TestTranslateLegacyResultEmptyResult(t *testing.T) {
	t.Parallel()
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: nil}
	out, err := TranslateLegacyResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	if out != resp {
		t.Fatal("empty result should be returned unchanged")
	}
}

func TestTranslateLegacyResultNonObject(t *testing.T) {
	t.Parallel()
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage("[1,2]")}
	out, err := TranslateLegacyResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Result) != "[1,2]" {
		t.Fatalf("non-object result changed: %q", string(out.Result))
	}
}

func TestTranslateLegacyResultInvalidJSON(t *testing.T) {
	t.Parallel()
	resp := &jsonrpc.Response{JSONRPC: jsonrpc.Version, Result: json.RawMessage("{bad")}
	out, err := TranslateLegacyResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Result) != "{bad" {
		t.Fatalf("invalid-json result changed: %q", string(out.Result))
	}
}
