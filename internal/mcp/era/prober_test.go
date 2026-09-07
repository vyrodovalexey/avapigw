package era

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

func TestNewHTTPProberNilLogger(t *testing.T) {
	t.Parallel()
	p := NewHTTPProber(func(context.Context, string) (*jsonrpc.Response, error) {
		return nil, nil
	}, nil)
	// Should not panic on Debug via a legacy classification.
	if got, _ := p.Probe(context.Background(), "u1", "u1"); got != EraLegacy {
		t.Fatalf("era = %v want legacy", got)
	}
}

func TestProbeModern(t *testing.T) {
	t.Parallel()
	p := NewHTTPProber(func(context.Context, string) (*jsonrpc.Response, error) {
		return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, nil
	}, nil)
	got, err := p.Probe(context.Background(), "u1", "u1")
	if err != nil || got != EraModern {
		t.Fatalf("Probe = %v,%v", got, err)
	}
}

func TestProbeLegacyNilResp(t *testing.T) {
	t.Parallel()
	p := NewHTTPProber(func(context.Context, string) (*jsonrpc.Response, error) {
		return nil, nil
	}, nil)
	got, err := p.Probe(context.Background(), "u1", "u1")
	if err != nil || got != EraLegacy {
		t.Fatalf("Probe = %v,%v", got, err)
	}
}

func TestProbeErrorClassify(t *testing.T) {
	t.Parallel()
	p := NewHTTPProber(func(context.Context, string) (*jsonrpc.Response, error) {
		return nil, &mcpproxy.UpstreamError{
			StatusCode: http.StatusBadRequest,
			Body:       `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"x"}}`,
		}
	}, nil)
	got, err := p.Probe(context.Background(), "u1", "u1")
	if err != nil || got != EraModern {
		t.Fatalf("Probe = %v,%v", got, err)
	}
}

func TestClassifyProbeError(t *testing.T) {
	t.Parallel()
	p := NewHTTPProber(nil, nil)
	tests := []struct {
		name string
		err  error
		want Era
	}{
		{"transport error", errors.New("connection refused"), EraLegacy},
		{"400 modern body", &mcpproxy.UpstreamError{StatusCode: 400, Body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"x"}}`}, EraModern},
		{"400 non-modern body", &mcpproxy.UpstreamError{StatusCode: 400, Body: `{"error":"session required"}`}, EraLegacy},
		{"500 upstream error", &mcpproxy.UpstreamError{StatusCode: 500, Body: ""}, EraLegacy},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := p.classifyProbeError("u1", tt.err); got != tt.want {
				t.Fatalf("classifyProbeError=%v want %v", got, tt.want)
			}
		})
	}
}

func TestIsModernErrorBodyCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"invalid json", "{bad", false},
		{"wrong version", `{"jsonrpc":"1.0","error":{"code":-32022}}`, false},
		{"nil error", `{"jsonrpc":"2.0","id":1}`, false},
		{"modern code", `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"x"}}`, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isModernErrorBody(tt.body); got != tt.want {
				t.Fatalf("isModernErrorBody=%v want %v", got, tt.want)
			}
		})
	}
}

func TestIsModernErrorCode(t *testing.T) {
	t.Parallel()
	modern := []int{
		protocol.UnsupportedProtocolVersion,
		protocol.InvalidParams,
		protocol.MissingRequiredClientCapability,
		protocol.HeaderMismatch,
	}
	for _, code := range modern {
		if !isModernErrorCode(code) {
			t.Fatalf("code %d should be modern", code)
		}
	}
	if isModernErrorCode(-32000) {
		t.Fatal("arbitrary code should not be modern")
	}
}
