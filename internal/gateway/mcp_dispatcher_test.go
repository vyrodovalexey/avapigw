package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func markerHandler(marker string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(marker))
	})
}

func TestMCPPathDispatcher_RoutesToMCP(t *testing.T) {
	t.Parallel()

	d := NewMCPPathDispatcher("/mcp", markerHandler("mcp"), markerHandler("next"))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	d.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "mcp", rec.Body.String())
}

func TestMCPPathDispatcher_RoutesToNext(t *testing.T) {
	t.Parallel()

	d := NewMCPPathDispatcher("/mcp", markerHandler("mcp"), markerHandler("next"))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/other", http.NoBody)
	d.ServeHTTP(rec, r)

	assert.Equal(t, "next", rec.Body.String())
}

func TestMCPPathDispatcher_DefaultPath(t *testing.T) {
	t.Parallel()

	d := NewMCPPathDispatcher("", markerHandler("mcp"), markerHandler("next"))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, config.DefaultMCPPath, http.NoBody)
	d.ServeHTTP(rec, r)

	assert.Equal(t, "mcp", rec.Body.String())
}

func TestMCPPathDispatcher_NilMCPHandler(t *testing.T) {
	t.Parallel()

	d := NewMCPPathDispatcher("/mcp", nil, markerHandler("next"))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	d.ServeHTTP(rec, r)

	// nil mcp handler => everything falls through to next.
	assert.Equal(t, "next", rec.Body.String())
}

func TestMCPPathDispatcher_WithWellKnown(t *testing.T) {
	t.Parallel()

	d := NewMCPPathDispatcher("/mcp", markerHandler("mcp"), markerHandler("next")).
		WithWellKnown("/.well-known/oauth-protected-resource", markerHandler("well-known"))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	d.ServeHTTP(rec, r)

	assert.Equal(t, "well-known", rec.Body.String())
}

func TestMCPPathDispatcher_WellKnownNotMatched(t *testing.T) {
	t.Parallel()

	d := NewMCPPathDispatcher("/mcp", markerHandler("mcp"), markerHandler("next")).
		WithWellKnown("/.well-known/oauth-protected-resource", markerHandler("well-known"))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	d.ServeHTTP(rec, r)

	assert.Equal(t, "mcp", rec.Body.String())
}

func TestMCPPathFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *config.GatewayConfig
		expected string
	}{
		{name: "nil config", cfg: nil, expected: config.DefaultMCPPath},
		{
			name:     "nil MCP section",
			cfg:      &config.GatewayConfig{},
			expected: config.DefaultMCPPath,
		},
		{
			name: "custom path",
			cfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{MCP: &config.MCPConfig{Path: "/rpc"}},
			},
			expected: "/rpc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, MCPPathFromConfig(tt.cfg))
		})
	}
}
