package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestMatchMCPRoute_CatchAll(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{{Name: "catch-all"}}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)

	match := matchMCPRoute(routes, r, "tools/call", "weather")
	require.NotNil(t, match)
	assert.Equal(t, "catch-all", match.Name)
}

func TestMatchMCPRoute_ByMethod(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{
		{Name: "tools", Match: []config.MCPRouteMatch{{Method: "tools/call"}}},
		{Name: "prompts", Match: []config.MCPRouteMatch{{Method: "prompts/get"}}},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)

	match := matchMCPRoute(routes, r, "prompts/get", "greeting")
	require.NotNil(t, match)
	assert.Equal(t, "prompts", match.Name)
}

func TestMatchMCPRoute_ByName(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{
		{Name: "weather", Match: []config.MCPRouteMatch{{Name: &config.StringMatch{Exact: "weather"}}}},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)

	assert.NotNil(t, matchMCPRoute(routes, r, "tools/call", "weather"))
	assert.Nil(t, matchMCPRoute(routes, r, "tools/call", "other"))
}

func TestMatchMCPRoute_ByPath(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{
		{Name: "p", Match: []config.MCPRouteMatch{{Path: &config.StringMatch{Prefix: "/mcp"}}}},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp/v2", http.NoBody)

	assert.NotNil(t, matchMCPRoute(routes, r, "tools/call", ""))
}

func TestMatchMCPRoute_ByHeaders(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{
		{Name: "tenant", Match: []config.MCPRouteMatch{
			{Headers: []config.HeaderMatchConfig{{Name: "X-Tenant", Exact: "acme"}}},
		}},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	r.Header.Set("X-Tenant", "acme")

	assert.NotNil(t, matchMCPRoute(routes, r, "tools/call", ""))

	r2 := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	assert.Nil(t, matchMCPRoute(routes, r2, "tools/call", ""))
}

func TestMatchMCPRoute_NoMatch(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{
		{Name: "tools", Match: []config.MCPRouteMatch{{Method: "tools/call"}}},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)

	assert.Nil(t, matchMCPRoute(routes, r, "resources/read", "file://x"))
}

func TestMatchMCPRoute_AndConditions(t *testing.T) {
	t.Parallel()

	routes := []config.MCPRoute{
		{Name: "both", Match: []config.MCPRouteMatch{
			{Method: "tools/call", Name: &config.StringMatch{Exact: "weather"}},
		}},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)

	assert.NotNil(t, matchMCPRoute(routes, r, "tools/call", "weather"))
	assert.Nil(t, matchMCPRoute(routes, r, "tools/call", "other"))
}

func TestStringMatchMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sm       *config.StringMatch
		value    string
		expected bool
	}{
		{name: "empty always matches", sm: &config.StringMatch{}, value: "x", expected: true},
		{name: "exact match", sm: &config.StringMatch{Exact: "abc"}, value: "abc", expected: true},
		{name: "exact mismatch", sm: &config.StringMatch{Exact: "abc"}, value: "abd", expected: false},
		{name: "prefix match", sm: &config.StringMatch{Prefix: "ab"}, value: "abc", expected: true},
		{name: "prefix mismatch", sm: &config.StringMatch{Prefix: "xy"}, value: "abc", expected: false},
		{name: "regex match", sm: &config.StringMatch{Regex: "^a.c$"}, value: "abc", expected: true},
		{name: "regex mismatch", sm: &config.StringMatch{Regex: "^a.c$"}, value: "xyz", expected: false},
		{name: "invalid regex", sm: &config.StringMatch{Regex: "["}, value: "abc", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, stringMatchMatches(tt.sm, tt.value))
		})
	}
}

func TestHeaderMatchMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hm       config.HeaderMatchConfig
		header   http.Header
		expected bool
	}{
		{
			name:     "exact match",
			hm:       config.HeaderMatchConfig{Name: "X-A", Exact: "v"},
			header:   http.Header{"X-A": {"v"}},
			expected: true,
		},
		{
			name:     "exact mismatch",
			hm:       config.HeaderMatchConfig{Name: "X-A", Exact: "v"},
			header:   http.Header{"X-A": {"w"}},
			expected: false,
		},
		{
			name:     "prefix match",
			hm:       config.HeaderMatchConfig{Name: "X-A", Prefix: "Bearer "},
			header:   http.Header{"X-A": {"Bearer abc"}},
			expected: true,
		},
		{
			name:     "regex match",
			hm:       config.HeaderMatchConfig{Name: "X-A", Regex: "^[0-9]+$"},
			header:   http.Header{"X-A": {"123"}},
			expected: true,
		},
		{
			name:     "invalid regex",
			hm:       config.HeaderMatchConfig{Name: "X-A", Regex: "["},
			header:   http.Header{"X-A": {"123"}},
			expected: false,
		},
		{
			name:     "name only present",
			hm:       config.HeaderMatchConfig{Name: "X-A"},
			header:   http.Header{"X-A": {"anything"}},
			expected: true,
		},
		{
			name:     "name only absent",
			hm:       config.HeaderMatchConfig{Name: "X-A"},
			header:   http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hm := tt.hm
			assert.Equal(t, tt.expected, headerMatchMatches(&hm, tt.header))
		})
	}
}
