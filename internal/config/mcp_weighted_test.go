package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMCPRoute_UpstreamRefs verifies the canonical helper returns the weighted
// refs when set, else maps the legacy list to zero-weight refs.
func TestMCPRoute_UpstreamRefs(t *testing.T) {
	// Legacy list -> zero-weight refs, order preserved.
	legacy := &MCPRoute{Upstreams: []string{"a", "b"}}
	refs := legacy.UpstreamRefs()
	if len(refs) != 2 || refs[0] != (MCPUpstreamRef{Name: "a"}) || refs[1] != (MCPUpstreamRef{Name: "b"}) {
		t.Fatalf("legacy UpstreamRefs = %+v", refs)
	}

	// Weighted list -> returned as-is.
	weighted := &MCPRoute{WeightedUpstreams: []MCPUpstreamRef{{Name: "x", Weight: 70}, {Name: "y", Weight: 30}}}
	refs = weighted.UpstreamRefs()
	if len(refs) != 2 || refs[0].Weight != 70 || refs[1].Weight != 30 {
		t.Fatalf("weighted UpstreamRefs = %+v", refs)
	}

	// Empty route -> empty refs.
	if got := (&MCPRoute{}).UpstreamRefs(); len(got) != 0 {
		t.Fatalf("empty UpstreamRefs = %+v", got)
	}
}

// TestMCPRoute_UpstreamNames verifies all names are returned regardless of
// weight (full fan-out is never reduced by weighting).
func TestMCPRoute_UpstreamNames(t *testing.T) {
	r := &MCPRoute{WeightedUpstreams: []MCPUpstreamRef{{Name: "x", Weight: 100}, {Name: "y", Weight: 0}}}
	names := r.UpstreamNames()
	if len(names) != 2 || names[0] != "x" || names[1] != "y" {
		t.Fatalf("UpstreamNames = %v (zero-weight upstream must not be dropped)", names)
	}
}

// TestMCPRoute_UpstreamRefs_BothSetPrefersWeighted asserts that when both
// Upstreams and WeightedUpstreams are set, the canonical helper returns the
// weighted list (the "both set" case is a validation error handled elsewhere;
// the helper itself is deterministic, not silent-drop). Full name list is
// derived from the returned refs.
func TestMCPRoute_UpstreamRefs_BothSetPrefersWeighted(t *testing.T) {
	r := &MCPRoute{
		Upstreams:         []string{"legacy"},
		WeightedUpstreams: []MCPUpstreamRef{{Name: "w1", Weight: 60}, {Name: "w2", Weight: 40}},
	}
	refs := r.UpstreamRefs()
	require.Len(t, refs, 2)
	assert.Equal(t, "w1", refs[0].Name)
	assert.Equal(t, 60, refs[0].Weight)
	assert.Equal(t, []string{"w1", "w2"}, r.UpstreamNames())
}

// TestMCPRoute_UpstreamNames_Legacy asserts the legacy list produces the full
// name list in order.
func TestMCPRoute_UpstreamNames_Legacy(t *testing.T) {
	r := &MCPRoute{Upstreams: []string{"a", "b", "c"}}
	assert.Equal(t, []string{"a", "b", "c"}, r.UpstreamNames())
}

// mcpWeightedSpec returns a spec with two MCPBackends (a, b) and a route whose
// weighted upstreams are supplied by the caller. It is the base for the weighted
// validator matrix, routed through validateMCP so both validateMCPUpstreams and
// validateMCPWeightedUpstreams light up.
func mcpWeightedSpec(refs []MCPUpstreamRef) GatewaySpec {
	return GatewaySpec{
		Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
		MCPBackends: []MCPBackend{
			{Name: "a", Hosts: []BackendHost{{Address: "10.0.0.1", Port: 9000}}},
			{Name: "b", Hosts: []BackendHost{{Address: "10.0.0.2", Port: 9000}}},
		},
		MCPRoutes: []MCPRoute{
			{Name: "mcp-route", WeightedUpstreams: refs},
		},
	}
}

// TestValidateMCPWeightedUpstreams_Matrix drives the full weighted-upstream
// validation matrix through validateMCP.
func TestValidateMCPWeightedUpstreams_Matrix(t *testing.T) {
	tests := []struct {
		name        string
		refs        []MCPUpstreamRef
		wantErr     bool
		errContains string
		wantWarn    bool
	}{
		{
			name: "valid 90/10",
			refs: []MCPUpstreamRef{{Name: "a", Weight: 90}, {Name: "b", Weight: 10}},
		},
		{
			name: "all-zero uniform allowed",
			refs: []MCPUpstreamRef{{Name: "a"}, {Name: "b"}},
		},
		{
			name:     "single zero-weight allowed (sum rule skipped)",
			refs:     []MCPUpstreamRef{{Name: "a"}},
			wantErr:  false,
			wantWarn: false,
		},
		{
			name:        "sum != 100",
			refs:        []MCPUpstreamRef{{Name: "a", Weight: 50}, {Name: "b", Weight: 40}},
			wantErr:     true,
			errContains: "weights must sum to 100, got 90",
		},
		{
			name:        "weight below range",
			refs:        []MCPUpstreamRef{{Name: "a", Weight: -1}, {Name: "b", Weight: 101}},
			wantErr:     true,
			errContains: "weight must be between 0 and 100",
			// -1 counts as zero-weight while 101 is positive, so the mixed
			// zero/positive transparency warning is also emitted.
			wantWarn: true,
		},
		{
			name:        "weight above range",
			refs:        []MCPUpstreamRef{{Name: "a", Weight: 101}},
			wantErr:     true,
			errContains: "weight must be between 0 and 100",
		},
		{
			name:        "empty name",
			refs:        []MCPUpstreamRef{{Name: "", Weight: 100}},
			wantErr:     true,
			errContains: "upstream name is required",
		},
		{
			name:        "unknown backend",
			refs:        []MCPUpstreamRef{{Name: "ghost", Weight: 100}},
			wantErr:     true,
			errContains: "references unknown MCP upstream",
		},
		{
			name:     "mixed zero/positive warns",
			refs:     []MCPUpstreamRef{{Name: "a", Weight: 100}, {Name: "b", Weight: 0}},
			wantErr:  false,
			wantWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator()
			spec := mcpWeightedSpec(tt.refs)
			v.validateMCPRoutes(spec.MCPRoutes, spec.MCPBackends)
			v.validateMCPBackends(spec.MCPBackends)

			if tt.wantErr {
				require.True(t, v.errors.HasErrors(), "expected an error")
				if tt.errContains != "" {
					assert.Contains(t, v.errors.Error(), tt.errContains)
				}
			} else {
				assert.False(t, v.errors.HasErrors(), v.errors.Error())
			}
			if tt.wantWarn {
				assert.NotEmpty(t, v.Warnings(), "expected a mixed-weight warning")
			} else {
				assert.Empty(t, v.Warnings())
			}
		})
	}
}

// TestValidateMCPUpstreams_BothSet asserts the one-of exclusivity error when both
// Upstreams and WeightedUpstreams are configured.
func TestValidateMCPUpstreams_BothSet(t *testing.T) {
	spec := GatewaySpec{
		Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
		MCPBackends: []MCPBackend{
			{Name: "a", Hosts: []BackendHost{{Address: "10.0.0.1", Port: 9000}}},
			{Name: "b", Hosts: []BackendHost{{Address: "10.0.0.2", Port: 9000}}},
		},
		MCPRoutes: []MCPRoute{
			{
				Name:              "mcp-route",
				Upstreams:         []string{"a"},
				WeightedUpstreams: []MCPUpstreamRef{{Name: "b", Weight: 100}},
			},
		},
	}
	errs := validateMCP(spec)
	require.True(t, errs.HasErrors())
	assert.Contains(t, errs.Error(), "only one of upstreams or weightedUpstreams may be set")
}
