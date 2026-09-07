package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// TestValidateUpstreamRefs_Weighted is a compile-smoke test over the weighted
// upstream admission rules (range, sum, both-set exclusivity).
func TestValidateUpstreamRefs_Weighted(t *testing.T) {
	v := &MCPRouteValidator{}

	tests := []struct {
		name    string
		spec    avapigwv1alpha1.MCPRouteSpec
		wantErr bool
	}{
		{
			name: "valid weighted 90/10",
			spec: avapigwv1alpha1.MCPRouteSpec{WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{
				{Name: "a", Weight: 90}, {Name: "b", Weight: 10},
			}},
		},
		{
			name: "all-zero allowed (uniform)",
			spec: avapigwv1alpha1.MCPRouteSpec{WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{
				{Name: "a"}, {Name: "b"},
			}},
		},
		{
			name: "sum != 100 rejected",
			spec: avapigwv1alpha1.MCPRouteSpec{WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{
				{Name: "a", Weight: 50}, {Name: "b", Weight: 40},
			}},
			wantErr: true,
		},
		{
			name: "weight out of range rejected",
			spec: avapigwv1alpha1.MCPRouteSpec{WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{
				{Name: "a", Weight: 200},
			}},
			wantErr: true,
		},
		{
			name: "empty name rejected",
			spec: avapigwv1alpha1.MCPRouteSpec{WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{
				{Name: "  ", Weight: 100},
			}},
			wantErr: true,
		},
		{
			name: "both forms rejected",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams:         []string{"a"},
				WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{{Name: "b", Weight: 100}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateUpstreamRefs(&tt.spec)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestWarnMixedWeightedUpstreams checks the mixed zero/positive warning fires.
func TestWarnMixedWeightedUpstreams(t *testing.T) {
	warnings := warnMixedWeightedUpstreams([]avapigwv1alpha1.MCPUpstreamRef{
		{Name: "a", Weight: 100}, {Name: "b", Weight: 0},
	})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 mixed-weight warning, got %d", len(warnings))
	}
	if none := warnMixedWeightedUpstreams([]avapigwv1alpha1.MCPUpstreamRef{
		{Name: "a"}, {Name: "b"},
	}); len(none) != 0 {
		t.Fatalf("all-zero should not warn, got %d", len(none))
	}
}

// TestValidateWeightedUpstreams_Matrix exercises validateWeightedUpstreams
// directly across the full admission matrix, including the len==0 guard.
func TestValidateWeightedUpstreams_Matrix(t *testing.T) {
	t.Parallel()

	v := &MCPRouteValidator{}
	tests := []struct {
		name    string
		refs    []avapigwv1alpha1.MCPUpstreamRef
		wantErr bool
	}{
		{name: "empty is rejected", refs: nil, wantErr: true},
		{name: "valid 90/10", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: 90}, {Name: "b", Weight: 10}}},
		{name: "all-zero allowed", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a"}, {Name: "b"}}},
		{name: "single allowed", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: 50}}},
		{name: "sum != 100", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: 50}, {Name: "b", Weight: 40}}, wantErr: true},
		{name: "weight below min", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: -1}}, wantErr: true},
		{name: "weight above max", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: 101}}, wantErr: true},
		{name: "empty name", refs: []avapigwv1alpha1.MCPUpstreamRef{{Name: "  ", Weight: 100}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateWeightedUpstreams(tt.refs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMCPRoute_ValidateCreate_RejectsBadWeight asserts a bad-weight weighted
// MCPRoute is rejected at admission.
func TestMCPRoute_ValidateCreate_RejectsBadWeight(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	spec := avapigwv1alpha1.MCPRouteSpec{
		Match:             []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
		WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: 50}, {Name: "b", Weight: 40}},
	}
	route := newMCPRouteWithSpec("bad-weight", "default", spec)

	_, err := validator.ValidateCreate(context.Background(), route)
	require.Error(t, err, "sum != 100 must be rejected")
}

// TestMCPRoute_ValidateCreate_AdmitsWeighted asserts a valid weighted MCPRoute is
// admitted and the mixed zero/positive warning is surfaced.
func TestMCPRoute_ValidateCreate_AdmitsWeighted(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	spec := avapigwv1alpha1.MCPRouteSpec{
		Match:             []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
		WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{{Name: "stable", Weight: 100}, {Name: "canary", Weight: 0}},
	}
	route := newMCPRouteWithSpec("weighted-ok", "default", spec)

	warnings, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err)
	assert.NotEmpty(t, warnings, "mixed zero/positive weights must emit an admission warning")
}

// TestMCPRoute_ValidateUpdate_RejectsBadWeight asserts a spec-changing update to
// a bad-weight weighted MCPRoute is rejected.
func TestMCPRoute_ValidateUpdate_RejectsBadWeight(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	oldRoute := newMCPRouteWithSpec("upd", "default", newValidMCPRouteSpec())
	newSpec := avapigwv1alpha1.MCPRouteSpec{
		Match:             []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
		WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{{Name: "a", Weight: 30}, {Name: "b", Weight: 30}},
	}
	newRoute := newMCPRouteWithSpec("upd", "default", newSpec)

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	require.Error(t, err)
}
