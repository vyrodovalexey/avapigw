// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"encoding/json"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// TestMCPRouteWeightedUpstreams_JSONRoundTrip proves the operator apply path
// (json.Marshal(mcpRoute.Spec) -> gateway json.Unmarshal into config.MCPRoute)
// preserves WeightedUpstreams exactly. A json-tag mismatch between the CRD and
// config types would silently drop the field here (P0-9).
func TestMCPRouteWeightedUpstreams_JSONRoundTrip(t *testing.T) {
	spec := avapigwv1alpha1.MCPRouteSpec{
		WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "backend-stable", Weight: 90},
			{Name: "backend-canary", Weight: 10},
		},
	}

	// Operator side: marshal the CRD spec (mirrors mcproute_controller.go:96).
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal MCPRouteSpec: %v", err)
	}

	// Gateway side: unmarshal into config.MCPRoute.
	var route config.MCPRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal into config.MCPRoute: %v", err)
	}

	if len(route.WeightedUpstreams) != 2 {
		t.Fatalf("weightedUpstreams dropped: got %d, want 2 (raw=%s)",
			len(route.WeightedUpstreams), raw)
	}
	want := []config.MCPUpstreamRef{
		{Name: "backend-stable", Weight: 90},
		{Name: "backend-canary", Weight: 10},
	}
	for i, w := range want {
		if route.WeightedUpstreams[i] != w {
			t.Errorf("ref[%d] = %+v, want %+v", i, route.WeightedUpstreams[i], w)
		}
	}
}

// TestMCPRouteLegacyUpstreams_JSONRoundTrip confirms the legacy Upstreams list
// still survives the same apply path unchanged (backward compatibility).
func TestMCPRouteLegacyUpstreams_JSONRoundTrip(t *testing.T) {
	spec := avapigwv1alpha1.MCPRouteSpec{Upstreams: []string{"a", "b"}}

	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal MCPRouteSpec: %v", err)
	}

	var route config.MCPRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal into config.MCPRoute: %v", err)
	}

	if len(route.WeightedUpstreams) != 0 {
		t.Errorf("weightedUpstreams should be empty, got %d", len(route.WeightedUpstreams))
	}
	if got := route.UpstreamNames(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("UpstreamNames() = %v, want [a b]", got)
	}
}
