//go:build functional
// +build functional

package functional

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// selectedTotal reads the mcp_upstream_selected_total counter for a route +
// upstream from the MCP metrics singleton used by the in-process handler.
func selectedTotal(route, upstream string) float64 {
	return testutil.ToFloat64(
		mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(route, upstream))
}

// driveWeightedCalls posts N single-upstream tools/call requests through the
// gateway. The tool name is BARE (no namespace prefix) so owner-pinning does not
// short-circuit weighted selection: every request is a candidate for weighted
// routing across the route's upstreams. Callers observe where traffic landed via
// the fake upstreams' callCount and/or the selection counter.
func driveWeightedCalls(t *testing.T, gi *helpers.MCPGatewayInstance, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		// Bare tool name "echo": Denamespace("echo") yields no owner so the
		// request falls through to weighted-random selection (HUB-501).
		body := helpers.MCPRequestBody{
			Method:    helpers.MCPMethodToolsCall,
			Name:      "echo",
			Arguments: map[string]any{"message": "w"},
			ID:        i + 1,
		}.MustBuild()
		resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
			Method: helpers.MCPMethodToolsCall,
			Name:   "echo",
		})
		require.NoError(t, err)
		rpc, err := helpers.DecodeMCPResponse(resp)
		require.NoError(t, err)
		require.Nil(t, rpc.Error, "weighted tools/call must succeed")
		resp.Body.Close()
	}
}

// weightedBackends builds two fake MCP upstreams and returns the fakes plus
// their MCPBackends named by the provided ids. The namespace prefix is set to a
// value that will never match the bare "echo" tool used by the distribution
// driver, so owner-pinning never pre-empts weighted selection.
func weightedBackends(
	t *testing.T, idA, idB string,
) (*fakeMCPUpstream, *fakeMCPUpstream, config.MCPBackend, config.MCPBackend) {
	t.Helper()
	upA := newFakeMCPUpstream(t)
	upB := newFakeMCPUpstream(t)
	beA, err := helpers.MCPBackendFromURL(idA, upA.URL())
	require.NoError(t, err)
	beB, err := helpers.MCPBackendFromURL(idB, upB.URL())
	require.NoError(t, err)
	return upA, upB, beA, beB
}

// TestFunctional_MCP_WeightedRouting_Distribution configures an MCPRoute with
// WeightedUpstreams 80/20 across two upstreams, drives a large number of
// single-upstream (tools/call) requests, and asserts the observed per-upstream
// distribution is approximately proportional within tolerance. The selected
// upstream is confirmed via the mcp_upstream_selected_total counter AND the
// per-upstream call counts on the fake upstreams (audit/metrics attribution).
func TestFunctional_MCP_WeightedRouting_Distribution(t *testing.T) {
	const (
		routeName = "mcp-weight-distribution"
		idStable  = "stable"
		idCanary  = "canary"
		n         = 2000
		// tolerance is generous enough to keep the test deterministic-in-practice
		// (binomial std-dev at 80/20 over 2000 draws is ~0.9%), while still
		// catching a broken split (e.g. 100/0 or 50/50).
		tolerance = 0.06 // 6 percentage points
	)

	upStable, upCanary, beStable, beCanary := weightedBackends(t, idStable, idCanary)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		RouteName: routeName,
		Backends:  []config.MCPBackend{beStable, beCanary},
		WeightedUpstreams: []config.MCPUpstreamRef{
			{Name: idStable, Weight: 80},
			{Name: idCanary, Weight: 20},
		},
	})

	beforeStable := selectedTotal(routeName, idStable)
	beforeCanary := selectedTotal(routeName, idCanary)

	driveWeightedCalls(t, gi, n)

	// Per-upstream attribution via the actual fake upstreams that served the
	// requests (the ground truth for where traffic landed).
	stableHits := upStable.callCount.Load()
	canaryHits := upCanary.callCount.Load()
	require.Equal(t, int64(n), stableHits+canaryHits,
		"every weighted request must land on exactly one upstream")

	stableFrac := float64(stableHits) / float64(n)
	canaryFrac := float64(canaryHits) / float64(n)
	t.Logf("weighted distribution 80/20: stable=%d (%.1f%%) canary=%d (%.1f%%) over N=%d",
		stableHits, stableFrac*100, canaryHits, canaryFrac*100, n)

	assert.InDelta(t, 0.80, stableFrac, tolerance,
		"stable upstream must receive ~80%% of single-upstream traffic")
	assert.InDelta(t, 0.20, canaryFrac, tolerance,
		"canary upstream must receive ~20%% of single-upstream traffic")

	// The mcp_upstream_selected_total counter must reflect the selection and
	// attribute per upstream (route+upstream labels). The counter is only
	// incremented when there is more than one live candidate (a genuine split).
	deltaStable := selectedTotal(routeName, idStable) - beforeStable
	deltaCanary := selectedTotal(routeName, idCanary) - beforeCanary
	assert.Equal(t, float64(stableHits), deltaStable,
		"mcp_upstream_selected_total{stable} must match observed stable hits")
	assert.Equal(t, float64(canaryHits), deltaCanary,
		"mcp_upstream_selected_total{canary} must match observed canary hits")
	assert.Equal(t, float64(n), deltaStable+deltaCanary,
		"the selection counter must account for every weighted request")
}

// TestFunctional_MCP_WeightedRouting_ZeroWeightCanary asserts a zero-weight
// upstream receives ~0% of traffic when a sibling has a positive weight (a 0%
// canary gets exactly 0%, not a residual share), mirroring APIRoute semantics.
func TestFunctional_MCP_WeightedRouting_ZeroWeightCanary(t *testing.T) {
	const (
		routeName = "mcp-weight-zero"
		idLive    = "live"
		idDark    = "dark"
		n         = 500
	)

	upLive, upDark, beLive, beDark := weightedBackends(t, idLive, idDark)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		RouteName: routeName,
		Backends:  []config.MCPBackend{beLive, beDark},
		WeightedUpstreams: []config.MCPUpstreamRef{
			{Name: idLive, Weight: 100},
			{Name: idDark, Weight: 0},
		},
	})

	driveWeightedCalls(t, gi, n)

	assert.Equal(t, int64(n), upLive.callCount.Load(),
		"the positive-weight upstream must receive ALL traffic")
	assert.Equal(t, int64(0), upDark.callCount.Load(),
		"a zero-weight upstream must receive exactly 0%% (0% canary)")
}

// TestFunctional_MCP_WeightedRouting_AllEqualUniform asserts that all-equal (and
// all-zero, which is the same "no weights configured" case) yields an
// approximately uniform split across the candidates.
func TestFunctional_MCP_WeightedRouting_AllEqualUniform(t *testing.T) {
	cases := []struct {
		name    string
		weights [2]int
	}{
		{name: "all-zero uniform", weights: [2]int{0, 0}},
		{name: "all-equal 50/50", weights: [2]int{50, 50}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			const n = 2000
			routeName := "mcp-weight-uniform-" + tc.name
			upA, _, beA, beB := weightedBackends(t, "left", "right")

			gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
				RouteName: routeName,
				Backends:  []config.MCPBackend{beA, beB},
				WeightedUpstreams: []config.MCPUpstreamRef{
					{Name: "left", Weight: tc.weights[0]},
					{Name: "right", Weight: tc.weights[1]},
				},
			})

			driveWeightedCalls(t, gi, n)

			leftFrac := float64(upA.callCount.Load()) / float64(n)
			t.Logf("%s: left=%.1f%% right=%.1f%% over N=%d",
				tc.name, leftFrac*100, (1-leftFrac)*100, n)
			assert.InDelta(t, 0.50, leftFrac, 0.06,
				"all-equal/all-zero weights must yield ~uniform distribution")
		})
	}
}

// TestFunctional_MCP_WeightedRouting_LegacyBackwardCompat confirms an MCPRoute
// using the legacy Upstreams []string still works: a single legacy upstream
// routes to that upstream, and multiple legacy upstreams distribute (uniform,
// equal weight) across all of them.
func TestFunctional_MCP_WeightedRouting_LegacyBackwardCompat(t *testing.T) {
	t.Run("single legacy upstream routes to that upstream", func(t *testing.T) {
		up := newFakeMCPUpstream(t)
		be, err := helpers.MCPBackendFromURL("only", up.URL())
		require.NoError(t, err)

		gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
			RouteName: "mcp-legacy-single",
			Backends:  []config.MCPBackend{be}, // legacy Upstreams derived from Backends
		})

		const n = 100
		driveWeightedCalls(t, gi, n)
		assert.Equal(t, int64(n), up.callCount.Load(),
			"a single legacy upstream must receive all traffic")
	})

	t.Run("multiple legacy upstreams distribute", func(t *testing.T) {
		upA, upB, beA, beB := weightedBackends(t, "la", "lb")

		gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
			RouteName: "mcp-legacy-multi",
			Backends:  []config.MCPBackend{beA, beB}, // legacy equal-weight list
		})

		const n = 2000
		driveWeightedCalls(t, gi, n)

		aHits := upA.callCount.Load()
		bHits := upB.callCount.Load()
		require.Equal(t, int64(n), aHits+bHits)
		aFrac := float64(aHits) / float64(n)
		t.Logf("legacy multi-upstream: la=%.1f%% lb=%.1f%% over N=%d",
			aFrac*100, (1-aFrac)*100, n)
		assert.InDelta(t, 0.50, aFrac, 0.06,
			"multiple legacy upstreams must distribute ~uniformly (equal weight)")
	})
}

// TestFunctional_MCP_WeightedRouting_NamespacedPinsToOwner confirms that despite
// weights, a NAMESPACED tools/call still pins to its owning upstream: the 0%
// canary owner still receives its own namespaced primitive because owner-pinning
// wins over weighted selection (weights apply ONLY to non-namespaced fallback).
func TestFunctional_MCP_WeightedRouting_NamespacedPinsToOwner(t *testing.T) {
	const (
		routeName = "mcp-weight-pin"
		idStable  = "stable"
		idCanary  = "canary"
	)
	upStable, upCanary, beStable, beCanary := weightedBackends(t, idStable, idCanary)

	gi := startFunctionalMCPGateway(t, helpers.MCPGatewayConfigOptions{
		RouteName: routeName,
		Backends:  []config.MCPBackend{beStable, beCanary},
		WeightedUpstreams: []config.MCPUpstreamRef{
			{Name: idStable, Weight: 100},
			{Name: idCanary, Weight: 0}, // 0% canary
		},
	})

	// A namespaced call to the 0%-weighted canary MUST still reach the canary
	// (owner-pinning wins over the 0 weight).
	const canaryTool = "canary.echo"
	body := helpers.MCPRequestBody{
		Method:    helpers.MCPMethodToolsCall,
		Name:      canaryTool,
		Arguments: map[string]any{"message": "pin"},
	}.MustBuild()
	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsCall,
		Name:   canaryTool,
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "namespaced tools/call to the canary owner must succeed")

	assert.Equal(t, int64(1), upCanary.callCount.Load(),
		"a namespaced primitive must pin to its owning upstream despite a 0 weight")
	assert.Equal(t, int64(0), upStable.callCount.Load(),
		"the stable upstream must not receive the canary-owned namespaced call")
	assert.Equal(t, "echo", upCanary.lastToolName.Load().(string),
		"the owning upstream must observe the de-namespaced tool name")
}

// TestFunctional_MCP_WeightedRouting_AggregationFansOutRegardlessOfWeight
// confirms tools/list aggregation still fans out to BOTH upstreams (union of
// tools) regardless of the configured weights — including a 0%-weight upstream,
// which must never be dropped from discovery/list.
func TestFunctional_MCP_WeightedRouting_AggregationFansOutRegardlessOfWeight(t *testing.T) {
	const (
		idAlpha = "alpha"
		idBeta  = "beta"
	)
	_, _, beAlpha, beBeta := weightedBackends(t, idAlpha, idBeta)

	gi := startFunctionalMCPGateway(t,
		helpers.MCPGatewayConfigOptions{
			RouteName: "mcp-weight-aggregate",
			Backends:  []config.MCPBackend{beAlpha, beBeta},
			WeightedUpstreams: []config.MCPUpstreamRef{
				{Name: idAlpha, Weight: 100},
				{Name: idBeta, Weight: 0}, // 0% weight must NOT drop it from aggregation
			},
		},
		helpers.WithMCPAggregator(),
	)

	body := helpers.MCPRequestBody{Method: helpers.MCPMethodToolsList}.MustBuild()
	resp, err := helpers.PostMCP(gi.BaseURL, gi.MCPPath, body, helpers.MCPRequestOptions{
		Method: helpers.MCPMethodToolsList,
	})
	require.NoError(t, err)
	rpc, err := helpers.DecodeMCPResponse(resp)
	require.NoError(t, err)
	require.Nil(t, rpc.Error, "aggregated tools/list must succeed")

	names, err := rpc.ToolNames()
	require.NoError(t, err)
	// Union of tools across BOTH upstreams, including the 0%-weight one.
	assert.Contains(t, names, fmt.Sprintf("%s.echo", idAlpha))
	assert.Contains(t, names, fmt.Sprintf("%s.echo", idBeta),
		"a 0%%-weight upstream must still contribute its tools to aggregation")
	assert.Contains(t, names, fmt.Sprintf("%s.sleep", idAlpha))
	assert.Contains(t, names, fmt.Sprintf("%s.sleep", idBeta))
}

// TestFunctional_MCP_WeightedRouting_ConfigValidation exercises the shared
// production validator over weighted MCPRoute configs: a valid 80/20 split is
// accepted; an out-of-range weight, a sum!=100, and both Upstreams+
// WeightedUpstreams set are all rejected.
func TestFunctional_MCP_WeightedRouting_ConfigValidation(t *testing.T) {
	newCfg := func(route config.MCPRoute, backends []config.MCPBackend) *config.GatewayConfig {
		cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
			Port:     18099,
			Backends: backends,
		})
		cfg.Spec.MCPRoutes = []config.MCPRoute{route}
		return cfg
	}
	be := func(name string) config.MCPBackend {
		b := helpers.MCPBackendToDeadPort(name, 1)
		return b
	}

	t.Run("valid weighted route is accepted", func(t *testing.T) {
		cfg := newCfg(config.MCPRoute{
			Name: "ok",
			WeightedUpstreams: []config.MCPUpstreamRef{
				{Name: "a", Weight: 80}, {Name: "b", Weight: 20},
			},
		}, []config.MCPBackend{be("a"), be("b")})
		require.NoError(t, config.NewValidator().Validate(cfg))
	})

	t.Run("out-of-range weight is rejected", func(t *testing.T) {
		cfg := newCfg(config.MCPRoute{
			Name:              "bad-range",
			WeightedUpstreams: []config.MCPUpstreamRef{{Name: "a", Weight: 150}},
		}, []config.MCPBackend{be("a")})
		require.Error(t, config.NewValidator().Validate(cfg))
	})

	t.Run("sum != 100 is rejected", func(t *testing.T) {
		cfg := newCfg(config.MCPRoute{
			Name: "bad-sum",
			WeightedUpstreams: []config.MCPUpstreamRef{
				{Name: "a", Weight: 50}, {Name: "b", Weight: 40},
			},
		}, []config.MCPBackend{be("a"), be("b")})
		require.Error(t, config.NewValidator().Validate(cfg))
	})

	t.Run("both Upstreams and WeightedUpstreams set is rejected", func(t *testing.T) {
		cfg := newCfg(config.MCPRoute{
			Name:              "both",
			Upstreams:         []string{"a"},
			WeightedUpstreams: []config.MCPUpstreamRef{{Name: "b", Weight: 100}},
		}, []config.MCPBackend{be("a"), be("b")})
		require.Error(t, config.NewValidator().Validate(cfg))
	})
}
