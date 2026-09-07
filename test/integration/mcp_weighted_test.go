//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
MCP Weighted Routing Integration Tests:

These tests target the REAL docker-compose MCP mock servers (mcp_mock_1 :8821,
mcp_mock_2 :8822). Weighted single-upstream selection happens in the gateway
BEFORE the upstream is called, and is attributed to the mcp_upstream_selected_total
counter (route+upstream labels) in that pre-call step. Consequently the observed
80/20 split is verifiable against the two real mocks via the counter even though
the actual gateway->mock round-trip returns HTTP 400 for tools/call (the Phase-1
short-key _meta mismatch documented in mcp_test.go). We assert the SELECTION
distribution — the routing decision — not the upstream payload, so these tests do
NOT depend on the mock _meta contract and are never skipped for that reason.
*/

// startWeightedIntegrationGateway starts an MCP gateway with a weighted route
// across two real mock upstreams using the given weights.
func startWeightedIntegrationGateway(
	t *testing.T, routeName string, refs []config.MCPUpstreamRef, backends []config.MCPBackend,
) *helpers.MCPGatewayInstance {
	t.Helper()
	port, err := helpers.GetFreeTCPPort()
	require.NoError(t, err)

	cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
		Name:              "mcp-weighted-integration-gw",
		Port:              port,
		RouteName:         routeName,
		Backends:          backends,
		WeightedUpstreams: refs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	gi, err := helpers.StartMCPGateway(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })
	return gi
}

// selectedTotal reads mcp_upstream_selected_total{route,upstream} from the MCP
// metrics singleton used by the in-process handler.
func selectedTotal(route, upstream string) float64 {
	return testutil.ToFloat64(
		mcpmetrics.GetMetrics().UpstreamSelectedTotal.WithLabelValues(route, upstream))
}

// driveBareToolsCalls posts N bare-named (non-namespaced) tools/call requests so
// each request exercises weighted-random selection across the route's upstreams.
// The upstream call itself may return 400 (mock _meta mismatch) but the SELECTION
// (counted before the call) is what we measure.
func driveBareToolsCalls(t *testing.T, gi *helpers.MCPGatewayInstance, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
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
		resp.Body.Close()
	}
}

// TestIntegration_MCP_WeightedRouting_Distribution configures an 80/20 weighted
// MCPRoute across BOTH real docker mocks and asserts the observed selection
// distribution (via mcp_upstream_selected_total) is approximately proportional.
func TestIntegration_MCP_WeightedRouting_Distribution(t *testing.T) {
	mcpCfg := helpers.GetMCPTestConfig()
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend1URL)
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend2URL)

	const (
		routeName = "mcp-int-weight-8020"
		idStable  = "stable"
		idCanary  = "canary"
		n         = 2000
		tolerance = 0.06
	)

	beStable, err := helpers.MCPBackendFromURL(idStable, mcpCfg.Backend1URL)
	require.NoError(t, err)
	beCanary, err := helpers.MCPBackendFromURL(idCanary, mcpCfg.Backend2URL)
	require.NoError(t, err)

	gi := startWeightedIntegrationGateway(t, routeName,
		[]config.MCPUpstreamRef{{Name: idStable, Weight: 80}, {Name: idCanary, Weight: 20}},
		[]config.MCPBackend{beStable, beCanary},
	)

	beforeStable := selectedTotal(routeName, idStable)
	beforeCanary := selectedTotal(routeName, idCanary)

	driveBareToolsCalls(t, gi, n)

	stable := selectedTotal(routeName, idStable) - beforeStable
	canary := selectedTotal(routeName, idCanary) - beforeCanary
	require.Equal(t, float64(n), stable+canary,
		"every weighted request must select exactly one upstream")

	stableFrac := stable / float64(n)
	canaryFrac := canary / float64(n)
	t.Logf("REAL-mock weighted distribution 80/20: stable=%.0f (%.1f%%) canary=%.0f (%.1f%%) over N=%d",
		stable, stableFrac*100, canary, canaryFrac*100, n)

	assert.InDelta(t, 0.80, stableFrac, tolerance,
		"stable upstream must receive ~80%% of weighted selections")
	assert.InDelta(t, 0.20, canaryFrac, tolerance,
		"canary upstream must receive ~20%% of weighted selections")
}

// TestIntegration_MCP_WeightedRouting_ZeroWeightCanary asserts a zero-weight
// upstream receives ~0% of selections when a sibling carries positive weight.
func TestIntegration_MCP_WeightedRouting_ZeroWeightCanary(t *testing.T) {
	mcpCfg := helpers.GetMCPTestConfig()
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend1URL)
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend2URL)

	const (
		routeName = "mcp-int-weight-zero"
		idLive    = "live"
		idDark    = "dark"
		n         = 500
	)

	beLive, err := helpers.MCPBackendFromURL(idLive, mcpCfg.Backend1URL)
	require.NoError(t, err)
	beDark, err := helpers.MCPBackendFromURL(idDark, mcpCfg.Backend2URL)
	require.NoError(t, err)

	gi := startWeightedIntegrationGateway(t, routeName,
		[]config.MCPUpstreamRef{{Name: idLive, Weight: 100}, {Name: idDark, Weight: 0}},
		[]config.MCPBackend{beLive, beDark},
	)

	beforeLive := selectedTotal(routeName, idLive)
	beforeDark := selectedTotal(routeName, idDark)

	driveBareToolsCalls(t, gi, n)

	assert.Equal(t, float64(n), selectedTotal(routeName, idLive)-beforeLive,
		"the positive-weight upstream must receive ALL selections")
	assert.Equal(t, float64(0), selectedTotal(routeName, idDark)-beforeDark,
		"a zero-weight upstream must receive exactly 0%% of selections")
}

// TestIntegration_MCP_WeightedRouting_LegacyBackwardCompat confirms a legacy
// Upstreams []string route still distributes across BOTH real mocks (equal
// weight), verified via the selection counter.
func TestIntegration_MCP_WeightedRouting_LegacyBackwardCompat(t *testing.T) {
	mcpCfg := helpers.GetMCPTestConfig()
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend1URL)
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend2URL)

	const (
		routeName = "mcp-int-legacy-multi"
		idA       = "lega"
		idB       = "legb"
		n         = 2000
	)

	beA, err := helpers.MCPBackendFromURL(idA, mcpCfg.Backend1URL)
	require.NoError(t, err)
	beB, err := helpers.MCPBackendFromURL(idB, mcpCfg.Backend2URL)
	require.NoError(t, err)

	// Legacy path: no WeightedUpstreams, upstreams derived from Backends.
	port, err := helpers.GetFreeTCPPort()
	require.NoError(t, err)
	cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
		Name:      "mcp-legacy-integration-gw",
		Port:      port,
		RouteName: routeName,
		Backends:  []config.MCPBackend{beA, beB},
	})
	require.Empty(t, cfg.Spec.MCPRoutes[0].WeightedUpstreams,
		"legacy route must not carry weighted upstreams")
	require.Equal(t, []string{idA, idB}, cfg.Spec.MCPRoutes[0].Upstreams)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gi, err := helpers.StartMCPGateway(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })

	beforeA := selectedTotal(routeName, idA)
	beforeB := selectedTotal(routeName, idB)

	driveBareToolsCalls(t, gi, n)

	a := selectedTotal(routeName, idA) - beforeA
	b := selectedTotal(routeName, idB) - beforeB
	require.Equal(t, float64(n), a+b)
	aFrac := a / float64(n)
	t.Logf("REAL-mock legacy multi distribution: lega=%.1f%% legb=%.1f%% over N=%d",
		aFrac*100, (1-aFrac)*100, n)
	assert.InDelta(t, 0.50, aFrac, 0.06,
		"legacy multi-upstream route must distribute ~uniformly (equal weight)")
}

// TestIntegration_MCP_WeightedRouting_AggregationFansOut confirms tools/list
// aggregation still fans out to BOTH real mocks (union of tools) regardless of
// the configured weights, including a 0%-weight upstream. It is skipped when the
// mocks reject the vendored _meta the aggregator emits (Phase-1 mismatch).
func TestIntegration_MCP_WeightedRouting_AggregationFansOut(t *testing.T) {
	mcpCfg := helpers.GetMCPTestConfig()
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend1URL)
	helpers.SkipIfMCPMockUnavailable(t, mcpCfg.Backend2URL)
	skipIfMockMetaMismatch(t, mcpCfg.Backend1URL)

	const (
		idAlpha = "alpha"
		idBeta  = "beta"
	)
	beAlpha, err := helpers.MCPBackendFromURL(idAlpha, mcpCfg.Backend1URL)
	require.NoError(t, err)
	beBeta, err := helpers.MCPBackendFromURL(idBeta, mcpCfg.Backend2URL)
	require.NoError(t, err)

	port, err := helpers.GetFreeTCPPort()
	require.NoError(t, err)
	cfg := helpers.BuildMCPGatewayConfig(helpers.MCPGatewayConfigOptions{
		Name:      "mcp-weighted-agg-gw",
		Port:      port,
		RouteName: "mcp-int-weight-agg",
		Backends:  []config.MCPBackend{beAlpha, beBeta},
		WeightedUpstreams: []config.MCPUpstreamRef{
			{Name: idAlpha, Weight: 100},
			{Name: idBeta, Weight: 0}, // 0% weight must NOT drop it from aggregation
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gi, err := helpers.StartMCPGateway(ctx, cfg, helpers.WithMCPAggregator())
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })

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
	assert.Contains(t, names, "alpha.echo")
	assert.Contains(t, names, "beta.echo",
		"a 0%%-weight upstream must still contribute its tools to aggregation")
}
