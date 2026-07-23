package proxy

// Tests for T3.E1 (review M4): with mixed weights, zero-weight destinations
// must receive NO traffic; when all weights are zero, selection stays
// uniform (historical behavior asserted by the existing
// TestReverseProxy_SelectDestination_WithZeroWeight).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

func newWeightTestProxy(t *testing.T) *ReverseProxy {
	t.Helper()
	r := router.New()
	registry := backend.NewRegistry(observability.NopLogger())
	return NewReverseProxy(r, registry)
}

// TestSelectDestination_ZeroWeightExcludedWhenOthersPositive is the M4
// acceptance criterion: [{A:100},{B:0}] must send 0% of traffic to B.
func TestSelectDestination_ZeroWeightExcludedWhenOthersPositive(t *testing.T) {
	t.Parallel()

	proxy := newWeightTestProxy(t)

	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "primary", Port: 8080}, Weight: 100},
		{Destination: config.Destination{Host: "canary-off", Port: 8080}, Weight: 0},
	}

	for i := 0; i < 2000; i++ {
		selected := proxy.selectDestination(destinations)
		require.NotNil(t, selected)
		assert.Equal(t, "primary", selected.Destination.Host,
			"a 0%% canary must receive no traffic (iteration %d)", i)
	}
}

// TestSelectDestination_MixedWeightsDistribution verifies positive weights
// keep their proportions with a zero-weight destination present.
func TestSelectDestination_MixedWeightsDistribution(t *testing.T) {
	t.Parallel()

	proxy := newWeightTestProxy(t)

	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "a", Port: 8080}, Weight: 75},
		{Destination: config.Destination{Host: "b", Port: 8080}, Weight: 25},
		{Destination: config.Destination{Host: "off", Port: 8080}, Weight: 0},
	}

	counts := map[string]int{}
	const iterations = 10000
	for i := 0; i < iterations; i++ {
		selected := proxy.selectDestination(destinations)
		require.NotNil(t, selected)
		counts[selected.Destination.Host]++
	}

	assert.Zero(t, counts["off"], "zero-weight destination must receive no traffic")
	// 75/25 split with generous tolerance (±10 percentage points).
	assert.InDelta(t, 0.75, float64(counts["a"])/iterations, 0.10)
	assert.InDelta(t, 0.25, float64(counts["b"])/iterations, 0.10)
}

// TestSelectDestination_AllZeroWeightsUniform pins the preserved behavior:
// all-zero weights select uniformly across every destination.
func TestSelectDestination_AllZeroWeightsUniform(t *testing.T) {
	t.Parallel()

	proxy := newWeightTestProxy(t)

	destinations := []config.RouteDestination{
		{Destination: config.Destination{Host: "a", Port: 8080}},
		{Destination: config.Destination{Host: "b", Port: 8080}},
		{Destination: config.Destination{Host: "c", Port: 8080}},
	}

	counts := map[string]int{}
	const iterations = 9000
	for i := 0; i < iterations; i++ {
		selected := proxy.selectDestination(destinations)
		require.NotNil(t, selected)
		counts[selected.Destination.Host]++
	}

	for _, host := range []string{"a", "b", "c"} {
		assert.InDelta(t, 1.0/3.0, float64(counts[host])/iterations, 0.08,
			"all-zero weights must select uniformly (host %s)", host)
	}
}

// TestSelectDestination_SingleAndEmpty pins the edge cases.
func TestSelectDestination_SingleAndEmpty(t *testing.T) {
	t.Parallel()

	proxy := newWeightTestProxy(t)

	assert.Nil(t, proxy.selectDestination(nil))

	single := []config.RouteDestination{
		{Destination: config.Destination{Host: "only", Port: 8080}, Weight: 0},
	}
	selected := proxy.selectDestination(single)
	require.NotNil(t, selected)
	assert.Equal(t, "only", selected.Destination.Host,
		"a single destination is always selected regardless of weight")
}
