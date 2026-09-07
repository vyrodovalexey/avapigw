package gateway

import (
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// TestSelectWeightedUpstream_Basic is a compile-smoke test covering the core
// selection paths: empty, single, all-zero uniform, weighted, and zero-weight
// exclusion. Full statistical distribution coverage is added by the test agent.
func TestSelectWeightedUpstream_Basic(t *testing.T) {
	// Empty -> ok=false.
	if _, ok := selectWeightedUpstream(nil); ok {
		t.Fatal("empty refs should return ok=false")
	}

	// Single -> that candidate.
	single := []config.MCPUpstreamRef{{Name: "only"}}
	if got, ok := selectWeightedUpstream(single); !ok || got.Name != "only" {
		t.Fatalf("single = %+v ok=%v", got, ok)
	}

	// All-zero -> uniform: every draw must be one of the candidates.
	allZero := []config.MCPUpstreamRef{{Name: "a"}, {Name: "b"}}
	for i := 0; i < 50; i++ {
		got, ok := selectWeightedUpstream(allZero)
		if !ok || (got.Name != "a" && got.Name != "b") {
			t.Fatalf("all-zero draw = %+v ok=%v", got, ok)
		}
	}

	// Weighted with a 0% canary: the zero-weight candidate must never be picked.
	weighted := []config.MCPUpstreamRef{{Name: "stable", Weight: 100}, {Name: "canary", Weight: 0}}
	for i := 0; i < 200; i++ {
		got, ok := selectWeightedUpstream(weighted)
		if !ok || got.Name != "stable" {
			t.Fatalf("0%% canary was selected: %+v", got)
		}
	}
}

// distributionTolerance is the ±absolute-share tolerance used by the
// statistical selection tests. Selection uses crypto/rand (no fixed seed), so a
// large sample size (N>=50k) with a wide 2-percentage-point tolerance keeps the
// tests deterministic-enough (non-flaky) while still proving proportionality.
const distributionTolerance = 0.02

// TestSelectWeightedUpstream_Distribution proves the cumulative weighted walk
// splits traffic proportionally: 90/10 over N>=50,000 draws lands within ±2%.
func TestSelectWeightedUpstream_Distribution(t *testing.T) {
	t.Parallel()

	refs := []config.MCPUpstreamRef{{Name: "stable", Weight: 90}, {Name: "canary", Weight: 10}}
	const iterations = 100000
	counts := map[string]int{}
	for i := 0; i < iterations; i++ {
		got, ok := selectWeightedUpstream(refs)
		if !ok {
			t.Fatalf("iteration %d: ok=false", i)
		}
		counts[got.Name]++
	}

	stableShare := float64(counts["stable"]) / iterations
	canaryShare := float64(counts["canary"]) / iterations
	t.Logf("observed 90/10 split: stable=%.4f canary=%.4f (N=%d)",
		stableShare, canaryShare, iterations)

	if stableShare < 0.90-distributionTolerance || stableShare > 0.90+distributionTolerance {
		t.Fatalf("stable share %.4f outside [%.2f,%.2f]",
			stableShare, 0.90-distributionTolerance, 0.90+distributionTolerance)
	}
	if canaryShare < 0.10-distributionTolerance || canaryShare > 0.10+distributionTolerance {
		t.Fatalf("canary share %.4f outside [%.2f,%.2f]",
			canaryShare, 0.10-distributionTolerance, 0.10+distributionTolerance)
	}
}

// TestSelectWeightedUpstream_AllZeroUniform proves the all-zero-weight branch
// selects uniformly across every candidate (each ~1/3 ± 2%).
func TestSelectWeightedUpstream_AllZeroUniform(t *testing.T) {
	t.Parallel()

	refs := []config.MCPUpstreamRef{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	const iterations = 90000
	counts := map[string]int{}
	for i := 0; i < iterations; i++ {
		got, ok := selectWeightedUpstream(refs)
		if !ok {
			t.Fatalf("iteration %d: ok=false", i)
		}
		counts[got.Name]++
	}

	for _, name := range []string{"a", "b", "c"} {
		share := float64(counts[name]) / iterations
		if share < 1.0/3.0-distributionTolerance || share > 1.0/3.0+distributionTolerance {
			t.Fatalf("all-zero uniform: %s share %.4f outside 1/3 ±%.2f", name, share, distributionTolerance)
		}
	}
}

// TestSelectWeightedUpstream_ZeroWeightExcluded proves that when any candidate
// carries a positive weight, zero-weight candidates receive 0% of traffic while
// the positive-weight candidates keep their proportions (±2%).
func TestSelectWeightedUpstream_ZeroWeightExcluded(t *testing.T) {
	t.Parallel()

	// The zero-weight candidate is placed in the MIDDLE so the cumulative walk
	// hits the `weight <= 0 continue` skip branch before reaching the tail.
	refs := []config.MCPUpstreamRef{{Name: "a", Weight: 50}, {Name: "c", Weight: 0}, {Name: "b", Weight: 50}}
	const iterations = 60000
	counts := map[string]int{}
	for i := 0; i < iterations; i++ {
		got, ok := selectWeightedUpstream(refs)
		if !ok {
			t.Fatalf("iteration %d: ok=false", i)
		}
		counts[got.Name]++
	}

	if counts["c"] != 0 {
		t.Fatalf("0%% candidate c was selected %d times (must be 0)", counts["c"])
	}
	for _, name := range []string{"a", "b"} {
		share := float64(counts[name]) / iterations
		if share < 0.50-distributionTolerance || share > 0.50+distributionTolerance {
			t.Fatalf("%s share %.4f outside 0.5 ±%.2f", name, share, distributionTolerance)
		}
	}
}

// NOTE on selectWeightedUpstream's remaining uncovered statements (mcp_select.go
// lines 64-69): that trailing loop is a DEFENSIVE fallback that is provably
// unreachable for the real implementation. secureRandomInt(totalWeight) returns
// a value in [0, totalWeight), so the cumulative walk over positive weights
// always returns inside the loop (the last positive-weight candidate closes the
// interval at randomValue < totalWeight). The unit-test-review (§2 item 4, §5)
// explicitly instructs NOT to fabricate an impossible test for this branch and
// to accept it as the sole sub-100% remainder; it does not block the ≥90% bar
// for the reachable surface. All reachable branches are covered above.

// TestSelectWeightedUpstream_SingleFastPath pins the single-candidate fast path.
func TestSelectWeightedUpstream_SingleFastPath(t *testing.T) {
	t.Parallel()

	refs := []config.MCPUpstreamRef{{Name: "only", Weight: 0}}
	got, ok := selectWeightedUpstream(refs)
	if !ok || got.Name != "only" {
		t.Fatalf("single fast path = %+v ok=%v", got, ok)
	}
}

// TestSelectWeightedUpstream_Empty pins the empty-candidate contract.
func TestSelectWeightedUpstream_Empty(t *testing.T) {
	t.Parallel()

	if _, ok := selectWeightedUpstream(nil); ok {
		t.Fatal("empty refs must return ok=false")
	}
	if _, ok := selectWeightedUpstream([]config.MCPUpstreamRef{}); ok {
		t.Fatal("empty slice must return ok=false")
	}
}

// TestSecureRandomInt_Bounds is a compile-smoke bound check.
func TestSecureRandomInt_Bounds(t *testing.T) {
	if secureRandomInt(0) != 0 {
		t.Fatal("secureRandomInt(0) must be 0")
	}
	for i := 0; i < 100; i++ {
		if n := secureRandomInt(5); n < 0 || n >= 5 {
			t.Fatalf("secureRandomInt(5) out of range: %d", n)
		}
	}
}

// TestSecureRandomInt_NonPositiveGuard pins the n<=0 guard (returns 0).
func TestSecureRandomInt_NonPositiveGuard(t *testing.T) {
	t.Parallel()

	if secureRandomInt(0) != 0 {
		t.Fatal("secureRandomInt(0) must be 0")
	}
	if secureRandomInt(-5) != 0 {
		t.Fatal("secureRandomInt(negative) must be 0")
	}
}

// TestSecureRandomInt_Distribution exercises the crypto/rand normal path and
// modulo reduction over many calls: secureRandomInt(4) must fill every bucket
// roughly uniformly (each ~0.25 ± 2%) and always stay in range.
func TestSecureRandomInt_Distribution(t *testing.T) {
	t.Parallel()

	const maxVal = 4
	const iterations = 40000
	counts := make([]int, maxVal)
	for i := 0; i < iterations; i++ {
		n := secureRandomInt(maxVal)
		if n < 0 || n >= maxVal {
			t.Fatalf("secureRandomInt(%d) out of range: %d", maxVal, n)
		}
		counts[n]++
	}
	for bucket, c := range counts {
		share := float64(c) / iterations
		if share < 0.25-distributionTolerance || share > 0.25+distributionTolerance {
			t.Fatalf("bucket %d share %.4f outside 0.25 ±%.2f", bucket, share, distributionTolerance)
		}
	}
}

// TestSecureRandomInt_CryptoRandFallbackUnreachable documents WHY the
// crypto/rand fallback branch (lines 81-87 of mcp_select.go) is NOT unit-tested.
//
// secureRandomInt calls the package-level crypto/rand.Read directly, which is
// not an injectable seam. The unit-test-review (§A-6, §6) explicitly notes this
// is a testability gap, NOT a runtime bug, and that covering the fallback would
// require adding a production seam (e.g. `var randRead = rand.Read`). This task
// constraint forbids modifying production code, so the fallback branch is left
// defensively uncovered here. The fallback's downstream effect —
// RecordCryptoRandFailure incrementing the counter — is covered directly by the
// metrics package test (TestRecordCryptoRandFailure). This test asserts the
// normal (non-fallback) contract only.
func TestSecureRandomInt_CryptoRandFallbackUnreachable(t *testing.T) {
	t.Parallel()

	// The normal crypto/rand path always yields an in-range value; the
	// math/rand fallback is only taken when rand.Read errors, which cannot be
	// forced without a production seam (documented above).
	for i := 0; i < 1000; i++ {
		if n := secureRandomInt(7); n < 0 || n >= 7 {
			t.Fatalf("secureRandomInt(7) out of range: %d", n)
		}
	}
}
