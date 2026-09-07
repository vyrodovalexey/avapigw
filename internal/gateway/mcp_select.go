package gateway

import (
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand/v2"

	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// selectWeightedUpstream picks one upstream ref using stateless weighted random
// selection. It mirrors proxy.selectDestination so MCP weighted routing follows
// exactly the same semantics as APIRoute destinations and stays HUB-501 safe
// (no shared counters, sticky state or cross-replica coordination).
//
// Weight semantics:
//   - empty candidate set -> ok=false;
//   - single candidate -> that candidate (fast path);
//   - all weights zero -> uniform selection across every candidate (the
//     historical "no weights configured" behavior);
//   - any positive weight -> zero-weight candidates are EXCLUDED and receive no
//     traffic (a canary set to 0% gets exactly 0%, not a residual share).
//
// It returns the selected ref and ok=true when a selection was made.
func selectWeightedUpstream(refs []config.MCPUpstreamRef) (config.MCPUpstreamRef, bool) {
	if len(refs) == 0 {
		return config.MCPUpstreamRef{}, false
	}

	if len(refs) == 1 {
		return refs[0], true
	}

	// Sum only the positive weights.
	totalWeight := 0
	for i := range refs {
		if refs[i].Weight > 0 {
			totalWeight += refs[i].Weight
		}
	}

	// All weights unset/zero: uniform selection across every candidate.
	if totalWeight == 0 {
		return refs[secureRandomInt(len(refs))], true
	}

	// Weighted mode: zero-weight candidates are skipped entirely.
	randomValue := secureRandomInt(totalWeight)
	cumulativeWeight := 0
	for i := range refs {
		weight := refs[i].Weight
		if weight <= 0 {
			continue
		}
		cumulativeWeight += weight
		if randomValue < cumulativeWeight {
			return refs[i], true
		}
	}

	// Defensive fallback: return the first positive-weight candidate.
	for i := range refs {
		if refs[i].Weight > 0 {
			return refs[i], true
		}
	}
	return refs[0], true
}

// secureRandomInt returns a cryptographically secure random integer in
// [0, maxVal). On a crypto/rand read failure it counts the fallback via the MCP
// metrics singleton and degrades to math/rand/v2 so selection never blocks.
func secureRandomInt(maxVal int) int {
	if maxVal <= 0 {
		return 0
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		observability.GetGlobalLogger().Warn("mcp: crypto/rand failure, falling back to math/rand",
			observability.Error(err),
		)
		mcpmetrics.GetMetrics().RecordCryptoRandFailure()
		return mathrand.IntN(maxVal) //nolint:gosec // fallback when crypto/rand is unavailable
	}

	n := binary.LittleEndian.Uint64(b[:])
	return int(n % uint64(maxVal)) //nolint:gosec // maxVal is validated above
}
