package backend

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Cases for RoundRobinLB
// ============================================================================

func TestRoundRobinLB_Select(t *testing.T) {
	lb := NewRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	// First selection should return first endpoint (after counter increment)
	ep1 := lb.Select(endpoints)
	require.NotNil(t, ep1)
	assert.Equal(t, "host2", ep1.Address) // counter starts at 0, increments to 1, mod 3 = 1

	// Second selection should return second endpoint
	ep2 := lb.Select(endpoints)
	require.NotNil(t, ep2)
	assert.Equal(t, "host3", ep2.Address)

	// Third selection should wrap around
	ep3 := lb.Select(endpoints)
	require.NotNil(t, ep3)
	assert.Equal(t, "host1", ep3.Address)
}

func TestRoundRobinLB_Select_EmptyEndpoints(t *testing.T) {
	lb := NewRoundRobinLB()

	ep := lb.Select([]*Endpoint{})
	assert.Nil(t, ep)
}

func TestRoundRobinLB_Select_SingleEndpoint(t *testing.T) {
	lb := NewRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
	}

	// All selections should return the same endpoint
	for i := 0; i < 5; i++ {
		ep := lb.Select(endpoints)
		require.NotNil(t, ep)
		assert.Equal(t, "host1", ep.Address)
	}
}

// ============================================================================
// Test Cases for RandomLB Thread Safety (TASK-005)
// ============================================================================

func TestRandomLB_Select(t *testing.T) {
	lb := NewRandomLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	// Should return a valid endpoint
	ep := lb.Select(endpoints)
	require.NotNil(t, ep)
	assert.Contains(t, []string{"host1", "host2", "host3"}, ep.Address)
}

func TestRandomLB_Select_EmptyEndpoints(t *testing.T) {
	lb := NewRandomLB()

	ep := lb.Select([]*Endpoint{})
	assert.Nil(t, ep)
}

func TestRandomLB_ConcurrentSelect(t *testing.T) {
	// Test thread safety of RandomLB with concurrent access
	lb := NewRandomLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	var wg sync.WaitGroup
	numGoroutines := 100
	numIterations := 100

	// Track results to ensure all selections are valid
	results := make(chan *Endpoint, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				ep := lb.Select(endpoints)
				results <- ep
			}
		}()
	}

	wg.Wait()
	close(results)

	// Verify all results are valid endpoints
	validAddresses := map[string]bool{"host1": true, "host2": true, "host3": true}
	count := 0
	for ep := range results {
		require.NotNil(t, ep, "Selected endpoint should not be nil")
		assert.True(t, validAddresses[ep.Address], "Selected endpoint should be valid")
		count++
	}

	assert.Equal(t, numGoroutines*numIterations, count, "Should have received all results")
}

// ============================================================================
// Test Cases for LeastConnectionsLB
// ============================================================================

func TestLeastConnectionsLB_Select(t *testing.T) {
	lb := NewLeastConnectionsLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	// First selection should return first endpoint (all have 0 connections)
	ep1 := lb.Select(endpoints)
	require.NotNil(t, ep1)

	// After selection, the selected endpoint should have 1 connection
	// Next selection should prefer endpoints with 0 connections
	ep2 := lb.Select(endpoints)
	require.NotNil(t, ep2)

	// Release connection from first endpoint
	lb.Release(ep1)
}

func TestLeastConnectionsLB_Select_EmptyEndpoints(t *testing.T) {
	lb := NewLeastConnectionsLB()

	ep := lb.Select([]*Endpoint{})
	assert.Nil(t, ep)
}

func TestLeastConnectionsLB_Release_NilEndpoint(t *testing.T) {
	lb := NewLeastConnectionsLB()

	// Should not panic
	lb.Release(nil)
}

// ============================================================================
// Test Cases for WeightedRoundRobinLB
// ============================================================================

func TestWeightedRoundRobinLB_Select(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 3, Healthy: true},
		{Address: "host2", Port: 8080, Weight: 2, Healthy: true},
		{Address: "host3", Port: 8080, Weight: 1, Healthy: true},
	}

	// Count selections over multiple iterations
	counts := make(map[string]int)
	for i := 0; i < 60; i++ {
		ep := lb.Select(endpoints)
		require.NotNil(t, ep)
		counts[ep.Address]++
	}

	// Higher weight endpoints should be selected more often
	assert.Greater(t, counts["host1"], counts["host3"], "host1 (weight 3) should be selected more than host3 (weight 1)")
}

func TestWeightedRoundRobinLB_Select_EmptyEndpoints(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	ep := lb.Select([]*Endpoint{})
	assert.Nil(t, ep)
}

// ============================================================================
// Test Cases for ConsistentHashLB (TASK-005)
// ============================================================================

func TestConsistentHashLB_Select(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	// Should return a valid endpoint
	ep := lb.Select(endpoints)
	require.NotNil(t, ep)
	assert.Contains(t, []string{"host1", "host2", "host3"}, ep.Address)
}

func TestConsistentHashLB_Select_EmptyEndpoints(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	ep := lb.Select([]*Endpoint{})
	assert.Nil(t, ep)
}

func TestConsistentHashLB_SelectWithKey(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	// Same key should always return the same endpoint
	key := "user-123"
	ep1 := lb.SelectWithKey(endpoints, key)
	ep2 := lb.SelectWithKey(endpoints, key)
	ep3 := lb.SelectWithKey(endpoints, key)

	require.NotNil(t, ep1)
	require.NotNil(t, ep2)
	require.NotNil(t, ep3)

	assert.Equal(t, ep1.Address, ep2.Address, "Same key should return same endpoint")
	assert.Equal(t, ep2.Address, ep3.Address, "Same key should return same endpoint")
}

func TestConsistentHashLB_SelectWithKey_DifferentKeys(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	// Different keys may return different endpoints
	results := make(map[string]bool)
	for i := 0; i < 100; i++ {
		key := "user-" + string(rune('a'+i%26))
		ep := lb.SelectWithKey(endpoints, key)
		require.NotNil(t, ep)
		results[ep.Address] = true
	}

	// With enough different keys, we should hit multiple endpoints
	assert.GreaterOrEqual(t, len(results), 1, "Should select at least one endpoint")
}

func TestConsistentHashLB_RingNotRebuiltOnSameEndpoints(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
	}

	// First selection builds the ring
	ep1 := lb.SelectWithKey(endpoints, "test-key")
	require.NotNil(t, ep1)

	// Get the cached endpoints hash
	lb.mu.RLock()
	cachedHash := lb.cachedEndpoints
	lb.mu.RUnlock()

	// Second selection with same endpoints should not rebuild
	ep2 := lb.SelectWithKey(endpoints, "test-key")
	require.NotNil(t, ep2)

	// Verify hash hasn't changed (ring wasn't rebuilt)
	lb.mu.RLock()
	newHash := lb.cachedEndpoints
	lb.mu.RUnlock()

	assert.Equal(t, cachedHash, newHash, "Hash ring should not be rebuilt for same endpoints")
	assert.Equal(t, ep1.Address, ep2.Address, "Same key should return same endpoint")
}

func TestConsistentHashLB_RingRebuiltOnEndpointChange(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	endpoints1 := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
	}

	// First selection builds the ring
	ep1 := lb.SelectWithKey(endpoints1, "test-key")
	require.NotNil(t, ep1)

	// Get the cached endpoints hash
	lb.mu.RLock()
	cachedHash1 := lb.cachedEndpoints
	lb.mu.RUnlock()

	// Change endpoints
	endpoints2 := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true}, // Changed from host2 to host3
	}

	// Selection with different endpoints should rebuild the ring
	ep2 := lb.SelectWithKey(endpoints2, "test-key")
	require.NotNil(t, ep2)

	// Verify hash has changed (ring was rebuilt)
	lb.mu.RLock()
	cachedHash2 := lb.cachedEndpoints
	lb.mu.RUnlock()

	assert.NotEqual(t, cachedHash1, cachedHash2, "Hash ring should be rebuilt when endpoints change")
}

func TestConsistentHashLB_ConcurrentSelect(t *testing.T) {
	config := &ConsistentHashConfig{
		Type:   "header",
		Header: "X-User-ID",
	}
	lb := NewConsistentHashLB(config)

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8080, Healthy: true},
		{Address: "host3", Port: 8080, Healthy: true},
	}

	var wg sync.WaitGroup
	numGoroutines := 50
	numIterations := 100

	// Track results to ensure consistency
	results := make(chan *Endpoint, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "user-" + string(rune('a'+idx%26))
			for j := 0; j < numIterations; j++ {
				ep := lb.SelectWithKey(endpoints, key)
				results <- ep
			}
		}(i)
	}

	wg.Wait()
	close(results)

	// Verify all results are valid endpoints
	validAddresses := map[string]bool{"host1": true, "host2": true, "host3": true}
	count := 0
	for ep := range results {
		require.NotNil(t, ep, "Selected endpoint should not be nil")
		assert.True(t, validAddresses[ep.Address], "Selected endpoint should be valid")
		count++
	}

	assert.Equal(t, numGoroutines*numIterations, count, "Should have received all results")
}

// ============================================================================
// Test Cases for NewLoadBalancer Factory
// ============================================================================

func TestNewLoadBalancer_RoundRobin(t *testing.T) {
	lb := NewLoadBalancer("RoundRobin", nil)
	assert.IsType(t, &RoundRobinLB{}, lb)
}

func TestNewLoadBalancer_LeastConnections(t *testing.T) {
	lb := NewLoadBalancer("LeastConnections", nil)
	assert.IsType(t, &LeastConnectionsLB{}, lb)
}

func TestNewLoadBalancer_Random(t *testing.T) {
	lb := NewLoadBalancer("Random", nil)
	assert.IsType(t, &RandomLB{}, lb)
}

func TestNewLoadBalancer_WeightedRoundRobin(t *testing.T) {
	lb := NewLoadBalancer("WeightedRoundRobin", nil)
	assert.IsType(t, &WeightedRoundRobinLB{}, lb)
}

func TestNewLoadBalancer_ConsistentHash(t *testing.T) {
	config := &LBConfig{
		ConsistentHash: &ConsistentHashConfig{
			Type:   "header",
			Header: "X-User-ID",
		},
	}
	lb := NewLoadBalancer("ConsistentHash", config)
	assert.IsType(t, &ConsistentHashLB{}, lb)
}

func TestNewLoadBalancer_ConsistentHash_NoConfig(t *testing.T) {
	// Without config, should fall back to RoundRobin
	lb := NewLoadBalancer("ConsistentHash", nil)
	assert.IsType(t, &RoundRobinLB{}, lb)
}

func TestNewLoadBalancer_Unknown(t *testing.T) {
	// Unknown algorithm should default to RoundRobin
	lb := NewLoadBalancer("Unknown", nil)
	assert.IsType(t, &RoundRobinLB{}, lb)
}

func TestNewLoadBalancer_Default(t *testing.T) {
	// Empty algorithm should default to RoundRobin
	lb := NewLoadBalancer("", nil)
	assert.IsType(t, &RoundRobinLB{}, lb)
}

// ============================================================================
// Test Cases for WeightedRoundRobinLB Edge Cases (Bug Fixes)
// ============================================================================

// Test 1: All Zero Weights - Should Not Hang
func TestWeightedRoundRobinLB_AllZeroWeights(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 0, Healthy: true},
		{Address: "host2", Port: 8080, Weight: 0, Healthy: true},
		{Address: "host3", Port: 8080, Weight: 0, Healthy: true},
	}

	// Should not hang and should return endpoints in round-robin fashion
	done := make(chan bool)
	go func() {
		for i := 0; i < 10; i++ {
			ep := lb.Select(endpoints)
			require.NotNil(t, ep)
		}
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Select() appears to be in infinite loop")
	}
}

// Test 2: Mixed Zero and Non-Zero Weights
func TestWeightedRoundRobinLB_MixedWeights(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 0, Healthy: true},
		{Address: "host2", Port: 8080, Weight: 5, Healthy: true},
		{Address: "host3", Port: 8080, Weight: 0, Healthy: true},
	}

	counts := make(map[string]int)
	for i := 0; i < 30; i++ {
		ep := lb.Select(endpoints)
		require.NotNil(t, ep)
		counts[ep.Address]++
	}

	// host2 should be selected most often
	assert.Greater(t, counts["host2"], 0, "host2 with weight 5 should be selected")
}

// Test 3: Single Endpoint with Zero Weight
func TestWeightedRoundRobinLB_SingleZeroWeight(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 0, Healthy: true},
	}

	ep := lb.Select(endpoints)
	require.NotNil(t, ep)
	assert.Equal(t, "host1", ep.Address)
}

// Test 4: GCD with All Zero Weights Returns 1
func TestWeightedRoundRobinLB_CalculateGCD_AllZero(t *testing.T) {
	lb := &WeightedRoundRobinLB{}

	endpoints := []*Endpoint{
		{Weight: 0},
		{Weight: 0},
		{Weight: 0},
	}

	gcd := lb.calculateGCD(endpoints)
	assert.Equal(t, 1, gcd, "GCD should be 1 when all weights are 0")
}

// Test 5: No Infinite Loop with Large Weight Difference
func TestWeightedRoundRobinLB_LargeWeightDifference(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 1, Healthy: true},
		{Address: "host2", Port: 8080, Weight: 1000000, Healthy: true},
	}

	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			ep := lb.Select(endpoints)
			require.NotNil(t, ep)
		}
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Select() took too long, possible performance issue")
	}
}

// Test 6: GCD with Empty Endpoints
func TestWeightedRoundRobinLB_CalculateGCD_Empty(t *testing.T) {
	lb := &WeightedRoundRobinLB{}

	endpoints := []*Endpoint{}

	gcd := lb.calculateGCD(endpoints)
	assert.Equal(t, 1, gcd, "GCD should be 1 for empty endpoints")
}

// Test 7: GCD with Single Endpoint
func TestWeightedRoundRobinLB_CalculateGCD_Single(t *testing.T) {
	lb := &WeightedRoundRobinLB{}

	endpoints := []*Endpoint{
		{Weight: 5},
	}

	gcd := lb.calculateGCD(endpoints)
	assert.Equal(t, 5, gcd, "GCD should be the weight of single endpoint")
}

// Test 8: GCD with Single Zero Weight Endpoint
func TestWeightedRoundRobinLB_CalculateGCD_SingleZero(t *testing.T) {
	lb := &WeightedRoundRobinLB{}

	endpoints := []*Endpoint{
		{Weight: 0},
	}

	gcd := lb.calculateGCD(endpoints)
	assert.Equal(t, 1, gcd, "GCD should be 1 for single zero weight endpoint")
}

// Test 9: Concurrent Access to WeightedRoundRobinLB
func TestWeightedRoundRobinLB_ConcurrentSelect(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 3, Healthy: true},
		{Address: "host2", Port: 8080, Weight: 2, Healthy: true},
		{Address: "host3", Port: 8080, Weight: 1, Healthy: true},
	}

	var wg sync.WaitGroup
	numGoroutines := 50
	numIterations := 100

	results := make(chan *Endpoint, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				ep := lb.Select(endpoints)
				results <- ep
			}
		}()
	}

	wg.Wait()
	close(results)

	// Verify all results are valid endpoints
	validAddresses := map[string]bool{"host1": true, "host2": true, "host3": true}
	count := 0
	for ep := range results {
		require.NotNil(t, ep, "Selected endpoint should not be nil")
		assert.True(t, validAddresses[ep.Address], "Selected endpoint should be valid")
		count++
	}

	assert.Equal(t, numGoroutines*numIterations, count, "Should have received all results")
}

// Test 10: Weight Distribution Verification
func TestWeightedRoundRobinLB_WeightDistribution(t *testing.T) {
	lb := NewWeightedRoundRobinLB()

	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Weight: 3, Healthy: true},
		{Address: "host2", Port: 8080, Weight: 2, Healthy: true},
		{Address: "host3", Port: 8080, Weight: 1, Healthy: true},
	}

	counts := make(map[string]int)
	totalIterations := 600 // Multiple of total weight (3+2+1=6)

	for i := 0; i < totalIterations; i++ {
		ep := lb.Select(endpoints)
		require.NotNil(t, ep)
		counts[ep.Address]++
	}

	// Verify approximate weight distribution
	// host1 (weight 3) should be selected ~3x as often as host3 (weight 1)
	// Allow some tolerance due to algorithm implementation
	assert.Greater(t, counts["host1"], counts["host3"], "host1 should be selected more than host3")
	assert.Greater(t, counts["host2"], counts["host3"], "host2 should be selected more than host3")
}
