package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNewRoundRobinBalancer(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}

	lb := NewRoundRobinBalancer(hosts)
	assert.NotNil(t, lb)
}

func TestRoundRobinBalancer_Next(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
		NewHost("10.0.0.3", 8080, 1),
	}

	// Mark all as healthy
	for _, h := range hosts {
		h.SetStatus(StatusHealthy)
	}

	lb := NewRoundRobinBalancer(hosts)

	// Should cycle through hosts
	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		host := lb.Next()
		assert.NotNil(t, host)
		seen[host.Address]++
	}

	// Each host should be selected 3 times
	assert.Equal(t, 3, seen["10.0.0.1"])
	assert.Equal(t, 3, seen["10.0.0.2"])
	assert.Equal(t, 3, seen["10.0.0.3"])
}

func TestRoundRobinBalancer_Next_EmptyHosts(t *testing.T) {
	t.Parallel()

	lb := NewRoundRobinBalancer([]*Host{})
	assert.Nil(t, lb.Next())
}

func TestRoundRobinBalancer_Next_NoHealthyHosts(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
	}
	hosts[0].SetStatus(StatusUnhealthy)

	lb := NewRoundRobinBalancer(hosts)
	assert.Nil(t, lb.Next())
}

func TestRoundRobinBalancer_Next_SkipsUnhealthy(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}
	hosts[0].SetStatus(StatusUnhealthy)
	hosts[1].SetStatus(StatusHealthy)

	lb := NewRoundRobinBalancer(hosts)

	// Should only return healthy host
	for i := 0; i < 5; i++ {
		host := lb.Next()
		assert.NotNil(t, host)
		assert.Equal(t, "10.0.0.2", host.Address)
	}
}

func TestRoundRobinBalancer_SetHosts(t *testing.T) {
	t.Parallel()

	hosts1 := []*Host{NewHost("10.0.0.1", 8080, 1)}
	hosts1[0].SetStatus(StatusHealthy)

	lb := NewRoundRobinBalancer(hosts1)

	hosts2 := []*Host{NewHost("10.0.0.2", 8080, 1)}
	hosts2[0].SetStatus(StatusHealthy)

	lb.SetHosts(hosts2)

	host := lb.Next()
	assert.Equal(t, "10.0.0.2", host.Address)
}

func TestNewWeightedBalancer(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 70),
		NewHost("10.0.0.2", 8080, 30),
	}

	lb := NewWeightedBalancer(hosts)
	assert.NotNil(t, lb)
}

func TestWeightedBalancer_Next(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 80),
		NewHost("10.0.0.2", 8080, 20),
	}

	for _, h := range hosts {
		h.SetStatus(StatusHealthy)
	}

	lb := NewWeightedBalancer(hosts)

	// Run many iterations to verify weighted distribution
	seen := make(map[string]int)
	iterations := 1000
	for i := 0; i < iterations; i++ {
		host := lb.Next()
		assert.NotNil(t, host)
		seen[host.Address]++
	}

	// Host with weight 80 should be selected more often
	// Allow some variance due to randomness
	assert.Greater(t, seen["10.0.0.1"], seen["10.0.0.2"])
}

func TestWeightedBalancer_Next_EmptyHosts(t *testing.T) {
	t.Parallel()

	lb := NewWeightedBalancer([]*Host{})
	assert.Nil(t, lb.Next())
}

func TestWeightedBalancer_Next_NoHealthyHosts(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 50),
	}
	hosts[0].SetStatus(StatusUnhealthy)

	lb := NewWeightedBalancer(hosts)
	assert.Nil(t, lb.Next())
}

func TestWeightedBalancer_SetHosts(t *testing.T) {
	t.Parallel()

	hosts1 := []*Host{NewHost("10.0.0.1", 8080, 100)}
	hosts1[0].SetStatus(StatusHealthy)

	lb := NewWeightedBalancer(hosts1)

	hosts2 := []*Host{NewHost("10.0.0.2", 8080, 100)}
	hosts2[0].SetStatus(StatusHealthy)

	lb.SetHosts(hosts2)

	host := lb.Next()
	assert.Equal(t, "10.0.0.2", host.Address)
}

func TestNewLeastConnBalancer(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}

	lb := NewLeastConnBalancer(hosts)
	assert.NotNil(t, lb)
}

func TestLeastConnBalancer_Next(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}

	for _, h := range hosts {
		h.SetStatus(StatusHealthy)
	}

	// Add connections to first host
	hosts[0].IncrementConnections()
	hosts[0].IncrementConnections()

	lb := NewLeastConnBalancer(hosts)

	// Should select host with fewer connections
	host := lb.Next()
	assert.Equal(t, "10.0.0.2", host.Address)
}

func TestLeastConnBalancer_Next_EmptyHosts(t *testing.T) {
	t.Parallel()

	lb := NewLeastConnBalancer([]*Host{})
	assert.Nil(t, lb.Next())
}

func TestLeastConnBalancer_Next_NoHealthyHosts(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
	}
	hosts[0].SetStatus(StatusUnhealthy)

	lb := NewLeastConnBalancer(hosts)
	assert.Nil(t, lb.Next())
}

func TestLeastConnBalancer_SetHosts(t *testing.T) {
	t.Parallel()

	hosts1 := []*Host{NewHost("10.0.0.1", 8080, 1)}
	hosts1[0].SetStatus(StatusHealthy)

	lb := NewLeastConnBalancer(hosts1)

	hosts2 := []*Host{NewHost("10.0.0.2", 8080, 1)}
	hosts2[0].SetStatus(StatusHealthy)

	lb.SetHosts(hosts2)

	host := lb.Next()
	assert.Equal(t, "10.0.0.2", host.Address)
}

func TestNewRandomBalancer(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}

	lb := NewRandomBalancer(hosts)
	assert.NotNil(t, lb)
}

func TestRandomBalancer_Next(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}

	for _, h := range hosts {
		h.SetStatus(StatusHealthy)
	}

	lb := NewRandomBalancer(hosts)

	// Run many iterations to verify both hosts are selected
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		host := lb.Next()
		assert.NotNil(t, host)
		seen[host.Address] = true
	}

	// Both hosts should be selected at least once
	assert.True(t, seen["10.0.0.1"])
	assert.True(t, seen["10.0.0.2"])
}

func TestRandomBalancer_Next_EmptyHosts(t *testing.T) {
	t.Parallel()

	lb := NewRandomBalancer([]*Host{})
	assert.Nil(t, lb.Next())
}

func TestRandomBalancer_Next_NoHealthyHosts(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
	}
	hosts[0].SetStatus(StatusUnhealthy)

	lb := NewRandomBalancer(hosts)
	assert.Nil(t, lb.Next())
}

func TestRandomBalancer_SetHosts(t *testing.T) {
	t.Parallel()

	hosts1 := []*Host{NewHost("10.0.0.1", 8080, 1)}
	hosts1[0].SetStatus(StatusHealthy)

	lb := NewRandomBalancer(hosts1)

	hosts2 := []*Host{NewHost("10.0.0.2", 8080, 1)}
	hosts2[0].SetStatus(StatusHealthy)

	lb.SetHosts(hosts2)

	host := lb.Next()
	assert.Equal(t, "10.0.0.2", host.Address)
}

func TestNewLoadBalancer(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}

	tests := []struct {
		algorithm    string
		expectedType string
	}{
		{config.LoadBalancerRoundRobin, "*backend.RoundRobinBalancer"},
		{config.LoadBalancerWeighted, "*backend.WeightedBalancer"},
		{config.LoadBalancerLeastConn, "*backend.LeastConnBalancer"},
		{config.LoadBalancerRandom, "*backend.RandomBalancer"},
		{"", "*backend.RoundRobinBalancer"},
		{"unknown", "*backend.RoundRobinBalancer"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			t.Parallel()
			lb := NewLoadBalancer(tt.algorithm, hosts)
			assert.NotNil(t, lb)
		})
	}
}

func TestSecureRandomInt(t *testing.T) {
	t.Parallel()

	// Test with zero
	assert.Equal(t, 0, secureRandomInt(0))

	// Test with negative
	assert.Equal(t, 0, secureRandomInt(-1))

	// Test with positive - should be in range
	for i := 0; i < 100; i++ {
		result := secureRandomInt(10)
		assert.GreaterOrEqual(t, result, 0)
		assert.Less(t, result, 10)
	}
}

func TestLoadBalancer_Concurrency(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
		NewHost("10.0.0.2", 8080, 1),
	}

	for _, h := range hosts {
		h.SetStatus(StatusHealthy)
	}

	lb := NewRoundRobinBalancer(hosts)

	// Concurrent access
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_ = lb.Next()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestWeightedBalancer_ZeroTotalWeight(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 0),
	}
	hosts[0].SetStatus(StatusHealthy)

	lb := NewWeightedBalancer(hosts)

	// With zero weight, should return nil
	assert.Nil(t, lb.Next())
}

func TestRoundRobinBalancer_UnknownStatus(t *testing.T) {
	t.Parallel()

	hosts := []*Host{
		NewHost("10.0.0.1", 8080, 1),
	}
	// Status is Unknown by default

	lb := NewRoundRobinBalancer(hosts)

	// Unknown status should be treated as healthy
	host := lb.Next()
	assert.NotNil(t, host)
}
