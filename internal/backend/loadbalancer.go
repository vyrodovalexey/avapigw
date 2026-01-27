package backend

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// LoadBalancer is the interface for load balancing algorithms.
type LoadBalancer interface {
	Next() *Host
	NextAvailable() *Host
	SetHosts(hosts []*Host)
}

// RoundRobinBalancer implements round-robin load balancing.
type RoundRobinBalancer struct {
	hosts   []*Host
	current atomic.Uint64
	mu      sync.RWMutex
}

// NewRoundRobinBalancer creates a new round-robin load balancer.
func NewRoundRobinBalancer(hosts []*Host) *RoundRobinBalancer {
	return &RoundRobinBalancer{
		hosts: hosts,
	}
}

// Next returns the next host in round-robin order.
func (b *RoundRobinBalancer) Next() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	healthy := b.getHealthyHosts()
	if len(healthy) == 0 {
		return nil
	}

	idx := b.current.Add(1) - 1
	return healthy[idx%uint64(len(healthy))]
}

// SetHosts updates the hosts.
func (b *RoundRobinBalancer) SetHosts(hosts []*Host) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hosts = hosts
}

// getHealthyHosts returns only healthy hosts.
func (b *RoundRobinBalancer) getHealthyHosts() []*Host {
	healthy := make([]*Host, 0, len(b.hosts))
	for _, host := range b.hosts {
		if host.Status() == StatusHealthy || host.Status() == StatusUnknown {
			healthy = append(healthy, host)
		}
	}
	return healthy
}

// getAvailableHosts returns only available hosts (healthy and with capacity).
func (b *RoundRobinBalancer) getAvailableHosts() []*Host {
	available := make([]*Host, 0, len(b.hosts))
	for _, host := range b.hosts {
		if host.IsAvailable() {
			available = append(available, host)
		}
	}
	return available
}

// NextAvailable returns the next available host in round-robin order.
// It considers health status and max sessions capacity.
func (b *RoundRobinBalancer) NextAvailable() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	available := b.getAvailableHosts()
	if len(available) == 0 {
		return nil
	}

	idx := b.current.Add(1) - 1
	return available[idx%uint64(len(available))]
}

// WeightedBalancer implements weighted load balancing.
type WeightedBalancer struct {
	hosts       []*Host
	totalWeight int
	mu          sync.RWMutex
}

// NewWeightedBalancer creates a new weighted load balancer.
func NewWeightedBalancer(hosts []*Host) *WeightedBalancer {
	b := &WeightedBalancer{
		hosts: hosts,
	}
	b.calculateTotalWeight()
	return b
}

// calculateTotalWeight calculates the total weight of all hosts.
func (b *WeightedBalancer) calculateTotalWeight() {
	b.totalWeight = 0
	for _, host := range b.hosts {
		if host.Status() == StatusHealthy || host.Status() == StatusUnknown {
			b.totalWeight += host.Weight
		}
	}
}

// Next returns the next host based on weights.
func (b *WeightedBalancer) Next() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 || b.totalWeight == 0 {
		return nil
	}

	healthy := make([]*Host, 0, len(b.hosts))
	totalWeight := 0
	for _, host := range b.hosts {
		if host.Status() == StatusHealthy || host.Status() == StatusUnknown {
			healthy = append(healthy, host)
			totalWeight += host.Weight
		}
	}

	if len(healthy) == 0 || totalWeight == 0 {
		return nil
	}

	r := secureRandomInt(totalWeight)
	for _, host := range healthy {
		r -= host.Weight
		if r < 0 {
			return host
		}
	}

	return healthy[len(healthy)-1]
}

// SetHosts updates the hosts.
func (b *WeightedBalancer) SetHosts(hosts []*Host) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hosts = hosts
	b.calculateTotalWeight()
}

// NextAvailable returns the next available host based on weights.
// It considers health status and max sessions capacity.
func (b *WeightedBalancer) NextAvailable() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	available := make([]*Host, 0, len(b.hosts))
	totalWeight := 0
	for _, host := range b.hosts {
		if host.IsAvailable() {
			available = append(available, host)
			totalWeight += host.Weight
		}
	}

	if len(available) == 0 || totalWeight == 0 {
		return nil
	}

	r := secureRandomInt(totalWeight)
	for _, host := range available {
		r -= host.Weight
		if r < 0 {
			return host
		}
	}

	return available[len(available)-1]
}

// LeastConnBalancer implements least-connections load balancing.
type LeastConnBalancer struct {
	hosts []*Host
	mu    sync.RWMutex
}

// NewLeastConnBalancer creates a new least-connections load balancer.
func NewLeastConnBalancer(hosts []*Host) *LeastConnBalancer {
	return &LeastConnBalancer{
		hosts: hosts,
	}
}

// Next returns the host with the least connections.
func (b *LeastConnBalancer) Next() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	var selected *Host
	minConns := int64(-1)

	for _, host := range b.hosts {
		if host.Status() != StatusHealthy && host.Status() != StatusUnknown {
			continue
		}

		conns := host.Connections()
		if minConns < 0 || conns < minConns {
			minConns = conns
			selected = host
		}
	}

	return selected
}

// SetHosts updates the hosts.
func (b *LeastConnBalancer) SetHosts(hosts []*Host) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hosts = hosts
}

// NextAvailable returns the available host with the least connections.
// It considers health status and max sessions capacity.
func (b *LeastConnBalancer) NextAvailable() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	var selected *Host
	minConns := int64(-1)

	for _, host := range b.hosts {
		if !host.IsAvailable() {
			continue
		}

		conns := host.Connections()
		if minConns < 0 || conns < minConns {
			minConns = conns
			selected = host
		}
	}

	return selected
}

// RandomBalancer implements random load balancing.
type RandomBalancer struct {
	hosts []*Host
	mu    sync.RWMutex
}

// NewRandomBalancer creates a new random load balancer.
func NewRandomBalancer(hosts []*Host) *RandomBalancer {
	return &RandomBalancer{
		hosts: hosts,
	}
}

// Next returns a random host.
func (b *RandomBalancer) Next() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	healthy := make([]*Host, 0, len(b.hosts))
	for _, host := range b.hosts {
		if host.Status() == StatusHealthy || host.Status() == StatusUnknown {
			healthy = append(healthy, host)
		}
	}

	if len(healthy) == 0 {
		return nil
	}

	return healthy[secureRandomInt(len(healthy))]
}

// SetHosts updates the hosts.
func (b *RandomBalancer) SetHosts(hosts []*Host) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hosts = hosts
}

// NextAvailable returns a random available host.
// It considers health status and max sessions capacity.
func (b *RandomBalancer) NextAvailable() *Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.hosts) == 0 {
		return nil
	}

	available := make([]*Host, 0, len(b.hosts))
	for _, host := range b.hosts {
		if host.IsAvailable() {
			available = append(available, host)
		}
	}

	if len(available) == 0 {
		return nil
	}

	return available[secureRandomInt(len(available))]
}

// NewLoadBalancer creates a load balancer based on the algorithm.
func NewLoadBalancer(algorithm string, hosts []*Host) LoadBalancer {
	switch algorithm {
	case config.LoadBalancerWeighted:
		return NewWeightedBalancer(hosts)
	case config.LoadBalancerLeastConn:
		return NewLeastConnBalancer(hosts)
	case config.LoadBalancerRandom:
		return NewRandomBalancer(hosts)
	default:
		return NewRoundRobinBalancer(hosts)
	}
}

// secureRandomInt returns a cryptographically secure random int in [0, n).
func secureRandomInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	// Safe conversion: result of modulo is always < n, which fits in int
	return int(binary.LittleEndian.Uint64(b[:]) % uint64(n)) //nolint:gosec // bounds checked
}
