package backend

import (
	"hash/fnv"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// LoadBalancer defines the interface for load balancing algorithms.
type LoadBalancer interface {
	Select(endpoints []*Endpoint) *Endpoint
}

// LBConfig holds configuration for load balancers.
type LBConfig struct {
	ConsistentHash *ConsistentHashConfig
}

// NewLoadBalancer creates a new load balancer based on the algorithm.
func NewLoadBalancer(algorithm string, config *LBConfig) LoadBalancer {
	switch algorithm {
	case "RoundRobin":
		return NewRoundRobinLB()
	case "LeastConnections":
		return NewLeastConnectionsLB()
	case "Random":
		return NewRandomLB()
	case "ConsistentHash":
		if config != nil && config.ConsistentHash != nil {
			return NewConsistentHashLB(config.ConsistentHash)
		}
		return NewRoundRobinLB()
	case "WeightedRoundRobin":
		return NewWeightedRoundRobinLB()
	default:
		return NewRoundRobinLB()
	}
}

// RoundRobinLB implements round-robin load balancing.
type RoundRobinLB struct {
	counter uint64
}

// NewRoundRobinLB creates a new round-robin load balancer.
func NewRoundRobinLB() *RoundRobinLB {
	return &RoundRobinLB{}
}

// Select selects an endpoint using round-robin.
func (lb *RoundRobinLB) Select(endpoints []*Endpoint) *Endpoint {
	if len(endpoints) == 0 {
		return nil
	}

	idx := atomic.AddUint64(&lb.counter, 1) % uint64(len(endpoints))
	return endpoints[idx]
}

// WeightedRoundRobinLB implements weighted round-robin load balancing.
type WeightedRoundRobinLB struct {
	mu            sync.Mutex
	currentWeight int
	maxWeight     int
	gcd           int
	index         int
}

// NewWeightedRoundRobinLB creates a new weighted round-robin load balancer.
func NewWeightedRoundRobinLB() *WeightedRoundRobinLB {
	return &WeightedRoundRobinLB{
		index: -1,
	}
}

// Select selects an endpoint using weighted round-robin.
// Falls back to simple round-robin if all weights are 0 to prevent infinite loops.
func (lb *WeightedRoundRobinLB) Select(endpoints []*Endpoint) *Endpoint {
	if len(endpoints) == 0 {
		return nil
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	// Recalculate GCD and max weight on each call to handle dynamic endpoint changes
	lb.gcd = lb.calculateGCD(endpoints)
	lb.maxWeight = lb.calculateMaxWeight(endpoints)

	// If all weights are 0 or maxWeight is 0, fall back to simple round-robin
	// This prevents infinite loops when no endpoint can satisfy the weight condition
	if lb.maxWeight == 0 || lb.gcd == 0 {
		lb.index = (lb.index + 1) % len(endpoints)
		return endpoints[lb.index]
	}

	// Maximum iterations to prevent infinite loop in edge cases
	// Worst case: we need to cycle through all endpoints at all weight levels
	maxIterations := len(endpoints) * (lb.maxWeight/lb.gcd + 1)

	for i := 0; i < maxIterations; i++ {
		lb.index = (lb.index + 1) % len(endpoints)
		if lb.index == 0 {
			lb.currentWeight -= lb.gcd
			if lb.currentWeight <= 0 {
				lb.currentWeight = lb.maxWeight
			}
		}

		if endpoints[lb.index].Weight >= lb.currentWeight {
			return endpoints[lb.index]
		}
	}

	// Fallback: return first endpoint if no match found after max iterations
	return endpoints[0]
}

func (lb *WeightedRoundRobinLB) calculateGCD(endpoints []*Endpoint) int {
	if len(endpoints) == 0 {
		return 1
	}

	result := endpoints[0].Weight
	for i := 1; i < len(endpoints); i++ {
		result = gcd(result, endpoints[i].Weight)
	}

	// Return 1 if GCD is 0 (all weights are 0) to prevent division by zero
	if result == 0 {
		return 1
	}
	return result
}

func (lb *WeightedRoundRobinLB) calculateMaxWeight(endpoints []*Endpoint) int {
	maxWeight := 0
	for _, ep := range endpoints {
		if ep.Weight > maxWeight {
			maxWeight = ep.Weight
		}
	}
	return maxWeight
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// LeastConnectionsLB implements least-connections load balancing.
type LeastConnectionsLB struct {
	connections map[string]*int64
	mu          sync.RWMutex
}

// NewLeastConnectionsLB creates a new least-connections load balancer.
func NewLeastConnectionsLB() *LeastConnectionsLB {
	return &LeastConnectionsLB{
		connections: make(map[string]*int64),
	}
}

// Select selects the endpoint with the least connections.
func (lb *LeastConnectionsLB) Select(endpoints []*Endpoint) *Endpoint {
	if len(endpoints) == 0 {
		return nil
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	var selected *Endpoint
	var minConns int64 = -1

	for _, ep := range endpoints {
		addr := ep.FullAddress()
		if _, exists := lb.connections[addr]; !exists {
			var zero int64
			lb.connections[addr] = &zero
		}

		conns := atomic.LoadInt64(lb.connections[addr])
		if minConns == -1 || conns < minConns {
			minConns = conns
			selected = ep
		}
	}

	if selected != nil {
		addr := selected.FullAddress()
		atomic.AddInt64(lb.connections[addr], 1)
	}

	return selected
}

// Release decrements the connection count for an endpoint.
func (lb *LeastConnectionsLB) Release(endpoint *Endpoint) {
	if endpoint == nil {
		return
	}

	lb.mu.RLock()
	defer lb.mu.RUnlock()

	addr := endpoint.FullAddress()
	if counter, exists := lb.connections[addr]; exists {
		atomic.AddInt64(counter, -1)
	}
}

// RandomLB implements random load balancing.
// Thread-safe implementation using a mutex-protected local random source.
type RandomLB struct {
	mu  sync.Mutex
	rng *rand.Rand
}

// NewRandomLB creates a new random load balancer.
func NewRandomLB() *RandomLB {
	//nolint:gosec // weak random is acceptable for load balancing
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &RandomLB{
		rng: rng,
	}
}

// Select selects a random endpoint.
// Thread-safe: uses mutex to protect the random number generator.
func (lb *RandomLB) Select(endpoints []*Endpoint) *Endpoint {
	if len(endpoints) == 0 {
		return nil
	}

	lb.mu.Lock()
	idx := lb.rng.Intn(len(endpoints))
	lb.mu.Unlock()

	return endpoints[idx]
}

// ConsistentHashLB implements consistent hash load balancing.
// Optimized with hash ring caching - only rebuilds when endpoints change.
type ConsistentHashLB struct {
	config          *ConsistentHashConfig
	hashRing        *HashRing
	mu              sync.RWMutex
	cachedEndpoints string // Hash of endpoint addresses for cache invalidation
}

// HashRing implements a consistent hash ring.
type HashRing struct {
	ring     map[uint32]*Endpoint
	sorted   []uint32
	replicas int
}

// NewConsistentHashLB creates a new consistent hash load balancer.
func NewConsistentHashLB(config *ConsistentHashConfig) *ConsistentHashLB {
	return &ConsistentHashLB{
		config: config,
		hashRing: &HashRing{
			ring:     make(map[uint32]*Endpoint),
			sorted:   make([]uint32, 0),
			replicas: 100,
		},
	}
}

// Select selects an endpoint using consistent hashing.
func (lb *ConsistentHashLB) Select(endpoints []*Endpoint) *Endpoint {
	if len(endpoints) == 0 {
		return nil
	}

	lb.rebuildRingIfNeeded(endpoints)

	// For now, use a simple hash of the first endpoint
	// In practice, this would use the configured hash key (header, cookie, or source IP)
	key := endpoints[0].FullAddress()
	return lb.getEndpoint(key)
}

// SelectWithKey selects an endpoint using the provided key.
func (lb *ConsistentHashLB) SelectWithKey(endpoints []*Endpoint, key string) *Endpoint {
	if len(endpoints) == 0 {
		return nil
	}

	lb.rebuildRingIfNeeded(endpoints)

	return lb.getEndpoint(key)
}

// computeEndpointsHash computes a hash of endpoint addresses for cache invalidation.
func (lb *ConsistentHashLB) computeEndpointsHash(endpoints []*Endpoint) string {
	h := fnv.New64a()
	for _, ep := range endpoints {
		_, _ = h.Write([]byte(ep.FullAddress())) // hash.Write never returns an error
	}
	return string(h.Sum(nil))
}

// rebuildRingIfNeeded rebuilds the hash ring only if endpoints have changed.
func (lb *ConsistentHashLB) rebuildRingIfNeeded(endpoints []*Endpoint) {
	endpointsHash := lb.computeEndpointsHash(endpoints)

	// Check if we need to rebuild (read lock first for performance)
	lb.mu.RLock()
	if lb.cachedEndpoints == endpointsHash && len(lb.hashRing.sorted) > 0 {
		lb.mu.RUnlock()
		return
	}
	lb.mu.RUnlock()

	// Need to rebuild - acquire write lock
	lb.mu.Lock()
	defer lb.mu.Unlock()

	// Double-check after acquiring write lock
	if lb.cachedEndpoints == endpointsHash && len(lb.hashRing.sorted) > 0 {
		return
	}

	lb.rebuildRing(endpoints)
	lb.cachedEndpoints = endpointsHash
}

func (lb *ConsistentHashLB) rebuildRing(endpoints []*Endpoint) {
	lb.hashRing.ring = make(map[uint32]*Endpoint)
	lb.hashRing.sorted = make([]uint32, 0, len(endpoints)*lb.hashRing.replicas)

	for _, ep := range endpoints {
		for i := 0; i < lb.hashRing.replicas; i++ {
			key := ep.FullAddress() + string(rune(i))
			hash := lb.hash(key)
			lb.hashRing.ring[hash] = ep
			lb.hashRing.sorted = append(lb.hashRing.sorted, hash)
		}
	}

	// Sort the hash ring using optimized sort.Slice (O(n log n) instead of O(n^2))
	sort.Slice(lb.hashRing.sorted, func(i, j int) bool {
		return lb.hashRing.sorted[i] < lb.hashRing.sorted[j]
	})
}

func (lb *ConsistentHashLB) getEndpoint(key string) *Endpoint {
	if len(lb.hashRing.sorted) == 0 {
		return nil
	}

	hash := lb.hash(key)

	// Binary search for the first hash >= key hash
	idx := lb.search(hash)
	return lb.hashRing.ring[lb.hashRing.sorted[idx]]
}

func (lb *ConsistentHashLB) search(hash uint32) int {
	low, high := 0, len(lb.hashRing.sorted)-1

	for low < high {
		mid := (low + high) / 2
		if lb.hashRing.sorted[mid] < hash {
			low = mid + 1
		} else {
			high = mid
		}
	}

	if low == len(lb.hashRing.sorted) {
		return 0
	}
	return low
}

func (lb *ConsistentHashLB) hash(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key)) // hash.Write never returns an error
	return h.Sum32()
}
