// Package backend provides backend management for the API Gateway.
package backend

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ManagerStats holds statistics about the backend manager.
type ManagerStats struct {
	// TotalBackends is the total number of registered backends.
	TotalBackends int
	// HealthyBackends is the number of backends with at least one healthy endpoint.
	HealthyBackends int
	// TotalEndpoints is the total number of endpoints across all backends.
	TotalEndpoints int
	// HealthyEndpoints is the total number of healthy endpoints.
	HealthyEndpoints int
	// Uptime is how long the manager has been running.
	Uptime time.Duration
}

// Manager manages backend services.
type Manager struct {
	backends  map[string]*Backend
	mu        sync.RWMutex
	logger    *zap.Logger
	startTime time.Time
	running   atomic.Bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// Backend represents a backend service with its configuration.
type Backend struct {
	Name           string
	Namespace      string
	Endpoints      []*Endpoint
	LoadBalancer   LoadBalancer
	HealthChecker  *HealthChecker
	CircuitBreaker *CircuitBreaker
	ConnectionPool *ConnectionPool
	mu             sync.RWMutex
}

// Endpoint represents a single backend endpoint.
type Endpoint struct {
	Address  string
	Port     int
	Weight   int
	Healthy  bool
	Metadata map[string]string
	mu       sync.RWMutex
}

// BackendConfig holds configuration for creating a backend service.
// It defines the endpoints, load balancing strategy, health checking,
// circuit breaker settings, and connection pooling for a backend.
type BackendConfig struct {
	Name           string
	Namespace      string
	Endpoints      []EndpointConfig
	LoadBalancing  *LoadBalancingConfig
	HealthCheck    *HealthCheckConfig
	CircuitBreaker *CircuitBreakerConfig
	ConnectionPool *ConnectionPoolConfig
}

// EndpointConfig holds configuration for a single backend endpoint.
// Each endpoint represents a network address that can receive traffic.
type EndpointConfig struct {
	Address  string
	Port     int
	Weight   int
	Metadata map[string]string
}

// LoadBalancingConfig holds load balancing configuration for a backend.
// Supported algorithms: RoundRobin, Random, LeastConnections, ConsistentHash.
type LoadBalancingConfig struct {
	Algorithm      string
	ConsistentHash *ConsistentHashConfig
}

// ConsistentHashConfig holds consistent hash configuration.
type ConsistentHashConfig struct {
	Type   string
	Header string
	Cookie string
}

// HealthCheckConfig holds health check configuration for backend endpoints.
// When enabled, endpoints are periodically checked and marked unhealthy
// if they fail to respond within the configured thresholds.
type HealthCheckConfig struct {
	Enabled            bool
	Interval           int
	Timeout            int
	HealthyThreshold   int
	UnhealthyThreshold int
	Path               string
	Port               int
}

// CircuitBreakerConfig holds circuit breaker configuration for a backend.
// The circuit breaker prevents cascading failures by temporarily stopping
// requests to unhealthy backends after consecutive errors.
type CircuitBreakerConfig struct {
	Enabled           bool
	ConsecutiveErrors int
	Interval          int
	BaseEjectionTime  int
	MaxEjectionPct    int
}

// ConnectionPoolConfig holds connection pool configuration for a backend.
// Connection pooling improves performance by reusing TCP connections
// instead of creating new ones for each request.
type ConnectionPoolConfig struct {
	MaxConnections        int
	MaxIdleConnections    int
	MaxConnectionsPerHost int
	IdleTimeout           int
}

// NewManager creates a new backend manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		backends: make(map[string]*Backend),
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the backend manager and all health checkers.
// This method is non-blocking and returns immediately.
func (m *Manager) Start(ctx context.Context) error {
	if m.running.Swap(true) {
		return fmt.Errorf("manager is already running")
	}

	m.startTime = time.Now()
	m.logger.Info("starting backend manager")

	// Start health checkers for all backends
	m.mu.RLock()
	for _, backend := range m.backends {
		if backend.HealthChecker != nil {
			backend.HealthChecker.Start(backend.Endpoints)
		}
	}
	m.mu.RUnlock()

	// Start background monitoring goroutine
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.monitorLoop(ctx)
	}()

	return nil
}

// Stop stops the backend manager and all health checkers.
// This method blocks until all goroutines have stopped.
func (m *Manager) Stop(ctx context.Context) error {
	if !m.running.Swap(false) {
		return fmt.Errorf("manager is not running")
	}

	m.logger.Info("stopping backend manager")

	// Signal stop
	close(m.stopCh)

	// Stop all health checkers
	m.mu.RLock()
	for _, backend := range m.backends {
		if backend.HealthChecker != nil {
			backend.HealthChecker.Stop()
		}
	}
	m.mu.RUnlock()

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("backend manager stopped successfully")
		return nil
	case <-ctx.Done():
		m.logger.Warn("backend manager stop timed out")
		return ctx.Err()
	}
}

// Wait blocks until the manager is stopped.
func (m *Manager) Wait() {
	m.wg.Wait()
}

// Stats returns statistics about the backend manager.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := ManagerStats{
		TotalBackends: len(m.backends),
	}

	if !m.startTime.IsZero() {
		stats.Uptime = time.Since(m.startTime)
	}

	for _, backend := range m.backends {
		endpoints := backend.GetAllEndpoints()
		stats.TotalEndpoints += len(endpoints)

		hasHealthy := false
		for _, ep := range endpoints {
			if ep.IsHealthy() {
				stats.HealthyEndpoints++
				hasHealthy = true
			}
		}
		if hasHealthy {
			stats.HealthyBackends++
		}
	}

	return stats
}

// IsRunning returns true if the manager is running.
func (m *Manager) IsRunning() bool {
	return m.running.Load()
}

// monitorLoop runs periodic monitoring tasks.
func (m *Manager) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			stats := m.Stats()
			m.logger.Debug("backend manager stats",
				zap.Int("totalBackends", stats.TotalBackends),
				zap.Int("healthyBackends", stats.HealthyBackends),
				zap.Int("totalEndpoints", stats.TotalEndpoints),
				zap.Int("healthyEndpoints", stats.HealthyEndpoints),
				zap.Duration("uptime", stats.Uptime),
			)
		}
	}
}

// GetBackend returns a backend by name.
func (m *Manager) GetBackend(name string) *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.backends[name]
}

// GetBackendByNamespace returns a backend by namespace and name.
func (m *Manager) GetBackendByNamespace(namespace, name string) *Backend {
	key := fmt.Sprintf("%s/%s", namespace, name)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.backends[key]
}

// AddBackend adds a new backend.
func (m *Manager) AddBackend(config BackendConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.buildBackendKey(config.Namespace, config.Name)

	if _, exists := m.backends[key]; exists {
		return fmt.Errorf("backend %s already exists", key)
	}

	backend := m.createBackendFromConfig(config)
	m.backends[key] = backend

	m.logger.Info("backend added",
		zap.String("name", key),
		zap.Int("endpoints", len(backend.Endpoints)),
	)

	return nil
}

// buildBackendKey constructs the backend key from namespace and name.
func (m *Manager) buildBackendKey(namespace, name string) string {
	if namespace != "" {
		return fmt.Sprintf("%s/%s", namespace, name)
	}
	return name
}

// createBackendFromConfig creates a Backend instance from the given configuration.
func (m *Manager) createBackendFromConfig(config BackendConfig) *Backend {
	backend := &Backend{
		Name:      config.Name,
		Namespace: config.Namespace,
		Endpoints: m.createEndpoints(config.Endpoints),
	}

	backend.LoadBalancer = m.createLoadBalancer(config.LoadBalancing)
	m.setupHealthChecker(backend, config.HealthCheck)
	m.setupCircuitBreaker(backend, config.CircuitBreaker)
	m.setupConnectionPool(backend, config.ConnectionPool)

	return backend
}

// createEndpoints creates endpoint instances from endpoint configurations.
func (m *Manager) createEndpoints(configs []EndpointConfig) []*Endpoint {
	endpoints := make([]*Endpoint, 0, len(configs))
	for _, epConfig := range configs {
		endpoint := &Endpoint{
			Address:  epConfig.Address,
			Port:     epConfig.Port,
			Weight:   epConfig.Weight,
			Healthy:  true,
			Metadata: epConfig.Metadata,
		}
		if endpoint.Weight <= 0 {
			endpoint.Weight = 1
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// DefaultLoadBalancerAlgorithm is the default load balancing algorithm used when none is specified.
const DefaultLoadBalancerAlgorithm = "RoundRobin"

// createLoadBalancer creates a load balancer from the configuration.
// Always returns a non-nil LoadBalancer, using RoundRobin as the default.
func (m *Manager) createLoadBalancer(config *LoadBalancingConfig) LoadBalancer {
	if config != nil && config.Algorithm != "" {
		return NewLoadBalancer(config.Algorithm, &LBConfig{
			ConsistentHash: config.ConsistentHash,
		})
	}
	return NewLoadBalancer(DefaultLoadBalancerAlgorithm, nil)
}

// setupHealthChecker configures the health checker for the backend if enabled.
func (m *Manager) setupHealthChecker(backend *Backend, config *HealthCheckConfig) {
	if config != nil && config.Enabled {
		backend.HealthChecker = NewHealthChecker(config, m.logger)
	}
}

// setupCircuitBreaker configures the circuit breaker for the backend if enabled.
func (m *Manager) setupCircuitBreaker(backend *Backend, config *CircuitBreakerConfig) {
	if config != nil && config.Enabled {
		backend.CircuitBreaker = NewCircuitBreaker(config)
	}
}

// setupConnectionPool configures the connection pool for the backend if provided.
func (m *Manager) setupConnectionPool(backend *Backend, config *ConnectionPoolConfig) {
	if config != nil {
		backend.ConnectionPool = NewConnectionPool(config)
	}
}

// RemoveBackend removes a backend by name.
func (m *Manager) RemoveBackend(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	backend, exists := m.backends[name]
	if !exists {
		return fmt.Errorf("backend %s not found", name)
	}

	// Stop health checker if running
	if backend.HealthChecker != nil {
		backend.HealthChecker.Stop()
	}

	// Close connection pool
	if backend.ConnectionPool != nil {
		backend.ConnectionPool.Close()
	}

	delete(m.backends, name)
	m.logger.Info("backend removed", zap.String("name", name))

	return nil
}

// UpdateBackend updates an existing backend.
func (m *Manager) UpdateBackend(config BackendConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := config.Name
	if config.Namespace != "" {
		key = fmt.Sprintf("%s/%s", config.Namespace, config.Name)
	}

	backend, exists := m.backends[key]
	if !exists {
		return fmt.Errorf("backend %s not found", key)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	// Update endpoints
	backend.Endpoints = make([]*Endpoint, 0, len(config.Endpoints))
	for _, epConfig := range config.Endpoints {
		endpoint := &Endpoint{
			Address:  epConfig.Address,
			Port:     epConfig.Port,
			Weight:   epConfig.Weight,
			Healthy:  true,
			Metadata: epConfig.Metadata,
		}
		if endpoint.Weight <= 0 {
			endpoint.Weight = 1
		}
		backend.Endpoints = append(backend.Endpoints, endpoint)
	}

	// Update load balancer
	if config.LoadBalancing != nil {
		backend.LoadBalancer = NewLoadBalancer(config.LoadBalancing.Algorithm, &LBConfig{
			ConsistentHash: config.LoadBalancing.ConsistentHash,
		})
	}

	m.logger.Info("backend updated",
		zap.String("name", key),
		zap.Int("endpoints", len(backend.Endpoints)),
	)

	return nil
}

// ListBackends returns all backend names.
func (m *Manager) ListBackends() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.backends))
	for name := range m.backends {
		names = append(names, name)
	}
	return names
}

// GetHealthyEndpoint returns a healthy endpoint from the backend using the configured load balancer.
// Returns nil if no healthy endpoints are available.
// The LoadBalancer is guaranteed to be non-nil as it is always set during backend creation.
func (b *Backend) GetHealthyEndpoint() *Endpoint {
	b.mu.RLock()
	defer b.mu.RUnlock()

	healthyEndpoints := make([]*Endpoint, 0)
	for _, ep := range b.Endpoints {
		ep.mu.RLock()
		if ep.Healthy {
			healthyEndpoints = append(healthyEndpoints, ep)
		}
		ep.mu.RUnlock()
	}

	if len(healthyEndpoints) == 0 {
		return nil
	}

	return b.LoadBalancer.Select(healthyEndpoints)
}

// GetAllEndpoints returns all endpoints.
func (b *Backend) GetAllEndpoints() []*Endpoint {
	b.mu.RLock()
	defer b.mu.RUnlock()

	endpoints := make([]*Endpoint, len(b.Endpoints))
	copy(endpoints, b.Endpoints)
	return endpoints
}

// GetHealthyEndpoints returns all healthy endpoints.
func (b *Backend) GetHealthyEndpoints() []*Endpoint {
	b.mu.RLock()
	defer b.mu.RUnlock()

	healthyEndpoints := make([]*Endpoint, 0)
	for _, ep := range b.Endpoints {
		ep.mu.RLock()
		if ep.Healthy {
			healthyEndpoints = append(healthyEndpoints, ep)
		}
		ep.mu.RUnlock()
	}
	return healthyEndpoints
}

// SetHealthy sets the health status of an endpoint.
func (e *Endpoint) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Healthy = healthy
}

// IsHealthy returns the health status of an endpoint.
func (e *Endpoint) IsHealthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Healthy
}

// FullAddress returns the complete network address of the endpoint in "host:port" format.
// This is suitable for use with net.Dial and similar functions.
// Example: "192.168.1.1:8080" or "backend-service.default.svc:80"
func (e *Endpoint) FullAddress() string {
	return fmt.Sprintf("%s:%d", e.Address, e.Port)
}
