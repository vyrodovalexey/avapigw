// Package backend provides backend service management for the API Gateway.
package backend

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Status represents the health status of a backend.
type Status int32

const (
	// StatusUnknown indicates the status is unknown.
	StatusUnknown Status = iota
	// StatusHealthy indicates the backend is healthy.
	StatusHealthy
	// StatusUnhealthy indicates the backend is unhealthy.
	StatusUnhealthy
)

// String returns the string representation of the status.
func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusHealthy:
		return "healthy"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// Backend represents a backend service.
type Backend interface {
	Name() string
	GetHost() (*Host, error)
	ReleaseHost(host *Host)
	Status() Status
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Host represents a single backend host.
type Host struct {
	Address     string
	Port        int
	Weight      int
	status      atomic.Int32
	connections atomic.Int64
	lastUsed    atomic.Int64
}

// NewHost creates a new host.
func NewHost(address string, port, weight int) *Host {
	h := &Host{
		Address: address,
		Port:    port,
		Weight:  weight,
	}
	h.status.Store(int32(StatusUnknown))
	return h
}

// URL returns the host URL (HTTP).
func (h *Host) URL() string {
	return fmt.Sprintf("http://%s:%d", h.Address, h.Port)
}

// TLSURL returns the host URL with HTTPS scheme.
func (h *Host) TLSURL() string {
	return fmt.Sprintf("https://%s:%d", h.Address, h.Port)
}

// URLWithScheme returns the host URL with the specified scheme.
func (h *Host) URLWithScheme(useTLS bool) string {
	if useTLS {
		return h.TLSURL()
	}
	return h.URL()
}

// Status returns the host status.
func (h *Host) Status() Status {
	return Status(h.status.Load())
}

// SetStatus sets the host status.
func (h *Host) SetStatus(status Status) {
	h.status.Store(int32(status))
}

// Connections returns the current connection count.
func (h *Host) Connections() int64 {
	return h.connections.Load()
}

// IncrementConnections increments the connection count.
func (h *Host) IncrementConnections() {
	h.connections.Add(1)
	h.lastUsed.Store(time.Now().UnixNano())
}

// DecrementConnections decrements the connection count.
func (h *Host) DecrementConnections() {
	h.connections.Add(-1)
}

// LastUsed returns the last used time.
func (h *Host) LastUsed() time.Time {
	return time.Unix(0, h.lastUsed.Load())
}

// ServiceBackend is the default backend implementation.
type ServiceBackend struct {
	name         string
	config       config.Backend
	hosts        []*Host
	loadBalancer LoadBalancer
	healthCheck  *HealthChecker
	pool         *ConnectionPool
	tlsBuilder   *TLSConfigBuilder
	tlsConfig    *tls.Config
	logger       observability.Logger
	status       atomic.Int32
	mu           sync.RWMutex
}

// BackendOption is a functional option for configuring a backend.
type BackendOption func(*ServiceBackend)

// WithBackendLogger sets the logger for the backend.
func WithBackendLogger(logger observability.Logger) BackendOption {
	return func(b *ServiceBackend) {
		b.logger = logger
	}
}

// WithLoadBalancer sets the load balancer for the backend.
func WithLoadBalancer(lb LoadBalancer) BackendOption {
	return func(b *ServiceBackend) {
		b.loadBalancer = lb
	}
}

// WithConnectionPool sets the connection pool for the backend.
func WithConnectionPool(pool *ConnectionPool) BackendOption {
	return func(b *ServiceBackend) {
		b.pool = pool
	}
}

// NewBackend creates a new backend from configuration.
func NewBackend(cfg config.Backend, opts ...BackendOption) (*ServiceBackend, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("backend name is required")
	}

	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("at least one host is required")
	}

	b := &ServiceBackend{
		name:   cfg.Name,
		config: cfg,
		hosts:  make([]*Host, 0, len(cfg.Hosts)),
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(b)
	}

	// Create hosts
	for _, hostCfg := range cfg.Hosts {
		weight := hostCfg.Weight
		if weight == 0 {
			weight = 1
		}
		host := NewHost(hostCfg.Address, hostCfg.Port, weight)
		b.hosts = append(b.hosts, host)
	}

	// Create load balancer if not provided
	if b.loadBalancer == nil {
		algorithm := config.LoadBalancerRoundRobin
		if cfg.LoadBalancer != nil && cfg.LoadBalancer.Algorithm != "" {
			algorithm = cfg.LoadBalancer.Algorithm
		}
		b.loadBalancer = NewLoadBalancer(algorithm, b.hosts)
	}

	// Build TLS configuration if enabled
	if cfg.TLS != nil && cfg.TLS.Enabled {
		b.tlsBuilder = NewTLSConfigBuilder(cfg.TLS, WithTLSLogger(b.logger))
		tlsConfig, err := b.tlsBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config for backend %s: %w", cfg.Name, err)
		}
		b.tlsConfig = tlsConfig

		b.logger.Info("TLS enabled for backend",
			observability.String("backend", cfg.Name),
			observability.String("mode", cfg.TLS.GetEffectiveMode()),
			observability.Bool("insecureSkipVerify", cfg.TLS.InsecureSkipVerify),
		)
	}

	// Create connection pool if not provided
	if b.pool == nil {
		poolCfg := DefaultPoolConfig()
		poolCfg.TLSConfig = b.tlsConfig
		b.pool = NewConnectionPool(poolCfg)
	}

	b.status.Store(int32(StatusUnknown))

	return b, nil
}

// Name returns the backend name.
func (b *ServiceBackend) Name() string {
	return b.name
}

// GetHost returns a host using the load balancer.
func (b *ServiceBackend) GetHost() (*Host, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	host := b.loadBalancer.Next()
	if host == nil {
		return nil, fmt.Errorf("no healthy hosts available for backend %s", b.name)
	}

	host.IncrementConnections()
	return host, nil
}

// ReleaseHost releases a host back to the pool.
func (b *ServiceBackend) ReleaseHost(host *Host) {
	if host != nil {
		host.DecrementConnections()
	}
}

// Status returns the backend status.
func (b *ServiceBackend) Status() Status {
	return Status(b.status.Load())
}

// Start starts the backend (health checking, etc.).
func (b *ServiceBackend) Start(ctx context.Context) error {
	b.logger.Info("starting backend",
		observability.String("name", b.name),
		observability.Int("hosts", len(b.hosts)),
	)

	// Start health checking if configured
	if b.config.HealthCheck != nil {
		b.healthCheck = NewHealthChecker(b.hosts, *b.config.HealthCheck, WithHealthCheckLogger(b.logger))
		b.healthCheck.Start(ctx)
	} else {
		// Mark all hosts as healthy if no health check configured
		for _, host := range b.hosts {
			host.SetStatus(StatusHealthy)
		}
	}

	b.status.Store(int32(StatusHealthy))
	return nil
}

// Stop stops the backend.
func (b *ServiceBackend) Stop(ctx context.Context) error {
	b.logger.Info("stopping backend",
		observability.String("name", b.name),
	)

	if b.healthCheck != nil {
		b.healthCheck.Stop()
	}

	b.status.Store(int32(StatusUnknown))
	return nil
}

// GetHosts returns all hosts.
func (b *ServiceBackend) GetHosts() []*Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	hosts := make([]*Host, len(b.hosts))
	copy(hosts, b.hosts)
	return hosts
}

// GetHealthyHosts returns all healthy hosts.
func (b *ServiceBackend) GetHealthyHosts() []*Host {
	b.mu.RLock()
	defer b.mu.RUnlock()

	healthy := make([]*Host, 0, len(b.hosts))
	for _, host := range b.hosts {
		if host.Status() == StatusHealthy {
			healthy = append(healthy, host)
		}
	}
	return healthy
}

// HTTPClient returns an HTTP client for this backend.
func (b *ServiceBackend) HTTPClient() *http.Client {
	return b.pool.Client()
}

// TLSConfig returns the TLS configuration for this backend.
func (b *ServiceBackend) TLSConfig() *tls.Config {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.tlsConfig
}

// IsTLSEnabled returns true if TLS is enabled for this backend.
func (b *ServiceBackend) IsTLSEnabled() bool {
	return b.config.TLS != nil && b.config.TLS.Enabled
}

// GetTLSMode returns the TLS mode for this backend.
func (b *ServiceBackend) GetTLSMode() string {
	if b.config.TLS == nil {
		return config.TLSModeInsecure
	}
	return b.config.TLS.GetEffectiveMode()
}

// RefreshTLSConfig refreshes the TLS configuration (e.g., after certificate rotation).
func (b *ServiceBackend) RefreshTLSConfig() error {
	if b.tlsBuilder == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Invalidate cached config
	b.tlsBuilder.Invalidate()

	// Rebuild TLS config
	tlsConfig, err := b.tlsBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to refresh TLS config: %w", err)
	}

	b.tlsConfig = tlsConfig

	// Update connection pool
	if b.pool != nil {
		b.pool.SetTLSConfig(tlsConfig)
	}

	b.logger.Info("refreshed TLS configuration for backend",
		observability.String("backend", b.name),
	)

	return nil
}

// Registry manages multiple backends.
type Registry struct {
	backends map[string]Backend
	mu       sync.RWMutex
	logger   observability.Logger
}

// NewRegistry creates a new backend registry.
func NewRegistry(logger observability.Logger) *Registry {
	return &Registry{
		backends: make(map[string]Backend),
		logger:   logger,
	}
}

// Register registers a backend.
func (r *Registry) Register(backend Backend) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := backend.Name()
	if _, exists := r.backends[name]; exists {
		return fmt.Errorf("backend already registered: %s", name)
	}

	r.backends[name] = backend
	r.logger.Info("registered backend",
		observability.String("name", name),
	)

	return nil
}

// Unregister removes a backend.
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.backends[name]; !exists {
		return fmt.Errorf("backend not found: %s", name)
	}

	delete(r.backends, name)
	r.logger.Info("unregistered backend",
		observability.String("name", name),
	)

	return nil
}

// Get returns a backend by name.
func (r *Registry) Get(name string) (Backend, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	backend, exists := r.backends[name]
	return backend, exists
}

// GetAll returns all backends.
func (r *Registry) GetAll() []Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()

	backends := make([]Backend, 0, len(r.backends))
	for _, backend := range r.backends {
		backends = append(backends, backend)
	}
	return backends
}

// StartAll starts all backends.
func (r *Registry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, backend := range r.backends {
		if err := backend.Start(ctx); err != nil {
			return fmt.Errorf("failed to start backend %s: %w", name, err)
		}
	}

	return nil
}

// StopAll stops all backends.
func (r *Registry) StopAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lastErr error
	for name, backend := range r.backends {
		if err := backend.Stop(ctx); err != nil {
			r.logger.Error("failed to stop backend",
				observability.String("name", name),
				observability.Error(err),
			)
			lastErr = err
		}
	}

	return lastErr
}

// LoadFromConfig loads backends from configuration.
func (r *Registry) LoadFromConfig(backends []config.Backend) error {
	for _, cfg := range backends {
		backend, err := NewBackend(cfg, WithBackendLogger(r.logger))
		if err != nil {
			return fmt.Errorf("failed to create backend %s: %w", cfg.Name, err)
		}

		if err := r.Register(backend); err != nil {
			return err
		}
	}

	return nil
}
