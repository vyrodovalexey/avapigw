// Package backend provides backend service management for the API Gateway.
package backend

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/backend/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Default configuration constants for backend services.
const (
	// DefaultHostWeight is the default weight for a host when not specified.
	DefaultHostWeight = 1
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

// HostRateLimiter provides rate limiting for a backend host.
type HostRateLimiter struct {
	rps       int
	burst     int
	tokens    int64
	lastCheck int64
	mu        sync.Mutex
}

// NewHostRateLimiter creates a new host rate limiter.
func NewHostRateLimiter(rps, burst int) *HostRateLimiter {
	return &HostRateLimiter{
		rps:       rps,
		burst:     burst,
		tokens:    int64(burst),
		lastCheck: time.Now().UnixNano(),
	}
}

// Allow checks if a request is allowed based on rate limiting.
func (rl *HostRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UnixNano()
	elapsed := time.Duration(now - rl.lastCheck)

	// Calculate tokens to add based on elapsed time
	tokensToAdd := int64(float64(rl.rps) * elapsed.Seconds())
	currentTokens := rl.tokens + tokensToAdd

	// Cap at burst limit
	if currentTokens > int64(rl.burst) {
		currentTokens = int64(rl.burst)
	}

	if currentTokens < 1 {
		return false
	}

	rl.tokens = currentTokens - 1
	rl.lastCheck = now
	return true
}

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
	Address       string
	Port          int
	Weight        int
	status        atomic.Int32
	connections   atomic.Int64
	lastUsed      atomic.Int64
	maxSessions   int
	maxSessionsOn bool
	rateLimiter   *HostRateLimiter
	rateLimiterOn bool
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
	return "http://" + net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
}

// TLSURL returns the host URL with HTTPS scheme.
func (h *Host) TLSURL() string {
	return "https://" + net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
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

// SetMaxSessions configures max sessions for this host.
func (h *Host) SetMaxSessions(maxSessions int) {
	h.maxSessions = maxSessions
	h.maxSessionsOn = maxSessions > 0
}

// SetRateLimiter configures rate limiting for this host.
func (h *Host) SetRateLimiter(rps, burst int) {
	if rps > 0 {
		h.rateLimiter = NewHostRateLimiter(rps, burst)
		h.rateLimiterOn = true
	}
}

// IsAvailable checks if the host can accept new connections.
// It considers health status, max sessions, and rate limiting.
func (h *Host) IsAvailable() bool {
	// Check health status
	status := h.Status()
	if status != StatusHealthy && status != StatusUnknown {
		return false
	}

	// Check max sessions
	if h.maxSessionsOn && h.connections.Load() >= int64(h.maxSessions) {
		return false
	}

	return true
}

// AllowRequest checks if a request is allowed based on rate limiting.
// Returns true if rate limiting is disabled or if the request is allowed.
func (h *Host) AllowRequest() bool {
	if !h.rateLimiterOn || h.rateLimiter == nil {
		return true
	}
	return h.rateLimiter.Allow()
}

// HasCapacity checks if the host has capacity for new connections.
// This is a lighter check than IsAvailable, only checking max sessions.
func (h *Host) HasCapacity() bool {
	if !h.maxSessionsOn {
		return true
	}
	return h.connections.Load() < int64(h.maxSessions)
}

// MaxSessions returns the max sessions limit for this host.
func (h *Host) MaxSessions() int {
	return h.maxSessions
}

// IsMaxSessionsEnabled returns true if max sessions limiting is enabled.
func (h *Host) IsMaxSessionsEnabled() bool {
	return h.maxSessionsOn
}

// IsRateLimitEnabled returns true if rate limiting is enabled.
func (h *Host) IsRateLimitEnabled() bool {
	return h.rateLimiterOn
}

// ServiceBackend is the default backend implementation.
type ServiceBackend struct {
	name           string
	config         config.Backend
	hosts          []*Host
	loadBalancer   LoadBalancer
	healthCheck    *HealthChecker
	pool           *ConnectionPool
	tlsBuilder     *TLSConfigBuilder
	tlsConfig      *tls.Config
	authProvider   auth.Provider
	vaultClient    vault.Client
	logger         observability.Logger
	metrics        *observability.Metrics
	status         atomic.Int32
	mu             sync.RWMutex
	maxSessionsCfg *config.MaxSessionsConfig
	rateLimitCfg   *config.RateLimitConfig
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

// WithAuthProvider sets the authentication provider for the backend.
func WithAuthProvider(provider auth.Provider) BackendOption {
	return func(b *ServiceBackend) {
		b.authProvider = provider
	}
}

// WithVaultClient sets the Vault client for creating auth providers.
func WithVaultClient(client vault.Client) BackendOption {
	return func(b *ServiceBackend) {
		// Store vault client for later use in auth provider creation
		b.vaultClient = client
	}
}

// WithMetrics sets the metrics for the backend.
func WithMetrics(metrics *observability.Metrics) BackendOption {
	return func(b *ServiceBackend) {
		b.metrics = metrics
	}
}

// NewBackend creates a new backend from configuration.
func NewBackend(cfg config.Backend, opts ...BackendOption) (*ServiceBackend, error) {
	if err := validateBackendConfig(cfg); err != nil {
		return nil, err
	}

	b := &ServiceBackend{
		name:           cfg.Name,
		config:         cfg,
		hosts:          make([]*Host, 0, len(cfg.Hosts)),
		logger:         observability.NopLogger(),
		maxSessionsCfg: cfg.MaxSessions,
		rateLimitCfg:   cfg.RateLimit,
	}

	for _, opt := range opts {
		opt(b)
	}

	b.initHosts(cfg.Hosts)
	b.initLoadBalancer(cfg.LoadBalancer)

	if err := b.initTLS(cfg); err != nil {
		return nil, err
	}

	b.initConnectionPool()

	if err := b.initAuthProvider(cfg); err != nil {
		return nil, err
	}

	b.status.Store(int32(StatusUnknown))

	b.logBackendConfig()

	return b, nil
}

// logBackendConfig logs the backend configuration.
func (b *ServiceBackend) logBackendConfig() {
	if b.maxSessionsCfg != nil && b.maxSessionsCfg.Enabled {
		b.logger.Info("max sessions enabled for backend",
			observability.String("backend", b.name),
			observability.Int("maxConcurrent", b.maxSessionsCfg.MaxConcurrent),
			observability.Int("queueSize", b.maxSessionsCfg.QueueSize),
		)
	}

	if b.rateLimitCfg != nil && b.rateLimitCfg.Enabled {
		b.logger.Info("rate limiting enabled for backend",
			observability.String("backend", b.name),
			observability.Int("requestsPerSecond", b.rateLimitCfg.RequestsPerSecond),
			observability.Int("burst", b.rateLimitCfg.Burst),
		)
	}
}

// validateBackendConfig validates the backend configuration.
func validateBackendConfig(cfg config.Backend) error {
	if cfg.Name == "" {
		return fmt.Errorf("backend name is required")
	}
	if len(cfg.Hosts) == 0 {
		return fmt.Errorf("at least one host is required")
	}
	return nil
}

// initHosts initializes the backend hosts.
func (b *ServiceBackend) initHosts(hostConfigs []config.BackendHost) {
	for _, hostCfg := range hostConfigs {
		weight := hostCfg.Weight
		if weight == 0 {
			weight = DefaultHostWeight
		}
		host := NewHost(hostCfg.Address, hostCfg.Port, weight)

		// Configure max sessions if enabled at backend level
		if b.maxSessionsCfg != nil && b.maxSessionsCfg.Enabled {
			host.SetMaxSessions(b.maxSessionsCfg.MaxConcurrent)
		}

		// Configure rate limiting if enabled at backend level
		if b.rateLimitCfg != nil && b.rateLimitCfg.Enabled {
			burst := b.rateLimitCfg.Burst
			if burst == 0 {
				burst = b.rateLimitCfg.RequestsPerSecond
			}
			host.SetRateLimiter(b.rateLimitCfg.RequestsPerSecond, burst)
		}

		b.hosts = append(b.hosts, host)
	}
}

// initLoadBalancer initializes the load balancer.
func (b *ServiceBackend) initLoadBalancer(lbCfg *config.LoadBalancer) {
	if b.loadBalancer != nil {
		return
	}

	algorithm := config.LoadBalancerRoundRobin
	if lbCfg != nil && lbCfg.Algorithm != "" {
		algorithm = lbCfg.Algorithm
	}
	b.loadBalancer = NewLoadBalancer(algorithm, b.hosts)
}

// initTLS initializes TLS configuration.
func (b *ServiceBackend) initTLS(cfg config.Backend) error {
	if cfg.TLS == nil || !cfg.TLS.Enabled {
		return nil
	}

	tlsOpts := []TLSConfigBuilderOption{WithTLSLogger(b.logger)}
	if b.vaultClient != nil {
		tlsOpts = append(tlsOpts, WithTLSVaultClient(b.vaultClient))
	}
	b.tlsBuilder = NewTLSConfigBuilder(cfg.TLS, tlsOpts...)
	tlsConfig, err := b.tlsBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build TLS config for backend %s: %w", cfg.Name, err)
	}
	b.tlsConfig = tlsConfig

	b.logger.Info("TLS enabled for backend",
		observability.String("backend", cfg.Name),
		observability.String("mode", cfg.TLS.GetEffectiveMode()),
		observability.Bool("insecureSkipVerify", cfg.TLS.InsecureSkipVerify),
	)

	return nil
}

// initConnectionPool initializes the connection pool.
func (b *ServiceBackend) initConnectionPool() {
	if b.pool != nil {
		return
	}

	poolCfg := DefaultPoolConfig()
	poolCfg.TLSConfig = b.tlsConfig
	b.pool = NewConnectionPool(poolCfg)
}

// initAuthProvider initializes the authentication provider.
func (b *ServiceBackend) initAuthProvider(cfg config.Backend) error {
	if b.authProvider != nil || cfg.Authentication == nil {
		return nil
	}

	authOpts := []auth.ProviderOption{
		auth.WithLogger(b.logger),
		auth.WithMetrics(auth.GetSharedMetrics()),
	}
	if b.vaultClient != nil {
		authOpts = append(authOpts, auth.WithVaultClient(b.vaultClient))
	}

	provider, err := auth.NewProvider(cfg.Name, cfg.Authentication, authOpts...)
	if err != nil {
		return fmt.Errorf("failed to create auth provider for backend %s: %w", cfg.Name, err)
	}
	b.authProvider = provider

	return nil
}

// Name returns the backend name.
func (b *ServiceBackend) Name() string {
	return b.name
}

// GetHost returns a host using the load balancer.
// It considers health status, max sessions, and rate limiting.
func (b *ServiceBackend) GetHost() (*Host, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	host := b.loadBalancer.Next()
	if host == nil {
		return nil, fmt.Errorf("no healthy hosts available for backend %s", b.name)
	}

	// Check rate limiting
	if !host.AllowRequest() {
		b.logger.Debug("host rate limited",
			observability.String("backend", b.name),
			observability.String("host", host.Address),
			observability.Int("port", host.Port),
		)
		return nil, fmt.Errorf("host rate limited for backend %s", b.name)
	}

	host.IncrementConnections()
	return host, nil
}

// GetAvailableHost returns an available host considering all constraints.
// This method tries to find a host that is healthy, has capacity, and allows the request.
func (b *ServiceBackend) GetAvailableHost() (*Host, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Try to get a host from the load balancer that is available
	for i := 0; i < len(b.hosts); i++ {
		host := b.loadBalancer.Next()
		if host == nil {
			break
		}

		if !host.IsAvailable() {
			continue
		}

		if !host.AllowRequest() {
			b.logger.Debug("host rate limited, trying next",
				observability.String("backend", b.name),
				observability.String("host", host.Address),
			)
			continue
		}

		host.IncrementConnections()
		return host, nil
	}

	return nil, fmt.Errorf("no available hosts for backend %s", b.name)
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
		opts := []HealthCheckOption{
			WithHealthCheckLogger(b.logger),
			WithBackendName(b.name),
		}
		if b.metrics != nil {
			opts = append(opts, WithHealthStatusCallback(
				func(backendName, hostAddr string, healthy bool) {
					b.metrics.SetBackendHealth(
						backendName, hostAddr, healthy,
					)
				},
			))
		}
		// Use TLS for health checks if backend has TLS enabled
		if b.tlsConfig != nil {
			opts = append(opts,
				WithHealthCheckClient(&http.Client{
					Timeout: b.config.HealthCheck.Timeout.Duration(),
					Transport: &http.Transport{
						TLSClientConfig: b.tlsConfig,
					},
				}),
				WithHealthCheckTLS(true),
			)
		}
		b.healthCheck = NewHealthChecker(
			b.hosts, *b.config.HealthCheck, opts...,
		)
		b.healthCheck.Start(ctx)
	} else {
		// Mark all hosts as healthy if no health check configured
		for _, host := range b.hosts {
			host.SetStatus(StatusHealthy)
			if b.metrics != nil {
				b.metrics.SetBackendHealth(
					b.name,
					net.JoinHostPort(
						host.Address,
						strconv.Itoa(host.Port),
					),
					true,
				)
			}
		}
	}

	b.status.Store(int32(StatusHealthy))
	return nil
}

// Stop stops the backend.
func (b *ServiceBackend) Stop(_ context.Context) error {
	b.logger.Info("stopping backend",
		observability.String("name", b.name),
	)

	if b.healthCheck != nil {
		b.healthCheck.Stop()
	}

	// Close auth provider
	if b.authProvider != nil {
		if err := b.authProvider.Close(); err != nil {
			b.logger.Error("failed to close auth provider",
				observability.String("backend", b.name),
				observability.Error(err),
			)
		}
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

// AuthProvider returns the authentication provider for this backend.
func (b *ServiceBackend) AuthProvider() auth.Provider {
	return b.authProvider
}

// ApplyAuth applies authentication to an HTTP request.
func (b *ServiceBackend) ApplyAuth(ctx context.Context, req *http.Request) error {
	if b.authProvider == nil {
		return nil
	}
	return b.authProvider.ApplyHTTP(ctx, req)
}

// GetGRPCDialOptions returns gRPC dial options including authentication.
func (b *ServiceBackend) GetGRPCDialOptions(ctx context.Context) ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	// Add auth options if provider is configured
	if b.authProvider != nil {
		authOpts, err := b.authProvider.ApplyGRPC(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth dial options: %w", err)
		}
		opts = append(opts, authOpts...)
	}

	return opts, nil
}

// RefreshAuth refreshes the authentication credentials.
func (b *ServiceBackend) RefreshAuth(ctx context.Context) error {
	if b.authProvider == nil {
		return nil
	}
	return b.authProvider.Refresh(ctx)
}

// Registry manages multiple backends.
type Registry struct {
	backends    map[string]Backend
	mu          sync.RWMutex
	logger      observability.Logger
	metrics     *observability.Metrics
	vaultClient vault.Client
}

// RegistryOption is a functional option for configuring a Registry.
type RegistryOption func(*Registry)

// WithRegistryMetrics sets the metrics for the registry.
func WithRegistryMetrics(m *observability.Metrics) RegistryOption {
	return func(r *Registry) {
		r.metrics = m
	}
}

// WithRegistryVaultClient sets the Vault client for the registry.
// When set, the client is passed to each backend created by
// LoadFromConfig and ReloadFromConfig so that backends requiring
// Vault (mTLS certs, KV credentials, OIDC tokens) can function.
func WithRegistryVaultClient(client vault.Client) RegistryOption {
	return func(r *Registry) {
		r.vaultClient = client
	}
}

// NewRegistry creates a new backend registry.
func NewRegistry(
	logger observability.Logger,
	opts ...RegistryOption,
) *Registry {
	r := &Registry{
		backends: make(map[string]Backend),
		logger:   logger,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
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
		// Check for context cancellation before starting each backend
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled while starting backends: %w", ctx.Err())
		default:
			// Context is still valid, proceed with starting the backend
		}

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
		// Check for context cancellation before stopping each backend
		// Note: We continue stopping backends even if context is canceled
		// to ensure proper cleanup, but we log the cancellation
		select {
		case <-ctx.Done():
			r.logger.Warn("context canceled while stopping backends, continuing cleanup",
				observability.String("backend", name),
				observability.Error(ctx.Err()),
			)
		default:
			// Context is still valid
		}

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
		opts := []BackendOption{WithBackendLogger(r.logger)}
		if r.metrics != nil {
			opts = append(opts, WithMetrics(r.metrics))
		}
		if r.vaultClient != nil {
			opts = append(opts, WithVaultClient(r.vaultClient))
		}
		b, err := NewBackend(cfg, opts...)
		if err != nil {
			return fmt.Errorf(
				"failed to create backend %s: %w",
				cfg.Name, err,
			)
		}

		if err := r.Register(b); err != nil {
			return err
		}
	}

	return nil
}

// ReloadFromConfig replaces all backends with new configuration.
// Uses copy-on-write to minimize the critical section: the new map
// is built outside the lock, then swapped atomically. Old backends
// are stopped after the swap so that the lock is not held during
// potentially slow I/O.
func (r *Registry) ReloadFromConfig(
	ctx context.Context,
	backends []config.Backend,
) error {
	// Check for context cancellation before starting the reload
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled before reload: %w", ctx.Err())
	default:
		// Context is still valid, proceed with reload
	}

	// 1. Build new backends map outside the lock.
	newMap := make(map[string]Backend, len(backends))
	for _, cfg := range backends {
		// Check for context cancellation during backend creation
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled while creating backends: %w", ctx.Err())
		default:
			// Context is still valid
		}

		opts := []BackendOption{WithBackendLogger(r.logger)}
		if r.metrics != nil {
			opts = append(opts, WithMetrics(r.metrics))
		}
		if r.vaultClient != nil {
			opts = append(opts, WithVaultClient(r.vaultClient))
		}
		b, err := NewBackend(cfg, opts...)
		if err != nil {
			return fmt.Errorf(
				"failed to create backend %s: %w",
				cfg.Name, err,
			)
		}
		newMap[cfg.Name] = b
	}

	// 2. Lock, swap the map atomically, unlock.
	r.mu.Lock()
	oldMap := r.backends
	r.backends = newMap
	r.mu.Unlock()

	// 3. Stop old backends outside the lock.
	// Note: We continue stopping backends even if context is canceled
	// to ensure proper cleanup
	for name, b := range oldMap {
		if err := b.Stop(ctx); err != nil {
			r.logger.Error("failed to stop backend during reload",
				observability.String("name", name),
				observability.Error(err),
			)
		}
	}

	// 4. Start new backends.
	for name, b := range newMap {
		// Check for context cancellation before starting each backend
		select {
		case <-ctx.Done():
			r.logger.Warn("context canceled while starting new backends",
				observability.String("backend", name),
				observability.Error(ctx.Err()),
			)
			return fmt.Errorf("context canceled while starting backends: %w", ctx.Err())
		default:
			// Context is still valid
		}

		if err := b.Start(ctx); err != nil {
			return fmt.Errorf(
				"failed to start backend %s: %w", name, err,
			)
		}
	}

	r.logger.Info("backends reloaded",
		observability.Int("count", len(backends)),
	)

	return nil
}
