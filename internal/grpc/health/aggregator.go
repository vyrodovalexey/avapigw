package health

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// BackendHealth represents the health status of a backend.
type BackendHealth struct {
	Address   string
	Service   string
	Healthy   bool
	LastCheck time.Time
	Error     error
}

// HealthAggregator aggregates health status from multiple backends.
type HealthAggregator struct {
	healthServer *HealthServer
	backends     []BackendConfig
	interval     time.Duration
	timeout      time.Duration
	logger       observability.Logger
	stopCh       chan struct{}
	wg           sync.WaitGroup
	mu           sync.RWMutex
	statuses     map[string]*BackendHealth
}

// BackendConfig contains backend health check configuration.
type BackendConfig struct {
	Name    string
	Address string
	Service string // Service name to check, empty for overall health
}

// AggregatorOption is a functional option for configuring the aggregator.
type AggregatorOption func(*HealthAggregator)

// WithAggregatorLogger sets the logger for the aggregator.
func WithAggregatorLogger(logger observability.Logger) AggregatorOption {
	return func(a *HealthAggregator) {
		a.logger = logger
	}
}

// WithCheckInterval sets the health check interval.
func WithCheckInterval(interval time.Duration) AggregatorOption {
	return func(a *HealthAggregator) {
		a.interval = interval
	}
}

// WithCheckTimeout sets the health check timeout.
func WithCheckTimeout(timeout time.Duration) AggregatorOption {
	return func(a *HealthAggregator) {
		a.timeout = timeout
	}
}

// NewHealthAggregator creates a new health aggregator.
func NewHealthAggregator(hs *HealthServer, backends []BackendConfig, opts ...AggregatorOption) *HealthAggregator {
	a := &HealthAggregator{
		healthServer: hs,
		backends:     backends,
		interval:     10 * time.Second,
		timeout:      5 * time.Second,
		logger:       observability.NopLogger(),
		stopCh:       make(chan struct{}),
		statuses:     make(map[string]*BackendHealth),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Start starts the health aggregator.
func (a *HealthAggregator) Start(ctx context.Context) {
	a.logger.Info("starting health aggregator",
		observability.Int("backends", len(a.backends)),
		observability.Duration("interval", a.interval),
	)

	// Initial check
	a.checkAllBackends(ctx)

	// Start periodic checks
	a.wg.Add(1)
	go a.run(ctx)
}

// Stop stops the health aggregator.
func (a *HealthAggregator) Stop() {
	a.logger.Info("stopping health aggregator")
	close(a.stopCh)
	a.wg.Wait()
}

// run runs the periodic health checks.
func (a *HealthAggregator) run(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.checkAllBackends(ctx)
		case <-a.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// checkAllBackends checks health of all backends.
func (a *HealthAggregator) checkAllBackends(ctx context.Context) {
	var wg sync.WaitGroup

	for _, backend := range a.backends {
		wg.Add(1)
		go func(b BackendConfig) {
			defer wg.Done()
			a.checkBackend(ctx, b)
		}(backend)
	}

	wg.Wait()

	// Update overall health based on backend statuses
	a.updateOverallHealth()
}

// checkBackend checks health of a single backend.
func (a *HealthAggregator) checkBackend(ctx context.Context, backend BackendConfig) {
	checkCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	healthy := false
	var checkErr error

	// Create gRPC connection using NewClient (non-blocking)
	conn, err := grpc.NewClient(backend.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		checkErr = err
		a.logger.Debug("failed to create client for backend",
			observability.String("backend", backend.Name),
			observability.String("address", backend.Address),
			observability.Error(err),
		)
	} else {
		defer conn.Close()

		// Check health - the RPC call will establish connection if needed
		client := healthpb.NewHealthClient(conn)
		resp, err := client.Check(checkCtx, &healthpb.HealthCheckRequest{
			Service: backend.Service,
		})
		if err != nil {
			checkErr = err
			a.logger.Debug("health check failed",
				observability.String("backend", backend.Name),
				observability.String("address", backend.Address),
				observability.Error(err),
			)
		} else {
			healthy = resp.GetStatus() == healthpb.HealthCheckResponse_SERVING
		}
	}

	// Update status
	a.mu.Lock()
	a.statuses[backend.Name] = &BackendHealth{
		Address:   backend.Address,
		Service:   backend.Service,
		Healthy:   healthy,
		LastCheck: time.Now(),
		Error:     checkErr,
	}
	a.mu.Unlock()

	// Update health server
	status := healthpb.HealthCheckResponse_NOT_SERVING
	if healthy {
		status = healthpb.HealthCheckResponse_SERVING
	}
	a.healthServer.SetServingStatus(backend.Name, status)

	a.logger.Debug("backend health check completed",
		observability.String("backend", backend.Name),
		observability.Bool("healthy", healthy),
	)
}

// updateOverallHealth updates the overall health based on backend statuses.
func (a *HealthAggregator) updateOverallHealth() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Overall health is SERVING if at least one backend is healthy
	anyHealthy := false
	for _, status := range a.statuses {
		if status.Healthy {
			anyHealthy = true
			break
		}
	}

	overallStatus := healthpb.HealthCheckResponse_NOT_SERVING
	if anyHealthy || len(a.statuses) == 0 {
		overallStatus = healthpb.HealthCheckResponse_SERVING
	}

	a.healthServer.SetServingStatus("", overallStatus)
}

// GetBackendHealth returns the health status of a backend.
func (a *HealthAggregator) GetBackendHealth(name string) (*BackendHealth, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status, ok := a.statuses[name]
	return status, ok
}

// GetAllBackendHealth returns health status of all backends.
func (a *HealthAggregator) GetAllBackendHealth() map[string]*BackendHealth {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]*BackendHealth, len(a.statuses))
	for k, v := range a.statuses {
		result[k] = v
	}
	return result
}

// AddBackend adds a backend to monitor.
func (a *HealthAggregator) AddBackend(backend BackendConfig) {
	a.mu.Lock()
	a.backends = append(a.backends, backend)
	a.mu.Unlock()

	a.logger.Info("added backend to health aggregator",
		observability.String("backend", backend.Name),
		observability.String("address", backend.Address),
	)
}

// RemoveBackend removes a backend from monitoring.
func (a *HealthAggregator) RemoveBackend(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, b := range a.backends {
		if b.Name == name {
			a.backends = append(a.backends[:i], a.backends[i+1:]...)
			delete(a.statuses, name)
			break
		}
	}

	a.logger.Info("removed backend from health aggregator",
		observability.String("backend", name),
	)
}
