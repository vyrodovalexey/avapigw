package backend

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// HealthChecker performs periodic health checks on backend hosts.
type HealthChecker struct {
	hosts              []*Host
	config             config.HealthCheck
	client             *http.Client
	logger             observability.Logger
	stopCh             chan struct{}
	stoppedCh          chan struct{}
	running            bool
	mu                 sync.Mutex
	healthyThreshold   int
	unhealthyThreshold int
	healthyCounts      map[*Host]int
	unhealthyCounts    map[*Host]int
}

// HealthCheckOption is a functional option for configuring the health checker.
type HealthCheckOption func(*HealthChecker)

// WithHealthCheckLogger sets the logger for the health checker.
func WithHealthCheckLogger(logger observability.Logger) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.logger = logger
	}
}

// WithHealthCheckClient sets the HTTP client for the health checker.
func WithHealthCheckClient(client *http.Client) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.client = client
	}
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(hosts []*Host, cfg config.HealthCheck, opts ...HealthCheckOption) *HealthChecker {
	timeout := cfg.Timeout.Duration()
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	hc := &HealthChecker{
		hosts:  hosts,
		config: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
		logger:             observability.NopLogger(),
		stopCh:             make(chan struct{}),
		stoppedCh:          make(chan struct{}),
		healthyThreshold:   cfg.HealthyThreshold,
		unhealthyThreshold: cfg.UnhealthyThreshold,
		healthyCounts:      make(map[*Host]int),
		unhealthyCounts:    make(map[*Host]int),
	}

	if hc.healthyThreshold == 0 {
		hc.healthyThreshold = 2
	}
	if hc.unhealthyThreshold == 0 {
		hc.unhealthyThreshold = 3
	}

	for _, opt := range opts {
		opt(hc)
	}

	return hc
}

// Start starts the health checker.
func (hc *HealthChecker) Start(ctx context.Context) {
	hc.mu.Lock()
	if hc.running {
		hc.mu.Unlock()
		return
	}
	hc.running = true
	hc.mu.Unlock()

	go hc.run(ctx)
}

// Stop stops the health checker.
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	if !hc.running {
		hc.mu.Unlock()
		return
	}
	hc.running = false
	hc.mu.Unlock()

	close(hc.stopCh)
	<-hc.stoppedCh
}

// run is the main health check loop.
func (hc *HealthChecker) run(ctx context.Context) {
	defer close(hc.stoppedCh)

	interval := hc.config.Interval.Duration()
	if interval == 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial health check
	hc.checkAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkAll(ctx)
		}
	}
}

// checkAll checks all hosts.
func (hc *HealthChecker) checkAll(ctx context.Context) {
	var wg sync.WaitGroup

	for _, host := range hc.hosts {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			hc.checkHost(ctx, h)
		}(host)
	}

	wg.Wait()
}

// checkHost checks a single host.
func (hc *HealthChecker) checkHost(ctx context.Context, host *Host) {
	url := host.URL() + hc.config.Path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		hc.recordFailure(host, err)
		return
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		hc.recordFailure(host, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		hc.recordSuccess(host)
	} else {
		hc.recordFailure(host, nil)
	}
}

// recordSuccess records a successful health check.
func (hc *HealthChecker) recordSuccess(host *Host) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.healthyCounts[host]++
	hc.unhealthyCounts[host] = 0

	if hc.healthyCounts[host] >= hc.healthyThreshold {
		if host.Status() != StatusHealthy {
			hc.logger.Info("host became healthy",
				observability.String("address", host.Address),
				observability.Int("port", host.Port),
			)
			host.SetStatus(StatusHealthy)
		}
	}
}

// recordFailure records a failed health check.
func (hc *HealthChecker) recordFailure(host *Host, err error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.unhealthyCounts[host]++
	hc.healthyCounts[host] = 0

	if hc.unhealthyCounts[host] >= hc.unhealthyThreshold {
		if host.Status() != StatusUnhealthy {
			hc.logger.Warn("host became unhealthy",
				observability.String("address", host.Address),
				observability.Int("port", host.Port),
				observability.Error(err),
			)
			host.SetStatus(StatusUnhealthy)
		}
	}
}

// IsRunning returns true if the health checker is running.
func (hc *HealthChecker) IsRunning() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.running
}
