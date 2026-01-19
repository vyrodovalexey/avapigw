package backend

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthChecker performs health checks on backend endpoints.
type HealthChecker struct {
	config    *HealthCheckConfig
	logger    *zap.Logger
	client    *http.Client
	stopCh    chan struct{}
	running   bool
	stopped   bool // Tracks if Stop() was called to prevent double-close panic
	mu        sync.RWMutex
	endpoints []*Endpoint
	results   map[string]*HealthCheckResult
	resultsMu sync.RWMutex
}

// HealthCheckResult holds the result of a health check.
type HealthCheckResult struct {
	Endpoint        *Endpoint
	Healthy         bool
	LastCheck       time.Time
	LastHealthy     time.Time
	ConsecutiveOK   int
	ConsecutiveFail int
	Error           error
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(config *HealthCheckConfig, logger *zap.Logger) *HealthChecker {
	if config == nil {
		config = &HealthCheckConfig{
			Enabled:            true,
			Interval:           10,
			Timeout:            5,
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
			Path:               "/health",
		}
	}

	return &HealthChecker{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
		stopCh:  make(chan struct{}),
		results: make(map[string]*HealthCheckResult),
	}
}

// Start starts the health checker.
// If the health checker was previously stopped, it recreates the stop channel.
func (hc *HealthChecker) Start(endpoints []*Endpoint) {
	hc.mu.Lock()
	if hc.running {
		hc.mu.Unlock()
		return
	}

	// Recreate stopCh if previously stopped to allow restart
	if hc.stopped {
		hc.stopCh = make(chan struct{})
		hc.stopped = false
	}

	hc.running = true
	hc.endpoints = endpoints
	hc.mu.Unlock()

	go hc.run()
}

// Stop stops the health checker.
// Safe to call multiple times - subsequent calls are no-ops.
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Guard against double-close panic: check both running and stopped flags
	if !hc.running || hc.stopped {
		return
	}

	hc.stopped = true
	close(hc.stopCh)
	hc.running = false
}

// IsRunning returns whether the health checker is running.
func (hc *HealthChecker) IsRunning() bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.running
}

// UpdateEndpoints updates the endpoints to check.
func (hc *HealthChecker) UpdateEndpoints(endpoints []*Endpoint) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.endpoints = endpoints
}

// GetResult returns the health check result for an endpoint.
func (hc *HealthChecker) GetResult(endpoint *Endpoint) *HealthCheckResult {
	hc.resultsMu.RLock()
	defer hc.resultsMu.RUnlock()
	return hc.results[endpoint.FullAddress()]
}

// GetAllResults returns all health check results.
func (hc *HealthChecker) GetAllResults() map[string]*HealthCheckResult {
	hc.resultsMu.RLock()
	defer hc.resultsMu.RUnlock()

	results := make(map[string]*HealthCheckResult)
	for k, v := range hc.results {
		results[k] = v
	}
	return results
}

func (hc *HealthChecker) run() {
	ticker := time.NewTicker(time.Duration(hc.config.Interval) * time.Second)
	defer ticker.Stop()

	// Run initial check
	hc.checkAll()

	for {
		select {
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

func (hc *HealthChecker) checkAll() {
	hc.mu.RLock()
	endpoints := make([]*Endpoint, len(hc.endpoints))
	copy(endpoints, hc.endpoints)
	hc.mu.RUnlock()

	var wg sync.WaitGroup
	for _, ep := range endpoints {
		wg.Add(1)
		go func(endpoint *Endpoint) {
			defer wg.Done()
			hc.checkEndpoint(endpoint)
		}(ep)
	}
	wg.Wait()
}

func (hc *HealthChecker) checkEndpoint(endpoint *Endpoint) {
	addr := endpoint.FullAddress()

	hc.resultsMu.Lock()
	result, exists := hc.results[addr]
	if !exists {
		result = &HealthCheckResult{
			Endpoint: endpoint,
			Healthy:  true,
		}
		hc.results[addr] = result
	}
	hc.resultsMu.Unlock()

	var err error
	var healthy bool

	if hc.config.Path != "" {
		healthy, err = hc.httpCheck(endpoint)
	} else {
		healthy, err = hc.tcpCheck(endpoint)
	}

	hc.resultsMu.Lock()
	result.LastCheck = time.Now()
	result.Error = err

	if healthy {
		hc.handleHealthyResult(result, endpoint, addr)
	} else {
		hc.handleUnhealthyResult(result, endpoint, addr, err)
	}
	hc.resultsMu.Unlock()
}

// handleHealthyResult processes a healthy check result.
// Caller must hold resultsMu lock.
func (hc *HealthChecker) handleHealthyResult(result *HealthCheckResult, endpoint *Endpoint, addr string) {
	result.ConsecutiveOK++
	result.ConsecutiveFail = 0
	result.LastHealthy = time.Now()

	if result.ConsecutiveOK < hc.config.HealthyThreshold {
		return
	}

	if !result.Healthy {
		hc.logger.Info("endpoint became healthy",
			zap.String("endpoint", addr),
		)
	}
	result.Healthy = true
	endpoint.SetHealthy(true)
}

// handleUnhealthyResult processes an unhealthy check result.
// Caller must hold resultsMu lock.
func (hc *HealthChecker) handleUnhealthyResult(result *HealthCheckResult, endpoint *Endpoint, addr string, err error) {
	result.ConsecutiveFail++
	result.ConsecutiveOK = 0

	if result.ConsecutiveFail < hc.config.UnhealthyThreshold {
		return
	}

	if result.Healthy {
		hc.logger.Warn("endpoint became unhealthy",
			zap.String("endpoint", addr),
			zap.Error(err),
		)
	}
	result.Healthy = false
	endpoint.SetHealthy(false)
}

func (hc *HealthChecker) httpCheck(endpoint *Endpoint) (bool, error) {
	port := hc.config.Port
	if port == 0 {
		port = endpoint.Port
	}

	url := fmt.Sprintf("http://%s:%d%s", endpoint.Address, port, hc.config.Path)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(hc.config.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Consider 2xx status codes as healthy
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}

	return false, fmt.Errorf("unhealthy status code: %d", resp.StatusCode)
}

func (hc *HealthChecker) tcpCheck(endpoint *Endpoint) (bool, error) {
	addr := endpoint.FullAddress()

	dialer := &net.Dialer{
		Timeout: time.Duration(hc.config.Timeout) * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(hc.config.Timeout)*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	return true, nil
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	config          *CircuitBreakerConfig
	state           CircuitState
	failures        int
	lastFailure     time.Time
	lastStateChange time.Time
	mu              sync.RWMutex
}

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed means the circuit is closed and requests are allowed.
	CircuitClosed CircuitState = iota
	// CircuitOpen means the circuit is open and requests are blocked.
	CircuitOpen
	// CircuitHalfOpen means the circuit is half-open and limited requests are allowed.
	CircuitHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = &CircuitBreakerConfig{
			Enabled:           true,
			ConsecutiveErrors: 5,
			Interval:          30,
			BaseEjectionTime:  30,
			MaxEjectionPct:    50,
		}
	}

	return &CircuitBreaker{
		config: config,
		state:  CircuitClosed,
	}
}

// Allow returns whether a request should be allowed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if we should transition to half-open
		if time.Since(cb.lastStateChange) > time.Duration(cb.config.BaseEjectionTime)*time.Second {
			cb.state = CircuitHalfOpen
			cb.lastStateChange = time.Now()
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return true
	}
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
		cb.lastStateChange = time.Now()
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.config.ConsecutiveErrors {
		cb.state = CircuitOpen
		cb.lastStateChange = time.Now()
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitClosed
	cb.failures = 0
	cb.lastStateChange = time.Now()
}
