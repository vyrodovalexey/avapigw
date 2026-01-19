// Package health provides health check endpoints for the API Gateway.
package health

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DependencyType represents the type of dependency.
type DependencyType string

const (
	// DependencyTypeDatabase is a database dependency.
	DependencyTypeDatabase DependencyType = "database"
	// DependencyTypeCache is a cache dependency.
	DependencyTypeCache DependencyType = "cache"
	// DependencyTypeHTTP is an HTTP service dependency.
	DependencyTypeHTTP DependencyType = "http"
	// DependencyTypeTCP is a TCP service dependency.
	DependencyTypeTCP DependencyType = "tcp"
	// DependencyTypeCustom is a custom dependency.
	DependencyTypeCustom DependencyType = "custom"
)

// DependencyCheck represents a dependency health check.
type DependencyCheck struct {
	name     string
	depType  DependencyType
	checkFn  func(ctx context.Context) error
	critical bool
}

// Name returns the name of the dependency check.
func (d *DependencyCheck) Name() string {
	return d.name
}

// Check performs the dependency health check.
func (d *DependencyCheck) Check(ctx context.Context) error {
	start := time.Now()
	err := d.checkFn(ctx)
	duration := time.Since(start).Seconds()

	healthy := err == nil
	RecordHealthCheck(d.name, healthy, duration)
	SetDependencyHealthStatus(d.name, string(d.depType), healthy)

	return err
}

// IsCritical returns true if the dependency is critical.
func (d *DependencyCheck) IsCritical() bool {
	return d.critical
}

// DependencyCheckOption is a function that configures a DependencyCheck.
type DependencyCheckOption func(*DependencyCheck)

// WithCritical marks the dependency as critical.
func WithCritical(critical bool) DependencyCheckOption {
	return func(d *DependencyCheck) {
		d.critical = critical
	}
}

// NewDependencyCheck creates a new dependency check.
func NewDependencyCheck(
	name string,
	depType DependencyType,
	checkFn func(ctx context.Context) error,
	opts ...DependencyCheckOption,
) *DependencyCheck {
	d := &DependencyCheck{
		name:     name,
		depType:  depType,
		checkFn:  checkFn,
		critical: true,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// HTTPHealthCheck creates an HTTP health check.
func HTTPHealthCheck(name, url string, timeout time.Duration, opts ...DependencyCheckOption) *DependencyCheck {
	return NewDependencyCheck(name, DependencyTypeHTTP, func(ctx context.Context) error {
		client := &http.Client{
			Timeout: timeout,
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("unhealthy status code: %d", resp.StatusCode)
		}

		return nil
	}, opts...)
}

// TCPHealthCheck creates a TCP health check.
func TCPHealthCheck(name, address string, timeout time.Duration, opts ...DependencyCheckOption) *DependencyCheck {
	return NewDependencyCheck(name, DependencyTypeTCP, func(ctx context.Context) error {
		dialer := &net.Dialer{
			Timeout: timeout,
		}

		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer conn.Close()

		return nil
	}, opts...)
}

// RedisHealthCheck creates a Redis health check.
func RedisHealthCheck(name string, client *redis.Client, opts ...DependencyCheckOption) *DependencyCheck {
	return NewDependencyCheck(name, DependencyTypeCache, func(ctx context.Context) error {
		if client == nil {
			return fmt.Errorf("redis client is nil")
		}

		result := client.Ping(ctx)
		if result.Err() != nil {
			return fmt.Errorf("redis ping failed: %w", result.Err())
		}

		return nil
	}, opts...)
}

// SQLHealthCheck creates a SQL database health check.
func SQLHealthCheck(name string, db *sql.DB, opts ...DependencyCheckOption) *DependencyCheck {
	return NewDependencyCheck(name, DependencyTypeDatabase, func(ctx context.Context) error {
		if db == nil {
			return fmt.Errorf("database connection is nil")
		}

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("database ping failed: %w", err)
		}

		return nil
	}, opts...)
}

// CustomHealthCheck creates a custom health check.
func CustomHealthCheck(
	name string,
	checkFn func(ctx context.Context) error,
	opts ...DependencyCheckOption,
) *DependencyCheck {
	return NewDependencyCheck(name, DependencyTypeCustom, checkFn, opts...)
}

// DetailedHealthStatus represents detailed health status.
type DetailedHealthStatus struct {
	Status       string                          `json:"status"`
	Timestamp    time.Time                       `json:"timestamp"`
	Uptime       string                          `json:"uptime,omitempty"`
	Version      string                          `json:"version,omitempty"`
	Checks       map[string]*DetailedCheckResult `json:"checks,omitempty"`
	Dependencies map[string]*DependencyStatus    `json:"dependencies,omitempty"`
	System       *SystemInfo                     `json:"system,omitempty"`
}

// DetailedCheckResult represents a detailed check result.
type DetailedCheckResult struct {
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
	Duration    string    `json:"duration,omitempty"`
	DurationMS  float64   `json:"duration_ms,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Critical    bool      `json:"critical,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastFailure time.Time `json:"last_failure,omitempty"`
}

// DependencyStatus represents a dependency status.
type DependencyStatus struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Latency     string    `json:"latency,omitempty"`
	LatencyMS   float64   `json:"latency_ms,omitempty"`
	Error       string    `json:"error,omitempty"`
	LastChecked time.Time `json:"last_checked"`
}

// SystemInfo represents system information.
type SystemInfo struct {
	Hostname     string `json:"hostname,omitempty"`
	NumCPU       int    `json:"num_cpu,omitempty"`
	NumGoroutine int    `json:"num_goroutine,omitempty"`
	MemoryAlloc  uint64 `json:"memory_alloc_bytes,omitempty"`
	MemorySys    uint64 `json:"memory_sys_bytes,omitempty"`
	GCPauseNs    uint64 `json:"gc_pause_ns,omitempty"`
	NumGC        uint32 `json:"num_gc,omitempty"`
}

// CompositeHealthCheck combines multiple health checks.
type CompositeHealthCheck struct {
	name   string
	checks []HealthCheck
}

// NewCompositeHealthCheck creates a new composite health check.
func NewCompositeHealthCheck(name string, checks ...HealthCheck) *CompositeHealthCheck {
	return &CompositeHealthCheck{
		name:   name,
		checks: checks,
	}
}

// Name returns the name of the composite health check.
func (c *CompositeHealthCheck) Name() string {
	return c.name
}

// Check performs all health checks and returns the first error.
func (c *CompositeHealthCheck) Check(ctx context.Context) error {
	for _, check := range c.checks {
		if err := check.Check(ctx); err != nil {
			return fmt.Errorf("%s: %w", check.Name(), err)
		}
	}
	return nil
}

// AddCheck adds a health check to the composite.
func (c *CompositeHealthCheck) AddCheck(check HealthCheck) {
	c.checks = append(c.checks, check)
}

// TimeoutHealthCheck wraps a health check with a timeout.
type TimeoutHealthCheck struct {
	check   HealthCheck
	timeout time.Duration
}

// NewTimeoutHealthCheck creates a new timeout health check.
func NewTimeoutHealthCheck(check HealthCheck, timeout time.Duration) *TimeoutHealthCheck {
	return &TimeoutHealthCheck{
		check:   check,
		timeout: timeout,
	}
}

// Name returns the name of the health check.
func (t *TimeoutHealthCheck) Name() string {
	return t.check.Name()
}

// Check performs the health check with a timeout.
func (t *TimeoutHealthCheck) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- t.check.Check(ctx)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("health check timed out after %v", t.timeout)
	}
}

// CachedHealthCheck caches health check results.
// Thread-safe implementation using mutex protection.
type CachedHealthCheck struct {
	check      HealthCheck
	cacheTTL   time.Duration
	mu         sync.RWMutex
	lastCheck  time.Time
	lastResult error
}

// NewCachedHealthCheck creates a new cached health check.
func NewCachedHealthCheck(check HealthCheck, cacheTTL time.Duration) *CachedHealthCheck {
	return &CachedHealthCheck{
		check:    check,
		cacheTTL: cacheTTL,
	}
}

// Name returns the name of the health check.
func (c *CachedHealthCheck) Name() string {
	return c.check.Name()
}

// Check performs the health check with caching.
// Thread-safe: uses mutex to protect lastCheck and lastResult.
func (c *CachedHealthCheck) Check(ctx context.Context) error {
	// First, try to read from cache with read lock
	c.mu.RLock()
	if time.Since(c.lastCheck) < c.cacheTTL {
		result := c.lastResult
		c.mu.RUnlock()
		return result
	}
	c.mu.RUnlock()

	// Cache expired, need to refresh with write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if time.Since(c.lastCheck) < c.cacheTTL {
		return c.lastResult
	}

	c.lastResult = c.check.Check(ctx)
	c.lastCheck = time.Now()
	return c.lastResult
}
