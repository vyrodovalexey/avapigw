// Package health provides health check and readiness probe endpoints.
package health

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

// Status represents the health status.
type Status string

const (
	// StatusHealthy indicates the service is healthy.
	StatusHealthy Status = "healthy"
	// StatusUnhealthy indicates the service is unhealthy.
	StatusUnhealthy Status = "unhealthy"
	// StatusDegraded indicates the service is degraded but operational.
	StatusDegraded Status = "degraded"
)

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status       Status            `json:"status"`
	Version      string            `json:"version,omitempty"`
	Uptime       string            `json:"uptime,omitempty"`
	UptimeSecs   int64             `json:"uptime_seconds,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	StartTime    time.Time         `json:"start_time,omitempty"`
	Hostname     string            `json:"hostname,omitempty"`
	GoVersion    string            `json:"go_version,omitempty"`
	NumGoroutine int               `json:"num_goroutines,omitempty"`
	MemoryMB     float64           `json:"memory_mb,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
}

// ReadinessResponse represents the readiness check response.
type ReadinessResponse struct {
	Status    Status           `json:"status"`
	Checks    map[string]Check `json:"checks,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// Check represents an individual health check result.
type Check struct {
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
}

// Checker provides health and readiness checking functionality.
type Checker struct {
	version   string
	startTime time.Time
	checks    map[string]CheckFunc
	mu        sync.RWMutex
}

// CheckFunc is a function that performs a health check.
type CheckFunc func() Check

// NewChecker creates a new health checker.
func NewChecker(version string) *Checker {
	return &Checker{
		version:   version,
		startTime: time.Now(),
		checks:    make(map[string]CheckFunc),
	}
}

// RegisterCheck registers a health check function.
func (c *Checker) RegisterCheck(name string, check CheckFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks[name] = check
}

// UnregisterCheck removes a health check function.
func (c *Checker) UnregisterCheck(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.checks, name)
}

// Health returns the health status with detailed information.
func (c *Checker) Health() HealthResponse {
	uptime := time.Since(c.startTime)
	hostname, _ := os.Hostname()

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memoryMB := float64(memStats.Alloc) / 1024 / 1024

	return HealthResponse{
		Status:       StatusHealthy,
		Version:      c.version,
		Uptime:       uptime.Round(time.Second).String(),
		UptimeSecs:   int64(uptime.Seconds()),
		Timestamp:    time.Now(),
		StartTime:    c.startTime,
		Hostname:     hostname,
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		MemoryMB:     memoryMB,
	}
}

// Readiness returns the readiness status.
func (c *Checker) Readiness() ReadinessResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	response := ReadinessResponse{
		Status:    StatusHealthy,
		Checks:    make(map[string]Check),
		Timestamp: time.Now(),
	}

	for name, checkFunc := range c.checks {
		check := checkFunc()
		response.Checks[name] = check

		if check.Status == StatusUnhealthy {
			response.Status = StatusUnhealthy
		} else if check.Status == StatusDegraded && response.Status != StatusUnhealthy {
			response.Status = StatusDegraded
		}
	}

	return response
}

// HealthHandler returns an HTTP handler for the health endpoint.
func (c *Checker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := c.Health()

		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}
}

// ReadinessHandler returns an HTTP handler for the readiness endpoint.
func (c *Checker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := c.Readiness()

		w.Header().Set(HeaderContentType, ContentTypeJSON)

		statusCode := http.StatusOK
		if response.Status == StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		}
		w.WriteHeader(statusCode)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}
}

// LivenessHandler returns an HTTP handler for the liveness endpoint (simple ping).
func (c *Checker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}

// Handler is a convenience type that wraps the checker for use with gin.
type Handler struct {
	checker *Checker
}

// NewHandler creates a new health handler.
func NewHandler(checker *Checker) *Handler {
	return &Handler{checker: checker}
}

// Health handles the health endpoint.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	h.checker.HealthHandler()(w, r)
}

// Readiness handles the readiness endpoint.
func (h *Handler) Readiness(w http.ResponseWriter, r *http.Request) {
	h.checker.ReadinessHandler()(w, r)
}

// Liveness handles the liveness endpoint.
func (h *Handler) Liveness(w http.ResponseWriter, r *http.Request) {
	h.checker.LivenessHandler()(w, r)
}
