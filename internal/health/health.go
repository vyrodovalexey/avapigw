// Package health provides health check and readiness probe endpoints.
package health

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
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
	logger    observability.Logger
	draining  atomic.Bool
}

// CheckFunc is a function that performs a health check.
type CheckFunc func() Check

// jsonMarshalFunc is the function used to marshal JSON responses.
// It defaults to json.Marshal but can be overridden in tests.
var jsonMarshalFunc = json.Marshal

// NewChecker creates a new health checker.
// The logger parameter provides structured logging; pass
// observability.NopLogger() when no logging is needed.
func NewChecker(version string, logger observability.Logger) *Checker {
	return &Checker{
		version:   version,
		startTime: time.Now(),
		checks:    make(map[string]CheckFunc),
		logger:    logger,
	}
}

// SetDraining marks the health checker as draining. While draining,
// health and readiness endpoints return 503 Service Unavailable so that
// load balancers stop sending new traffic before connections are drained.
func (c *Checker) SetDraining(draining bool) {
	c.draining.Store(draining)
	if draining {
		c.logger.Info("health checker marked as draining")
	} else {
		c.logger.Info("health checker draining cleared")
	}
}

// IsDraining returns true if the health checker is in draining mode.
func (c *Checker) IsDraining() bool {
	return c.draining.Load()
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

	hm := GetHealthMetrics()
	for name, checkFunc := range c.checks {
		check := checkFunc()
		response.Checks[name] = check

		switch {
		case check.Status == StatusUnhealthy:
			response.Status = StatusUnhealthy
			hm.checkStatus.WithLabelValues(name).Set(0)
		case check.Status == StatusDegraded &&
			response.Status != StatusUnhealthy:
			response.Status = StatusDegraded
			hm.checkStatus.WithLabelValues(name).Set(0)
		default:
			hm.checkStatus.WithLabelValues(name).Set(1)
		}
	}

	return response
}

// HealthHandler returns an HTTP handler for the health endpoint.
// When the checker is in draining mode, it returns 503 Service Unavailable
// so that load balancers stop sending new traffic.
func (c *Checker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		GetHealthMetrics().checksTotal.WithLabelValues(
			"health",
		).Inc()

		// Return 503 when draining to signal load balancers
		if c.draining.Load() {
			response := HealthResponse{
				Status:    StatusUnhealthy,
				Version:   c.version,
				Timestamp: time.Now(),
				Details:   map[string]string{"reason": "draining"},
			}
			data, err := jsonMarshalFunc(response)
			if err != nil {
				c.logger.Error("health: failed to encode draining response", observability.Error(err))
				http.Error(w, "failed to encode response", http.StatusInternalServerError)
				return
			}
			w.Header().Set(HeaderContentType, ContentTypeJSON)
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write(data); err != nil {
				c.logger.Error("health: failed to write draining response", observability.Error(err))
			}
			return
		}

		response := c.Health()

		// Pre-encode the response to catch errors before writing headers
		data, err := jsonMarshalFunc(response)
		if err != nil {
			c.logger.Error("health: failed to encode response", observability.Error(err))
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}

		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write(data); err != nil {
			// Headers already sent, can only log the error
			c.logger.Error("health: failed to write response", observability.Error(err))
		}
	}
}

// ReadinessHandler returns an HTTP handler for the readiness endpoint.
// When the checker is in draining mode, it returns 503 Service Unavailable
// so that load balancers stop sending new traffic.
func (c *Checker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		GetHealthMetrics().checksTotal.WithLabelValues(
			"readiness",
		).Inc()

		// Return 503 when draining to signal load balancers
		if c.draining.Load() {
			response := ReadinessResponse{
				Status:    StatusUnhealthy,
				Timestamp: time.Now(),
				Checks: map[string]Check{
					"draining": {Status: StatusUnhealthy, Message: "gateway is draining"},
				},
			}
			data, err := jsonMarshalFunc(response)
			if err != nil {
				c.logger.Error("readiness: failed to encode draining response", observability.Error(err))
				http.Error(w, "failed to encode response", http.StatusInternalServerError)
				return
			}
			w.Header().Set(HeaderContentType, ContentTypeJSON)
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write(data); err != nil {
				c.logger.Error("readiness: failed to write draining response", observability.Error(err))
			}
			return
		}

		response := c.Readiness()

		// Pre-encode the response to catch errors before writing headers
		data, err := jsonMarshalFunc(response)
		if err != nil {
			c.logger.Error("readiness: failed to encode response", observability.Error(err))
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}

		w.Header().Set(HeaderContentType, ContentTypeJSON)

		statusCode := http.StatusOK
		if response.Status == StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		}
		w.WriteHeader(statusCode)

		if _, err := w.Write(data); err != nil {
			// Headers already sent, can only log the error
			c.logger.Error("readiness: failed to write response", observability.Error(err))
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
