// Package health provides health check endpoints for the API Gateway.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Default timeout values for health checks.
const (
	// DefaultReadinessProbeTimeout is the default timeout for readiness probes.
	DefaultReadinessProbeTimeout = 5 * time.Second

	// DefaultLivenessProbeTimeout is the default timeout for liveness/health probes.
	DefaultLivenessProbeTimeout = 10 * time.Second
)

// HandlerConfig holds configuration for the health handler.
type HandlerConfig struct {
	// ReadinessProbeTimeout is the timeout for readiness probe checks.
	ReadinessProbeTimeout time.Duration

	// LivenessProbeTimeout is the timeout for liveness/health probe checks.
	LivenessProbeTimeout time.Duration
}

// DefaultHandlerConfig returns a HandlerConfig with default values.
func DefaultHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		ReadinessProbeTimeout: DefaultReadinessProbeTimeout,
		LivenessProbeTimeout:  DefaultLivenessProbeTimeout,
	}
}

// Handler handles health check requests.
type Handler struct {
	checks    []HealthCheck
	logger    *zap.Logger
	mu        sync.RWMutex
	startTime time.Time
	config    *HandlerConfig
}

// HealthCheck defines the interface for health checks.
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) error
}

// HealthCheckFunc is a function type that implements HealthCheck.
type HealthCheckFunc struct {
	name      string
	checkFunc func(ctx context.Context) error
}

// Name returns the name of the health check.
func (f *HealthCheckFunc) Name() string {
	return f.name
}

// Check performs the health check.
func (f *HealthCheckFunc) Check(ctx context.Context) error {
	return f.checkFunc(ctx)
}

// NewHealthCheckFunc creates a new health check function.
func NewHealthCheckFunc(name string, check func(ctx context.Context) error) *HealthCheckFunc {
	return &HealthCheckFunc{
		name:      name,
		checkFunc: check,
	}
}

// HealthStatus represents the overall health status.
type HealthStatus struct {
	Status    string                  `json:"status"`
	Timestamp time.Time               `json:"timestamp"`
	Uptime    string                  `json:"uptime,omitempty"`
	Checks    map[string]*CheckResult `json:"checks,omitempty"`
}

// CheckResult represents the result of a single health check.
type CheckResult struct {
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	Duration  string    `json:"duration,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewHandler creates a new health handler with default configuration.
func NewHandler(logger *zap.Logger) *Handler {
	return NewHandlerWithConfig(logger, nil)
}

// NewHandlerWithConfig creates a new health handler with the given configuration.
func NewHandlerWithConfig(logger *zap.Logger, config *HandlerConfig) *Handler {
	if config == nil {
		config = DefaultHandlerConfig()
	}
	return &Handler{
		checks:    make([]HealthCheck, 0),
		logger:    logger,
		startTime: time.Now(),
		config:    config,
	}
}

// SetConfig updates the handler configuration.
func (h *Handler) SetConfig(config *HandlerConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if config != nil {
		h.config = config
	}
}

// GetConfig returns the current handler configuration.
func (h *Handler) GetConfig() *HandlerConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.config
}

// getReadinessTimeout returns the configured readiness probe timeout.
func (h *Handler) getReadinessTimeout() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.config != nil && h.config.ReadinessProbeTimeout > 0 {
		return h.config.ReadinessProbeTimeout
	}
	return DefaultReadinessProbeTimeout
}

// getLivenessTimeout returns the configured liveness probe timeout.
func (h *Handler) getLivenessTimeout() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.config != nil && h.config.LivenessProbeTimeout > 0 {
		return h.config.LivenessProbeTimeout
	}
	return DefaultLivenessProbeTimeout
}

// AddCheck adds a health check.
func (h *Handler) AddCheck(check HealthCheck) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks = append(h.checks, check)
}

// RemoveCheck removes a health check by name.
func (h *Handler) RemoveCheck(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, check := range h.checks {
		if check.Name() == name {
			h.checks = append(h.checks[:i], h.checks[i+1:]...)
			return
		}
	}
}

// LivenessHandler returns a handler for liveness probes.
// Liveness probes indicate whether the application is running.
func (h *Handler) LivenessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"timestamp": time.Now().UTC(),
		})
	}
}

// ReadinessHandler returns a handler for readiness probes.
// Readiness probes indicate whether the application is ready to serve traffic.
func (h *Handler) ReadinessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		timeout := h.getReadinessTimeout()
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		status := h.runChecks(ctx)

		statusCode := http.StatusOK
		if status.Status != "ok" {
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, status)
	}
}

// HealthHandler returns a handler for detailed health checks.
func (h *Handler) HealthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		timeout := h.getLivenessTimeout()
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		status := h.runChecks(ctx)
		status.Uptime = time.Since(h.startTime).String()

		statusCode := http.StatusOK
		if status.Status != "ok" {
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, status)
	}
}

// runChecks runs all health checks and returns the status.
func (h *Handler) runChecks(ctx context.Context) *HealthStatus {
	h.mu.RLock()
	checks := make([]HealthCheck, len(h.checks))
	copy(checks, h.checks)
	h.mu.RUnlock()

	status := &HealthStatus{
		Status:    "ok",
		Timestamp: time.Now().UTC(),
		Checks:    make(map[string]*CheckResult),
	}

	if len(checks) == 0 {
		return status
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, check := range checks {
		wg.Add(1)
		go func(c HealthCheck) {
			defer wg.Done()

			start := time.Now()
			err := c.Check(ctx)
			duration := time.Since(start)

			result := &CheckResult{
				Status:    "ok",
				Duration:  duration.String(),
				Timestamp: time.Now().UTC(),
			}

			if err != nil {
				result.Status = "error"
				result.Error = err.Error()

				mu.Lock()
				status.Status = "error"
				mu.Unlock()

				h.logger.Warn("health check failed",
					zap.String("check", c.Name()),
					zap.Error(err),
					zap.Duration("duration", duration),
				)
			}

			mu.Lock()
			status.Checks[c.Name()] = result
			mu.Unlock()
		}(check)
	}

	wg.Wait()
	return status
}

// HTTPHandler returns a standard http.Handler for health checks.
func (h *Handler) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeout := h.getLivenessTimeout()
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		status := h.runChecks(ctx)
		status.Uptime = time.Since(h.startTime).String()

		statusCode := http.StatusOK
		if status.Status != "ok" {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(status); err != nil {
			h.logger.Error("failed to write health check response", zap.Error(err))
		}
	})
}

// LivenessHTTPHandler returns a standard http.Handler for liveness probes.
func (h *Handler) LivenessHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"timestamp": time.Now().UTC(),
		}); err != nil {
			h.logger.Error("failed to write liveness response", zap.Error(err))
		}
	})
}

// ReadinessHTTPHandler returns a standard http.Handler for readiness probes.
func (h *Handler) ReadinessHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeout := h.getReadinessTimeout()
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		status := h.runChecks(ctx)

		statusCode := http.StatusOK
		if status.Status != "ok" {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(status); err != nil {
			h.logger.Error("failed to write readiness response", zap.Error(err))
		}
	})
}

// RegisterRoutes registers health check routes on a Gin engine.
func (h *Handler) RegisterRoutes(engine *gin.Engine) {
	engine.GET("/health", h.HealthHandler())
	engine.GET("/healthz", h.LivenessHandler())
	engine.GET("/livez", h.LivenessHandler())
	engine.GET("/readyz", h.ReadinessHandler())
	engine.GET("/ready", h.ReadinessHandler())
}

// RegisterRoutesOnGroup registers health check routes on a Gin router group.
func (h *Handler) RegisterRoutesOnGroup(group *gin.RouterGroup) {
	group.GET("/health", h.HealthHandler())
	group.GET("/healthz", h.LivenessHandler())
	group.GET("/livez", h.LivenessHandler())
	group.GET("/readyz", h.ReadinessHandler())
	group.GET("/ready", h.ReadinessHandler())
}
