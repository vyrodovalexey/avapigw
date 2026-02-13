// Package backend provides backend service management for the API Gateway.
package backend

import (
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// CircuitBreakerManagerOption is a functional option for configuring CircuitBreakerManager.
type CircuitBreakerManagerOption func(*CircuitBreakerManager)

// WithCircuitBreakerManagerStateCallback sets a callback for circuit breaker state changes.
func WithCircuitBreakerManagerStateCallback(
	fn middleware.CircuitBreakerStateFunc,
) CircuitBreakerManagerOption {
	return func(m *CircuitBreakerManager) {
		m.stateCallback = fn
	}
}

// CircuitBreakerManager manages per-backend circuit breakers.
// It creates and caches circuit breakers for each backend based on their configuration.
type CircuitBreakerManager struct {
	breakers      map[string]*middleware.CircuitBreaker
	mu            sync.RWMutex
	logger        observability.Logger
	stateCallback middleware.CircuitBreakerStateFunc
}

// NewCircuitBreakerManager creates a new circuit breaker manager.
func NewCircuitBreakerManager(
	logger observability.Logger,
	opts ...CircuitBreakerManagerOption,
) *CircuitBreakerManager {
	if logger == nil {
		logger = observability.NopLogger()
	}

	m := &CircuitBreakerManager{
		breakers: make(map[string]*middleware.CircuitBreaker),
		logger:   logger,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// GetOrCreate returns the circuit breaker for a backend, creating if needed.
// If the backend doesn't have circuit breaker configuration, returns nil.
func (m *CircuitBreakerManager) GetOrCreate(backend *config.Backend) *middleware.CircuitBreaker {
	if backend == nil {
		return nil
	}

	// Check if circuit breaker is configured for this backend
	if backend.CircuitBreaker == nil || !backend.CircuitBreaker.Enabled {
		return nil
	}

	// Check cache first
	m.mu.RLock()
	if cb, ok := m.breakers[backend.Name]; ok {
		m.mu.RUnlock()
		return cb
	}
	m.mu.RUnlock()

	// Create new circuit breaker
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, ok := m.breakers[backend.Name]; ok {
		return cb
	}

	cb := m.createCircuitBreaker(backend)
	m.breakers[backend.Name] = cb

	m.logger.Info("created circuit breaker for backend",
		observability.String("backend", backend.Name),
		observability.Int("threshold", backend.CircuitBreaker.Threshold),
		observability.Duration("timeout", backend.CircuitBreaker.Timeout.Duration()),
	)

	return cb
}

// createCircuitBreaker creates a new circuit breaker from backend configuration.
func (m *CircuitBreakerManager) createCircuitBreaker(
	backend *config.Backend,
) *middleware.CircuitBreaker {
	cfg := backend.CircuitBreaker

	opts := []middleware.CircuitBreakerOption{
		middleware.WithCircuitBreakerLogger(m.logger),
	}
	if m.stateCallback != nil {
		opts = append(opts,
			middleware.WithCircuitBreakerStateCallback(m.stateCallback),
		)
	}

	return middleware.NewCircuitBreaker(
		"backend-"+backend.Name,
		cfg.Threshold,
		cfg.Timeout.Duration(),
		opts...,
	)
}

// Get returns the circuit breaker for a backend by name.
// Returns nil if no circuit breaker exists for the backend.
func (m *CircuitBreakerManager) Get(backendName string) *middleware.CircuitBreaker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.breakers[backendName]
}

// Execute executes a function with circuit breaker protection for a backend.
// If no circuit breaker exists for the backend, the function is executed directly.
func (m *CircuitBreakerManager) Execute(backendName string, fn func() (interface{}, error)) (interface{}, error) {
	cb := m.Get(backendName)
	if cb == nil {
		// No circuit breaker configured, execute directly
		return fn()
	}

	return cb.Execute(fn)
}

// Remove removes the circuit breaker for a backend.
func (m *CircuitBreakerManager) Remove(backendName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.breakers, backendName)
}

// Clear removes all circuit breakers.
func (m *CircuitBreakerManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.breakers = make(map[string]*middleware.CircuitBreaker)
}

// GetAll returns all circuit breakers.
func (m *CircuitBreakerManager) GetAll() map[string]*middleware.CircuitBreaker {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*middleware.CircuitBreaker, len(m.breakers))
	for k, v := range m.breakers {
		result[k] = v
	}
	return result
}

// Count returns the number of circuit breakers.
func (m *CircuitBreakerManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.breakers)
}

// CreateFromConfig creates circuit breakers for all backends in the configuration.
func (m *CircuitBreakerManager) CreateFromConfig(backends []config.Backend) {
	for i := range backends {
		backend := &backends[i]
		if backend.CircuitBreaker != nil && backend.CircuitBreaker.Enabled {
			m.GetOrCreate(backend)
		}
	}
}
