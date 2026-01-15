package circuitbreaker

import (
	"sync"

	"go.uber.org/zap"
)

// Registry manages multiple circuit breakers.
type Registry struct {
	breakers sync.Map
	config   *Config
	logger   *zap.Logger
}

// NewRegistry creates a new circuit breaker registry.
func NewRegistry(config *Config, logger *zap.Logger) *Registry {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Registry{
		config: config,
		logger: logger,
	}
}

// Get returns a circuit breaker by name, or nil if not found.
func (r *Registry) Get(name string) *CircuitBreaker {
	value, ok := r.breakers.Load(name)
	if !ok {
		return nil
	}
	return value.(*CircuitBreaker)
}

// GetOrCreate returns an existing circuit breaker or creates a new one.
func (r *Registry) GetOrCreate(name string) *CircuitBreaker {
	// Try to load existing
	if value, ok := r.breakers.Load(name); ok {
		return value.(*CircuitBreaker)
	}

	// Create new circuit breaker
	cb := NewCircuitBreaker(name, r.config, r.logger)

	// Store or get existing (handles race condition)
	actual, loaded := r.breakers.LoadOrStore(name, cb)
	if loaded {
		return actual.(*CircuitBreaker)
	}

	r.logger.Debug("created circuit breaker",
		zap.String("name", name),
	)

	return cb
}

// GetOrCreateWithConfig returns an existing circuit breaker or creates a new one with custom config.
func (r *Registry) GetOrCreateWithConfig(name string, config *Config) *CircuitBreaker {
	// Try to load existing
	if value, ok := r.breakers.Load(name); ok {
		return value.(*CircuitBreaker)
	}

	// Create new circuit breaker with custom config
	cb := NewCircuitBreaker(name, config, r.logger)

	// Store or get existing (handles race condition)
	actual, loaded := r.breakers.LoadOrStore(name, cb)
	if loaded {
		return actual.(*CircuitBreaker)
	}

	r.logger.Debug("created circuit breaker with custom config",
		zap.String("name", name),
	)

	return cb
}

// Remove removes a circuit breaker from the registry.
func (r *Registry) Remove(name string) {
	r.breakers.Delete(name)
	r.logger.Debug("removed circuit breaker",
		zap.String("name", name),
	)
}

// List returns all circuit breakers in the registry.
func (r *Registry) List() []*CircuitBreaker {
	var breakers []*CircuitBreaker
	r.breakers.Range(func(key, value interface{}) bool {
		breakers = append(breakers, value.(*CircuitBreaker))
		return true
	})
	return breakers
}

// ListNames returns the names of all circuit breakers in the registry.
func (r *Registry) ListNames() []string {
	var names []string
	r.breakers.Range(func(key, value interface{}) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}

// ResetAll resets all circuit breakers to closed state.
func (r *Registry) ResetAll() {
	r.breakers.Range(func(key, value interface{}) bool {
		cb := value.(*CircuitBreaker)
		cb.Reset()
		return true
	})
	r.logger.Info("reset all circuit breakers")
}

// Stats returns statistics for all circuit breakers.
func (r *Registry) Stats() map[string]Stats {
	stats := make(map[string]Stats)
	r.breakers.Range(func(key, value interface{}) bool {
		name := key.(string)
		cb := value.(*CircuitBreaker)
		stats[name] = cb.Stats()
		return true
	})
	return stats
}

// Count returns the number of circuit breakers in the registry.
func (r *Registry) Count() int {
	count := 0
	r.breakers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Clear removes all circuit breakers from the registry.
func (r *Registry) Clear() {
	r.breakers.Range(func(key, value interface{}) bool {
		r.breakers.Delete(key)
		return true
	})
	r.logger.Info("cleared all circuit breakers")
}

// UpdateConfig updates the default configuration for new circuit breakers.
func (r *Registry) UpdateConfig(config *Config) {
	if config != nil {
		r.config = config
	}
}
