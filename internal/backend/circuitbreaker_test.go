package backend

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewCircuitBreakerManager(t *testing.T) {
	t.Parallel()

	t.Run("creates manager with logger", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()
		manager := NewCircuitBreakerManager(logger)

		assert.NotNil(t, manager)
		assert.NotNil(t, manager.breakers)
		assert.NotNil(t, manager.logger)
	})

	t.Run("creates manager with nil logger", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)

		assert.NotNil(t, manager)
		assert.NotNil(t, manager.logger)
	})
}

func TestCircuitBreakerManager_GetOrCreate(t *testing.T) {
	t.Parallel()

	t.Run("returns nil for nil backend", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		cb := manager.GetOrCreate(nil)

		assert.Nil(t, cb)
	})

	t.Run("returns nil when circuit breaker not configured", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
		}

		cb := manager.GetOrCreate(backend)

		assert.Nil(t, cb)
	})

	t.Run("returns nil when circuit breaker disabled", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled: false,
			},
		}

		cb := manager.GetOrCreate(backend)

		assert.Nil(t, cb)
	})

	t.Run("creates circuit breaker when configured", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		cb := manager.GetOrCreate(backend)

		assert.NotNil(t, cb)
	})

	t.Run("returns cached circuit breaker", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		cb1 := manager.GetOrCreate(backend)
		cb2 := manager.GetOrCreate(backend)

		assert.Same(t, cb1, cb2)
	})
}

func TestCircuitBreakerManager_Get(t *testing.T) {
	t.Parallel()

	t.Run("returns nil for non-existent backend", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		cb := manager.Get("non-existent")

		assert.Nil(t, cb)
	})

	t.Run("returns circuit breaker for existing backend", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		_ = manager.GetOrCreate(backend)
		cb := manager.Get("test-backend")

		assert.NotNil(t, cb)
	})
}

func TestCircuitBreakerManager_Execute(t *testing.T) {
	t.Parallel()

	t.Run("executes function directly when no circuit breaker", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		executed := false

		result, err := manager.Execute("non-existent", func() (interface{}, error) {
			executed = true
			return "success", nil
		})

		assert.True(t, executed)
		assert.NoError(t, err)
		assert.Equal(t, "success", result)
	})

	t.Run("executes function through circuit breaker", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		_ = manager.GetOrCreate(backend)
		executed := false

		result, err := manager.Execute("test-backend", func() (interface{}, error) {
			executed = true
			return "success", nil
		})

		assert.True(t, executed)
		assert.NoError(t, err)
		assert.Equal(t, "success", result)
	})

	t.Run("returns error from function", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		_ = manager.GetOrCreate(backend)
		expectedErr := errors.New("test error")

		result, err := manager.Execute("test-backend", func() (interface{}, error) {
			return nil, expectedErr
		})

		assert.Nil(t, result)
		assert.Equal(t, expectedErr, err)
	})
}

func TestCircuitBreakerManager_Remove(t *testing.T) {
	t.Parallel()

	t.Run("removes circuit breaker", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		_ = manager.GetOrCreate(backend)
		require.NotNil(t, manager.Get("test-backend"))

		manager.Remove("test-backend")

		assert.Nil(t, manager.Get("test-backend"))
	})

	t.Run("does nothing for non-existent backend", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		manager.Remove("non-existent")

		// Should not panic
		assert.Equal(t, 0, manager.Count())
	})
}

func TestCircuitBreakerManager_Clear(t *testing.T) {
	t.Parallel()

	t.Run("clears all circuit breakers", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)

		for i := 0; i < 3; i++ {
			backend := &config.Backend{
				Name: "test-backend-" + string(rune('a'+i)),
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:   true,
					Threshold: 5,
					Timeout:   config.Duration(10 * time.Second),
				},
			}
			_ = manager.GetOrCreate(backend)
		}

		require.Equal(t, 3, manager.Count())

		manager.Clear()

		assert.Equal(t, 0, manager.Count())
	})
}

func TestCircuitBreakerManager_GetAll(t *testing.T) {
	t.Parallel()

	t.Run("returns all circuit breakers", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)

		for i := 0; i < 3; i++ {
			backend := &config.Backend{
				Name: "test-backend-" + string(rune('a'+i)),
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:   true,
					Threshold: 5,
					Timeout:   config.Duration(10 * time.Second),
				},
			}
			_ = manager.GetOrCreate(backend)
		}

		all := manager.GetAll()

		assert.Len(t, all, 3)
	})

	t.Run("returns copy of map", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		_ = manager.GetOrCreate(backend)
		all := manager.GetAll()

		// Modifying the returned map should not affect the manager
		delete(all, "test-backend")

		assert.Equal(t, 1, manager.Count())
	})
}

func TestCircuitBreakerManager_Count(t *testing.T) {
	t.Parallel()

	t.Run("returns correct count", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)

		assert.Equal(t, 0, manager.Count())

		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		_ = manager.GetOrCreate(backend)

		assert.Equal(t, 1, manager.Count())
	})
}

func TestCircuitBreakerManager_CreateFromConfig(t *testing.T) {
	t.Parallel()

	t.Run("creates circuit breakers from config", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)

		backends := []config.Backend{
			{
				Name: "backend-1",
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:   true,
					Threshold: 5,
					Timeout:   config.Duration(10 * time.Second),
				},
			},
			{
				Name: "backend-2",
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:   true,
					Threshold: 10,
					Timeout:   config.Duration(20 * time.Second),
				},
			},
			{
				Name: "backend-3",
				// No circuit breaker config
			},
		}

		manager.CreateFromConfig(backends)

		assert.Equal(t, 2, manager.Count())
		assert.NotNil(t, manager.Get("backend-1"))
		assert.NotNil(t, manager.Get("backend-2"))
		assert.Nil(t, manager.Get("backend-3"))
	})
}

func TestCircuitBreakerManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent access safely", func(t *testing.T) {
		t.Parallel()

		manager := NewCircuitBreakerManager(nil)
		backend := &config.Backend{
			Name: "test-backend",
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
		}

		done := make(chan bool)

		// Concurrent GetOrCreate
		for i := 0; i < 10; i++ {
			go func() {
				_ = manager.GetOrCreate(backend)
				done <- true
			}()
		}

		// Concurrent Get
		for i := 0; i < 10; i++ {
			go func() {
				_ = manager.Get("test-backend")
				done <- true
			}()
		}

		// Concurrent Execute
		for i := 0; i < 10; i++ {
			go func() {
				_, _ = manager.Execute("test-backend", func() (interface{}, error) {
					return nil, nil
				})
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 30; i++ {
			<-done
		}

		// Should have exactly one circuit breaker
		assert.Equal(t, 1, manager.Count())
	})
}
