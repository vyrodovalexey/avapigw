package circuitbreaker

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for NewRegistry
// ============================================================================

func TestNewRegistry(t *testing.T) {
	t.Run("with nil config uses default", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		require.NotNil(t, registry)
		assert.NotNil(t, registry.config)
		// Verify default config values
		assert.Equal(t, 5, registry.config.MaxFailures)
		assert.Equal(t, 30*time.Second, registry.config.Timeout)
		assert.Equal(t, 3, registry.config.HalfOpenMax)
		assert.Equal(t, 2, registry.config.SuccessThreshold)
	})

	t.Run("with nil logger uses nop logger", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		require.NotNil(t, registry)
		assert.NotNil(t, registry.logger)
		// Nop logger should not panic when used
		registry.logger.Info("test message")
	})

	t.Run("with custom config and logger", func(t *testing.T) {
		customConfig := &Config{
			MaxFailures:      10,
			Timeout:          60 * time.Second,
			HalfOpenMax:      5,
			SuccessThreshold: 3,
		}
		logger, _ := zap.NewDevelopment()

		registry := NewRegistry(customConfig, logger)

		require.NotNil(t, registry)
		assert.Equal(t, customConfig, registry.config)
		assert.Equal(t, logger, registry.logger)
		assert.Equal(t, 10, registry.config.MaxFailures)
		assert.Equal(t, 60*time.Second, registry.config.Timeout)
	})
}

// ============================================================================
// Test Cases for Registry.Get
// ============================================================================

func TestRegistry_Get(t *testing.T) {
	t.Run("returns nil for non-existent breaker", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.Get("non-existent")

		assert.Nil(t, cb)
	})

	t.Run("returns existing breaker", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		// Create a breaker first
		created := registry.GetOrCreate("test-breaker")
		require.NotNil(t, created)

		// Get should return the same breaker
		cb := registry.Get("test-breaker")

		assert.NotNil(t, cb)
		assert.Same(t, created, cb)
		assert.Equal(t, "test-breaker", cb.Name())
	})

	t.Run("returns correct breaker among multiple", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		cb1 := registry.GetOrCreate("breaker-1")
		cb2 := registry.GetOrCreate("breaker-2")
		cb3 := registry.GetOrCreate("breaker-3")

		assert.Same(t, cb1, registry.Get("breaker-1"))
		assert.Same(t, cb2, registry.Get("breaker-2"))
		assert.Same(t, cb3, registry.Get("breaker-3"))
	})
}

// ============================================================================
// Test Cases for Registry.GetOrCreate
// ============================================================================

func TestRegistry_GetOrCreate(t *testing.T) {
	t.Run("creates new breaker if not exists", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.GetOrCreate("test")

		assert.NotNil(t, cb)
		assert.Equal(t, "test", cb.Name())
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("returns existing breaker if exists", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		cb1 := registry.GetOrCreate("test")
		cb2 := registry.GetOrCreate("test")

		assert.Same(t, cb1, cb2)
	})

	t.Run("creates breakers with registry config", func(t *testing.T) {
		customConfig := &Config{
			MaxFailures:      3,
			Timeout:          10 * time.Millisecond,
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}
		registry := NewRegistry(customConfig, nil)

		cb := registry.GetOrCreate("test")

		// Verify the breaker uses the registry's config by testing behavior
		// Record failures to open the circuit
		cb.RecordFailure()
		cb.RecordFailure()
		cb.RecordFailure()

		assert.Equal(t, StateOpen, cb.State())
	})

	t.Run("creates multiple different breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb1 := registry.GetOrCreate("breaker-1")
		cb2 := registry.GetOrCreate("breaker-2")
		cb3 := registry.GetOrCreate("breaker-3")

		assert.NotSame(t, cb1, cb2)
		assert.NotSame(t, cb2, cb3)
		assert.NotSame(t, cb1, cb3)
		assert.Equal(t, "breaker-1", cb1.Name())
		assert.Equal(t, "breaker-2", cb2.Name())
		assert.Equal(t, "breaker-3", cb3.Name())
	})
}

func TestRegistry_GetOrCreate_Concurrent(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup
	breakers := make([]*CircuitBreaker, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			breakers[idx] = registry.GetOrCreate("shared")
		}(i)
	}

	wg.Wait()

	// All should be the same instance
	for i := 1; i < 100; i++ {
		assert.Same(t, breakers[0], breakers[i])
	}

	// Count should be 1
	assert.Equal(t, 1, registry.Count())
}

func TestRegistry_GetOrCreate_Concurrent_MultipleNames(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup
	numNames := 10
	numGoroutines := 100

	results := make(map[string][]*CircuitBreaker)
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "breaker-" + string(rune('0'+idx%numNames))
			cb := registry.GetOrCreate(name)

			mu.Lock()
			results[name] = append(results[name], cb)
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Verify each name has only one unique breaker instance
	for name, breakers := range results {
		for i := 1; i < len(breakers); i++ {
			assert.Same(t, breakers[0], breakers[i], "All breakers for %s should be the same instance", name)
		}
	}

	// Count should be equal to numNames
	assert.Equal(t, numNames, registry.Count())
}

// ============================================================================
// Test Cases for Registry.GetOrCreateWithConfig
// ============================================================================

func TestRegistry_GetOrCreateWithConfig(t *testing.T) {
	t.Run("creates new breaker with custom config", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		customConfig := &Config{
			MaxFailures:      2,
			Timeout:          10 * time.Millisecond,
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}

		cb := registry.GetOrCreateWithConfig("custom-breaker", customConfig)

		assert.NotNil(t, cb)
		assert.Equal(t, "custom-breaker", cb.Name())

		// Verify custom config is used - circuit should open after 2 failures
		cb.RecordFailure()
		cb.RecordFailure()
		assert.Equal(t, StateOpen, cb.State())
	})

	t.Run("returns existing breaker ignores new config", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		config1 := &Config{
			MaxFailures:      2,
			Timeout:          10 * time.Millisecond,
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}
		config2 := &Config{
			MaxFailures:      10,
			Timeout:          100 * time.Millisecond,
			HalfOpenMax:      5,
			SuccessThreshold: 3,
		}

		cb1 := registry.GetOrCreateWithConfig("test", config1)
		cb2 := registry.GetOrCreateWithConfig("test", config2)

		assert.Same(t, cb1, cb2)

		// Verify original config is still used (MaxFailures = 2)
		cb2.RecordFailure()
		cb2.RecordFailure()
		assert.Equal(t, StateOpen, cb2.State())
	})

	t.Run("creates breaker with nil config uses default", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.GetOrCreateWithConfig("nil-config", nil)

		assert.NotNil(t, cb)
		assert.Equal(t, "nil-config", cb.Name())
	})
}

func TestRegistry_GetOrCreateWithConfig_Concurrent(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup
	breakers := make([]*CircuitBreaker, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			config := &Config{
				MaxFailures:      idx + 1, // Different config for each goroutine
				Timeout:          time.Duration(idx+1) * time.Millisecond,
				HalfOpenMax:      1,
				SuccessThreshold: 1,
			}
			breakers[idx] = registry.GetOrCreateWithConfig("shared", config)
		}(i)
	}

	wg.Wait()

	// All should be the same instance (first one wins)
	for i := 1; i < 100; i++ {
		assert.Same(t, breakers[0], breakers[i])
	}

	// Count should be 1
	assert.Equal(t, 1, registry.Count())
}

// ============================================================================
// Test Cases for Registry.Remove
// ============================================================================

func TestRegistry_Remove(t *testing.T) {
	t.Run("removes existing breaker", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("test-breaker")
		require.Equal(t, 1, registry.Count())

		registry.Remove("test-breaker")

		assert.Equal(t, 0, registry.Count())
		assert.Nil(t, registry.Get("test-breaker"))
	})

	t.Run("removing non-existent breaker no error", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		// Should not panic or error
		registry.Remove("non-existent")

		assert.Equal(t, 0, registry.Count())
	})

	t.Run("removes only specified breaker", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("breaker-1")
		registry.GetOrCreate("breaker-2")
		registry.GetOrCreate("breaker-3")
		require.Equal(t, 3, registry.Count())

		registry.Remove("breaker-2")

		assert.Equal(t, 2, registry.Count())
		assert.NotNil(t, registry.Get("breaker-1"))
		assert.Nil(t, registry.Get("breaker-2"))
		assert.NotNil(t, registry.Get("breaker-3"))
	})

	t.Run("can recreate after remove", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		cb1 := registry.GetOrCreate("test")
		registry.Remove("test")

		cb2 := registry.GetOrCreate("test")

		assert.NotSame(t, cb1, cb2)
		assert.Equal(t, "test", cb2.Name())
	})
}

// ============================================================================
// Test Cases for Registry.List
// ============================================================================

func TestRegistry_List(t *testing.T) {
	t.Run("returns empty list initially", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		list := registry.List()

		assert.Empty(t, list)
		// Note: List() returns nil when empty, which is idiomatic Go
	})

	t.Run("returns all breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		cb1 := registry.GetOrCreate("breaker-1")
		cb2 := registry.GetOrCreate("breaker-2")
		cb3 := registry.GetOrCreate("breaker-3")

		list := registry.List()

		assert.Len(t, list, 3)
		assert.Contains(t, list, cb1)
		assert.Contains(t, list, cb2)
		assert.Contains(t, list, cb3)
	})

	t.Run("order is not guaranteed", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("a")
		registry.GetOrCreate("b")
		registry.GetOrCreate("c")

		// Call List multiple times - order may vary
		list1 := registry.List()
		list2 := registry.List()

		// Both should have same elements
		assert.Len(t, list1, 3)
		assert.Len(t, list2, 3)

		// Extract names and sort for comparison
		names1 := make([]string, 3)
		names2 := make([]string, 3)
		for i, cb := range list1 {
			names1[i] = cb.Name()
		}
		for i, cb := range list2 {
			names2[i] = cb.Name()
		}
		sort.Strings(names1)
		sort.Strings(names2)
		assert.Equal(t, names1, names2)
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("test")

		list1 := registry.List()
		list2 := registry.List()

		// Modifying one list should not affect the other
		list1[0] = nil
		assert.NotNil(t, list2[0])
	})
}

// ============================================================================
// Test Cases for Registry.ListNames
// ============================================================================

func TestRegistry_ListNames(t *testing.T) {
	t.Run("returns empty list initially", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		names := registry.ListNames()

		assert.Empty(t, names)
		// Note: ListNames() returns nil when empty, which is idiomatic Go
	})

	t.Run("returns all breaker names", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("breaker-1")
		registry.GetOrCreate("breaker-2")
		registry.GetOrCreate("breaker-3")

		names := registry.ListNames()

		assert.Len(t, names, 3)
		assert.Contains(t, names, "breaker-1")
		assert.Contains(t, names, "breaker-2")
		assert.Contains(t, names, "breaker-3")
	})

	t.Run("names match breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("alpha")
		registry.GetOrCreate("beta")
		registry.GetOrCreate("gamma")

		names := registry.ListNames()
		breakers := registry.List()

		// All names should correspond to breakers
		breakerNames := make([]string, len(breakers))
		for i, cb := range breakers {
			breakerNames[i] = cb.Name()
		}

		sort.Strings(names)
		sort.Strings(breakerNames)
		assert.Equal(t, names, breakerNames)
	})
}

// ============================================================================
// Test Cases for Registry.ResetAll
// ============================================================================

func TestRegistry_ResetAll(t *testing.T) {
	t.Run("resets all breakers to closed state", func(t *testing.T) {
		config := &Config{
			MaxFailures:      1,
			Timeout:          time.Hour, // Long timeout to keep circuit open
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}
		registry := NewRegistry(config, nil)

		// Create breakers and open them
		cb1 := registry.GetOrCreate("breaker-1")
		cb2 := registry.GetOrCreate("breaker-2")
		cb3 := registry.GetOrCreate("breaker-3")

		cb1.RecordFailure()
		cb2.RecordFailure()
		cb3.RecordFailure()

		require.Equal(t, StateOpen, cb1.State())
		require.Equal(t, StateOpen, cb2.State())
		require.Equal(t, StateOpen, cb3.State())

		registry.ResetAll()

		assert.Equal(t, StateClosed, cb1.State())
		assert.Equal(t, StateClosed, cb2.State())
		assert.Equal(t, StateClosed, cb3.State())
	})

	t.Run("works with empty registry", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		// Should not panic
		registry.ResetAll()

		assert.Equal(t, 0, registry.Count())
	})

	t.Run("resets counters as well", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		cb := registry.GetOrCreate("test")

		// Record some operations
		cb.RecordSuccess()
		cb.RecordSuccess()
		cb.RecordFailure()

		require.Equal(t, 2, cb.Stats().Successes)
		require.Equal(t, 1, cb.Stats().Failures)

		registry.ResetAll()

		stats := cb.Stats()
		assert.Equal(t, 0, stats.Successes)
		assert.Equal(t, 0, stats.Failures)
		assert.Equal(t, 0, stats.TotalRequests)
	})
}

// ============================================================================
// Test Cases for Registry.Stats
// ============================================================================

func TestRegistry_Stats(t *testing.T) {
	t.Run("returns empty map initially", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		stats := registry.Stats()

		assert.Empty(t, stats)
		assert.NotNil(t, stats)
	})

	t.Run("returns stats for all breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		cb1 := registry.GetOrCreate("breaker-1")
		cb2 := registry.GetOrCreate("breaker-2")

		// Record different operations for each breaker
		cb1.RecordSuccess()
		cb1.RecordSuccess()
		cb2.RecordFailure()
		cb2.RecordFailure()
		cb2.RecordFailure()

		stats := registry.Stats()

		assert.Len(t, stats, 2)

		assert.Contains(t, stats, "breaker-1")
		assert.Equal(t, 2, stats["breaker-1"].Successes)
		assert.Equal(t, 0, stats["breaker-1"].Failures)

		assert.Contains(t, stats, "breaker-2")
		assert.Equal(t, 0, stats["breaker-2"].Successes)
		assert.Equal(t, 3, stats["breaker-2"].Failures)
	})

	t.Run("stats reflect current state", func(t *testing.T) {
		config := &Config{
			MaxFailures:      2,
			Timeout:          time.Hour,
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}
		registry := NewRegistry(config, nil)
		cb := registry.GetOrCreate("test")

		// Open the circuit
		cb.RecordFailure()
		cb.RecordFailure()

		stats := registry.Stats()

		assert.Equal(t, StateOpen, stats["test"].State)
	})
}

// ============================================================================
// Test Cases for Registry.Count
// ============================================================================

func TestRegistry_Count(t *testing.T) {
	t.Run("returns 0 initially", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		count := registry.Count()

		assert.Equal(t, 0, count)
	})

	t.Run("returns correct count after adding breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		registry.GetOrCreate("breaker-1")
		assert.Equal(t, 1, registry.Count())

		registry.GetOrCreate("breaker-2")
		assert.Equal(t, 2, registry.Count())

		registry.GetOrCreate("breaker-3")
		assert.Equal(t, 3, registry.Count())
	})

	t.Run("count decreases after remove", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("breaker-1")
		registry.GetOrCreate("breaker-2")
		registry.GetOrCreate("breaker-3")
		require.Equal(t, 3, registry.Count())

		registry.Remove("breaker-2")

		assert.Equal(t, 2, registry.Count())
	})

	t.Run("duplicate GetOrCreate does not increase count", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		registry.GetOrCreate("test")
		registry.GetOrCreate("test")
		registry.GetOrCreate("test")

		assert.Equal(t, 1, registry.Count())
	})
}

// ============================================================================
// Test Cases for Registry.Clear
// ============================================================================

func TestRegistry_Clear(t *testing.T) {
	t.Run("removes all breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("breaker-1")
		registry.GetOrCreate("breaker-2")
		registry.GetOrCreate("breaker-3")
		require.Equal(t, 3, registry.Count())

		registry.Clear()

		assert.Equal(t, 0, registry.Count())
		assert.Nil(t, registry.Get("breaker-1"))
		assert.Nil(t, registry.Get("breaker-2"))
		assert.Nil(t, registry.Get("breaker-3"))
	})

	t.Run("Count returns 0 after clear", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("test-1")
		registry.GetOrCreate("test-2")

		registry.Clear()

		assert.Equal(t, 0, registry.Count())
	})

	t.Run("clear on empty registry", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		// Should not panic
		registry.Clear()

		assert.Equal(t, 0, registry.Count())
	})

	t.Run("can add breakers after clear", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("old-breaker")
		registry.Clear()

		cb := registry.GetOrCreate("new-breaker")

		assert.NotNil(t, cb)
		assert.Equal(t, "new-breaker", cb.Name())
		assert.Equal(t, 1, registry.Count())
	})

	t.Run("List returns empty after clear", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		registry.GetOrCreate("test-1")
		registry.GetOrCreate("test-2")

		registry.Clear()

		assert.Empty(t, registry.List())
		assert.Empty(t, registry.ListNames())
	})
}

// ============================================================================
// Test Cases for Registry.UpdateConfig
// ============================================================================

func TestRegistry_UpdateConfig(t *testing.T) {
	t.Run("updates config for new breakers", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		// Create a breaker with default config
		cb1 := registry.GetOrCreate("old-breaker")

		// Update config
		newConfig := &Config{
			MaxFailures:      2,
			Timeout:          10 * time.Millisecond,
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}
		registry.UpdateConfig(newConfig)

		// Create a new breaker - should use new config
		cb2 := registry.GetOrCreate("new-breaker")

		// Old breaker should still use old config (5 failures to open)
		cb1.RecordFailure()
		cb1.RecordFailure()
		assert.Equal(t, StateClosed, cb1.State())

		// New breaker should use new config (2 failures to open)
		cb2.RecordFailure()
		cb2.RecordFailure()
		assert.Equal(t, StateOpen, cb2.State())
	})

	t.Run("nil config is ignored", func(t *testing.T) {
		customConfig := &Config{
			MaxFailures:      10,
			Timeout:          time.Hour,
			HalfOpenMax:      5,
			SuccessThreshold: 3,
		}
		registry := NewRegistry(customConfig, nil)

		registry.UpdateConfig(nil)

		// Config should remain unchanged
		assert.Equal(t, 10, registry.config.MaxFailures)
		assert.Equal(t, time.Hour, registry.config.Timeout)
	})

	t.Run("does not affect existing breakers", func(t *testing.T) {
		config1 := &Config{
			MaxFailures:      5,
			Timeout:          time.Hour,
			HalfOpenMax:      3,
			SuccessThreshold: 2,
		}
		registry := NewRegistry(config1, nil)
		cb := registry.GetOrCreate("existing")

		// Update config
		config2 := &Config{
			MaxFailures:      1,
			Timeout:          time.Millisecond,
			HalfOpenMax:      1,
			SuccessThreshold: 1,
		}
		registry.UpdateConfig(config2)

		// Existing breaker should still use original config
		cb.RecordFailure()
		assert.Equal(t, StateClosed, cb.State()) // Would be open if using new config
	})
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestRegistry_Concurrent_GetRemove(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup

	// Pre-populate some breakers
	for i := 0; i < 10; i++ {
		registry.GetOrCreate("breaker-" + string(rune('0'+i)))
	}

	// Concurrent Get operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "breaker-" + string(rune('0'+idx%10))
			_ = registry.Get(name)
		}(i)
	}

	// Concurrent Remove operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "breaker-" + string(rune('0'+idx%10))
			registry.Remove(name)
		}(i)
	}

	// Concurrent GetOrCreate operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "breaker-" + string(rune('0'+idx%10))
			_ = registry.GetOrCreate(name)
		}(i)
	}

	wg.Wait()

	// Should complete without race conditions
	// Final state may vary, but should be consistent
	count := registry.Count()
	assert.GreaterOrEqual(t, count, 0)
	assert.LessOrEqual(t, count, 10)
}

func TestRegistry_Concurrent_ListWhileModifying(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup

	// Concurrent List operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.List()
		}()
	}

	// Concurrent ListNames operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.ListNames()
		}()
	}

	// Concurrent Add operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			registry.GetOrCreate("breaker-" + string(rune('A'+idx%26)))
		}(i)
	}

	// Concurrent Remove operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			registry.Remove("breaker-" + string(rune('A'+idx%26)))
		}(i)
	}

	wg.Wait()

	// Should complete without race conditions
	// Verify registry is in a consistent state
	count := registry.Count()
	list := registry.List()
	names := registry.ListNames()

	assert.Equal(t, count, len(list))
	assert.Equal(t, count, len(names))
}

func TestRegistry_Concurrent_StatsAndReset(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup

	// Pre-populate breakers
	for i := 0; i < 10; i++ {
		registry.GetOrCreate("breaker-" + string(rune('0'+i)))
	}

	// Concurrent Stats operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.Stats()
		}()
	}

	// Concurrent ResetAll operations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.ResetAll()
		}()
	}

	// Concurrent Count operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.Count()
		}()
	}

	wg.Wait()

	// Should complete without race conditions
	assert.Equal(t, 10, registry.Count())
}

func TestRegistry_Concurrent_ClearWhileAccessing(t *testing.T) {
	registry := NewRegistry(nil, nil)
	var wg sync.WaitGroup

	// Pre-populate breakers
	for i := 0; i < 10; i++ {
		registry.GetOrCreate("breaker-" + string(rune('0'+i)))
	}

	// Concurrent Get operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = registry.Get("breaker-" + string(rune('0'+idx%10)))
		}(i)
	}

	// Concurrent Clear operations
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.Clear()
		}()
	}

	// Concurrent GetOrCreate operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = registry.GetOrCreate("breaker-" + string(rune('0'+idx%10)))
		}(i)
	}

	wg.Wait()

	// Should complete without race conditions
	// Final state may vary
	count := registry.Count()
	assert.GreaterOrEqual(t, count, 0)
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestRegistry_EdgeCases(t *testing.T) {
	t.Run("empty string name", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.GetOrCreate("")

		assert.NotNil(t, cb)
		assert.Equal(t, "", cb.Name())
		assert.Equal(t, 1, registry.Count())
	})

	t.Run("special characters in name", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.GetOrCreate("test/breaker:with-special_chars.v1")

		assert.NotNil(t, cb)
		assert.Equal(t, "test/breaker:with-special_chars.v1", cb.Name())
	})

	t.Run("unicode name", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.GetOrCreate("测试断路器")

		assert.NotNil(t, cb)
		assert.Equal(t, "测试断路器", cb.Name())
	})

	t.Run("very long name", func(t *testing.T) {
		registry := NewRegistry(nil, nil)
		longName := ""
		for i := 0; i < 1000; i++ {
			longName += "a"
		}

		cb := registry.GetOrCreate(longName)

		assert.NotNil(t, cb)
		assert.Equal(t, longName, cb.Name())
	})

	t.Run("whitespace name", func(t *testing.T) {
		registry := NewRegistry(nil, nil)

		cb := registry.GetOrCreate("   ")

		assert.NotNil(t, cb)
		assert.Equal(t, "   ", cb.Name())
	})
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestRegistry_Integration_FullLifecycle(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := &Config{
		MaxFailures:      2,
		Timeout:          10 * time.Millisecond,
		HalfOpenMax:      1,
		SuccessThreshold: 1,
	}
	registry := NewRegistry(config, logger)

	// Create breakers
	cb1 := registry.GetOrCreate("service-a")
	cb2 := registry.GetOrCreate("service-b")

	assert.Equal(t, 2, registry.Count())

	// Use breakers
	cb1.RecordSuccess()
	cb2.RecordFailure()
	cb2.RecordFailure()

	// Check states
	assert.Equal(t, StateClosed, cb1.State())
	assert.Equal(t, StateOpen, cb2.State())

	// Get stats
	stats := registry.Stats()
	assert.Equal(t, 1, stats["service-a"].Successes)
	assert.Equal(t, StateOpen, stats["service-b"].State)

	// Reset all
	registry.ResetAll()
	assert.Equal(t, StateClosed, cb1.State())
	assert.Equal(t, StateClosed, cb2.State())

	// Remove one
	registry.Remove("service-a")
	assert.Equal(t, 1, registry.Count())
	assert.Nil(t, registry.Get("service-a"))

	// Clear all
	registry.Clear()
	assert.Equal(t, 0, registry.Count())
}

func TestRegistry_Integration_ConfigUpdate(t *testing.T) {
	registry := NewRegistry(nil, nil)

	// Create breaker with default config
	cb1 := registry.GetOrCreate("breaker-1")

	// Update config
	newConfig := &Config{
		MaxFailures:      1,
		Timeout:          time.Millisecond,
		HalfOpenMax:      1,
		SuccessThreshold: 1,
	}
	registry.UpdateConfig(newConfig)

	// Create new breaker with updated config
	cb2 := registry.GetOrCreate("breaker-2")

	// Verify different behaviors
	cb1.RecordFailure()
	assert.Equal(t, StateClosed, cb1.State()) // Default: 5 failures to open

	cb2.RecordFailure()
	assert.Equal(t, StateOpen, cb2.State()) // New config: 1 failure to open
}
