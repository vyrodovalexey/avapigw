package gateway

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewCacheFactory_Basic(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	require.NotNil(t, factory)
	assert.NotNil(t, factory.caches)
	assert.NotNil(t, factory.logger)
	assert.Nil(t, factory.vaultClient)
}

func TestNewCacheFactory_NilLogger(t *testing.T) {
	t.Parallel()

	factory := NewCacheFactory(nil, nil)

	require.NotNil(t, factory)
	assert.NotNil(t, factory.logger) // should default to NopLogger
}

func TestCacheFactory_GetOrCreate_CreatesNewCache(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000), // 60s in nanoseconds
	}

	c, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestCacheFactory_GetOrCreate_ReusesExistingCache(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000),
	}

	c1, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)
	require.NotNil(t, c1)

	c2, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)
	require.NotNil(t, c2)

	// Should be the same cache instance
	assert.Equal(t, c1, c2)
}

func TestCacheFactory_GetOrCreate_DifferentRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000),
	}

	c1, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)
	require.NotNil(t, c1)

	c2, err := factory.GetOrCreate("route2", cfg)
	require.NoError(t, err)
	require.NotNil(t, c2)

	// Different routes should get different cache instances
	assert.NotEqual(t, c1, c2)
}

func TestCacheFactory_GetOrCreate_ThreadSafety(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000),
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			routeName := "shared-route"
			_, err := factory.GetOrCreate(routeName, cfg)
			results[idx] = err
		}(i)
	}

	wg.Wait()

	for i, err := range results {
		assert.NoError(t, err, "goroutine %d failed", i)
	}

	// All goroutines should have gotten the same cache
	factory.mu.RLock()
	assert.Len(t, factory.caches, 1)
	factory.mu.RUnlock()
}

func TestCacheFactory_GetOrCreate_NilConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	// cache.New returns ErrInvalidConfig for nil config
	c, err := factory.GetOrCreate("route1", nil)
	assert.Error(t, err)
	assert.Nil(t, c)
}

func TestCacheFactory_GetOrCreate_DisabledCache(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: false,
		Type:    config.CacheTypeMemory,
	}

	c, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)
	require.NotNil(t, c) // Returns a disabled cache (no-op)
}

func TestCacheFactory_Close_Empty(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	err := factory.Close()
	assert.NoError(t, err)
}

func TestCacheFactory_Close_WithCaches(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000),
	}

	_, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)

	_, err = factory.GetOrCreate("route2", cfg)
	require.NoError(t, err)

	err = factory.Close()
	assert.NoError(t, err)

	// After close, caches map should be empty
	factory.mu.RLock()
	assert.Empty(t, factory.caches)
	factory.mu.RUnlock()
}

func TestCacheFactory_Close_ThenGetOrCreate(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000),
	}

	_, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)

	err = factory.Close()
	require.NoError(t, err)

	// Should be able to create new caches after close
	c, err := factory.GetOrCreate("route1", cfg)
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestCacheFactory_GetOrCreate_ConcurrentDifferentRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := NewCacheFactory(logger, nil)

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeMemory,
		TTL:     config.Duration(60_000_000_000),
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			routeName := "route-" + string(rune('A'+idx))
			_, err := factory.GetOrCreate(routeName, cfg)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	factory.mu.RLock()
	assert.Len(t, factory.caches, goroutines)
	factory.mu.RUnlock()
}

func TestCacheFactory_GetOrCreate_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		routeName string
		cfg       *config.CacheConfig
		expectErr bool
	}{
		{
			name:      "memory cache",
			routeName: "route-memory",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    config.CacheTypeMemory,
				TTL:     config.Duration(60_000_000_000),
			},
			expectErr: false,
		},
		{
			name:      "disabled cache",
			routeName: "route-disabled",
			cfg: &config.CacheConfig{
				Enabled: false,
			},
			expectErr: false,
		},
		{
			name:      "nil config",
			routeName: "route-nil",
			cfg:       nil,
			expectErr: true,
		},
		{
			name:      "unknown cache type",
			routeName: "route-unknown",
			cfg: &config.CacheConfig{
				Enabled: true,
				Type:    "unknown-type",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			factory := NewCacheFactory(logger, nil)

			c, err := factory.GetOrCreate(tt.routeName, tt.cfg)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, c)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}
