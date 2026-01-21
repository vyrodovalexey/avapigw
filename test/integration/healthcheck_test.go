//go:build integration
// +build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_HealthCheck_BackendStatus(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("healthy backend is marked healthy", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
		}

		healthCfg := config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(1 * time.Second),
			Timeout:            config.Duration(2 * time.Second),
			HealthyThreshold:   1,
			UnhealthyThreshold: 2,
		}

		checker := backend.NewHealthChecker(hosts, healthCfg, backend.WithHealthCheckLogger(observability.NopLogger()))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		checker.Start(ctx)
		defer checker.Stop()

		// Wait for health check to run
		time.Sleep(2 * time.Second)

		// Host should be marked healthy
		assert.Equal(t, backend.StatusHealthy, hosts[0].Status())
	})

	t.Run("unhealthy backend is marked unhealthy", func(t *testing.T) {
		// Use a port that's not running
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 19999, 1),
		}

		healthCfg := config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(500 * time.Millisecond),
			Timeout:            config.Duration(1 * time.Second),
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		}

		checker := backend.NewHealthChecker(hosts, healthCfg, backend.WithHealthCheckLogger(observability.NopLogger()))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		checker.Start(ctx)
		defer checker.Stop()

		// Wait for health check to run
		time.Sleep(2 * time.Second)

		// Host should be marked unhealthy
		assert.Equal(t, backend.StatusUnhealthy, hosts[0].Status())
	})

	t.Run("multiple hosts health check", func(t *testing.T) {
		helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		healthCfg := config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(1 * time.Second),
			Timeout:            config.Duration(2 * time.Second),
			HealthyThreshold:   1,
			UnhealthyThreshold: 2,
		}

		checker := backend.NewHealthChecker(hosts, healthCfg, backend.WithHealthCheckLogger(observability.NopLogger()))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		checker.Start(ctx)
		defer checker.Stop()

		// Wait for health check to run
		time.Sleep(2 * time.Second)

		// Both hosts should be marked healthy
		assert.Equal(t, backend.StatusHealthy, hosts[0].Status())
		assert.Equal(t, backend.StatusHealthy, hosts[1].Status())
	})
}

func TestIntegration_HealthCheck_DirectCheck(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("direct health check to backend", func(t *testing.T) {
		client := helpers.HTTPClient()
		resp, err := client.Get(testCfg.Backend1URL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestIntegration_Backend_Registry(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("register and start backend", func(t *testing.T) {
		registry := backend.NewRegistry(observability.NopLogger())

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 1},
			},
			HealthCheck: &config.HealthCheck{
				Path:               "/health",
				Interval:           config.Duration(1 * time.Second),
				Timeout:            config.Duration(2 * time.Second),
				HealthyThreshold:   1,
				UnhealthyThreshold: 2,
			},
		}

		b, err := backend.NewBackend(cfg, backend.WithBackendLogger(observability.NopLogger()))
		require.NoError(t, err)

		err = registry.Register(b)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		// Wait for health check
		time.Sleep(2 * time.Second)

		// Get backend
		retrieved, exists := registry.Get("test-backend")
		require.True(t, exists)
		assert.Equal(t, backend.StatusHealthy, retrieved.Status())

		// Stop all
		err = registry.StopAll(ctx)
		require.NoError(t, err)
	})

	t.Run("load backends from config", func(t *testing.T) {
		registry := backend.NewRegistry(observability.NopLogger())

		backends := []config.Backend{
			{
				Name: "backend-1",
				Hosts: []config.BackendHost{
					{Address: "127.0.0.1", Port: 8801, Weight: 1},
				},
			},
			{
				Name: "backend-2",
				Hosts: []config.BackendHost{
					{Address: "127.0.0.1", Port: 8802, Weight: 1},
				},
			},
		}

		err := registry.LoadFromConfig(backends)
		require.NoError(t, err)

		all := registry.GetAll()
		assert.Len(t, all, 2)
	})

	t.Run("duplicate backend registration fails", func(t *testing.T) {
		registry := backend.NewRegistry(observability.NopLogger())

		cfg := config.Backend{
			Name: "duplicate-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 1},
			},
		}

		b1, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		b2, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		err = registry.Register(b1)
		require.NoError(t, err)

		err = registry.Register(b2)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})

	t.Run("unregister backend", func(t *testing.T) {
		registry := backend.NewRegistry(observability.NopLogger())

		cfg := config.Backend{
			Name: "removable-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 1},
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		err = registry.Register(b)
		require.NoError(t, err)

		_, exists := registry.Get("removable-backend")
		require.True(t, exists)

		err = registry.Unregister("removable-backend")
		require.NoError(t, err)

		_, exists = registry.Get("removable-backend")
		assert.False(t, exists)
	})
}
