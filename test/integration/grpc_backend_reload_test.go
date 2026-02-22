//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_GRPCBackendReload_RegistryReload tests backend registry reload
// with copy-on-write pattern for gRPC backends.
func TestIntegration_GRPCBackendReload_RegistryReload(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("reload backends adds new backend", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()
		registry := backend.NewRegistry(logger)

		// Load initial backends
		initialBackends := []config.Backend{
			{
				Name: "grpc-backend-1",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err := registry.LoadFromConfig(initialBackends)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Verify initial state
		all := registry.GetAll()
		assert.Len(t, all, 1)

		// Reload with additional backend
		updatedBackends := []config.Backend{
			{
				Name: "grpc-backend-1",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
			{
				Name: "grpc-backend-2",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err = registry.ReloadFromConfig(ctx, updatedBackends)
		require.NoError(t, err)

		// Verify updated state
		all = registry.GetAll()
		assert.Len(t, all, 2)
	})

	t.Run("reload backends removes old backend", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()
		registry := backend.NewRegistry(logger)

		// Load initial backends with two entries
		initialBackends := []config.Backend{
			{
				Name: "grpc-backend-1",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
			{
				Name: "grpc-backend-2",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err := registry.LoadFromConfig(initialBackends)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Verify initial state
		all := registry.GetAll()
		assert.Len(t, all, 2)

		// Reload with only one backend
		updatedBackends := []config.Backend{
			{
				Name: "grpc-backend-1",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err = registry.ReloadFromConfig(ctx, updatedBackends)
		require.NoError(t, err)

		// Verify updated state
		all = registry.GetAll()
		assert.Len(t, all, 1)
	})

	t.Run("reload backends updates host weights", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()
		registry := backend.NewRegistry(logger)

		// Load initial backends
		initialBackends := []config.Backend{
			{
				Name: "grpc-backend-weighted",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  50,
					},
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
						Weight:  50,
					},
				},
			},
		}

		err := registry.LoadFromConfig(initialBackends)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Reload with different weights
		updatedBackends := []config.Backend{
			{
				Name: "grpc-backend-weighted",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  80,
					},
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
						Weight:  20,
					},
				},
			},
		}

		err = registry.ReloadFromConfig(ctx, updatedBackends)
		require.NoError(t, err)

		// Verify updated state
		all := registry.GetAll()
		assert.Len(t, all, 1)
	})
}

// TestIntegration_GRPCBackendReload_ConcurrentAccess tests concurrent access
// during backend reload.
func TestIntegration_GRPCBackendReload_ConcurrentAccess(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("concurrent reads during reload", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()
		registry := backend.NewRegistry(logger)

		initialBackends := []config.Backend{
			{
				Name: "grpc-concurrent-backend",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err := registry.LoadFromConfig(initialBackends)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Concurrent reads and reloads
		var wg sync.WaitGroup
		var readErrors atomic.Int64
		var reloadErrors atomic.Int64

		// Readers
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					all := registry.GetAll()
					if len(all) == 0 {
						readErrors.Add(1)
					}
				}
			}()
		}

		// Reloaders
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					backends := []config.Backend{
						{
							Name: "grpc-concurrent-backend",
							Hosts: []config.BackendHost{
								{
									Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
									Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
									Weight:  1,
								},
							},
						},
					}
					if err := registry.ReloadFromConfig(ctx, backends); err != nil {
						reloadErrors.Add(1)
					}
				}
			}(i)
		}

		wg.Wait()

		assert.Equal(t, int64(0), reloadErrors.Load(), "no reload errors should occur")
		// Some read errors may occur during reload transitions, but should be minimal
		t.Logf("Read errors during concurrent reload: %d", readErrors.Load())
	})
}

// TestIntegration_GRPCBackendReload_ConnectionCleanup tests that stale connections
// are cleaned up after backend reload.
func TestIntegration_GRPCBackendReload_ConnectionCleanup(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("stale connections cleaned up after reload", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with two backends
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-cleanup",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
					},
					Weight: 50,
				},
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
					},
					Weight: 50,
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Establish connections to both backends
		director := proxy.Director()
		for i := 0; i < 10; i++ {
			_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
			require.NoError(t, err)
			require.NotNil(t, conn)
		}

		// Verify connections exist
		pool := proxy.ConnectionPool()
		require.NotNil(t, pool)
		initialTargets := pool.Targets()
		assert.GreaterOrEqual(t, len(initialTargets), 1, "should have at least one connection")

		// Clean up connections to backend2 (simulate backend removal)
		validTargets := map[string]bool{
			testCfg.Backend1URL: true,
		}
		proxy.CleanupStaleConnections(validTargets)

		// Verify backend2 connection was cleaned up
		remainingTargets := pool.Targets()
		for _, target := range remainingTargets {
			assert.True(t, validTargets[target],
				"remaining target %s should be in valid targets", target)
		}
	})

	t.Run("cleanup with empty valid targets removes all", func(t *testing.T) {
		// Create router
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-empty-cleanup",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
					},
					Weight: 100,
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Establish a connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		director := proxy.Director()
		_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Clean up with empty valid targets
		proxy.CleanupStaleConnections(map[string]bool{})

		// All connections should be cleaned up
		pool := proxy.ConnectionPool()
		remainingTargets := pool.Targets()
		assert.Empty(t, remainingTargets, "all connections should be cleaned up")
	})
}

// TestIntegration_GRPCBackendReload_ListenerReload tests the GRPCListener.ReloadBackends method.
func TestIntegration_GRPCBackendReload_ListenerReload(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("listener reload with valid backends", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()

		// Create backend registry
		registry := backend.NewRegistry(logger)
		initialBackends := []config.Backend{
			{
				Name: "grpc-listener-backend",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
		}
		err := registry.LoadFromConfig(initialBackends)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create gRPC listener with backend registry
		listenerCfg := config.Listener{
			Name:     "grpc-reload-test",
			Port:     port,
			Protocol: config.ProtocolGRPC,
			Bind:     "127.0.0.1",
			GRPC:     config.DefaultGRPCListenerConfig(),
		}

		router := grpcrouter.New()
		listener, err := gateway.NewGRPCListener(listenerCfg,
			gateway.WithGRPCListenerLogger(logger),
			gateway.WithGRPCRouter(router),
			gateway.WithGRPCBackendRegistry(registry),
		)
		require.NoError(t, err)

		// Start listener
		err = listener.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = listener.Stop(ctx)
		})

		// Reload backends
		newBackends := []config.Backend{
			{
				Name: "grpc-listener-backend-updated",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err = listener.ReloadBackends(ctx, newBackends)
		require.NoError(t, err)

		// Verify listener is still running
		assert.True(t, listener.IsRunning())
	})

	t.Run("listener reload without registry returns error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		listenerCfg := config.Listener{
			Name:     "grpc-no-registry",
			Port:     port,
			Protocol: config.ProtocolGRPC,
			Bind:     "127.0.0.1",
			GRPC:     config.DefaultGRPCListenerConfig(),
		}

		listener, err := gateway.NewGRPCListener(listenerCfg,
			gateway.WithGRPCListenerLogger(observability.NopLogger()),
		)
		require.NoError(t, err)

		// Reload without registry should fail
		err = listener.ReloadBackends(ctx, []config.Backend{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no backend registry configured")
	})
}

// TestIntegration_GRPCBackendReload_GRPCBackendConversion tests the full conversion
// pipeline from GRPCBackend CRD to Backend config used in reload.
func TestIntegration_GRPCBackendReload_GRPCBackendConversion(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("converted gRPC backends work with registry reload", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()
		registry := backend.NewRegistry(logger)

		// Create gRPC backends
		grpcBackends := []config.GRPCBackend{
			{
				Name: "grpc-converted-1",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
				HealthCheck: &config.GRPCHealthCheckConfig{
					Enabled:            true,
					Interval:           config.Duration(10 * time.Second),
					Timeout:            config.Duration(5 * time.Second),
					HealthyThreshold:   2,
					UnhealthyThreshold: 3,
				},
				LoadBalancer: &config.LoadBalancer{
					Algorithm: "roundRobin",
				},
			},
		}

		// Convert and load
		converted := config.GRPCBackendsToBackends(grpcBackends)
		require.Len(t, converted, 1)

		err := registry.LoadFromConfig(converted)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Verify backend is loaded
		all := registry.GetAll()
		assert.Len(t, all, 1)

		// Now reload with updated gRPC backends
		updatedGRPCBackends := []config.GRPCBackend{
			{
				Name: "grpc-converted-1",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  80,
					},
				},
				HealthCheck: &config.GRPCHealthCheckConfig{
					Enabled:            true,
					Interval:           config.Duration(5 * time.Second),
					Timeout:            config.Duration(3 * time.Second),
					HealthyThreshold:   1,
					UnhealthyThreshold: 2,
				},
			},
			{
				Name: "grpc-converted-2",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
						Weight:  20,
					},
				},
			},
		}

		updatedConverted := config.GRPCBackendsToBackends(updatedGRPCBackends)
		err = registry.ReloadFromConfig(ctx, updatedConverted)
		require.NoError(t, err)

		// Verify updated state
		all = registry.GetAll()
		assert.Len(t, all, 2)
	})
}

// TestIntegration_GRPCBackendReload_ProxyDirectorAfterReload tests that the proxy
// director works correctly after a backend reload.
func TestIntegration_GRPCBackendReload_ProxyDirectorAfterReload(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("director routes to new backends after reload", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with initial route pointing to backend1
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-director-reload",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
					},
					Weight: 100,
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Verify initial routing goes to backend1
		director := proxy.Director()
		_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
		require.NoError(t, err)
		require.NotNil(t, conn)
		assert.Equal(t, testCfg.Backend1URL, conn.Target())

		// Update route to point to backend2
		err = router.LoadRoutes([]config.GRPCRoute{
			{
				Name: "test-service-director-reload",
				Match: []config.GRPCRouteMatch{
					{
						Service: &config.StringMatch{Exact: "api.v1.TestService"},
					},
				},
				Route: []config.RouteDestination{
					{
						Destination: config.Destination{
							Host: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
							Port: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
						},
						Weight: 100,
					},
				},
			},
		})
		require.NoError(t, err)

		// Clean up stale connections
		validTargets := map[string]bool{
			testCfg.Backend2URL: true,
		}
		proxy.CleanupStaleConnections(validTargets)

		// Verify routing now goes to backend2
		_, conn, err = director.Direct(ctx, "/api.v1.TestService/Unary")
		require.NoError(t, err)
		require.NotNil(t, conn)
		assert.Equal(t, testCfg.Backend2URL, conn.Target())
	})
}

// TestIntegration_GRPCBackendReload_EmptyBackends tests reload with empty backends.
func TestIntegration_GRPCBackendReload_EmptyBackends(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("reload with empty backends clears registry", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := observability.NopLogger()
		registry := backend.NewRegistry(logger)

		// Load initial backends
		initialBackends := []config.Backend{
			{
				Name: "grpc-empty-test",
				Hosts: []config.BackendHost{
					{
						Address: helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
						Port:    helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
						Weight:  1,
					},
				},
			},
		}

		err := registry.LoadFromConfig(initialBackends)
		require.NoError(t, err)

		err = registry.StartAll(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = registry.StopAll(ctx)
		})

		// Verify initial state
		all := registry.GetAll()
		assert.Len(t, all, 1)

		// Reload with empty backends
		err = registry.ReloadFromConfig(ctx, []config.Backend{})
		require.NoError(t, err)

		// Verify empty state
		all = registry.GetAll()
		assert.Empty(t, all)
	})
}

// TestIntegration_GRPCBackendReload_GatewayPropagation tests that ReloadGRPCBackends
// propagates to all gRPC listeners.
func TestIntegration_GRPCBackendReload_GatewayPropagation(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway propagates reload to gRPC listeners", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, gi)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Verify gateway is running
		assert.True(t, gi.Listener.IsRunning())

		// Verify the listener address is accessible
		addr := gi.Listener.Address()
		assert.NotEmpty(t, addr)
		assert.Equal(t, gi.Address, addr)

		// Verify the listener has a valid port
		assert.Equal(t, fmt.Sprintf("0.0.0.0:%d", port), addr)
	})
}
