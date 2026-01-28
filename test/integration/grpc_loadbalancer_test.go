//go:build integration
// +build integration

package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_GRPCLoadBalancer_RoundRobin(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("round robin distributes requests evenly", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with equal weights (triggers round-robin)
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-rr",
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
					Weight: 1,
				},
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
					},
					Weight: 1,
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Track which backend is selected
		director := proxy.Director()
		backend1Count := 0
		backend2Count := 0

		// Make multiple requests
		numRequests := 100
		for i := 0; i < numRequests; i++ {
			_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
			require.NoError(t, err)
			require.NotNil(t, conn)

			target := conn.Target()
			if target == testCfg.Backend1URL {
				backend1Count++
			} else if target == testCfg.Backend2URL {
				backend2Count++
			}
		}

		// With round-robin, distribution should be roughly equal
		// Allow 20% variance
		totalRequests := backend1Count + backend2Count
		assert.Greater(t, totalRequests, 0)

		if totalRequests > 0 {
			backend1Ratio := float64(backend1Count) / float64(totalRequests)
			backend2Ratio := float64(backend2Count) / float64(totalRequests)

			// Each backend should get between 30% and 70% of requests
			assert.Greater(t, backend1Ratio, 0.3, "Backend 1 should get at least 30%% of requests")
			assert.Less(t, backend1Ratio, 0.7, "Backend 1 should get at most 70%% of requests")
			assert.Greater(t, backend2Ratio, 0.3, "Backend 2 should get at least 30%% of requests")
			assert.Less(t, backend2Ratio, 0.7, "Backend 2 should get at most 70%% of requests")
		}
	})

	t.Run("round robin with single backend", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with single backend
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-single",
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

		// All requests should go to the single backend
		director := proxy.Director()
		for i := 0; i < 10; i++ {
			_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
			require.NoError(t, err)
			require.NotNil(t, conn)
			assert.Equal(t, testCfg.Backend1URL, conn.Target())
		}
	})
}

func TestIntegration_GRPCLoadBalancer_Weighted(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("weighted distribution respects weights", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with 80/20 weights
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-weighted",
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
					Weight: 80,
				},
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
					},
					Weight: 20,
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Track which backend is selected
		director := proxy.Director()
		backend1Count := 0
		backend2Count := 0

		// Make many requests to get statistical significance
		numRequests := 1000
		for i := 0; i < numRequests; i++ {
			_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
			require.NoError(t, err)
			require.NotNil(t, conn)

			target := conn.Target()
			if target == testCfg.Backend1URL {
				backend1Count++
			} else if target == testCfg.Backend2URL {
				backend2Count++
			}
		}

		// With 80/20 weights, backend1 should get significantly more requests
		totalRequests := backend1Count + backend2Count
		assert.Greater(t, totalRequests, 0)

		if totalRequests > 0 {
			backend1Ratio := float64(backend1Count) / float64(totalRequests)

			// Backend 1 should get between 60% and 95% (allowing for variance)
			assert.Greater(t, backend1Ratio, 0.6, "Backend 1 should get at least 60%% of requests with 80%% weight")
			assert.Less(t, backend1Ratio, 0.95, "Backend 1 should get at most 95%% of requests")
		}
	})

	t.Run("weighted with zero weight backend", func(t *testing.T) {
		// Create router with one zero-weight backend
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-zero-weight",
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
				{
					Destination: config.Destination{
						Host: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
						Port: helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port,
					},
					Weight: 0, // Zero weight - should still get some traffic (treated as 1)
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Verify route is created correctly
		route, exists := router.GetRoute("test-service-zero-weight")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 2)
	})

	t.Run("weighted distribution is thread-safe", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-concurrent",
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

		// Make concurrent requests
		var wg sync.WaitGroup
		var successCount atomic.Int64
		var errorCount atomic.Int64

		numGoroutines := 10
		requestsPerGoroutine := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				director := proxy.Director()
				for j := 0; j < requestsPerGoroutine; j++ {
					_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
					if err == nil && conn != nil {
						successCount.Add(1)
					} else {
						errorCount.Add(1)
					}
				}
			}()
		}

		wg.Wait()

		// All requests should succeed
		totalRequests := int64(numGoroutines * requestsPerGoroutine)
		assert.Equal(t, totalRequests, successCount.Load(), "All concurrent requests should succeed")
		assert.Equal(t, int64(0), errorCount.Load(), "No errors should occur")
	})
}

func TestIntegration_GRPCLoadBalancer_NoDestinations(t *testing.T) {
	t.Parallel()

	t.Run("route with no destinations returns error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with empty destinations
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-no-dest",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{}, // Empty destinations
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Directing should fail
		director := proxy.Director()
		_, _, err = director.Direct(ctx, "/api.v1.TestService/Unary")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no destination")
	})
}

func TestIntegration_GRPCLoadBalancer_StaticDirector(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("static director always routes to same target", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create connection pool
		pool := grpcproxy.NewConnectionPool(grpcproxy.WithPoolLogger(observability.NopLogger()))
		defer pool.Close()

		// Create static director
		director := grpcproxy.NewStaticDirector(
			testCfg.Backend1URL,
			pool,
			observability.NopLogger(),
		)

		// All requests should go to the same target
		for i := 0; i < 10; i++ {
			_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
			require.NoError(t, err)
			require.NotNil(t, conn)
			assert.Equal(t, testCfg.Backend1URL, conn.Target())
		}
	})

	t.Run("static director forwards metadata", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create connection pool
		pool := grpcproxy.NewConnectionPool(grpcproxy.WithPoolLogger(observability.NopLogger()))
		defer pool.Close()

		// Create static director
		director := grpcproxy.NewStaticDirector(
			testCfg.Backend1URL,
			pool,
			observability.NopLogger(),
		)

		// Add metadata to context
		md := metadata.Pairs(
			"x-request-id", "test-123",
			"x-custom-header", "custom-value",
		)
		ctx = metadata.NewIncomingContext(ctx, md)

		// Direct should work and forward metadata
		outCtx, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.NotNil(t, outCtx)

		// Verify outgoing metadata is set
		outMD, ok := metadata.FromOutgoingContext(outCtx)
		require.True(t, ok)
		assert.Contains(t, outMD.Get("x-request-id"), "test-123")
		assert.Contains(t, outMD.Get("x-custom-header"), "custom-value")
	})
}
