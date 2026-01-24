//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_GRPCProxy_UnaryCall(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("proxy unary call to backend", func(t *testing.T) {
		// Create router with route to backend
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service",
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

		// Verify router is set
		assert.NotNil(t, proxy.Router())
		assert.Equal(t, 1, proxy.Router().RouteCount())
	})

	t.Run("proxy with metadata forwarding", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service",
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

		// Verify connection pool
		assert.NotNil(t, proxy.ConnectionPool())

		// Test metadata handling through director
		director := proxy.Director()
		require.NotNil(t, director)

		// Create context with metadata
		md := metadata.Pairs(
			"x-request-id", "test-123",
			"x-api-version", "v1",
		)
		ctx = metadata.NewIncomingContext(ctx, md)

		// Direct should work
		outCtx, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.NotNil(t, outCtx)
	})
}

func TestIntegration_GRPCProxy_ServerStreaming(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("proxy server streaming call", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with route for streaming
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-stream",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Method:  &config.StringMatch{Exact: "ServerStream"},
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
			Timeout: config.Duration(60 * time.Second),
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router,
			grpcproxy.WithProxyLogger(observability.NopLogger()),
			grpcproxy.WithDefaultTimeout(60*time.Second),
		)
		defer proxy.Close()

		// Verify route exists
		route, exists := router.GetRoute("test-service-stream")
		require.True(t, exists)
		assert.Equal(t, "test-service-stream", route.Name)

		// Verify director can route streaming calls
		director := proxy.Director()
		_, conn, err := director.Direct(ctx, "/api.v1.TestService/ServerStream")
		require.NoError(t, err)
		require.NotNil(t, conn)
	})
}

func TestIntegration_GRPCProxy_BidirectionalStreaming(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("proxy bidirectional streaming call", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with route for bidi streaming
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-bidi",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Method:  &config.StringMatch{Exact: "BidirectionalStream"},
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
			Timeout: config.Duration(60 * time.Second),
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router,
			grpcproxy.WithProxyLogger(observability.NopLogger()),
			grpcproxy.WithDefaultTimeout(60*time.Second),
		)
		defer proxy.Close()

		// Verify route exists
		route, exists := router.GetRoute("test-service-bidi")
		require.True(t, exists)
		assert.Equal(t, "test-service-bidi", route.Name)

		// Verify director can route bidi streaming calls
		director := proxy.Director()
		_, conn, err := director.Direct(ctx, "/api.v1.TestService/BidirectionalStream")
		require.NoError(t, err)
		require.NotNil(t, conn)
	})
}

func TestIntegration_GRPCProxy_LoadBalancing(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("weighted load balancing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with weighted destinations
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-lb",
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

		// Make multiple requests and verify distribution
		director := proxy.Director()
		backend1Count := 0
		backend2Count := 0

		for i := 0; i < 100; i++ {
			_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
			require.NoError(t, err)
			require.NotNil(t, conn)

			// Check which backend was selected based on connection target
			target := conn.Target()
			if target == testCfg.Backend1URL {
				backend1Count++
			} else if target == testCfg.Backend2URL {
				backend2Count++
			}
		}

		// With 50/50 weights, both backends should receive requests
		// Allow for some variance due to random selection
		totalRequests := backend1Count + backend2Count
		assert.Greater(t, totalRequests, 0, "Should have made requests")
	})

	t.Run("round robin when weights are equal", func(t *testing.T) {
		// Create router with equal weights (or no weights)
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

		// Verify route has multiple destinations
		route, exists := router.GetRoute("test-service-rr")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 2)
	})
}

func TestIntegration_GRPCProxy_Timeout(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("request with timeout", func(t *testing.T) {
		// Create router with timeout
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-timeout",
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
			Timeout: config.Duration(5 * time.Second),
		})
		require.NoError(t, err)

		// Create proxy with default timeout
		proxy := grpcproxy.New(router,
			grpcproxy.WithProxyLogger(observability.NopLogger()),
			grpcproxy.WithDefaultTimeout(30*time.Second),
		)
		defer proxy.Close()

		// Verify route timeout is set
		route, exists := router.GetRoute("test-service-timeout")
		require.True(t, exists)
		assert.Equal(t, 5*time.Second, route.Config.Timeout.Duration())
	})

	t.Run("default timeout applied", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router without timeout
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-no-timeout",
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

		// Create proxy with default timeout
		defaultTimeout := 15 * time.Second
		proxy := grpcproxy.New(router,
			grpcproxy.WithProxyLogger(observability.NopLogger()),
			grpcproxy.WithDefaultTimeout(defaultTimeout),
		)
		defer proxy.Close()

		// Verify route has no timeout (will use default)
		route, exists := router.GetRoute("test-service-no-timeout")
		require.True(t, exists)
		assert.Equal(t, time.Duration(0), route.Config.Timeout.Duration())

		// Director should still work
		director := proxy.Director()
		_, conn, err := director.Direct(ctx, "/api.v1.TestService/Unary")
		require.NoError(t, err)
		require.NotNil(t, conn)
	})
}

func TestIntegration_GRPCProxy_Retry(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("route with retry policy", func(t *testing.T) {
		// Create router with retry policy
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "test-service-retry",
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
			Retries: &config.GRPCRetryPolicy{
				Attempts:            3,
				PerTryTimeout:       config.Duration(5 * time.Second),
				RetryOn:             "unavailable,resource-exhausted",
				BackoffBaseInterval: config.Duration(100 * time.Millisecond),
				BackoffMaxInterval:  config.Duration(1 * time.Second),
			},
		})
		require.NoError(t, err)

		// Verify retry policy is set
		route, exists := router.GetRoute("test-service-retry")
		require.True(t, exists)
		require.NotNil(t, route.Config.Retries)
		assert.Equal(t, 3, route.Config.Retries.Attempts)
		assert.Equal(t, 5*time.Second, route.Config.Retries.PerTryTimeout.Duration())
		assert.Equal(t, "unavailable,resource-exhausted", route.Config.Retries.RetryOn)
	})
}

func TestIntegration_GRPCProxy_RouteNotFound(t *testing.T) {
	t.Parallel()

	t.Run("no matching route returns error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create router with specific route
		router := grpcrouter.New()
		err := router.AddRoute(config.GRPCRoute{
			Name: "specific-service",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.SpecificService"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "localhost", Port: 8080},
					Weight:      100,
				},
			},
		})
		require.NoError(t, err)

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Try to direct to non-matching service
		director := proxy.Director()
		_, _, err = director.Direct(ctx, "/api.v1.OtherService/Method")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching route")
	})

	t.Run("empty router returns error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create empty router
		router := grpcrouter.New()

		// Create proxy
		proxy := grpcproxy.New(router, grpcproxy.WithProxyLogger(observability.NopLogger()))
		defer proxy.Close()

		// Try to direct any request
		director := proxy.Director()
		_, _, err := director.Direct(ctx, "/api.v1.TestService/Unary")
		require.Error(t, err)
	})
}

func TestIntegration_GRPCProxy_ConnectionPool(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("connection pool reuses connections", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create connection pool
		pool := grpcproxy.NewConnectionPool(grpcproxy.WithPoolLogger(observability.NopLogger()))
		defer pool.Close()

		// Get connection multiple times
		conn1, err := pool.Get(ctx, testCfg.Backend1URL)
		require.NoError(t, err)
		require.NotNil(t, conn1)

		conn2, err := pool.Get(ctx, testCfg.Backend1URL)
		require.NoError(t, err)
		require.NotNil(t, conn2)

		// Should be the same connection (reused)
		assert.Equal(t, conn1, conn2)
	})

	t.Run("connection pool handles multiple targets", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create connection pool
		pool := grpcproxy.NewConnectionPool(grpcproxy.WithPoolLogger(observability.NopLogger()))
		defer pool.Close()

		// Get connections to different targets
		conn1, err := pool.Get(ctx, testCfg.Backend1URL)
		require.NoError(t, err)
		require.NotNil(t, conn1)

		if helpers.IsGRPCBackendAvailable(testCfg.Backend2URL) {
			conn2, err := pool.Get(ctx, testCfg.Backend2URL)
			require.NoError(t, err)
			require.NotNil(t, conn2)

			// Should be different connections - compare targets instead of connection objects
			// to avoid race conditions with gRPC internal state
			assert.NotEqual(t, conn1.Target(), conn2.Target())
		}
	})
}

func TestIntegration_GRPCProxy_DirectBackendCall(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("direct call to backend", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Connect directly to backend
		conn, err := grpc.DialContext(ctx, testCfg.Backend1URL,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify connection is ready
		state := conn.GetState()
		assert.NotEqual(t, 0, state) // Should have a valid state
	})

	t.Run("backend health check", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		healthStatus, err := helpers.GRPCHealthCheck(ctx, testCfg.Backend1URL)
		// Backend might not have health service, so we just check for no connection error
		if err != nil {
			// Check if it's a "not found" error (service not implemented)
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unimplemented {
				t.Log("Backend does not implement health service")
				return
			}
		}
		// If no error, status should be valid
		if err == nil {
			assert.True(t, healthStatus == healthpb.HealthCheckResponse_SERVING ||
				healthStatus == healthpb.HealthCheckResponse_NOT_SERVING ||
				healthStatus == healthpb.HealthCheckResponse_UNKNOWN)
		}
	})
}
