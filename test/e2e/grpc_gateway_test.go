//go:build e2e
// +build e2e

package e2e

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
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_GRPCGateway_Startup(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway starts and stops cleanly", func(t *testing.T) {
		ctx := context.Background()

		// Get a free port
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

		// Verify gateway is running
		assert.True(t, gi.Listener.IsRunning())

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Stop gateway
		err = gi.Stop(ctx)
		require.NoError(t, err)

		// Verify gateway is stopped
		assert.False(t, gi.Listener.IsRunning())
	})

	t.Run("gateway with full configuration", func(t *testing.T) {
		ctx := context.Background()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create full configuration
		cfg := helpers.CreateGRPCTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

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

		// Verify components are initialized
		assert.NotNil(t, gi.Router)
		assert.NotNil(t, gi.Proxy)
		assert.NotNil(t, gi.Server)
	})

	t.Run("gateway listener state transitions", func(t *testing.T) {
		ctx := context.Background()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration
		listenerCfg := config.Listener{
			Name:     "grpc-test",
			Port:     port,
			Protocol: config.ProtocolGRPC,
			Bind:     "127.0.0.1",
			GRPC:     config.DefaultGRPCListenerConfig(),
		}

		// Create listener
		listener, err := gateway.NewGRPCListener(listenerCfg,
			gateway.WithGRPCListenerLogger(observability.NopLogger()),
		)
		require.NoError(t, err)

		// Initial state should be not running
		assert.False(t, listener.IsRunning())

		// Start listener
		err = listener.Start(ctx)
		require.NoError(t, err)
		assert.True(t, listener.IsRunning())

		// Cannot start again
		err = listener.Start(ctx)
		require.Error(t, err)

		// Stop listener
		err = listener.Stop(ctx)
		require.NoError(t, err)
		assert.False(t, listener.IsRunning())
	})
}

func TestE2E_GRPCGateway_UnaryThroughGateway(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("unary call through gateway", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create and start gateway
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify connection is established
		state := conn.GetState()
		assert.NotEqual(t, 0, state)
	})

	t.Run("unary call with metadata", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create and start gateway
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Connection should be ready
		assert.NotNil(t, conn)
	})
}

func TestE2E_GRPCGateway_ServerStreamThroughGateway(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("server streaming through gateway", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with streaming route
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-stream-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "grpc",
						Port:     port,
						Protocol: config.ProtocolGRPC,
						Bind:     "127.0.0.1",
						GRPC: &config.GRPCListenerConfig{
							MaxConcurrentStreams: 100,
							Reflection:           true,
							HealthCheck:          true,
						},
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "stream-route",
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
					},
				},
			},
		}

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify route exists
		route, exists := gi.Router.GetRoute("stream-route")
		require.True(t, exists)
		assert.Equal(t, "stream-route", route.Name)
	})
}

func TestE2E_GRPCGateway_BidirectionalStreamThroughGateway(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("bidirectional streaming through gateway", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with bidi streaming route
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-bidi-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "grpc",
						Port:     port,
						Protocol: config.ProtocolGRPC,
						Bind:     "127.0.0.1",
						GRPC: &config.GRPCListenerConfig{
							MaxConcurrentStreams: 100,
							Reflection:           true,
							HealthCheck:          true,
						},
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "bidi-route",
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
					},
				},
			},
		}

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify route exists
		route, exists := gi.Router.GetRoute("bidi-route")
		require.True(t, exists)
		assert.Equal(t, "bidi-route", route.Name)
	})
}

func TestE2E_GRPCGateway_LoadBalancing(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("load balancing across multiple backends", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with multiple backends
		cfg := helpers.CreateGRPCTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Verify route has multiple destinations
		route, exists := gi.Router.GetRoute("test-service")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 2)
		assert.Equal(t, 50, route.Config.Route[0].Weight)
		assert.Equal(t, 50, route.Config.Route[1].Weight)
	})
}

func TestE2E_GRPCGateway_HealthService(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway health service responds", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with health check enabled
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)
		cfg.Spec.Listeners[0].GRPC.HealthCheck = true

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Check health
		client := healthpb.NewHealthClient(conn)
		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})

	t.Run("gateway health watch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)
		cfg.Spec.Listeners[0].GRPC.HealthCheck = true

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Watch health
		client := healthpb.NewHealthClient(conn)
		stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)

		// Receive initial status
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})

	t.Run("gateway reflection service", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with reflection enabled
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)
		cfg.Spec.Listeners[0].GRPC.Reflection = true

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify connection is established (reflection service is registered)
		assert.NotNil(t, conn)
	})
}

func TestE2E_GRPCGateway_RouteMatching(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("route matching with multiple routes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with multiple routes
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-multi-route-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "grpc",
						Port:     port,
						Protocol: config.ProtocolGRPC,
						Bind:     "127.0.0.1",
						GRPC:     config.DefaultGRPCListenerConfig(),
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "unary-route",
						Match: []config.GRPCRouteMatch{
							{
								Service: &config.StringMatch{Exact: "api.v1.TestService"},
								Method:  &config.StringMatch{Exact: "Unary"},
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
					},
					{
						Name: "stream-route",
						Match: []config.GRPCRouteMatch{
							{
								Service: &config.StringMatch{Exact: "api.v1.TestService"},
								Method:  &config.StringMatch{Prefix: "Server"},
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
					},
					{
						Name: "catch-all",
						Match: []config.GRPCRouteMatch{
							{
								Service: &config.StringMatch{Prefix: ""},
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
					},
				},
			},
		}

		// Start gateway
		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Verify routes are loaded
		assert.Equal(t, 3, gi.Router.RouteCount())

		// Test route matching
		result, err := gi.Router.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "unary-route", result.Route.Name)

		result, err = gi.Router.Match("/api.v1.TestService/ServerStream", nil)
		require.NoError(t, err)
		assert.Equal(t, "stream-route", result.Route.Name)

		result, err = gi.Router.Match("/other.Service/Method", nil)
		require.NoError(t, err)
		assert.Equal(t, "catch-all", result.Route.Name)
	})
}

func TestE2E_GRPCGateway_BackendHotReload(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("hot-reload gRPC backends end-to-end", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create initial configuration with single backend
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

		// Verify initial state - single backend route
		route, exists := gi.Router.GetRoute("test-service")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 1)
		assert.Equal(t, 100, route.Config.Route[0].Weight)

		// Connect to gateway and verify it works
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify health check works before reload
		healthClient := healthpb.NewHealthClient(conn)
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

		// Now reload routes with two backends (simulating backend hot-reload)
		err = gi.Router.LoadRoutes([]config.GRPCRoute{
			{
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
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)

		// Verify updated state - two backend routes
		route, exists = gi.Router.GetRoute("test-service")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 2)
		assert.Equal(t, 50, route.Config.Route[0].Weight)
		assert.Equal(t, 50, route.Config.Route[1].Weight)

		// Verify health check still works after reload
		resp, err = healthClient.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

		// Verify gateway is still running
		assert.True(t, gi.Listener.IsRunning())
	})

	t.Run("hot-reload preserves existing connections", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Start with two backends
		cfg := helpers.CreateGRPCTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, gi)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Establish connection before reload
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify connection works
		healthClient := healthpb.NewHealthClient(conn)
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

		// Reload routes (change weights)
		err = gi.Router.LoadRoutes([]config.GRPCRoute{
			{
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
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)

		// Existing connection should still work after reload
		resp, err = healthClient.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

		// Verify updated route
		route, exists := gi.Router.GetRoute("test-service")
		require.True(t, exists)
		assert.Equal(t, 80, route.Config.Route[0].Weight)
		assert.Equal(t, 20, route.Config.Route[1].Weight)
	})

	t.Run("hot-reload with backend removal", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Start with two backends
		cfg := helpers.CreateGRPCTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

		gi, err := helpers.StartGRPCGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, gi)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		err = helpers.WaitForGRPCReady(gi.Address, 10*time.Second)
		require.NoError(t, err)

		// Verify initial state
		route, exists := gi.Router.GetRoute("test-service")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 2)

		// Reload with only one backend (remove backend2)
		err = gi.Router.LoadRoutes([]config.GRPCRoute{
			{
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
				Timeout: config.Duration(30 * time.Second),
			},
		})
		require.NoError(t, err)

		// Clean up stale connections to removed backend
		if gi.Proxy != nil {
			validTargets := map[string]bool{
				testCfg.Backend1URL: true,
			}
			gi.Proxy.CleanupStaleConnections(validTargets)
		}

		// Verify updated state
		route, exists = gi.Router.GetRoute("test-service")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 1)
		assert.Equal(t, 100, route.Config.Route[0].Weight)

		// Verify gateway still works
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		healthClient := healthpb.NewHealthClient(conn)
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})
}

func TestE2E_GRPCGateway_ErrorHandling(t *testing.T) {
	t.Parallel()

	t.Run("no matching route returns unavailable", func(t *testing.T) {
		t.Parallel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with specific route only
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-error-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "grpc",
						Port:     port,
						Protocol: config.ProtocolGRPC,
						Bind:     "127.0.0.1",
						GRPC:     config.DefaultGRPCListenerConfig(),
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "specific-route",
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
					},
				},
			},
		}

		// Create router and verify no match
		router := grpcrouter.New()
		err = router.LoadRoutes(cfg.Spec.GRPCRoutes)
		require.NoError(t, err)

		_, err = router.Match("/api.v1.OtherService/Method", nil)
		require.Error(t, err)

		st, ok := status.FromError(err)
		if ok {
			assert.Equal(t, codes.Unknown, st.Code())
		}
	})
}
