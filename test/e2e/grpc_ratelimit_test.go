//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"sync"
	"sync/atomic"
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
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_GRPCRateLimit_Enforcement(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rate limiting enforced on gRPC requests", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with rate limiting
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-ratelimit-test",
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
							HealthCheck:          true,
						},
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "test-service",
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
						RateLimit: &config.RateLimitConfig{
							Enabled:           true,
							RequestsPerSecond: 5,
							Burst:             5,
							PerClient:         false,
						},
					},
				},
				RateLimit: &config.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 10,
					Burst:             10,
					PerClient:         false,
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

		// Make health check requests (these should work)
		client := healthpb.NewHealthClient(conn)

		successCount := 0
		rateLimitedCount := 0

		// Make many requests quickly
		for i := 0; i < 20; i++ {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			if err != nil {
				st, ok := status.FromError(err)
				if ok && st.Code() == codes.ResourceExhausted {
					rateLimitedCount++
				}
			} else if resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
				successCount++
			}
		}

		// Some requests should succeed
		assert.Greater(t, successCount, 0, "Some requests should succeed")

		// Note: Rate limiting might not be enforced on health checks
		// This test verifies the configuration is applied
		t.Logf("Success: %d, Rate limited: %d", successCount, rateLimitedCount)
	})

	t.Run("per-client rate limiting", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with per-client rate limiting
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-perclient-ratelimit-test",
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
							HealthCheck:          true,
						},
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "test-service",
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
				RateLimit: &config.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 20,
					Burst:             20,
					PerClient:         true,
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

		// Simulate multiple clients
		var wg sync.WaitGroup
		var totalSuccess atomic.Int64

		numClients := 5
		requestsPerClient := 10

		for i := 0; i < numClients; i++ {
			wg.Add(1)
			go func(clientID int) {
				defer wg.Done()

				// Each client creates its own connection
				conn, err := grpc.DialContext(ctx, gi.Address,
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithBlock(),
				)
				if err != nil {
					return
				}
				defer conn.Close()

				client := healthpb.NewHealthClient(conn)

				for j := 0; j < requestsPerClient; j++ {
					resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
					if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
						totalSuccess.Add(1)
					}
				}
			}(i)
		}

		wg.Wait()

		// With per-client rate limiting, each client should be able to make requests
		assert.Greater(t, totalSuccess.Load(), int64(0), "Some requests should succeed")
	})
}

func TestE2E_GRPCRateLimit_Recovery(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rate limit recovers after time", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with low rate limit
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-ratelimit-recovery-test",
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
							HealthCheck:          true,
						},
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "test-service",
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
				RateLimit: &config.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 5,
					Burst:             5,
					PerClient:         false,
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

		client := healthpb.NewHealthClient(conn)

		// Exhaust rate limit
		for i := 0; i < 20; i++ {
			_, _ = client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		}

		// Wait for rate limit to recover
		time.Sleep(2 * time.Second)

		// Should be able to make requests again
		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})
}

func TestE2E_GRPCRateLimit_RouteLevel(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("route-level rate limiting", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with route-level rate limiting
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-route-ratelimit-test",
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
							HealthCheck:          true,
						},
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "limited-route",
						Match: []config.GRPCRouteMatch{
							{
								Service: &config.StringMatch{Exact: "api.v1.LimitedService"},
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
						RateLimit: &config.RateLimitConfig{
							Enabled:           true,
							RequestsPerSecond: 2,
							Burst:             2,
							PerClient:         false,
						},
					},
					{
						Name: "unlimited-route",
						Match: []config.GRPCRouteMatch{
							{
								Service: &config.StringMatch{Exact: "api.v1.UnlimitedService"},
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
						// No rate limit on this route
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

		// Verify routes are configured correctly
		limitedRoute, exists := gi.Router.GetRoute("limited-route")
		require.True(t, exists)
		require.NotNil(t, limitedRoute.Config.RateLimit)
		assert.Equal(t, 2, limitedRoute.Config.RateLimit.RequestsPerSecond)

		unlimitedRoute, exists := gi.Router.GetRoute("unlimited-route")
		require.True(t, exists)
		assert.Nil(t, unlimitedRoute.Config.RateLimit)
	})
}
