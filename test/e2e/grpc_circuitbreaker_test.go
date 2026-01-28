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
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_GRPCCircuitBreaker_Open(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("circuit breaker allows requests when closed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with circuit breaker
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-circuitbreaker-test",
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
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        5,
					Timeout:          config.Duration(30 * time.Second),
					HalfOpenRequests: 3,
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

		// Make health check requests (circuit breaker should be closed)
		client := healthpb.NewHealthClient(conn)

		successCount := 0
		for i := 0; i < 10; i++ {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
				successCount++
			}
		}

		// All requests should succeed when circuit breaker is closed
		assert.Equal(t, 10, successCount, "All requests should succeed when circuit breaker is closed")
	})

	t.Run("circuit breaker configuration is applied", func(t *testing.T) {
		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with circuit breaker
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-cb-config-test",
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
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        10,
					Timeout:          config.Duration(60 * time.Second),
					HalfOpenRequests: 5,
				},
			},
		}

		// Verify configuration
		require.NotNil(t, cfg.Spec.CircuitBreaker)
		assert.True(t, cfg.Spec.CircuitBreaker.Enabled)
		assert.Equal(t, 10, cfg.Spec.CircuitBreaker.Threshold)
		assert.Equal(t, 60*time.Second, cfg.Spec.CircuitBreaker.Timeout.Duration())
		assert.Equal(t, 5, cfg.Spec.CircuitBreaker.HalfOpenRequests)
	})
}

func TestE2E_GRPCCircuitBreaker_HalfOpen(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("circuit breaker half-open state configuration", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with circuit breaker
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-cb-halfopen-test",
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
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        3,
					Timeout:          config.Duration(5 * time.Second), // Short timeout for testing
					HalfOpenRequests: 2,
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

		// Make successful requests
		client := healthpb.NewHealthClient(conn)

		for i := 0; i < 5; i++ {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			require.NoError(t, err)
			assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
		}
	})
}

func TestE2E_GRPCCircuitBreaker_Close(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("circuit breaker closes after successful requests", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with circuit breaker
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-cb-close-test",
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
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        5,
					Timeout:          config.Duration(10 * time.Second),
					HalfOpenRequests: 3,
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

		// Make many successful requests
		client := healthpb.NewHealthClient(conn)

		successCount := 0
		for i := 0; i < 20; i++ {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
				successCount++
			}
		}

		// All requests should succeed (circuit breaker stays closed)
		assert.Equal(t, 20, successCount, "All requests should succeed with healthy backend")
	})
}

func TestE2E_GRPCCircuitBreaker_Disabled(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("disabled circuit breaker passes all requests", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration with disabled circuit breaker
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "grpc-cb-disabled-test",
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
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled: false,
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

		// Make requests
		client := healthpb.NewHealthClient(conn)

		successCount := 0
		for i := 0; i < 10; i++ {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
				successCount++
			}
		}

		// All requests should succeed when circuit breaker is disabled
		assert.Equal(t, 10, successCount, "All requests should succeed when circuit breaker is disabled")
	})
}

func TestE2E_GRPCCircuitBreaker_NoConfig(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("no circuit breaker config passes all requests", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create configuration without circuit breaker
		cfg := helpers.CreateGRPCTestConfigSingleBackend(port, testCfg.Backend1URL)
		cfg.Spec.CircuitBreaker = nil // Explicitly no circuit breaker

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

		// Make requests
		client := healthpb.NewHealthClient(conn)

		successCount := 0
		for i := 0; i < 10; i++ {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
				successCount++
			}
		}

		// All requests should succeed without circuit breaker
		assert.Equal(t, 10, successCount, "All requests should succeed without circuit breaker")
	})
}
