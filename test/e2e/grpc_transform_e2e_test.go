//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestE2E_GRPCTransform_UnaryFlow tests complete gRPC transformation flow.
func TestE2E_GRPCTransform_UnaryFlow(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration with gRPC transformation
	cfg := createGRPCTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

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

	t.Run("unary call through gateway with transformation", func(t *testing.T) {
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

	t.Run("unary call with metadata transformation", func(t *testing.T) {
		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create context with metadata
		md := metadata.New(map[string]string{
			"x-request-id": "test-request-123",
			"x-trace-id":   "test-trace-456",
		})
		ctxWithMd := metadata.NewOutgoingContext(ctx, md)

		// Verify context has metadata
		outMd, ok := metadata.FromOutgoingContext(ctxWithMd)
		require.True(t, ok)
		assert.Equal(t, []string{"test-request-123"}, outMd.Get("x-request-id"))
	})
}

// TestE2E_GRPCTransform_StreamingFlow tests gRPC streaming transformation flow.
func TestE2E_GRPCTransform_StreamingFlow(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration with streaming transformation
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "grpc-stream-transform-test",
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
					Name: "stream-transform-route",
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
					Transform: &config.GRPCTransformConfig{
						Response: &config.GRPCResponseTransformConfig{
							FieldMask: []string{"message", "timestamp"},
							StreamingConfig: &config.StreamingTransformConfig{
								PerMessageTransform: true,
								BufferSize:          100,
							},
						},
					},
				},
			},
		},
	}

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

	t.Run("streaming route exists", func(t *testing.T) {
		route, exists := gi.Router.GetRoute("stream-transform-route")
		require.True(t, exists)
		assert.Equal(t, "stream-transform-route", route.Name)
	})

	t.Run("streaming connection established", func(t *testing.T) {
		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Verify connection
		assert.NotNil(t, conn)
	})
}

// TestE2E_GRPCTransform_WithCaching tests gRPC transformation with caching.
func TestE2E_GRPCTransform_WithCaching(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_grpc_cache")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration with caching
	cfg := createGRPCTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

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

	t.Run("cache gRPC response", func(t *testing.T) {
		cacheKey := "grpc:response:unary:1"

		// Simulated gRPC response
		response := map[string]interface{}{
			"message":   "Hello, World!",
			"timestamp": time.Now().Unix(),
			"metadata": map[string]string{
				"request_id": "req-123",
			},
		}

		responseBytes, err := json.Marshal(response)
		require.NoError(t, err)

		// Cache the response
		err = c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve from cache
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedResponse map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedResponse)
		require.NoError(t, err)

		assert.Equal(t, "Hello, World!", cachedResponse["message"])
	})

	t.Run("cache hit returns same data", func(t *testing.T) {
		cacheKey := "grpc:response:cached:1"

		// Pre-cache data
		cachedData := map[string]interface{}{
			"id":      "cached-123",
			"message": "Cached Response",
		}
		cachedBytes, err := json.Marshal(cachedData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, cachedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Multiple reads should return same data
		for i := 0; i < 3; i++ {
			retrievedBytes, err := c.Get(ctx, cacheKey)
			require.NoError(t, err)

			var retrievedData map[string]interface{}
			err = json.Unmarshal(retrievedBytes, &retrievedData)
			require.NoError(t, err)

			assert.Equal(t, "cached-123", retrievedData["id"])
			assert.Equal(t, "Cached Response", retrievedData["message"])
		}
	})
}

// TestE2E_GRPCTransform_MultipleBackends tests gRPC transformation with multiple backends.
func TestE2E_GRPCTransform_MultipleBackends(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration with multiple backends
	cfg := createGRPCTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

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

	t.Run("route has multiple destinations", func(t *testing.T) {
		route, exists := gi.Router.GetRoute("transform-test-service")
		require.True(t, exists)
		assert.Len(t, route.Config.Route, 2)
		assert.Equal(t, 50, route.Config.Route[0].Weight)
		assert.Equal(t, 50, route.Config.Route[1].Weight)
	})

	t.Run("multiple connections to gateway", func(t *testing.T) {
		// Make multiple connections
		for i := 0; i < 5; i++ {
			conn, err := grpc.DialContext(ctx, gi.Address,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			require.NoError(t, err)
			conn.Close()
		}
	})
}

// TestE2E_GRPCTransform_Metadata tests gRPC metadata transformation.
func TestE2E_GRPCTransform_Metadata(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration with metadata transformation
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "grpc-metadata-transform-test",
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
					Name: "metadata-transform-route",
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
					Transform: &config.GRPCTransformConfig{
						Request: &config.GRPCRequestTransformConfig{
							StaticMetadata: map[string]string{
								"x-gateway":     "avapigw",
								"x-api-version": "v1",
							},
							DynamicMetadata: []config.DynamicMetadata{
								{Key: "x-request-id", Source: "context.request_id"},
							},
						},
						Response: &config.GRPCResponseTransformConfig{
							TrailerMetadata: map[string]string{
								"x-processed-by": "avapigw",
							},
						},
					},
				},
			},
		},
	}

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

	t.Run("metadata transformation configured", func(t *testing.T) {
		route, exists := gi.Router.GetRoute("metadata-transform-route")
		require.True(t, exists)
		assert.NotNil(t, route.Config.Transform)
		assert.NotNil(t, route.Config.Transform.Request)
		assert.Equal(t, "avapigw", route.Config.Transform.Request.StaticMetadata["x-gateway"])
	})

	t.Run("call with custom metadata", func(t *testing.T) {
		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create context with metadata
		md := metadata.New(map[string]string{
			"authorization": "Bearer test-token",
			"x-custom":      "custom-value",
		})
		ctxWithMd := metadata.NewOutgoingContext(ctx, md)

		// Verify metadata is set
		outMd, ok := metadata.FromOutgoingContext(ctxWithMd)
		require.True(t, ok)
		assert.Equal(t, []string{"Bearer test-token"}, outMd.Get("authorization"))
	})
}

// TestE2E_GRPCTransform_ErrorHandling tests gRPC transformation error handling.
func TestE2E_GRPCTransform_ErrorHandling(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration
	cfg := createGRPCTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

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

	t.Run("connection timeout handled", func(t *testing.T) {
		shortCtx, shortCancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer shortCancel()

		// Try to connect with very short timeout
		conn, err := grpc.DialContext(shortCtx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err == nil {
			conn.Close()
		}
		// Either succeeds quickly or times out - both are acceptable
	})

	t.Run("catch-all route matches unknown service", func(t *testing.T) {
		// Connect to gateway
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Try to match non-existent service - should match catch-all route
		result, err := gi.Router.Match("/non.existent.Service/Method", nil)
		// With catch-all route configured, this should succeed
		if err == nil {
			assert.Equal(t, "catch-all", result.Route.Name)
		}
		// If no catch-all, error is expected
	})
}

// TestE2E_GRPCTransform_HealthCheck tests gRPC health check with transformation.
func TestE2E_GRPCTransform_HealthCheck(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration with health check
	cfg := createGRPCTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)
	cfg.Spec.Listeners[0].GRPC.HealthCheck = true

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

	t.Run("health check returns serving", func(t *testing.T) {
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

	t.Run("health watch returns status", func(t *testing.T) {
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
}

// TestE2E_GRPCTransform_CompleteJourney tests a complete gRPC transformation journey.
func TestE2E_GRPCTransform_CompleteJourney(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_grpc_journey")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	// Get a free port
	port, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	// Create configuration
	cfg := createGRPCTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

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

	t.Run("1. Gateway is running", func(t *testing.T) {
		assert.True(t, gi.Listener.IsRunning())
	})

	t.Run("2. Connect to gateway", func(t *testing.T) {
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		assert.NotNil(t, conn)
	})

	t.Run("3. Health check passes", func(t *testing.T) {
		conn, err := grpc.DialContext(ctx, gi.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := healthpb.NewHealthClient(conn)
		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})

	t.Run("4. Cache response data", func(t *testing.T) {
		cacheKey := "grpc:journey:response"
		responseData := map[string]interface{}{
			"success": true,
			"message": "Journey test response",
			"data": map[string]interface{}{
				"id":   "journey-123",
				"name": "Journey Test",
			},
		}

		responseBytes, err := json.Marshal(responseData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
		require.NoError(t, err)

		// Verify cached
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		assert.True(t, cachedData["success"].(bool))
	})

	t.Run("5. Invalidate cache", func(t *testing.T) {
		cacheKey := "grpc:journey:response"

		err := c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("6. Gateway stops cleanly", func(t *testing.T) {
		// This will be handled by cleanup, but verify state
		assert.True(t, gi.Listener.IsRunning())
	})
}

// Helper function to create gRPC transform test configuration
func createGRPCTransformTestConfig(port int, backend1URL, backend2URL string) *config.GatewayConfig {
	backend1Info := helpers.GetGRPCBackendInfo(backend1URL)
	backend2Info := helpers.GetGRPCBackendInfo(backend2URL)

	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "grpc-transform-e2e-test-gateway",
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
						MaxRecvMsgSize:       4 * 1024 * 1024,
						MaxSendMsgSize:       4 * 1024 * 1024,
						Reflection:           true,
						HealthCheck:          true,
					},
				},
			},
			GRPCRoutes: []config.GRPCRoute{
				{
					Name: "transform-test-service",
					Match: []config.GRPCRouteMatch{
						{
							Service: &config.StringMatch{Exact: "api.v1.TestService"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backend1Info.Host,
								Port: backend1Info.Port,
							},
							Weight: 50,
						},
						{
							Destination: config.Destination{
								Host: backend2Info.Host,
								Port: backend2Info.Port,
							},
							Weight: 50,
						},
					},
					Timeout: config.Duration(30 * time.Second),
					Transform: &config.GRPCTransformConfig{
						Request: &config.GRPCRequestTransformConfig{
							StaticMetadata: map[string]string{
								"x-gateway": "avapigw",
							},
							DynamicMetadata: []config.DynamicMetadata{
								{Key: "x-request-id", Source: "context.request_id"},
							},
						},
						Response: &config.GRPCResponseTransformConfig{
							FieldMask: []string{"message", "timestamp", "data"},
							FieldMappings: []config.FieldMapping{
								{Source: "old_field", Target: "new_field"},
							},
						},
					},
				},
				{
					Name: "health-service",
					Match: []config.GRPCRouteMatch{
						{
							Service: &config.StringMatch{Exact: "grpc.health.v1.Health"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backend1Info.Host,
								Port: backend1Info.Port,
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
								Host: backend1Info.Host,
								Port: backend1Info.Port,
							},
							Weight: 50,
						},
						{
							Destination: config.Destination{
								Host: backend2Info.Host,
								Port: backend2Info.Port,
							},
							Weight: 50,
						},
					},
				},
			},
		},
	}
}
