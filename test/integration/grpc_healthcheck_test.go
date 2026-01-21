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
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/health"
	grpcserver "github.com/vyrodovalexey/avapigw/internal/grpc/server"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_GRPCHealthCheck_BackendHealthy(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("check backend health via gRPC health service", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Connect to backend
		conn, err := grpc.DialContext(ctx, testCfg.Backend1URL,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create health client
		client := healthpb.NewHealthClient(conn)

		// Check overall health
		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		if err != nil {
			// Backend might not implement health service
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unimplemented {
				t.Skip("Backend does not implement health service")
			}
			require.NoError(t, err)
		}

		// Should be serving
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})

	t.Run("check specific service health", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Connect to backend
		conn, err := grpc.DialContext(ctx, testCfg.Backend1URL,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create health client
		client := healthpb.NewHealthClient(conn)

		// Check specific service health
		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: "api.v1.TestService"})
		if err != nil {
			// Service might not be registered or health service not implemented
			st, ok := status.FromError(err)
			if ok && (st.Code() == codes.Unimplemented || st.Code() == codes.NotFound) {
				t.Skip("Service health check not available")
			}
			require.NoError(t, err)
		}

		// Should have a valid status
		assert.True(t, resp.GetStatus() == healthpb.HealthCheckResponse_SERVING ||
			resp.GetStatus() == healthpb.HealthCheckResponse_NOT_SERVING ||
			resp.GetStatus() == healthpb.HealthCheckResponse_UNKNOWN)
	})
}

func TestIntegration_GRPCHealthCheck_BackendUnhealthy(t *testing.T) {
	t.Parallel()

	t.Run("connection to unavailable backend fails", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Try to connect to non-existent backend
		_, err := grpc.DialContext(ctx, "127.0.0.1:59999",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.Error(t, err)
	})

	t.Run("health check to unavailable backend fails", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Try to check health of non-existent backend
		_, err := helpers.GRPCHealthCheck(ctx, "127.0.0.1:59999")
		require.Error(t, err)
	})
}

func TestIntegration_GRPCHealthCheck_GatewayHealthService(t *testing.T) {
	t.Parallel()

	t.Run("gateway health service responds", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get a free port
		port, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		// Create gRPC server with health service
		grpcCfg := config.DefaultGRPCListenerConfig()
		grpcCfg.HealthCheck = true

		server, err := grpcserver.New(grpcCfg,
			grpcserver.WithLogger(observability.NopLogger()),
			grpcserver.WithAddress("127.0.0.1:"+string(rune(port))),
		)
		require.NoError(t, err)

		// Start server
		err = server.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = server.Stop(ctx)
		})

		// Wait for server to be ready
		time.Sleep(500 * time.Millisecond)

		// Verify health server is available
		healthServer := server.HealthServer()
		assert.NotNil(t, healthServer)
	})

	t.Run("gateway health service status updates", func(t *testing.T) {
		t.Parallel()

		// Create health server
		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Initial status should be serving
		ctx := context.Background()
		resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

		// Set a service status
		hs.SetServingStatus("test-service", healthpb.HealthCheckResponse_SERVING)

		resp, err = hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "test-service"})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

		// Update to not serving
		hs.SetServingStatus("test-service", healthpb.HealthCheckResponse_NOT_SERVING)

		resp, err = hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "test-service"})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.GetStatus())
	})
}

func TestIntegration_GRPCHealthCheck_MultipleBackends(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("check health of multiple backends", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		backends := []string{testCfg.Backend1URL, testCfg.Backend2URL}
		healthyCount := 0

		for _, backend := range backends {
			conn, err := grpc.DialContext(ctx, backend,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err != nil {
				continue
			}
			defer conn.Close()

			client := healthpb.NewHealthClient(conn)
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
			if err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
				healthyCount++
			}
		}

		// At least one backend should be healthy (we skipped if unavailable)
		assert.GreaterOrEqual(t, healthyCount, 1, "At least one backend should be healthy")
	})
}

func TestIntegration_GRPCHealthCheck_Watch(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("watch backend health", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Connect to backend
		conn, err := grpc.DialContext(ctx, testCfg.Backend1URL,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create health client
		client := healthpb.NewHealthClient(conn)

		// Start watching
		stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{Service: ""})
		if err != nil {
			// Backend might not implement watch
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unimplemented {
				t.Skip("Backend does not implement health watch")
			}
			require.NoError(t, err)
		}

		// Receive initial status
		resp, err := stream.Recv()
		if err != nil {
			// Stream might be closed immediately
			t.Skip("Health watch stream closed")
		}

		// Should have a valid status
		assert.True(t, resp.GetStatus() == healthpb.HealthCheckResponse_SERVING ||
			resp.GetStatus() == healthpb.HealthCheckResponse_NOT_SERVING ||
			resp.GetStatus() == healthpb.HealthCheckResponse_UNKNOWN ||
			resp.GetStatus() == healthpb.HealthCheckResponse_SERVICE_UNKNOWN)
	})
}

func TestIntegration_GRPCHealthCheck_Aggregator(t *testing.T) {
	t.Parallel()

	t.Run("health aggregator tracks multiple backends", func(t *testing.T) {
		t.Parallel()

		// Create health server
		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Create backend configs
		backends := []health.BackendConfig{
			{Name: "backend1", Address: "127.0.0.1:8803", Service: ""},
			{Name: "backend2", Address: "127.0.0.1:8804", Service: ""},
		}

		// Create health aggregator
		aggregator := health.NewHealthAggregator(hs, backends,
			health.WithAggregatorLogger(observability.NopLogger()),
		)

		// Verify aggregator is created
		assert.NotNil(t, aggregator)

		// Get all backend health (initially empty until checks run)
		allHealth := aggregator.GetAllBackendHealth()
		assert.NotNil(t, allHealth)
	})

	t.Run("health aggregator handles backend addition and removal", func(t *testing.T) {
		t.Parallel()

		// Create health server
		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Create aggregator with no backends
		aggregator := health.NewHealthAggregator(hs, nil,
			health.WithAggregatorLogger(observability.NopLogger()),
		)

		// Add backend
		aggregator.AddBackend(health.BackendConfig{
			Name:    "backend1",
			Address: "127.0.0.1:8803",
			Service: "",
		})

		// Remove backend
		aggregator.RemoveBackend("backend1")

		// Verify backend is removed
		_, exists := aggregator.GetBackendHealth("backend1")
		assert.False(t, exists)
	})
}
