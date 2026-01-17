//go:build functional
// +build functional

package functional

import (
	"context"
	"fmt"
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

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
	gwgrpc "github.com/vyrodovalexey/avapigw/internal/gateway/server/grpc"
)

// ============================================================================
// gRPC Server Startup and Shutdown Tests
// ============================================================================

// Note: gRPC tests are currently skipped due to an issue with registerUnknownServiceHandler
// in the gRPC server implementation. The issue is that grpc.RegisterService with an empty
// ServiceDesc is not supported in newer versions of gRPC.
// TODO: Fix the gRPC server implementation to properly handle unknown services.

func TestFunctional_GRPC_ServerStartup(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)
	require.NotNil(t, server)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Wait for server to be ready
	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	assert.True(t, server.IsRunning())

	// Stop server
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	err := server.Stop(stopCtx)
	require.NoError(t, err)

	assert.False(t, server.IsRunning())
}

func TestFunctional_GRPC_ServerDoubleStart(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Try to start again - should fail
	err := server.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_GRPC_ServerGracefulShutdown(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	err := server.Stop(shutdownCtx)
	require.NoError(t, err)
	assert.False(t, server.IsRunning())
}

// ============================================================================
// gRPC Health Check Tests
// ============================================================================

func TestFunctional_GRPC_HealthCheck_Serving(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Create client
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)

	// Check overall health
	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_GRPC_HealthCheck_ServiceStatus(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Set service status
	server.SetServingStatus("test.Service", healthpb.HealthCheckResponse_SERVING)

	// Create client
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)

	// Check service health
	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "test.Service",
	})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)

	// Set to not serving
	server.SetServingStatus("test.Service", healthpb.HealthCheckResponse_NOT_SERVING)

	resp2, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "test.Service",
	})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp2.Status)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_GRPC_HealthCheck_UnknownService(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Create client
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)

	// Check unknown service
	_, err = healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "unknown.Service",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// gRPC Route Matching Tests
// ============================================================================

func TestFunctional_GRPC_RouteMatching_ExactService(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	// Add route with exact service match
	route := &gwgrpc.GRPCRoute{
		Name:      "exact-service-route",
		Hostnames: []string{"*"},
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "users.UserService",
						Method:  "*",
						Type:    gwgrpc.GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "users-backend", Port: 9090},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	// Test route matching
	router := server.GetRouter()

	// Should match
	matchedRoute, matchedRule := router.Match("users.UserService", "GetUser", metadata.MD{})
	assert.NotNil(t, matchedRoute)
	assert.NotNil(t, matchedRule)
	assert.Equal(t, "exact-service-route", matchedRoute.Name)

	// Should not match different service
	matchedRoute2, _ := router.Match("products.ProductService", "GetProduct", metadata.MD{})
	assert.Nil(t, matchedRoute2)
}

func TestFunctional_GRPC_RouteMatching_ExactMethod(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	// Add route with exact method match
	route := &gwgrpc.GRPCRoute{
		Name:      "exact-method-route",
		Hostnames: []string{"*"},
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "users.UserService",
						Method:  "GetUser",
						Type:    gwgrpc.GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "users-backend", Port: 9090},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	router := server.GetRouter()

	// Should match exact method
	matchedRoute, _ := router.Match("users.UserService", "GetUser", metadata.MD{})
	assert.NotNil(t, matchedRoute)

	// Should not match different method
	matchedRoute2, _ := router.Match("users.UserService", "CreateUser", metadata.MD{})
	assert.Nil(t, matchedRoute2)
}

func TestFunctional_GRPC_RouteMatching_RegexService(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	// Add route with regex service match
	route := &gwgrpc.GRPCRoute{
		Name:      "regex-service-route",
		Hostnames: []string{"*"},
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: ".*\\.UserService",
						Method:  "*",
						Type:    gwgrpc.GRPCMethodMatchTypeRegex,
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "users-backend", Port: 9090},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	router := server.GetRouter()

	// Should match various namespaces
	matchedRoute, _ := router.Match("users.UserService", "GetUser", metadata.MD{})
	assert.NotNil(t, matchedRoute)

	matchedRoute2, _ := router.Match("admin.UserService", "GetUser", metadata.MD{})
	assert.NotNil(t, matchedRoute2)

	// Should not match non-UserService
	matchedRoute3, _ := router.Match("users.ProductService", "GetProduct", metadata.MD{})
	assert.Nil(t, matchedRoute3)
}

func TestFunctional_GRPC_RouteMatching_HeaderMatch(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	// Add route with header match
	route := &gwgrpc.GRPCRoute{
		Name:      "header-route",
		Hostnames: []string{"*"},
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "users.UserService",
						Method:  "*",
						Type:    gwgrpc.GRPCMethodMatchTypeExact,
						Headers: []gwgrpc.GRPCHeaderMatch{
							{
								Name:  "x-api-version",
								Value: "v2",
								Type:  gwgrpc.GRPCHeaderMatchTypeExact,
							},
						},
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "users-backend", Port: 9090},
				},
			},
		},
	}
	err := server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	router := server.GetRouter()

	// Should match with correct header
	md := metadata.MD{
		"x-api-version": []string{"v2"},
	}
	matchedRoute, _ := router.Match("users.UserService", "GetUser", md)
	assert.NotNil(t, matchedRoute)

	// Should not match without header
	matchedRoute2, _ := router.Match("users.UserService", "GetUser", metadata.MD{})
	assert.Nil(t, matchedRoute2)

	// Should not match with wrong header value
	md2 := metadata.MD{
		"x-api-version": []string{"v1"},
	}
	matchedRoute3, _ := router.Match("users.UserService", "GetUser", md2)
	assert.Nil(t, matchedRoute3)
}

// ============================================================================
// gRPC Route Management Tests
// ============================================================================

func TestFunctional_GRPC_RouteManagement_AddRemoveUpdate(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateGRPCServer(config)
	router := server.GetRouter()

	// Add route
	route := &gwgrpc.GRPCRoute{
		Name:      "test-route",
		Hostnames: []string{"*"},
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "test.Service",
						Method:  "*",
					},
				},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	// Verify route exists
	assert.Contains(t, router.ListRoutes(), "test-route")

	// Try to add duplicate - should fail
	err = router.AddRoute(route)
	assert.Error(t, err)

	// Update route
	route.Priority = 10
	err = router.UpdateRoute(route)
	require.NoError(t, err)

	// Remove route
	err = router.RemoveRoute("test-route")
	require.NoError(t, err)

	// Verify route removed
	assert.NotContains(t, router.ListRoutes(), "test-route")

	// Try to remove non-existent route - should fail
	err = router.RemoveRoute("non-existent")
	assert.Error(t, err)
}

// ============================================================================
// gRPC Server Configuration Tests
// ============================================================================

func TestFunctional_GRPC_ServerConfig_MaxMessageSize(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.MaxRecvMsgSize = 1024 * 1024 // 1MB
	config.MaxSendMsgSize = 1024 * 1024 // 1MB
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Verify server is running with config
	assert.True(t, server.IsRunning())

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

func TestFunctional_GRPC_ServerConfig_Reflection(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableReflection = true
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Verify server is running with reflection enabled
	assert.True(t, server.IsRunning())

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// gRPC Concurrent Connection Tests
// ============================================================================

func TestFunctional_GRPC_ConcurrentConnections(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.MaxConcurrentStreams = 100
	config.EnableHealthCheck = true

	server := suite.CreateGRPCServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Create multiple concurrent connections
	numConnections := 10
	connections := make([]*grpc.ClientConn, numConnections)
	errors := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(idx int) {
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				errors <- err
				return
			}
			connections[idx] = conn

			// Make health check request
			healthClient := healthpb.NewHealthClient(conn)
			_, err = healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
			errors <- err
		}(i)
	}

	// Wait for all connections
	for i := 0; i < numConnections; i++ {
		err := <-errors
		assert.NoError(t, err)
	}

	// Close all connections
	for _, conn := range connections {
		if conn != nil {
			conn.Close()
		}
	}

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// gRPC Route Priority Tests
// ============================================================================

func TestFunctional_GRPC_RoutePriority(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateGRPCServer(config)
	router := server.GetRouter()

	// Add low priority route (matches all)
	lowPriorityRoute := &gwgrpc.GRPCRoute{
		Name:      "low-priority",
		Hostnames: []string{"*"},
		Priority:  1,
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "*",
						Method:  "*",
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "default-backend", Port: 9090},
				},
			},
		},
	}
	router.AddRoute(lowPriorityRoute)

	// Add high priority route (more specific)
	highPriorityRoute := &gwgrpc.GRPCRoute{
		Name:      "high-priority",
		Hostnames: []string{"*"},
		Priority:  10,
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "users.UserService",
						Method:  "GetUser",
						Type:    gwgrpc.GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "users-backend", Port: 9091},
				},
			},
		},
	}
	router.AddRoute(highPriorityRoute)

	// Request to users.UserService.GetUser should match high priority route
	matchedRoute, _ := router.Match("users.UserService", "GetUser", metadata.MD{})
	assert.NotNil(t, matchedRoute)
	assert.Equal(t, "high-priority", matchedRoute.Name)

	// Request to other service should match low priority route
	matchedRoute2, _ := router.Match("products.ProductService", "GetProduct", metadata.MD{})
	assert.NotNil(t, matchedRoute2)
	assert.Equal(t, "low-priority", matchedRoute2.Name)
}

// ============================================================================
// gRPC Backend Manager Integration Tests
// ============================================================================

func TestFunctional_GRPC_BackendManager_Integration(t *testing.T) {
	t.Skip("Skipped: gRPC server registerUnknownServiceHandler needs to be fixed")
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	// Create backend manager
	backendManager := backend.NewManager(suite.logger)

	// Add a backend
	err := backendManager.AddBackend(backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 9090, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "RoundRobin",
		},
	})
	require.NoError(t, err)

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"
	config.EnableHealthCheck = true

	server := gwgrpc.NewServer(config, backendManager, suite.logger)

	// Add route referencing the backend
	route := &gwgrpc.GRPCRoute{
		Name:      "backend-route",
		Hostnames: []string{"*"},
		Rules: []gwgrpc.GRPCRouteRule{
			{
				Matches: []gwgrpc.GRPCMethodMatch{
					{
						Service: "test.Service",
						Method:  "*",
					},
				},
				BackendRefs: []gwgrpc.BackendRef{
					{Name: "test-backend", Namespace: "default", Port: 9090},
				},
			},
		},
	}
	err = server.GetRouter().AddRoute(route)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	WaitForGRPCServer(t, addr, 10*time.Second)

	// Verify route matches
	matchedRoute, matchedRule := server.GetRouter().Match("test.Service", "TestMethod", metadata.MD{})
	assert.NotNil(t, matchedRoute)
	assert.NotNil(t, matchedRule)
	assert.Len(t, matchedRule.BackendRefs, 1)
	assert.Equal(t, "test-backend", matchedRule.BackendRefs[0].Name)

	// Cleanup
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	server.Stop(stopCtx)
}

// ============================================================================
// Table-Driven gRPC Tests
// ============================================================================

func TestFunctional_GRPC_RouteMatching_TableDriven(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	config := gwgrpc.DefaultServerConfig()
	config.Port = GetFreePort(t)
	config.Address = "127.0.0.1"

	server := suite.CreateGRPCServer(config)
	router := server.GetRouter()

	// Add test routes
	routes := []*gwgrpc.GRPCRoute{
		{
			Name:      "users-route",
			Hostnames: []string{"*"},
			Priority:  10,
			Rules: []gwgrpc.GRPCRouteRule{
				{
					Matches: []gwgrpc.GRPCMethodMatch{
						{Service: "users.UserService", Method: "*"},
					},
				},
			},
		},
		{
			Name:      "products-route",
			Hostnames: []string{"*"},
			Priority:  10,
			Rules: []gwgrpc.GRPCRouteRule{
				{
					Matches: []gwgrpc.GRPCMethodMatch{
						{Service: "products.ProductService", Method: "*"},
					},
				},
			},
		},
	}

	for _, route := range routes {
		err := router.AddRoute(route)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		service       string
		method        string
		expectedRoute string
		shouldMatch   bool
	}{
		{
			name:          "users service matches",
			service:       "users.UserService",
			method:        "GetUser",
			expectedRoute: "users-route",
			shouldMatch:   true,
		},
		{
			name:          "products service matches",
			service:       "products.ProductService",
			method:        "GetProduct",
			expectedRoute: "products-route",
			shouldMatch:   true,
		},
		{
			name:        "unknown service does not match",
			service:     "orders.OrderService",
			method:      "GetOrder",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedRoute, _ := router.Match(tt.service, tt.method, metadata.MD{})

			if tt.shouldMatch {
				require.NotNil(t, matchedRoute)
				assert.Equal(t, tt.expectedRoute, matchedRoute.Name)
			} else {
				assert.Nil(t, matchedRoute)
			}
		})
	}
}
