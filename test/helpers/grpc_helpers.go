// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	grpcserver "github.com/vyrodovalexey/avapigw/internal/grpc/server"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCTestConfig holds gRPC test configuration from environment variables.
type GRPCTestConfig struct {
	Backend1URL string
	Backend2URL string
	GatewayPort int
}

// GetGRPCTestConfig returns gRPC test configuration from environment variables.
func GetGRPCTestConfig() GRPCTestConfig {
	cfg := GRPCTestConfig{
		Backend1URL: getEnvOrDefault("TEST_GRPC_BACKEND1_URL", "127.0.0.1:8803"),
		Backend2URL: getEnvOrDefault("TEST_GRPC_BACKEND2_URL", "127.0.0.1:8804"),
		GatewayPort: 19000,
	}
	return cfg
}

// IsGRPCBackendAvailable checks if a gRPC backend is available.
func IsGRPCBackendAvailable(address string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Try to check health
	client := healthpb.NewHealthClient(conn)
	resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		// Backend might not have health service, but connection succeeded
		return true
	}

	return resp.GetStatus() == healthpb.HealthCheckResponse_SERVING
}

// SkipIfGRPCBackendUnavailable skips the test if the gRPC backend is not available.
func SkipIfGRPCBackendUnavailable(t interface{ Skip(...interface{}) }, address string) {
	if !IsGRPCBackendAvailable(address) {
		t.Skip("gRPC backend not available at", address, "- skipping test")
	}
}

// GRPCGatewayInstance represents a running gRPC gateway instance for testing.
type GRPCGatewayInstance struct {
	Gateway  *gateway.Gateway
	Config   *config.GatewayConfig
	Router   *grpcrouter.Router
	Proxy    *grpcproxy.Proxy
	Server   *grpcserver.Server
	Address  string
	Listener *gateway.GRPCListener
}

// StartGRPCGateway starts a gRPC gateway instance with the given configuration.
func StartGRPCGateway(ctx context.Context, configPath string) (*GRPCGatewayInstance, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return StartGRPCGatewayWithConfig(ctx, cfg)
}

// StartGRPCGatewayWithConfig starts a gRPC gateway instance with the given configuration struct.
func StartGRPCGatewayWithConfig(ctx context.Context, cfg *config.GatewayConfig) (*GRPCGatewayInstance, error) {
	logger := observability.NopLogger()

	// Find gRPC listener configuration
	var grpcListenerCfg *config.Listener
	for i := range cfg.Spec.Listeners {
		if cfg.Spec.Listeners[i].Protocol == config.ProtocolGRPC {
			grpcListenerCfg = &cfg.Spec.Listeners[i]
			break
		}
	}

	if grpcListenerCfg == nil {
		return nil, fmt.Errorf("no gRPC listener found in configuration")
	}

	// Create gRPC router
	router := grpcrouter.New()
	if err := router.LoadRoutes(cfg.Spec.GRPCRoutes); err != nil {
		return nil, fmt.Errorf("failed to load gRPC routes: %w", err)
	}

	// Create gRPC listener
	listener, err := gateway.NewGRPCListener(*grpcListenerCfg,
		gateway.WithGRPCListenerLogger(logger),
		gateway.WithGRPCRouter(router),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC listener: %w", err)
	}

	// Start listener
	if err := listener.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start gRPC listener: %w", err)
	}

	address := listener.Address()

	return &GRPCGatewayInstance{
		Config:   cfg,
		Router:   router,
		Proxy:    listener.Proxy(),
		Server:   listener.Server(),
		Address:  address,
		Listener: listener,
	}, nil
}

// Stop stops the gRPC gateway instance.
func (gi *GRPCGatewayInstance) Stop(ctx context.Context) error {
	if gi.Listener != nil {
		return gi.Listener.Stop(ctx)
	}
	return nil
}

// WaitForGRPCReady waits for a gRPC server to become ready.
func WaitForGRPCReady(address string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for gRPC server at %s to become ready", address)
		case <-ticker.C:
			conn, err := grpc.DialContext(ctx, address,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err == nil {
				conn.Close()
				return nil
			}
		}
	}
}

// GRPCClient returns a gRPC client connection for testing.
func GRPCClient(ctx context.Context, address string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

// MakeGRPCUnaryCall makes a generic gRPC unary call.
func MakeGRPCUnaryCall(ctx context.Context, conn *grpc.ClientConn, fullMethod string, request, response interface{}) error {
	return conn.Invoke(ctx, fullMethod, request, response)
}

// MakeGRPCUnaryCallWithMetadata makes a gRPC unary call with metadata.
func MakeGRPCUnaryCallWithMetadata(ctx context.Context, conn *grpc.ClientConn, fullMethod string, md metadata.MD, request, response interface{}) error {
	ctx = metadata.NewOutgoingContext(ctx, md)
	return conn.Invoke(ctx, fullMethod, request, response)
}

// CreateGRPCTestConfig creates a test configuration with gRPC support.
func CreateGRPCTestConfig(port int, backend1, backend2 string) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "grpc-test-gateway",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "grpc",
					Port:     port,
					Protocol: config.ProtocolGRPC,
					Bind:     "0.0.0.0",
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
					Name: "test-service",
					Match: []config.GRPCRouteMatch{
						{
							Service: &config.StringMatch{Exact: "api.v1.TestService"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: parseHost(backend1),
								Port: parsePort(backend1),
							},
							Weight: 50,
						},
						{
							Destination: config.Destination{
								Host: parseHost(backend2),
								Port: parsePort(backend2),
							},
							Weight: 50,
						},
					},
					Timeout: config.Duration(30 * time.Second),
				},
			},
		},
	}
}

// CreateGRPCTestConfigSingleBackend creates a test configuration with a single gRPC backend.
func CreateGRPCTestConfigSingleBackend(port int, backend string) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "grpc-test-gateway-single",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "grpc",
					Port:     port,
					Protocol: config.ProtocolGRPC,
					Bind:     "0.0.0.0",
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
					Name: "test-service",
					Match: []config.GRPCRouteMatch{
						{
							Service: &config.StringMatch{Exact: "api.v1.TestService"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: parseHost(backend),
								Port: parsePort(backend),
							},
							Weight: 100,
						},
					},
					Timeout: config.Duration(30 * time.Second),
				},
			},
		},
	}
}

// GetFreeGRPCPort returns a free port for gRPC testing.
func GetFreeGRPCPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// parseHost extracts the host from an address string.
func parseHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// parsePort extracts the port from an address string.
func parsePort(address string) int {
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// GRPCTestBackendInfo contains information about a test backend.
type GRPCTestBackendInfo struct {
	Address string
	Host    string
	Port    int
}

// GetGRPCBackendInfo parses backend address into structured info.
func GetGRPCBackendInfo(address string) GRPCTestBackendInfo {
	return GRPCTestBackendInfo{
		Address: address,
		Host:    parseHost(address),
		Port:    parsePort(address),
	}
}

// GRPCHealthCheck performs a health check on a gRPC server.
func GRPCHealthCheck(ctx context.Context, address string) (healthpb.HealthCheckResponse_ServingStatus, error) {
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return healthpb.HealthCheckResponse_UNKNOWN, err
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return healthpb.HealthCheckResponse_UNKNOWN, err
	}

	return resp.GetStatus(), nil
}

// GRPCEnvConfig returns configuration based on environment variables.
type GRPCEnvConfig struct {
	Backend1URL string
	Backend2URL string
}

// LoadGRPCEnvConfig loads gRPC configuration from environment variables.
func LoadGRPCEnvConfig() GRPCEnvConfig {
	return GRPCEnvConfig{
		Backend1URL: os.Getenv("TEST_GRPC_BACKEND1_URL"),
		Backend2URL: os.Getenv("TEST_GRPC_BACKEND2_URL"),
	}
}
