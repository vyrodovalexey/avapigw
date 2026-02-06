//go:build e2e

// Package operator_test contains E2E tests for the apigw-operator.
package operator_test

import (
	"sync"

	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

var (
	sharedGRPCServer     *operatorgrpc.Server
	sharedGRPCServerOnce sync.Once
	sharedGRPCServerErr  error
)

// getSharedGRPCServer returns a shared gRPC server instance for tests.
// This avoids duplicate Prometheus metrics registration.
func getSharedGRPCServer() (*operatorgrpc.Server, error) {
	sharedGRPCServerOnce.Do(func() {
		sharedGRPCServer, sharedGRPCServerErr = operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
			Port: 29999,
		})
	})
	return sharedGRPCServer, sharedGRPCServerErr
}
