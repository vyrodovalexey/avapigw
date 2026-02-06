//go:build integration

// Package operator_test contains integration tests for the apigw-operator.
package operator_test

import (
	"sync"

	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

var (
	sharedGRPCServer     *operatorgrpc.Server
	sharedGRPCServerOnce sync.Once
)

// getSharedGRPCServer returns a shared gRPC server instance for integration tests.
// This avoids duplicate Prometheus metrics registration across tests.
func getSharedGRPCServer() *operatorgrpc.Server {
	sharedGRPCServerOnce.Do(func() {
		var err error
		sharedGRPCServer, err = operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
			Port: 19460,
		})
		if err != nil {
			panic("failed to create shared gRPC server: " + err.Error())
		}
	})
	return sharedGRPCServer
}
