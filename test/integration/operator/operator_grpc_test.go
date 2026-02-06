//go:build integration

// Package operator_test contains integration tests for the apigw-operator.
package operator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// TestIntegration_Operator_GRPC_ServerLifecycle tests gRPC server lifecycle.
func TestIntegration_Operator_GRPC_ServerLifecycle(t *testing.T) {
	// Note: We use the shared server to avoid duplicate Prometheus metrics registration.
	// The server creation tests are limited because we can only create one server per test run.

	t.Run("shared server is available", func(t *testing.T) {
		server := getSharedGRPCServer()
		require.NotNil(t, server)
	})

	t.Run("fails with nil config", func(t *testing.T) {
		_, err := operatorgrpc.NewServer(nil)
		assert.Error(t, err)
	})
}

// TestIntegration_Operator_GRPC_ConfigOperations tests configuration operations.
func TestIntegration_Operator_GRPC_ConfigOperations(t *testing.T) {
	server := getSharedGRPCServer()

	ctx := context.Background()

	t.Run("applies API route", func(t *testing.T) {
		config := map[string]interface{}{
			"match": []map[string]interface{}{
				{"uri": map[string]string{"prefix": "/api/v1"}},
			},
			"route": []map[string]interface{}{
				{"destination": map[string]interface{}{"host": "backend", "port": 8080}},
			},
		}
		configJSON, _ := json.Marshal(config)

		err := server.ApplyAPIRoute(ctx, "test-route", "default", configJSON)
		assert.NoError(t, err)
	})

	t.Run("applies gRPC route", func(t *testing.T) {
		config := map[string]interface{}{
			"match": []map[string]interface{}{
				{"service": map[string]string{"prefix": "api.v1"}},
			},
			"route": []map[string]interface{}{
				{"destination": map[string]interface{}{"host": "grpc-backend", "port": 9000}},
			},
		}
		configJSON, _ := json.Marshal(config)

		err := server.ApplyGRPCRoute(ctx, "test-grpc-route", "default", configJSON)
		assert.NoError(t, err)
	})

	t.Run("applies backend", func(t *testing.T) {
		config := map[string]interface{}{
			"hosts": []map[string]interface{}{
				{"address": "10.0.1.10", "port": 8080, "weight": 1},
			},
		}
		configJSON, _ := json.Marshal(config)

		err := server.ApplyBackend(ctx, "test-backend", "default", configJSON)
		assert.NoError(t, err)
	})

	t.Run("applies gRPC backend", func(t *testing.T) {
		config := map[string]interface{}{
			"hosts": []map[string]interface{}{
				{"address": "grpc-service.default.svc", "port": 9000, "weight": 1},
			},
		}
		configJSON, _ := json.Marshal(config)

		err := server.ApplyGRPCBackend(ctx, "test-grpc-backend", "default", configJSON)
		assert.NoError(t, err)
	})

	t.Run("deletes API route", func(t *testing.T) {
		err := server.DeleteAPIRoute(ctx, "test-route", "default")
		assert.NoError(t, err)
	})

	t.Run("deletes gRPC route", func(t *testing.T) {
		err := server.DeleteGRPCRoute(ctx, "test-grpc-route", "default")
		assert.NoError(t, err)
	})

	t.Run("deletes backend", func(t *testing.T) {
		err := server.DeleteBackend(ctx, "test-backend", "default")
		assert.NoError(t, err)
	})

	t.Run("deletes gRPC backend", func(t *testing.T) {
		err := server.DeleteGRPCBackend(ctx, "test-grpc-backend", "default")
		assert.NoError(t, err)
	})
}

// TestIntegration_Operator_GRPC_ConfigRetrieval tests configuration retrieval.
func TestIntegration_Operator_GRPC_ConfigRetrieval(t *testing.T) {
	server := getSharedGRPCServer()

	ctx := context.Background()

	// Apply some configurations
	routeConfig := map[string]interface{}{
		"match": []map[string]interface{}{
			{"uri": map[string]string{"prefix": "/api"}},
		},
	}
	routeJSON, _ := json.Marshal(routeConfig)
	_ = server.ApplyAPIRoute(ctx, "route1", "ns1", routeJSON)
	_ = server.ApplyAPIRoute(ctx, "route2", "ns2", routeJSON)

	backendConfig := map[string]interface{}{
		"hosts": []map[string]interface{}{
			{"address": "10.0.1.10", "port": 8080},
		},
	}
	backendJSON, _ := json.Marshal(backendConfig)
	_ = server.ApplyBackend(ctx, "backend1", "ns1", backendJSON)

	t.Run("retrieves all configs", func(t *testing.T) {
		configsJSON, err := server.GetAllConfigs()
		require.NoError(t, err)
		require.NotEmpty(t, configsJSON)

		var configs map[string]interface{}
		err = json.Unmarshal(configsJSON, &configs)
		require.NoError(t, err)

		assert.Contains(t, configs, "apiRoutes")
		assert.Contains(t, configs, "grpcRoutes")
		assert.Contains(t, configs, "backends")
		assert.Contains(t, configs, "grpcBackends")
	})
}

// TestIntegration_Operator_GRPC_GatewayRegistration tests gateway registration.
func TestIntegration_Operator_GRPC_GatewayRegistration(t *testing.T) {
	server := getSharedGRPCServer()

	// Use unique gateway names to avoid conflicts with other tests
	t.Run("registers gateway", func(t *testing.T) {
		initialCount := server.GetGatewayCount()
		server.RegisterGateway("int-gateway-1", "avapigw-system")
		assert.Equal(t, initialCount+1, server.GetGatewayCount())
		// Cleanup
		defer server.UnregisterGateway("int-gateway-1", "avapigw-system")
	})

	t.Run("registers multiple gateways", func(t *testing.T) {
		initialCount := server.GetGatewayCount()
		server.RegisterGateway("int-gateway-2", "avapigw-system")
		server.RegisterGateway("int-gateway-3", "avapigw-system")
		assert.Equal(t, initialCount+2, server.GetGatewayCount())
		// Cleanup
		defer server.UnregisterGateway("int-gateway-2", "avapigw-system")
		defer server.UnregisterGateway("int-gateway-3", "avapigw-system")
	})

	t.Run("updates gateway heartbeat", func(t *testing.T) {
		server.RegisterGateway("int-gateway-heartbeat", "avapigw-system")
		server.UpdateGatewayHeartbeat("int-gateway-heartbeat", "avapigw-system")
		// Should not error
		// Cleanup
		defer server.UnregisterGateway("int-gateway-heartbeat", "avapigw-system")
	})

	t.Run("unregisters gateway", func(t *testing.T) {
		server.RegisterGateway("int-gateway-unreg", "avapigw-system")
		initialCount := server.GetGatewayCount()
		server.UnregisterGateway("int-gateway-unreg", "avapigw-system")
		assert.Equal(t, initialCount-1, server.GetGatewayCount())
	})
}

// TestIntegration_Operator_GRPC_ConfigPersistence tests configuration persistence.
func TestIntegration_Operator_GRPC_ConfigPersistence(t *testing.T) {
	server := getSharedGRPCServer()

	ctx := context.Background()

	t.Run("config persists after multiple operations", func(t *testing.T) {
		// Apply config
		config := map[string]interface{}{"key": "value1"}
		configJSON, _ := json.Marshal(config)
		err := server.ApplyAPIRoute(ctx, "persistent-route", "default", configJSON)
		require.NoError(t, err)

		// Update config
		config["key"] = "value2"
		configJSON, _ = json.Marshal(config)
		err = server.ApplyAPIRoute(ctx, "persistent-route", "default", configJSON)
		require.NoError(t, err)

		// Verify config exists
		allConfigs, err := server.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, "default/persistent-route")
	})

	t.Run("config removed after delete", func(t *testing.T) {
		// Delete config
		err := server.DeleteAPIRoute(ctx, "persistent-route", "default")
		require.NoError(t, err)

		// Verify config is removed
		allConfigs, err := server.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.NotContains(t, apiRoutes, "default/persistent-route")
	})
}

// TestIntegration_Operator_GRPC_ConcurrentOperations tests concurrent operations.
func TestIntegration_Operator_GRPC_ConcurrentOperations(t *testing.T) {
	server := getSharedGRPCServer()

	ctx := context.Background()

	t.Run("handles concurrent applies", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(idx int) {
				config := map[string]interface{}{"index": idx}
				configJSON, _ := json.Marshal(config)
				_ = server.ApplyAPIRoute(ctx, "concurrent-route", "default", configJSON)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for concurrent operations")
			}
		}
	})

	t.Run("handles concurrent gateway registrations", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(idx int) {
				server.RegisterGateway("concurrent-gateway", "default")
				server.UpdateGatewayHeartbeat("concurrent-gateway", "default")
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for concurrent operations")
			}
		}
	})
}

// TestIntegration_Operator_GRPC_NamespaceIsolation tests namespace isolation.
func TestIntegration_Operator_GRPC_NamespaceIsolation(t *testing.T) {
	server := getSharedGRPCServer()

	ctx := context.Background()

	t.Run("configs are isolated by namespace", func(t *testing.T) {
		config1 := map[string]interface{}{"namespace": "ns1"}
		config1JSON, _ := json.Marshal(config1)
		err := server.ApplyAPIRoute(ctx, "same-name", "ns1", config1JSON)
		require.NoError(t, err)

		config2 := map[string]interface{}{"namespace": "ns2"}
		config2JSON, _ := json.Marshal(config2)
		err = server.ApplyAPIRoute(ctx, "same-name", "ns2", config2JSON)
		require.NoError(t, err)

		// Both should exist
		allConfigs, err := server.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, "ns1/same-name")
		assert.Contains(t, apiRoutes, "ns2/same-name")
	})

	t.Run("delete only affects specific namespace", func(t *testing.T) {
		err := server.DeleteAPIRoute(ctx, "same-name", "ns1")
		require.NoError(t, err)

		allConfigs, err := server.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.NotContains(t, apiRoutes, "ns1/same-name")
		assert.Contains(t, apiRoutes, "ns2/same-name")
	})
}
