// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

// Package operator provides the client for connecting to the avapigw operator.
//
// The operator client enables the gateway to receive configuration updates
// from the Kubernetes operator via gRPC streaming. This allows for dynamic
// configuration management without requiring file-based configuration.
//
// # Architecture
//
// The operator client consists of several components:
//
//   - Client: The main gRPC client that connects to the operator, handles
//     registration, streaming, and heartbeats.
//   - ConfigHandler: Processes configuration updates and applies them to
//     the gateway.
//   - Metrics: Prometheus metrics for monitoring the operator connection.
//
// # Usage
//
// To use the operator client, create a new client with configuration:
//
//	cfg := &operator.Config{
//	    Enabled:          true,
//	    Address:          "operator.avapigw-system.svc:9090",
//	    GatewayName:      "my-gateway",
//	    GatewayNamespace: "default",
//	}
//
//	client, err := operator.NewClient(cfg,
//	    operator.WithLogger(logger),
//	    operator.WithMetricsRegistry(registry),
//	)
//	if err != nil {
//	    return err
//	}
//
//	// Set up configuration handler
//	handler := operator.NewConfigHandler(applier,
//	    operator.WithHandlerLogger(logger),
//	)
//	client.SetConfigUpdateHandler(handler.HandleUpdate)
//	client.SetSnapshotHandler(handler.HandleSnapshot)
//
//	// Start the client
//	if err := client.Start(ctx); err != nil {
//	    return err
//	}
//
//	// Stop on shutdown
//	defer client.Stop()
//
// # Connection Management
//
// The client automatically handles:
//   - Initial connection with configurable timeout
//   - Gateway registration with the operator
//   - Configuration streaming with automatic reconnection
//   - Heartbeat messages for keep-alive
//   - Exponential backoff for reconnection attempts
//
// # TLS Support
//
// The client supports both insecure and TLS connections:
//
//	cfg := &operator.Config{
//	    // ...
//	    TLS: &operator.TLSConfig{
//	        Enabled:  true,
//	        CertFile: "/path/to/client.crt",
//	        KeyFile:  "/path/to/client.key",
//	        CAFile:   "/path/to/ca.crt",
//	    },
//	}
//
// # Metrics
//
// The following Prometheus metrics are exposed:
//
//   - avapigw_gateway_operator_connected: Connection status (1=connected, 0=disconnected)
//   - avapigw_gateway_operator_reconnects_total: Total reconnection attempts
//   - avapigw_gateway_operator_config_updates_total: Configuration updates received
//   - avapigw_gateway_operator_config_apply_duration_seconds: Time to apply configuration
//   - avapigw_gateway_operator_heartbeat_latency_seconds: Heartbeat latency
package operator
