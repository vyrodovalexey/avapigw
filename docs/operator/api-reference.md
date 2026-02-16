# AVAPIGW Operator API Reference

This document provides a comprehensive reference for the gRPC API used by the AVAPIGW Operator to communicate with gateway instances.

## Table of Contents

- [Overview](#overview)
- [Service Definition](#service-definition)
- [Configuration Service](#configuration-service)
- [Message Types](#message-types)
- [Error Handling](#error-handling)
- [Authentication](#authentication)
- [Examples](#examples)

## Overview

The AVAPIGW Operator communicates with gateway instances using a gRPC API over mutual TLS (mTLS). This API allows the operator to push configuration updates to gateways in real-time, enabling hot configuration updates without service restarts.

### API Characteristics

- **Protocol**: gRPC over HTTP/2
- **Security**: Mutual TLS (mTLS) authentication
- **Serialization**: Protocol Buffers (protobuf)
- **Communication Pattern**: Bidirectional streaming and unary calls
- **API Version**: v1alpha1

### Service Endpoints

| Service | Port | Purpose |
|---------|------|---------|
| ConfigurationService | 9444 | Configuration management |
| HealthService | 9444 | Health checking |

## Service Definition

The complete service definition is available in `proto/operator/v1alpha1/config.proto`:

```protobuf
syntax = "proto3";

package avapigw.operator.v1alpha1;

option go_package = "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1;operatorv1alpha1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";

// ConfigurationService provides configuration management for API gateways.
// The operator pushes configuration updates to connected gateways via streaming.
service ConfigurationService {
  // RegisterGateway registers a gateway instance with the operator.
  // Returns the initial configuration snapshot.
  rpc RegisterGateway(RegisterGatewayRequest) returns (RegisterGatewayResponse);

  // StreamConfiguration establishes a server-side streaming connection
  // for receiving configuration updates from the operator.
  rpc StreamConfiguration(StreamConfigurationRequest) returns (stream ConfigurationUpdate);

  // GetConfiguration returns the current configuration snapshot.
  rpc GetConfiguration(GetConfigurationRequest) returns (ConfigurationSnapshot);

  // Heartbeat sends a keep-alive signal to the operator.
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // AcknowledgeConfiguration acknowledges receipt and application of a configuration update.
  rpc AcknowledgeConfiguration(AcknowledgeConfigurationRequest) returns (AcknowledgeConfigurationResponse);
}
```

## Configuration Service

The ConfigurationService uses a snapshot-based approach where the operator maintains the complete configuration state and pushes updates to gateways via streaming or on-demand requests.

### Core Operations

#### RegisterGateway

Registers a gateway instance with the operator and returns the initial configuration snapshot.

**Request:**
```protobuf
message RegisterGatewayRequest {
  // Gateway information.
  GatewayInfo gateway = 1;
  
  // Capabilities supported by this gateway.
  GatewayCapabilities capabilities = 2;
}
```

**Response:**
```protobuf
message RegisterGatewayResponse {
  // Whether registration was successful.
  bool success = 1;
  
  // Error message if registration failed.
  string error_message = 2;
  
  // Session ID for this gateway connection.
  string session_id = 3;
  
  // Initial configuration snapshot.
  ConfigurationSnapshot initial_config = 4;
  
  // Recommended heartbeat interval.
  google.protobuf.Duration heartbeat_interval = 5;
}
```

**Features:**
- **Session Management** - Each gateway gets a unique session ID for tracking
- **Capability Negotiation** - Gateway reports supported features
- **Initial Configuration** - Complete configuration snapshot provided on registration
- **Heartbeat Scheduling** - Operator recommends heartbeat interval (default: 30s)

#### GetConfiguration

Returns the current configuration snapshot for immediate consumption.

**Request:**
```protobuf
message GetConfigurationRequest {
  // Session ID from registration.
  string session_id = 1;
  
  // Gateway information.
  GatewayInfo gateway = 2;
  
  // Namespaces to include (empty = all namespaces).
  repeated string namespaces = 3;
  
  // Resource types to include (empty = all types).
  repeated ResourceType resource_types = 4;
}
```

**Response:**
```protobuf
message ConfigurationSnapshot {
  // Snapshot version.
  string version = 1;
  
  // Timestamp when the snapshot was created.
  google.protobuf.Timestamp timestamp = 2;
  
  // API routes.
  repeated ConfigurationResource api_routes = 3;
  
  // gRPC routes.
  repeated ConfigurationResource grpc_routes = 4;
  
  // HTTP backends.
  repeated ConfigurationResource backends = 5;
  
  // gRPC backends.
  repeated ConfigurationResource grpc_backends = 6;
  
  // Total number of resources.
  int32 total_resources = 7;
  
  // Checksum of the configuration (for validation).
  string checksum = 8;
}
```

**Features:**
- **Namespace Filtering** - Request configuration for specific namespaces
- **Resource Type Filtering** - Request only specific resource types
- **Version Tracking** - Monotonically increasing version numbers
- **Integrity Checking** - SHA-256 checksum for validation
- **Complete State** - Full configuration snapshot in single response

#### StreamConfiguration

Establishes a server-side streaming connection for receiving real-time configuration updates.

**Request:**
```protobuf
message StreamConfigurationRequest {
  // Session ID from registration.
  string session_id = 1;
  
  // Gateway information.
  GatewayInfo gateway = 2;
  
  // Last known configuration version (for resumption).
  string last_config_version = 3;
  
  // Namespaces to watch (empty = all namespaces).
  repeated string namespaces = 4;
  
  // Resource types to watch (empty = all types).
  repeated ResourceType resource_types = 5;
}
```

**Response Stream:**
```protobuf
message ConfigurationUpdate {
  // Update type.
  UpdateType type = 1;
  
  // Configuration version (monotonically increasing).
  string version = 2;
  
  // Timestamp of the update.
  google.protobuf.Timestamp timestamp = 3;
  
  // Resource that was updated.
  ConfigurationResource resource = 4;
  
  // Full snapshot (for FULL_SYNC type).
  ConfigurationSnapshot snapshot = 5;
  
  // Sequence number for ordering.
  int64 sequence = 6;
  
  // Whether this is the last update in a batch.
  bool is_last_in_batch = 7;
}
```

**Update Types:**
```protobuf
enum UpdateType {
  UPDATE_TYPE_UNSPECIFIED = 0;
  UPDATE_TYPE_ADDED = 1;        // A resource was added
  UPDATE_TYPE_MODIFIED = 2;     // A resource was modified
  UPDATE_TYPE_DELETED = 3;      // A resource was deleted
  UPDATE_TYPE_FULL_SYNC = 4;    // Full configuration sync
  UPDATE_TYPE_HEARTBEAT = 5;    // Heartbeat/keep-alive message
}
```

**Features:**
- **Real-time Updates** - Immediate notification of configuration changes
- **Resumable Streams** - Can resume from last known version
- **Selective Watching** - Filter by namespace and resource type
- **Ordered Delivery** - Sequence numbers ensure proper ordering
- **Batch Support** - Multiple updates can be batched together
- **Full Sync Support** - Complete configuration refresh when needed

#### Heartbeat

Sends a keep-alive signal to maintain gateway registration and report status.

**Request:**
```protobuf
message HeartbeatRequest {
  // Session ID from registration.
  string session_id = 1;
  
  // Gateway information.
  GatewayInfo gateway = 2;
  
  // Current gateway status.
  GatewayStatus status = 3;
  
  // Last applied configuration version.
  string last_applied_version = 4;
}
```

**Response:**
```protobuf
message HeartbeatResponse {
  // Whether the heartbeat was acknowledged.
  bool acknowledged = 1;
  
  // Server timestamp.
  google.protobuf.Timestamp server_time = 2;
  
  // Whether the gateway should reconnect (e.g., for config refresh).
  bool should_reconnect = 3;
  
  // Message from the operator.
  string message = 4;
}
```

**Features:**
- **Session Maintenance** - Keeps gateway registration active
- **Status Reporting** - Gateway reports current health and metrics
- **Reconnection Signaling** - Operator can request gateway reconnection
- **Version Tracking** - Track last applied configuration version

#### AcknowledgeConfiguration

Acknowledges receipt and application of a configuration update.

**Request:**
```protobuf
message AcknowledgeConfigurationRequest {
  // Session ID from registration.
  string session_id = 1;
  
  // Gateway information.
  GatewayInfo gateway = 2;
  
  // Configuration version being acknowledged.
  string config_version = 3;
  
  // Whether the configuration was applied successfully.
  bool success = 4;
  
  // Error message if application failed.
  string error_message = 5;
  
  // Time taken to apply the configuration.
  google.protobuf.Duration apply_duration = 6;
}
```

**Response:**
```protobuf
message AcknowledgeConfigurationResponse {
  // Whether the acknowledgment was received.
  bool received = 1;
  
  // Server timestamp.
  google.protobuf.Timestamp server_time = 2;
}
```

**Features:**
- **Delivery Confirmation** - Confirms configuration was received and applied
- **Error Reporting** - Reports configuration application failures
- **Performance Tracking** - Measures configuration application time
- **Reliability** - Ensures operator knows configuration state

#### DeleteAPIRoute

Removes an HTTP route configuration from the gateway.

**Request:**
```protobuf
message DeleteAPIRouteRequest {
  string name = 1;                    // Route name
  string namespace = 2;               // Kubernetes namespace
  int64 generation = 3;               // Resource generation
}
```

**Response:**
```protobuf
message DeleteAPIRouteResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp deleted_at = 3; // Deletion timestamp
  string gateway_id = 4;              // Gateway instance ID
}
```

#### ApplyGRPCRoute

Applies a gRPC route configuration to the gateway.

**Request:**
```protobuf
message ApplyGRPCRouteRequest {
  string name = 1;                    // Route name
  string namespace = 2;               // Kubernetes namespace
  bytes config = 3;                   // JSON-encoded gRPC route configuration
  int64 generation = 4;               // Resource generation
  map<string, string> labels = 5;     // Route labels
  map<string, string> annotations = 6; // Route annotations
}
```

**Response:**
```protobuf
message ApplyGRPCRouteResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp applied_at = 3; // Application timestamp
  string gateway_id = 4;              // Gateway instance ID
  repeated string warnings = 5;       // Configuration warnings
}
```

#### DeleteGRPCRoute

Removes a gRPC route configuration from the gateway.

**Request:**
```protobuf
message DeleteGRPCRouteRequest {
  string name = 1;                    // Route name
  string namespace = 2;               // Kubernetes namespace
  int64 generation = 3;               // Resource generation
}
```

**Response:**
```protobuf
message DeleteGRPCRouteResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp deleted_at = 3; // Deletion timestamp
  string gateway_id = 4;              // Gateway instance ID
}
```

### Backend Operations

#### ApplyBackend

Applies an HTTP backend configuration to the gateway.

**Request:**
```protobuf
message ApplyBackendRequest {
  string name = 1;                    // Backend name
  string namespace = 2;               // Kubernetes namespace
  bytes config = 3;                   // JSON-encoded backend configuration
  int64 generation = 4;               // Resource generation
  map<string, string> labels = 5;     // Backend labels
  map<string, string> annotations = 6; // Backend annotations
}
```

**Response:**
```protobuf
message ApplyBackendResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp applied_at = 3; // Application timestamp
  string gateway_id = 4;              // Gateway instance ID
  repeated string warnings = 5;       // Configuration warnings
  BackendHealthStatus health_status = 6; // Initial health status
}
```

#### DeleteBackend

Removes an HTTP backend configuration from the gateway.

**Request:**
```protobuf
message DeleteBackendRequest {
  string name = 1;                    // Backend name
  string namespace = 2;               // Kubernetes namespace
  int64 generation = 3;               // Resource generation
}
```

**Response:**
```protobuf
message DeleteBackendResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp deleted_at = 3; // Deletion timestamp
  string gateway_id = 4;              // Gateway instance ID
}
```

#### ApplyGRPCBackend

Applies a gRPC backend configuration to the gateway.

**Request:**
```protobuf
message ApplyGRPCBackendRequest {
  string name = 1;                    // Backend name
  string namespace = 2;               // Kubernetes namespace
  bytes config = 3;                   // JSON-encoded gRPC backend configuration
  int64 generation = 4;               // Resource generation
  map<string, string> labels = 5;     // Backend labels
  map<string, string> annotations = 6; // Backend annotations
}
```

**Response:**
```protobuf
message ApplyGRPCBackendResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp applied_at = 3; // Application timestamp
  string gateway_id = 4;              // Gateway instance ID
  repeated string warnings = 5;       // Configuration warnings
  BackendHealthStatus health_status = 6; // Initial health status
}
```

#### DeleteGRPCBackend

Removes a gRPC backend configuration from the gateway.

**Request:**
```protobuf
message DeleteGRPCBackendRequest {
  string name = 1;                    // Backend name
  string namespace = 2;               // Kubernetes namespace
  int64 generation = 3;               // Resource generation
}
```

**Response:**
```protobuf
message DeleteGRPCBackendResponse {
  bool success = 1;                   // Operation success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp deleted_at = 3; // Deletion timestamp
  string gateway_id = 4;              // Gateway instance ID
}
```

### Status and Health Operations

#### GetGatewayStatus

Retrieves the current status of the gateway instance.

**Request:**
```protobuf
message GetGatewayStatusRequest {
  bool include_routes = 1;            // Include route status
  bool include_backends = 2;          // Include backend status
  bool include_metrics = 3;           // Include performance metrics
}
```

**Response:**
```protobuf
message GetGatewayStatusResponse {
  string gateway_id = 1;              // Gateway instance ID
  string version = 2;                 // Gateway version
  google.protobuf.Timestamp started_at = 3; // Gateway start time
  GatewayHealth health = 4;           // Overall health status
  repeated RouteStatus routes = 5;    // Route status (if requested)
  repeated BackendStatus backends = 6; // Backend status (if requested)
  GatewayMetrics metrics = 7;         // Performance metrics (if requested)
  map<string, string> labels = 8;     // Gateway labels
}
```

#### StreamConfigUpdates

Establishes a bidirectional stream for real-time configuration updates.

**Request:**
```protobuf
message StreamConfigUpdatesRequest {
  string gateway_id = 1;              // Gateway instance ID
  repeated string namespaces = 2;     // Namespaces to watch (empty = all)
  bool include_status_updates = 3;    // Include status updates in stream
}
```

**Response (Stream):**
```protobuf
message ConfigUpdate {
  string update_id = 1;               // Unique update ID
  google.protobuf.Timestamp timestamp = 2; // Update timestamp
  ConfigUpdateType type = 3;          // Update type
  oneof update {
    ApplyAPIRouteRequest apply_api_route = 4;
    DeleteAPIRouteRequest delete_api_route = 5;
    ApplyGRPCRouteRequest apply_grpc_route = 6;
    DeleteGRPCRouteRequest delete_grpc_route = 7;
    ApplyBackendRequest apply_backend = 8;
    DeleteBackendRequest delete_backend = 9;
    ApplyGRPCBackendRequest apply_grpc_backend = 10;
    DeleteGRPCBackendRequest delete_grpc_backend = 11;
    StatusUpdate status_update = 12;
  }
}
```

### Gateway Registration

#### RegisterGateway

Registers a gateway instance with the operator.

**Request:**
```protobuf
message RegisterGatewayRequest {
  string gateway_id = 1;              // Unique gateway instance ID
  string version = 2;                 // Gateway version
  repeated string capabilities = 3;   // Supported capabilities
  map<string, string> labels = 4;     // Gateway labels
  string namespace = 5;               // Gateway namespace
  GatewayEndpoint endpoint = 6;       // Gateway endpoint information
}
```

**Response:**
```protobuf
message RegisterGatewayResponse {
  bool success = 1;                   // Registration success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp registered_at = 3; // Registration timestamp
  google.protobuf.Duration heartbeat_interval = 4; // Required heartbeat interval
  repeated ConfigUpdate initial_config = 5; // Initial configuration
}
```

#### UnregisterGateway

Unregisters a gateway instance from the operator.

**Request:**
```protobuf
message UnregisterGatewayRequest {
  string gateway_id = 1;              // Gateway instance ID
  string reason = 2;                  // Unregistration reason
}
```

**Response:**
```protobuf
message UnregisterGatewayResponse {
  bool success = 1;                   // Unregistration success
  string message = 2;                 // Human-readable message
  google.protobuf.Timestamp unregistered_at = 3; // Unregistration timestamp
}
```

#### Heartbeat

Sends a heartbeat to maintain gateway registration.

**Request:**
```protobuf
message HeartbeatRequest {
  string gateway_id = 1;              // Gateway instance ID
  GatewayHealth health = 2;           // Current health status
  GatewayMetrics metrics = 3;         // Current metrics (optional)
}
```

**Response:**
```protobuf
message HeartbeatResponse {
  bool success = 1;                   // Heartbeat acknowledgment
  google.protobuf.Timestamp timestamp = 2; // Server timestamp
  google.protobuf.Duration next_heartbeat = 3; // Next heartbeat interval
  repeated ConfigUpdate pending_updates = 4; // Pending configuration updates
}
```

## Message Types

### Common Types

#### ConfigUpdateType

```protobuf
enum ConfigUpdateType {
  CONFIG_UPDATE_TYPE_UNSPECIFIED = 0;
  CONFIG_UPDATE_TYPE_APPLY_API_ROUTE = 1;
  CONFIG_UPDATE_TYPE_DELETE_API_ROUTE = 2;
  CONFIG_UPDATE_TYPE_APPLY_GRPC_ROUTE = 3;
  CONFIG_UPDATE_TYPE_DELETE_GRPC_ROUTE = 4;
  CONFIG_UPDATE_TYPE_APPLY_BACKEND = 5;
  CONFIG_UPDATE_TYPE_DELETE_BACKEND = 6;
  CONFIG_UPDATE_TYPE_APPLY_GRPC_BACKEND = 7;
  CONFIG_UPDATE_TYPE_DELETE_GRPC_BACKEND = 8;
  CONFIG_UPDATE_TYPE_STATUS_UPDATE = 9;
}
```

#### GatewayHealth

```protobuf
message GatewayHealth {
  HealthStatus status = 1;            // Overall health status
  repeated HealthCheck checks = 2;    // Individual health checks
  google.protobuf.Timestamp last_check = 3; // Last health check time
}

enum HealthStatus {
  HEALTH_STATUS_UNSPECIFIED = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_UNHEALTHY = 2;
  HEALTH_STATUS_DEGRADED = 3;
  HEALTH_STATUS_UNKNOWN = 4;
}

message HealthCheck {
  string name = 1;                    // Health check name
  HealthStatus status = 2;            // Check status
  string message = 3;                 // Status message
  google.protobuf.Timestamp timestamp = 4; // Check timestamp
}
```

#### GatewayMetrics

```protobuf
message GatewayMetrics {
  uint64 requests_total = 1;          // Total requests processed
  uint64 requests_per_second = 2;     // Current RPS
  double average_latency_ms = 3;      // Average latency in milliseconds
  uint64 active_connections = 4;      // Active connections
  uint64 memory_usage_bytes = 5;      // Memory usage in bytes
  double cpu_usage_percent = 6;       // CPU usage percentage
  repeated RouteMetrics route_metrics = 7; // Per-route metrics
  repeated BackendMetrics backend_metrics = 8; // Per-backend metrics
}
```

#### RouteStatus

```protobuf
message RouteStatus {
  string name = 1;                    // Route name
  string namespace = 2;               // Route namespace
  RouteType type = 3;                 // Route type (HTTP/gRPC)
  RouteState state = 4;               // Current state
  google.protobuf.Timestamp last_updated = 5; // Last update time
  repeated string warnings = 6;       // Configuration warnings
  RouteMetrics metrics = 7;           // Route metrics
}

enum RouteType {
  ROUTE_TYPE_UNSPECIFIED = 0;
  ROUTE_TYPE_HTTP = 1;
  ROUTE_TYPE_GRPC = 2;
}

enum RouteState {
  ROUTE_STATE_UNSPECIFIED = 0;
  ROUTE_STATE_ACTIVE = 1;
  ROUTE_STATE_INACTIVE = 2;
  ROUTE_STATE_ERROR = 3;
}
```

#### BackendStatus

```protobuf
message BackendStatus {
  string name = 1;                    // Backend name
  string namespace = 2;               // Backend namespace
  BackendType type = 3;               // Backend type (HTTP/gRPC)
  BackendState state = 4;             // Current state
  BackendHealthStatus health_status = 5; // Health status
  google.protobuf.Timestamp last_updated = 6; // Last update time
  repeated string warnings = 7;       // Configuration warnings
  BackendMetrics metrics = 8;         // Backend metrics
}

enum BackendType {
  BACKEND_TYPE_UNSPECIFIED = 0;
  BACKEND_TYPE_HTTP = 1;
  BACKEND_TYPE_GRPC = 2;
}

enum BackendState {
  BACKEND_STATE_UNSPECIFIED = 0;
  BACKEND_STATE_ACTIVE = 1;
  BACKEND_STATE_INACTIVE = 2;
  BACKEND_STATE_ERROR = 3;
}

message BackendHealthStatus {
  HealthStatus overall_status = 1;    // Overall backend health
  repeated HostHealth host_health = 2; // Per-host health status
  google.protobuf.Timestamp last_check = 3; // Last health check
}

message HostHealth {
  string address = 1;                 // Host address
  int32 port = 2;                     // Host port
  HealthStatus status = 3;            // Host health status
  string message = 4;                 // Status message
  google.protobuf.Timestamp last_check = 5; // Last check time
  double response_time_ms = 6;        // Response time in milliseconds
}
```

#### GatewayEndpoint

```protobuf
message GatewayEndpoint {
  string address = 1;                 // Gateway address
  int32 http_port = 2;                // HTTP port
  int32 grpc_port = 3;                // gRPC port
  int32 metrics_port = 4;             // Metrics port
  bool tls_enabled = 5;               // TLS enabled
  repeated string protocols = 6;      // Supported protocols
}
```

#### StatusUpdate

```protobuf
message StatusUpdate {
  string resource_type = 1;           // Resource type (route/backend)
  string name = 2;                    // Resource name
  string namespace = 3;               // Resource namespace
  google.protobuf.Struct status = 4;  // Status data
  google.protobuf.Timestamp timestamp = 5; // Update timestamp
}
```

## Error Handling

### Error Codes

The API uses standard gRPC status codes:

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Success |
| 1 | CANCELLED | Operation cancelled |
| 2 | UNKNOWN | Unknown error |
| 3 | INVALID_ARGUMENT | Invalid request parameters |
| 4 | DEADLINE_EXCEEDED | Request timeout |
| 5 | NOT_FOUND | Resource not found |
| 6 | ALREADY_EXISTS | Resource already exists |
| 7 | PERMISSION_DENIED | Insufficient permissions |
| 8 | RESOURCE_EXHAUSTED | Resource limits exceeded |
| 9 | FAILED_PRECONDITION | Precondition failed |
| 10 | ABORTED | Operation aborted |
| 11 | OUT_OF_RANGE | Value out of range |
| 12 | UNIMPLEMENTED | Method not implemented |
| 13 | INTERNAL | Internal server error |
| 14 | UNAVAILABLE | Service unavailable |
| 15 | DATA_LOSS | Data loss or corruption |
| 16 | UNAUTHENTICATED | Authentication required |

### Error Response Format

```protobuf
message ErrorDetail {
  string code = 1;                    // Error code
  string message = 2;                 // Error message
  map<string, string> metadata = 3;   // Additional error metadata
  repeated string stack_trace = 4;    // Stack trace (debug mode)
}
```

### Common Error Scenarios

#### Configuration Validation Errors

```json
{
  "code": 3,
  "message": "INVALID_ARGUMENT",
  "details": [
    {
      "code": "VALIDATION_FAILED",
      "message": "Route match condition is invalid",
      "metadata": {
        "field": "spec.match[0].uri.regex",
        "value": "[invalid-regex",
        "reason": "Invalid regular expression syntax"
      }
    }
  ]
}
```

#### Resource Conflict Errors

```json
{
  "code": 6,
  "message": "ALREADY_EXISTS",
  "details": [
    {
      "code": "DUPLICATE_ROUTE",
      "message": "Route with same match conditions already exists",
      "metadata": {
        "existing_route": "api-v1",
        "existing_namespace": "production",
        "conflict_field": "spec.match[0].uri.prefix"
      }
    }
  ]
}
```

#### Backend Health Errors

```json
{
  "code": 9,
  "message": "FAILED_PRECONDITION",
  "details": [
    {
      "code": "BACKEND_UNHEALTHY",
      "message": "Backend has no healthy hosts",
      "metadata": {
        "backend_name": "api-backend",
        "total_hosts": "3",
        "healthy_hosts": "0"
      }
    }
  ]
}
```

## Authentication

### Mutual TLS (mTLS)

All API communication uses mutual TLS authentication:

1. **Server Certificate**: Operator presents server certificate
2. **Client Certificate**: Gateway presents client certificate
3. **Certificate Validation**: Both sides validate certificates
4. **Secure Channel**: Encrypted communication channel

### Certificate Management

Certificates can be managed through:

- **Self-signed**: Automatically generated certificates
- **Vault PKI**: HashiCorp Vault PKI integration
- **External CA**: Custom certificate authority

### Connection Security

```go
// Example client configuration
config := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
    ServerName:   "avapigw-operator.avapigw-system.svc",
    MinVersion:   tls.VersionTLS12,
}

conn, err := grpc.Dial(
    "avapigw-operator.avapigw-system.svc:9444",
    grpc.WithTransportCredentials(credentials.NewTLS(config)),
)
```

## Examples

### Basic Route Application

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    
    pb "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Connect to operator
    conn, err := grpc.Dial(
        "avapigw-operator.avapigw-system.svc:9444",
        grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewConfigurationServiceClient(conn)
    
    // Prepare route configuration
    routeConfig := map[string]interface{}{
        "match": []map[string]interface{}{
            {
                "uri": map[string]string{
                    "prefix": "/api/v1",
                },
                "methods": []string{"GET", "POST"},
            },
        },
        "route": []map[string]interface{}{
            {
                "destination": map[string]interface{}{
                    "host": "api-backend",
                    "port": 8080,
                },
                "weight": 100,
            },
        },
        "timeout": "30s",
    }
    
    configBytes, _ := json.Marshal(routeConfig)
    
    // Apply route
    resp, err := client.ApplyAPIRoute(context.Background(), &pb.ApplyAPIRouteRequest{
        Name:       "api-v1",
        Namespace:  "production",
        Config:     configBytes,
        Generation: 1,
        Labels: map[string]string{
            "app":     "my-app",
            "version": "v1",
        },
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Route applied: %s at %s", resp.Message, resp.AppliedAt.AsTime())
}
```

### Streaming Configuration Updates

```go
func streamUpdates(client pb.ConfigurationServiceClient) {
    stream, err := client.StreamConfigUpdates(context.Background(), &pb.StreamConfigUpdatesRequest{
        GatewayId:            "gateway-1",
        Namespaces:           []string{"production", "staging"},
        IncludeStatusUpdates: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    for {
        update, err := stream.Recv()
        if err != nil {
            log.Printf("Stream error: %v", err)
            break
        }
        
        log.Printf("Received update: %s at %s", 
            update.UpdateId, 
            update.Timestamp.AsTime())
        
        switch update.Type {
        case pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_APPLY_API_ROUTE:
            applyRoute := update.GetApplyApiRoute()
            log.Printf("Apply route: %s/%s", applyRoute.Namespace, applyRoute.Name)
            
        case pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_DELETE_API_ROUTE:
            deleteRoute := update.GetDeleteApiRoute()
            log.Printf("Delete route: %s/%s", deleteRoute.Namespace, deleteRoute.Name)
            
        case pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_STATUS_UPDATE:
            statusUpdate := update.GetStatusUpdate()
            log.Printf("Status update: %s %s/%s", 
                statusUpdate.ResourceType,
                statusUpdate.Namespace, 
                statusUpdate.Name)
        }
    }
}
```

### Gateway Registration

```go
func registerGateway(client pb.ConfigurationServiceClient) {
    resp, err := client.RegisterGateway(context.Background(), &pb.RegisterGatewayRequest{
        GatewayId: "gateway-1",
        Version:   "v1.0.0",
        Capabilities: []string{
            "http-routing",
            "grpc-routing", 
            "tls-termination",
            "rate-limiting",
        },
        Labels: map[string]string{
            "environment": "production",
            "region":      "us-west-2",
        },
        Namespace: "avapigw-system",
        Endpoint: &pb.GatewayEndpoint{
            Address:     "gateway-1.avapigw-system.svc",
            HttpPort:    8080,
            GrpcPort:    9000,
            MetricsPort: 9090,
            TlsEnabled:  true,
            Protocols:   []string{"HTTP/1.1", "HTTP/2", "gRPC"},
        },
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Gateway registered at %s", resp.RegisteredAt.AsTime())
    log.Printf("Heartbeat interval: %s", resp.HeartbeatInterval.AsDuration())
    
    // Apply initial configuration
    for _, config := range resp.InitialConfig {
        log.Printf("Initial config: %s", config.UpdateId)
    }
}
```

### Health Status Monitoring

```go
func monitorHealth(client pb.ConfigurationServiceClient) {
    resp, err := client.GetGatewayStatus(context.Background(), &pb.GetGatewayStatusRequest{
        IncludeRoutes:   true,
        IncludeBackends: true,
        IncludeMetrics:  true,
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Gateway %s (version %s)", resp.GatewayId, resp.Version)
    log.Printf("Health: %s", resp.Health.Status)
    log.Printf("Started: %s", resp.StartedAt.AsTime())
    
    // Route status
    for _, route := range resp.Routes {
        log.Printf("Route %s/%s: %s", route.Namespace, route.Name, route.State)
    }
    
    // Backend status
    for _, backend := range resp.Backends {
        log.Printf("Backend %s/%s: %s (health: %s)", 
            backend.Namespace, 
            backend.Name, 
            backend.State,
            backend.HealthStatus.OverallStatus)
    }
    
    // Metrics
    if resp.Metrics != nil {
        log.Printf("Metrics - RPS: %d, Latency: %.2fms, Connections: %d",
            resp.Metrics.RequestsPerSecond,
            resp.Metrics.AverageLatencyMs,
            resp.Metrics.ActiveConnections)
    }
}
```

## Authentication and Authorization Types

### AuthenticationConfig

The `AuthenticationConfig` type provides route-level authentication configuration.

```protobuf
message AuthenticationConfig {
  bool enabled = 1;                     // Enable authentication
  JWTAuthConfig jwt = 2;                // JWT authentication
  APIKeyAuthConfig api_key = 3;         // API key authentication
  MTLSAuthConfig mtls = 4;              // mTLS authentication
  OIDCAuthConfig oidc = 5;              // OIDC authentication
  bool allow_anonymous = 6;             // Allow anonymous access
  repeated string skip_paths = 7;       // Paths to skip authentication
}
```

#### JWTAuthConfig

```protobuf
message JWTAuthConfig {
  bool enabled = 1;                     // Enable JWT authentication
  string issuer = 2;                    // Expected token issuer
  repeated string audience = 3;         // Expected token audience
  string jwks_url = 4;                  // JWKS URL for key validation
  string secret = 5;                    // Secret for HMAC algorithms
  string public_key = 6;                // Public key for RSA/ECDSA
  string algorithm = 7;                 // Expected signing algorithm
  ClaimMappingConfig claim_mapping = 8; // JWT claim mapping
}
```

#### APIKeyAuthConfig

```protobuf
message APIKeyAuthConfig {
  bool enabled = 1;                     // Enable API key authentication
  string header = 2;                    // Header name for API key
  string query = 3;                     // Query parameter name for API key
  string hash_algorithm = 4;            // Hash algorithm for stored keys
  string vault_path = 5;                // Vault path for API keys
}
```

#### MTLSAuthConfig

```protobuf
message MTLSAuthConfig {
  bool enabled = 1;                     // Enable mTLS authentication
  string ca_file = 2;                   // CA certificate file path
  string extract_identity = 3;          // How to extract identity (cn, san, ou)
  repeated string allowed_cns = 4;      // Allowed common names
  repeated string allowed_ous = 5;      // Allowed organizational units
}
```

#### OIDCAuthConfig

```protobuf
message OIDCAuthConfig {
  bool enabled = 1;                     // Enable OIDC authentication
  repeated OIDCProviderConfig providers = 2; // OIDC providers
}

message OIDCProviderConfig {
  string name = 1;                      // Provider name
  string issuer_url = 2;                // OIDC issuer URL
  string client_id = 3;                 // OIDC client ID
  string client_secret = 4;             // OIDC client secret
  SecretKeySelector client_secret_ref = 5; // Secret reference
  repeated string scopes = 6;           // Requested scopes
}
```

### AuthorizationConfig

The `AuthorizationConfig` type provides route-level authorization configuration.

```protobuf
message AuthorizationConfig {
  bool enabled = 1;                     // Enable authorization
  string default_policy = 2;            // Default policy (allow/deny)
  RBACConfig rbac = 3;                  // RBAC configuration
  ABACConfig abac = 4;                  // ABAC configuration
  ExternalAuthzConfig external = 5;     // External authorization
  repeated string skip_paths = 6;       // Paths to skip authorization
  AuthzCacheConfig cache = 7;           // Authorization caching
}
```

#### RBACConfig

```protobuf
message RBACConfig {
  bool enabled = 1;                     // Enable RBAC
  repeated RBACPolicyConfig policies = 2; // RBAC policies
  map<string, StringList> role_hierarchy = 3; // Role inheritance
}

message RBACPolicyConfig {
  string name = 1;                      // Policy name
  repeated string roles = 2;            // Matching roles
  repeated string resources = 3;        // Applicable resources
  repeated string actions = 4;          // Allowed actions
  string effect = 5;                    // Policy effect (allow/deny)
  int32 priority = 6;                   // Policy priority
}
```

#### ABACConfig

```protobuf
message ABACConfig {
  bool enabled = 1;                     // Enable ABAC
  repeated ABACPolicyConfig policies = 2; // ABAC policies
}

message ABACPolicyConfig {
  string name = 1;                      // Policy name
  string expression = 2;                // CEL expression
  repeated string resources = 3;        // Applicable resources
  repeated string actions = 4;          // Applicable actions
  string effect = 5;                    // Policy effect (allow/deny)
  int32 priority = 6;                   // Policy priority
}
```

#### ExternalAuthzConfig

```protobuf
message ExternalAuthzConfig {
  bool enabled = 1;                     // Enable external authorization
  OPAAuthzConfig opa = 2;               // OPA configuration
  google.protobuf.Duration timeout = 3; // Request timeout
  bool fail_open = 4;                   // Allow on failure
}

message OPAAuthzConfig {
  string url = 1;                       // OPA server URL
  string policy = 2;                    // OPA policy path
  map<string, string> headers = 3;      // Additional headers
}
```

### Backend Transform and Cache Types

#### BackendTransformConfig

```protobuf
message BackendTransformConfig {
  BackendRequestTransform request = 1;   // Request transformation
  BackendResponseTransform response = 2; // Response transformation
}

message BackendRequestTransform {
  string template = 1;                   // Go template for request body
  HeaderOperation headers = 2;           // Header manipulation
}

message BackendResponseTransform {
  repeated string allow_fields = 1;      // Fields to include
  repeated string deny_fields = 2;       // Fields to exclude
  map<string, string> field_mappings = 3; // Field name mappings
  HeaderOperation headers = 4;           // Header manipulation
}
```

#### BackendCacheConfig

```protobuf
message BackendCacheConfig {
  bool enabled = 1;                      // Enable caching
  google.protobuf.Duration ttl = 2;      // Cache TTL
  repeated string key_components = 3;    // Cache key components
  google.protobuf.Duration stale_while_revalidate = 4; // Stale serving time
  string type = 5;                       // Cache type (memory, redis)
}
```

#### BackendEncodingConfig

```protobuf
message BackendEncodingConfig {
  BackendEncodingSettings request = 1;   // Request encoding
  BackendEncodingSettings response = 2;  // Response encoding
}

message BackendEncodingSettings {
  string content_type = 1;               // Content type
  string compression = 2;                // Compression algorithm
}
```

### gRPC Backend Transform Types

#### GRPCBackendTransformConfig

```protobuf
message GRPCBackendTransformConfig {
  GRPCFieldMaskConfig field_mask = 1;    // Field mask configuration
  GRPCMetadataManipulation metadata = 2; // Metadata manipulation
}

message GRPCFieldMaskConfig {
  repeated string paths = 1;             // Field paths to include
}

message GRPCMetadataManipulation {
  map<string, string> static = 1;       // Static metadata values
  map<string, string> dynamic = 2;      // Dynamic metadata templates
}
```

## Configuration Examples

### JWT Authentication Example

```go
func applyJWTAuth(client pb.ConfigurationServiceClient) {
    authConfig := &AuthenticationConfig{
        Enabled: true,
        Jwt: &JWTAuthConfig{
            Enabled:   true,
            Issuer:    "https://auth.example.com",
            Audience:  []string{"api.example.com"},
            JwksUrl:   "https://auth.example.com/.well-known/jwks.json",
            Algorithm: "RS256",
            ClaimMapping: &ClaimMappingConfig{
                Roles:       "roles",
                Permissions: "permissions",
                Email:       "email",
                Name:        "name",
            },
        },
        AllowAnonymous: false,
        SkipPaths:      []string{"/health", "/metrics"},
    }
    
    routeConfig := map[string]interface{}{
        "match": []map[string]interface{}{
            {
                "uri": map[string]string{"prefix": "/api/v1"},
                "headers": []map[string]interface{}{
                    {
                        "name":    "Authorization",
                        "present": true,
                    },
                },
            },
        },
        "route": []map[string]interface{}{
            {
                "destination": map[string]interface{}{
                    "host": "api-backend",
                    "port": 8080,
                },
            },
        },
        "authentication": authConfig,
    }
    
    configBytes, _ := json.Marshal(routeConfig)
    
    resp, err := client.ApplyAPIRoute(context.Background(), &pb.ApplyAPIRouteRequest{
        Name:       "secure-api",
        Namespace:  "production",
        Config:     configBytes,
        Generation: 1,
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Secure route applied: %s", resp.Message)
}
```

### RBAC Authorization Example

```go
func applyRBACAuthz(client pb.ConfigurationServiceClient) {
    authzConfig := &AuthorizationConfig{
        Enabled:       true,
        DefaultPolicy: "deny",
        Rbac: &RBACConfig{
            Enabled: true,
            Policies: []*RBACPolicyConfig{
                {
                    Name:      "admin-policy",
                    Roles:     []string{"admin", "super-admin"},
                    Resources: []string{"*"},
                    Actions:   []string{"*"},
                    Effect:    "allow",
                    Priority:  100,
                },
                {
                    Name:      "user-read-policy",
                    Roles:     []string{"user"},
                    Resources: []string{"/api/v1/users/*"},
                    Actions:   []string{"GET"},
                    Effect:    "allow",
                    Priority:  50,
                },
            },
            RoleHierarchy: map[string]*StringList{
                "super-admin": {Values: []string{"admin", "user", "viewer"}},
                "admin":       {Values: []string{"user", "viewer"}},
                "user":        {Values: []string{"viewer"}},
            },
        },
        Cache: &AuthzCacheConfig{
            Enabled: true,
            Ttl:     &duration.Duration{Seconds: 300}, // 5 minutes
            MaxSize: 1000,
            Type:    "memory",
        },
    }
    
    // Apply to route configuration...
}
```

### Backend Transform Example

```go
func applyBackendTransform(client pb.ConfigurationServiceClient) {
    transformConfig := &BackendTransformConfig{
        Request: &BackendRequestTransform{
            Template: `{
                "data": {{.Body}},
                "metadata": {
                    "timestamp": "{{.Timestamp}}",
                    "requestId": "{{.RequestID}}",
                    "source": "gateway"
                }
            }`,
            Headers: &HeaderOperation{
                Set: map[string]string{
                    "X-Gateway-Transform": "enabled",
                    "X-Request-ID":        "{{.RequestID}}",
                },
                Remove: []string{"X-Internal-Header"},
            },
        },
        Response: &BackendResponseTransform{
            AllowFields: []string{"id", "name", "email", "created_at"},
            DenyFields:  []string{"password", "secret", "internal_id"},
            FieldMappings: map[string]string{
                "created_at": "createdAt",
                "updated_at": "updatedAt",
            },
            Headers: &HeaderOperation{
                Set: map[string]string{
                    "X-Response-Transform": "applied",
                },
            },
        },
    }
    
    backendConfig := map[string]interface{}{
        "hosts": []map[string]interface{}{
            {
                "address": "api-backend.internal",
                "port":    8080,
                "weight":  1,
            },
        },
        "transform": transformConfig,
    }
    
    configBytes, _ := json.Marshal(backendConfig)
    
    resp, err := client.ApplyBackend(context.Background(), &pb.ApplyBackendRequest{
        Name:       "api-backend-transform",
        Namespace:  "production",
        Config:     configBytes,
        Generation: 1,
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Backend with transform applied: %s", resp.Message)
}
```

For more examples and advanced usage patterns, see the [examples/operator/](../../examples/operator/) directory.