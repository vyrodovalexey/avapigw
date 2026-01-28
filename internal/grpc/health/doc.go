// Package health provides gRPC health service implementation for the API Gateway.
//
// The health package implements the grpc.health.v1.Health service for:
//   - Gateway health checking
//   - Backend health aggregation
//   - Service-specific health status
//
// Example usage:
//
//	hs := health.NewHealthServer(
//	    health.WithLogger(logger),
//	)
//
//	// Register with gRPC server
//	healthpb.RegisterHealthServer(grpcServer, hs)
//
//	// Set service status
//	hs.SetServingStatus("my-service", healthpb.HealthCheckResponse_SERVING)
package health
