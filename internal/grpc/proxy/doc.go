// Package proxy provides gRPC reverse proxy functionality for the API Gateway.
//
// The proxy package implements transparent gRPC proxying with support for:
//   - All streaming modes (unary, server streaming, client streaming, bidirectional)
//   - Transparent message proxying without unmarshaling
//   - Metadata forwarding
//   - Connection pooling
//   - Load balancing
//
// Example usage:
//
//	r := router.New()
//	// ... add routes ...
//
//	p := proxy.New(r,
//	    proxy.WithLogger(logger),
//	    proxy.WithConnectionPool(pool),
//	)
//
//	// Use as unknown service handler
//	grpcServer := grpc.NewServer(
//	    grpc.UnknownServiceHandler(p.StreamHandler()),
//	)
package proxy
