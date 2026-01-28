// Package server provides gRPC server implementation for the API Gateway.
//
// The server package implements a configurable gRPC server with support for:
//   - Configurable max concurrent streams
//   - Configurable message sizes
//   - Keepalive configuration
//   - TLS support
//   - Graceful shutdown
//   - Interceptor chains
//
// Example usage:
//
//	cfg := &config.GRPCListenerConfig{
//	    MaxConcurrentStreams: 100,
//	    MaxRecvMsgSize:       4 * 1024 * 1024,
//	}
//
//	srv, err := server.New(cfg,
//	    server.WithLogger(logger),
//	    server.WithUnaryInterceptors(interceptors...),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := srv.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
package server
