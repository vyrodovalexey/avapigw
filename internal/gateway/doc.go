// Package gateway provides the core API Gateway functionality.
//
// This package implements the main Gateway struct that orchestrates
// listeners, routing, middleware, proxying, and lifecycle management
// for both HTTP and gRPC protocols.
//
// # Features
//
//   - HTTP and HTTPS listener management with TLS support
//   - gRPC listener management with reflection support
//   - Configuration hot-reload without restart
//   - Graceful shutdown with configurable timeout
//   - Route-level middleware configuration
//   - Gateway state management (stopped, starting, running, stopping)
//
// # Usage
//
// Create and start a gateway:
//
//	gw, err := gateway.New(cfg, logger, metrics)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := gw.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer gw.Stop(ctx)
//
// # Configuration Reload
//
// The gateway supports live configuration reload:
//
//	if err := gw.Reload(ctx, newConfig); err != nil {
//	    logger.Error("reload failed", observability.Error(err))
//	}
package gateway
