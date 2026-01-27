// Package backend provides backend service management for the
// API Gateway.
//
// This package implements backend host management, load balancing,
// circuit breaking, health checking, connection pooling, and TLS
// configuration for upstream services.
//
// # Features
//
//   - Backend registry for managing upstream services
//   - Load balancing: round-robin, weighted, random, least-connections
//   - Circuit breaker with configurable thresholds
//   - Active and passive health checking
//   - Connection pooling with configurable limits
//   - TLS configuration for backend connections
//   - Host-level rate limiting
//   - Backend authentication support
//
// # Backend Registry
//
// The Registry manages backend service definitions:
//
//	registry := backend.NewRegistry(logger)
//	err := registry.Register(ctx, backendConfig)
//
// # Load Balancing
//
// Multiple load balancing algorithms are supported:
//
//	balancer := backend.NewLoadBalancer(config.LBRoundRobin, hosts)
//	host := balancer.NextAvailable()
//
// # Circuit Breaker
//
// The CircuitBreakerManager tracks backend failures:
//
//	cbm := backend.NewCircuitBreakerManager(cfg, logger)
//	if cbm.IsOpen(backendName) {
//	    // Backend is unavailable
//	}
package backend
