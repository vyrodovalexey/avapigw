// Package proxy provides HTTP reverse proxy functionality for the
// API Gateway.
//
// This package implements request proxying to backend services with
// support for load balancing, circuit breaking, header manipulation,
// and error handling.
//
// # Features
//
//   - HTTP reverse proxy with configurable transport
//   - Hop-by-hop header removal per RFC 7230
//   - Backend selection via router and load balancer
//   - Circuit breaker integration for fault tolerance
//   - Custom error handling and response modification
//   - Streaming response support with flush interval
//   - Structured error types for proxy failures
//
// # Usage
//
// Create and configure a reverse proxy:
//
//	proxy, err := proxy.New(
//	    routerInstance,
//	    backendRegistry,
//	    proxy.WithProxyLogger(logger),
//	    proxy.WithTransport(transport),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	http.Handle("/", proxy)
package proxy
