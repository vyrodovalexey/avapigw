// Package route provides shared utilities for route controllers in the avapigw operator.
//
// This package eliminates code duplication across route controllers (HTTPRoute, GRPCRoute,
// TCPRoute, TLSRoute) by providing:
//   - Generic parent reference validation with protocol-specific listener matching
//   - Generic backend reference validation for Services and Backend CRDs
//   - Hostname matching utilities with wildcard support
//   - Watch handler utilities for efficient route lookups using field indexers
//
// # Architecture
//
// The package follows the Gateway API specification for route-to-gateway binding:
//   - Routes reference Gateways via ParentRefs
//   - Gateways expose Listeners with specific protocols
//   - Routes are accepted by Listeners based on protocol and hostname matching
//
// # Parent Reference Validation
//
// Route controllers can use the shared validation functions to validate parent references:
//
//	validator := route.NewParentRefValidator(client, recorder, controllerName)
//	statuses, err := validator.ValidateParentRefs(ctx, route, matcher)
//
// The validator checks:
//   - Gateway existence
//   - Listener protocol compatibility
//   - Hostname matching (with wildcard support)
//
// # Listener Matchers
//
// Protocol-specific listener matchers implement the ListenerMatcher interface:
//
//	// For HTTP routes
//	matcher := &route.HTTPListenerMatcher{}
//
//	// For gRPC routes
//	matcher := &route.GRPCListenerMatcher{}
//
//	// For TCP routes (with optional port matching)
//	matcher := route.NewTCPListenerMatcherWithPort(port)
//
//	// For TLS routes
//	matcher := &route.TLSListenerMatcher{}
//
// # Hostname Matching
//
// The package provides hostname matching with wildcard support:
//
//	// Check if route hostnames match listener hostname
//	matches := route.HostnameMatches(routeHostnames, listenerHostname)
//
//	// Direct hostname comparison with wildcard support
//	match := route.HostnameMatch("api.example.com", "*.example.com") // true
//
// Wildcard matching rules:
//   - Exact match: "example.com" matches "example.com"
//   - Listener wildcard: "*.example.com" matches "api.example.com"
//   - Route wildcard: "*.example.com" matches "api.example.com"
//   - Both wildcards: "*.example.com" matches "*.example.com" (same suffix)
//
// # Backend Reference Validation
//
// The BackendRefValidator validates backend references:
//
//	validator := route.NewBackendRefValidator(client, recorder)
//	err := validator.ValidateBackendRefs(ctx, route, backendRefs)
//
// Supported backend kinds:
//   - Service (core Kubernetes Service)
//   - Backend (custom avapigw Backend CRD)
//
// # Watch Handlers
//
// Generic watch handlers for efficient route lookups using field indexers:
//
//	handler := route.NewWatchHandler(client, gatewayIndexField, backendIndexField)
//	requests := handler.FindHTTPRoutesForGateway(ctx, gateway)
//	requests := handler.FindHTTPRoutesForBackend(ctx, backend)
//
// The watch handlers use field indexers for O(1) lookups instead of full list scans.
//
// # Thread Safety
//
// All types in this package are safe for concurrent use by multiple goroutines.
package route
