// Package router provides gRPC routing functionality for the API Gateway.
//
// The router package implements gRPC route matching based on:
//   - Service name (exact, prefix, regex, wildcard)
//   - Method name (exact, prefix, regex, wildcard)
//   - Metadata (headers) matching
//   - Authority matching
//
// Routes are evaluated in priority order with first-match-wins semantics.
// Within a match block, conditions use AND semantics.
// Between match blocks, conditions use OR semantics.
//
// Example usage:
//
//	r := router.New()
//	err := r.AddRoute(config.GRPCRoute{
//	    Name: "test-service",
//	    Match: []config.GRPCRouteMatch{
//	        {
//	            Service: &config.StringMatch{Exact: "api.v1.TestService"},
//	            Method:  &config.StringMatch{Exact: "Unary"},
//	        },
//	    },
//	    Route: []config.RouteDestination{
//	        {Destination: config.Destination{Host: "127.0.0.1", Port: 8803}},
//	    },
//	})
//
//	result, err := r.Match("/api.v1.TestService/Unary", metadata)
package router
