// Package router provides HTTP routing functionality for the
// API Gateway.
//
// This package implements request routing with support for exact,
// prefix, and regex path matching, method filtering, header matching,
// and query parameter matching with priority-based route selection.
//
// # Features
//
//   - Exact, prefix, and regex path matching
//   - Path parameter extraction from URL patterns
//   - HTTP method filtering
//   - Header-based route matching
//   - Query parameter-based route matching
//   - Priority-based route selection with deterministic ordering
//   - Thread-safe route registration and lookup
//
// # Usage
//
// Create a router and register routes:
//
//	r := router.New()
//	err := r.BuildRoutes(routes)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	result := r.Match(request)
//	if result != nil {
//	    // Route matched, use result.Route and result.PathParams
//	}
package router
