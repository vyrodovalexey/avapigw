// Package abac provides Attribute-Based Access Control authorization
// for the API Gateway.
//
// This package implements an ABAC engine using CEL (Common Expression
// Language) for flexible policy evaluation based on subject, resource,
// action, and environment attributes.
//
// # Features
//
//   - CEL expression-based policy evaluation
//   - Subject, resource, action, and environment attributes
//   - Compiled policy caching for performance
//   - Custom CEL functions for IP range and time checks
//   - Prometheus metrics for authorization decisions
//
// # Usage
//
// Create an ABAC engine and evaluate authorization requests:
//
//	engine, err := abac.NewEngine(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	decision, err := engine.Evaluate(ctx, &abac.Request{
//	    Subject:  map[string]interface{}{"role": "admin"},
//	    Resource: "/api/users",
//	    Action:   "GET",
//	})
package abac
