// Package rbac provides Role-Based Access Control authorization for
// the API Gateway.
//
// This package implements an RBAC engine that evaluates access
// decisions based on subject roles, permissions, and group
// memberships against configured policies.
//
// # Features
//
//   - Role and permission-based policy evaluation
//   - Group membership support
//   - Wildcard matching for resources and actions
//   - Regex pattern matching for resource paths
//   - Policy priority ordering
//   - Prometheus metrics for authorization decisions
//
// # Usage
//
// Create an RBAC engine and evaluate authorization requests:
//
//	engine, err := rbac.NewEngine(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	decision, err := engine.Evaluate(ctx, &rbac.Request{
//	    Subject:  "alice",
//	    Roles:    []string{"admin"},
//	    Resource: "/api/users",
//	    Action:   "GET",
//	})
package rbac
