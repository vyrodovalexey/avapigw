// Package policy provides shared utilities for policy controllers in the avapigw operator.
//
// This package eliminates code duplication across policy controllers (AuthPolicy, RateLimitPolicy)
// by providing:
//   - Generic target reference validation for Gateway, HTTPRoute, and GRPCRoute targets
//   - Generic watch handler utilities for efficient policy lookups when targets change
//
// # Usage
//
// Policy controllers can use the shared validation functions:
//
//	validator := policy.NewTargetRefValidator(client)
//	err := validator.ValidateTargetRef(ctx, policy)
//
// # Watch Handlers
//
// Generic watch handlers for efficient policy lookups:
//
//	handler := policy.NewPolicyWatchHandler[*v1alpha1.AuthPolicy](client)
//	requests := handler.FindPoliciesForTarget(ctx, "Gateway", namespace, name)
package policy
