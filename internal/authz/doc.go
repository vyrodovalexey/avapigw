// Package authz provides authorization capabilities for the API Gateway.
//
// This package implements multiple authorization mechanisms:
//   - RBAC (Role-Based Access Control) with claim-based roles
//   - ABAC (Attribute-Based Access Control) using CEL expressions
//   - External authorization via OPA or custom authorizers
//
// The package provides both HTTP middleware and gRPC interceptors for
// seamless integration with both protocols.
//
// # Architecture
//
// The authz package is organized into subpackages:
//   - rbac: Role-based access control engine
//   - abac: Attribute-based access control with CEL
//   - external: External authorization (OPA, gRPC, HTTP)
//
// # Usage
//
// Create an authorizer with the desired configuration:
//
//	cfg := &authz.Config{
//	    Enabled:       true,
//	    DefaultPolicy: authz.PolicyDeny,
//	    RBAC: &rbac.Config{
//	        Enabled: true,
//	        Policies: []rbac.Policy{
//	            {
//	                Name:      "admin-access",
//	                Roles:     []string{"admin"},
//	                Resources: []string{"*"},
//	                Actions:   []string{"*"},
//	            },
//	        },
//	    },
//	}
//
//	authorizer, err := authz.New(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use as HTTP middleware
//	handler := authorizer.HTTPMiddleware()(yourHandler)
//
//	// Use as gRPC interceptor
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(authorizer.UnaryInterceptor()),
//	    grpc.StreamInterceptor(authorizer.StreamInterceptor()),
//	)
package authz
