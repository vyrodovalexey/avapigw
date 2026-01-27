// Package external provides external authorization clients for the
// API Gateway.
//
// This package implements integration with external authorization
// services, primarily Open Policy Agent (OPA), for policy-based
// access control decisions.
//
// # Features
//
//   - OPA (Open Policy Agent) client with HTTP API integration
//   - Configurable retry with exponential backoff
//   - Structured authorization input/output
//   - Prometheus metrics for authorization requests
//   - Timeout and context cancellation support
//
// # OPA Integration
//
// The OPAClient sends authorization requests to an OPA server:
//
//	client, err := external.NewOPAClient(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	result, err := client.Authorize(ctx, &external.OPAInput{
//	    Subject:  map[string]interface{}{"user": "alice"},
//	    Resource: "/api/data",
//	    Action:   "read",
//	})
package external
