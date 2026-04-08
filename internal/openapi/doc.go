// Package openapi provides OpenAPI 3.x request validation middleware
// for the API Gateway.
//
// It supports loading OpenAPI specifications from file paths or URLs,
// caching parsed specs for reuse, and hot-reloading when spec files change.
//
// The package provides configurable validation of request bodies, parameters,
// headers, and security requirements. Validation can operate in fail-on-error
// mode (rejecting invalid requests with 400 Bad Request) or log-only mode
// (logging validation errors but allowing requests through).
//
// # Usage
//
// Create a validator and use it as HTTP middleware:
//
//	loader := openapi.NewSpecLoader()
//	validator, err := openapi.NewValidator(
//	    openapi.WithLoader(loader),
//	    openapi.WithSpecFile("/path/to/spec.yaml"),
//	    openapi.WithFailOnError(true),
//	)
//	handler := openapi.Middleware(validator)(yourHandler)
package openapi
