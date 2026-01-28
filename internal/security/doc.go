// Package security provides security middleware and utilities for the API Gateway.
//
// This package implements various security features:
//   - Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
//   - HSTS (HTTP Strict Transport Security)
//   - Content Security Policy
//   - Permissions Policy
//
// # Usage
//
// Create security middleware with the desired configuration:
//
//	cfg := &security.Config{
//	    Headers: &security.HeadersConfig{
//	        Enabled:            true,
//	        XFrameOptions:      "DENY",
//	        XContentTypeOptions: "nosniff",
//	        XXSSProtection:     "1; mode=block",
//	    },
//	    HSTS: &security.HSTSConfig{
//	        Enabled:           true,
//	        MaxAge:            31536000,
//	        IncludeSubDomains: true,
//	        Preload:           true,
//	    },
//	}
//
//	middleware := security.NewMiddleware(cfg, logger)
//	handler := middleware.Handler()(yourHandler)
package security
