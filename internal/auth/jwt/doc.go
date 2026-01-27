// Package jwt provides JSON Web Token validation and signing
// for the API Gateway.
//
// This package implements JWT validation with support for multiple
// algorithms, JWKS key management, token signing, and claims
// extraction.
//
// # Features
//
//   - Token validation with configurable options
//   - JWKS (JSON Web Key Set) fetching and caching
//   - Token signing with RSA, ECDSA, Ed25519, and HMAC
//   - Claims extraction and custom claim validation
//   - Clock skew tolerance for distributed systems
//   - Prometheus metrics for validation operations
//
// # Validation
//
// The Validator interface validates JWT tokens:
//
//	validator, err := jwt.NewValidator(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	claims, err := validator.Validate(ctx, tokenString)
//	if err != nil {
//	    // Handle invalid token
//	}
//
// # Signing
//
// The Signer creates signed JWT tokens:
//
//	signer, err := jwt.NewSigner(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	token, err := signer.Sign(ctx, claims)
package jwt
