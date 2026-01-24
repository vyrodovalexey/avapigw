// Package auth provides authentication capabilities for the API Gateway.
//
// This package implements multiple authentication mechanisms:
//   - JWT (JSON Web Token) validation with support for multiple algorithms
//   - API Key authentication with hashing support
//   - mTLS (mutual TLS) certificate validation
//   - OIDC (OpenID Connect) provider integration
//
// The package provides both HTTP middleware and gRPC interceptors for
// seamless integration with both protocols.
//
// # Architecture
//
// The auth package is organized into subpackages:
//   - jwt: JWT validation, signing, and JWK key management
//   - apikey: API Key validation and storage
//   - mtls: mTLS certificate validation and identity extraction
//   - oidc: OIDC provider integration and token validation
//
// # Usage
//
// Create an authenticator with the desired configuration:
//
//	cfg := &auth.Config{
//	    JWT: &jwt.Config{
//	        Enabled:   true,
//	        Issuer:    "https://auth.example.com",
//	        Audience:  []string{"api.example.com"},
//	        JWKSUrl:   "https://auth.example.com/.well-known/jwks.json",
//	    },
//	}
//
//	authenticator, err := auth.New(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use as HTTP middleware
//	handler := authenticator.HTTPMiddleware()(yourHandler)
//
//	// Use as gRPC interceptor
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(authenticator.UnaryInterceptor()),
//	    grpc.StreamInterceptor(authenticator.StreamInterceptor()),
//	)
//
// # Vault Integration
//
// The auth package optionally integrates with HashiCorp Vault for:
//   - JWT signing keys via Transit secrets engine
//   - API Key storage via KV secrets engine
//   - Certificate management via PKI secrets engine
//
// Enable Vault integration in the configuration:
//
//	cfg := &auth.Config{
//	    JWT: &jwt.Config{
//	        Vault: &jwt.VaultConfig{
//	            Enabled:      true,
//	            TransitMount: "transit",
//	            KeyName:      "jwt-signing-key",
//	        },
//	    },
//	}
package auth
