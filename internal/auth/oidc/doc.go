// Package oidc provides OpenID Connect provider integration for the
// API Gateway.
//
// This package implements OIDC discovery, token validation, user info
// retrieval, and token introspection for identity provider
// integration.
//
// # Features
//
//   - OIDC discovery document fetching and caching
//   - Access and ID token validation via JWKS
//   - UserInfo endpoint integration
//   - Token introspection support
//   - Multiple provider support
//   - Prometheus metrics for provider operations
//
// # Provider
//
// The Provider interface represents an OIDC identity provider:
//
//	provider, err := oidc.NewProvider(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer provider.Close()
//
//	tokenInfo, err := provider.ValidateToken(ctx, accessToken)
//	if err != nil {
//	    // Handle invalid token
//	}
//
// # Discovery
//
// The package automatically fetches and caches OIDC discovery
// documents from the provider's well-known endpoint.
package oidc
