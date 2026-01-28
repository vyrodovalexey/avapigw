// Package auth provides authentication providers for backend connections.
//
// This package implements authentication mechanisms for outgoing requests
// to backend services. It supports three authentication types:
//
//   - JWT: Token-based authentication using static tokens, Vault-stored tokens,
//     or OIDC client credentials flow
//   - Basic: Username/password authentication with static credentials or
//     Vault-stored credentials
//   - mTLS: Mutual TLS authentication using file-based or Vault PKI certificates
//
// # Usage
//
// Create a provider using the factory function:
//
//	cfg := &config.BackendAuthConfig{
//	    Type: "jwt",
//	    JWT: &config.BackendJWTAuthConfig{
//	        Enabled:     true,
//	        TokenSource: "static",
//	        StaticToken: "my-token",
//	    },
//	}
//	provider, err := auth.NewProvider(cfg, auth.WithLogger(logger))
//	if err != nil {
//	    // handle error
//	}
//	defer provider.Close()
//
// Apply authentication to HTTP requests:
//
//	err := provider.ApplyHTTP(ctx, req)
//
// Get gRPC dial options:
//
//	opts, err := provider.ApplyGRPC(ctx)
//
// # Token Caching
//
// JWT and Basic providers cache credentials to minimize Vault/OIDC calls.
// The cache TTL is configurable and tokens are refreshed before expiry.
//
// # Observability
//
// All providers emit Prometheus metrics for authentication operations:
//   - backend_auth_requests_total: Total authentication requests
//   - backend_auth_request_duration_seconds: Request duration histogram
//   - backend_auth_token_refresh_total: Token refresh operations
//   - backend_auth_errors_total: Authentication errors
package auth
