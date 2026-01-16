// Package core provides protocol-agnostic implementations of common gateway
// functionality such as rate limiting, circuit breaking, and authentication.
//
// This package eliminates code duplication between HTTP middleware and gRPC
// interceptors by providing shared core logic that can be used by both protocols.
//
// # Rate Limiting
//
// The RateLimitCore provides protocol-agnostic rate limiting:
//
//	core := NewRateLimitCore(RateLimitCoreConfig{
//	    Limiter:   limiter,
//	    Logger:    logger,
//	    SkipPaths: []string{"/health", "/ready"},
//	})
//
//	result, err := core.Check(ctx, "client-key")
//	if !result.Allowed {
//	    // Handle rate limit exceeded
//	}
//
// # Circuit Breaker
//
// The CircuitBreakerCore provides protocol-agnostic circuit breaking:
//
//	core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
//	    Registry:  registry,
//	    Logger:    logger,
//	    SkipPaths: []string{"/health"},
//	})
//
//	if !core.Allow("backend-name") {
//	    // Circuit is open
//	}
//
// # Authentication
//
// The AuthCore provides protocol-agnostic authentication:
//
//	core := NewAuthCore(AuthCoreConfig{
//	    JWTValidator:    jwtValidator,
//	    APIKeyValidator: apiKeyValidator,
//	    Logger:          logger,
//	})
//
//	result := core.Authenticate(ctx, credentials)
//	if !result.Authenticated {
//	    // Handle authentication failure
//	}
package core
