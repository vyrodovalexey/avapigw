// Package apikey provides API key authentication for the API Gateway.
//
// This package implements API key validation, storage, and management
// with support for multiple hash algorithms and key lifecycle states.
//
// # Features
//
//   - Multiple hash algorithms: SHA-256, SHA-512, bcrypt, plaintext
//   - Key lifecycle management: active, disabled, expired, revoked
//   - In-memory key store with Vault integration support
//   - Prometheus metrics for validation operations
//   - Constant-time comparison for secure key validation
//
// # Key Storage
//
// The Store interface provides key retrieval by value or ID:
//
//	store, err := apikey.NewStore(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	key, err := store.Get(ctx, "my-api-key")
//
// # Validation
//
// The Validator validates API keys and returns key metadata:
//
//	validator, err := apikey.NewValidator(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	info, err := validator.Validate(ctx, "my-api-key")
//	if err != nil {
//	    // Handle invalid key
//	}
package apikey
