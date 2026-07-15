// Package apikey provides API key authentication for the API Gateway.
//
// This package implements API key validation, storage, and management
// with support for multiple hash algorithms and key lifecycle states.
//
// # Features
//
//   - Multiple hash algorithms: SHA-256, SHA-512, bcrypt, plaintext
//   - Hash-only static keys: entries may set only a pre-computed hash
//     (Key empty) for sha256/sha512/bcrypt; raw keys never need to be
//     stored in configuration
//   - Key lifecycle management: active, disabled, expired, revoked
//   - In-memory key store with Vault integration support
//   - Bounded Vault key cache (LRU eviction, eager TTL expiry, cache keys
//     are SHA-256 digests — raw keys are never used as map keys)
//   - Prometheus metrics for validation operations
//   - Constant-time comparison for secure key validation
//   - Timing equalization: unknown keys are compared against a random
//     dummy hash generated at construction time so not-found lookups cost
//     the same as failed comparisons
//
// # Algorithm / store compatibility
//
// The Vault store addresses secrets by the deterministic digest of the raw
// key, so it supports sha256 and sha512 only. bcrypt hashes embed a random
// salt and cannot address Vault paths; Config.Validate rejects the
// bcrypt+vault combination at load time.
//
// # Error semantics
//
// Store lookups distinguish genuine misses (ErrAPIKeyNotFound, metric
// reason "not_found") from backing-store failures such as Vault transport
// or permission errors (ErrStoreUnavailable, metric reason "store_error").
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
