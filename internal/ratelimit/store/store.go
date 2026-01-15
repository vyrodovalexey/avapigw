// Package store provides storage backends for rate limiting.
package store

import (
	"context"
	"time"
)

// Store defines the interface for rate limit storage.
type Store interface {
	// Get retrieves the value for the given key.
	Get(ctx context.Context, key string) (int64, error)

	// Set sets the value for the given key with an expiration.
	Set(ctx context.Context, key string, value int64, expiration time.Duration) error

	// Increment increments the value for the given key by delta.
	Increment(ctx context.Context, key string, delta int64) (int64, error)

	// IncrementWithExpiry increments the value and sets expiration if key is new.
	IncrementWithExpiry(ctx context.Context, key string, delta int64, expiration time.Duration) (int64, error)

	// Delete removes the key from the store.
	Delete(ctx context.Context, key string) error

	// Close closes the store and releases resources.
	Close() error
}

// ErrKeyNotFound is returned when a key is not found in the store.
type ErrKeyNotFound struct {
	Key string
}

func (e *ErrKeyNotFound) Error() string {
	return "key not found: " + e.Key
}

// IsKeyNotFound returns true if the error is a key not found error.
func IsKeyNotFound(err error) bool {
	_, ok := err.(*ErrKeyNotFound)
	return ok
}
