// Package gateway provides the core API Gateway functionality.
package gateway

import "errors"

// Sentinel errors for gateway operations.
var (
	// ErrGatewayNotStopped indicates that the gateway is not in
	// stopped state when a start operation is attempted.
	ErrGatewayNotStopped = errors.New("gateway is not in stopped state")

	// ErrGatewayNotRunning indicates that the gateway is not
	// running when a stop operation is attempted.
	ErrGatewayNotRunning = errors.New("gateway is not running")

	// ErrNilConfig indicates that a nil configuration was provided.
	ErrNilConfig = errors.New("configuration is required")

	// ErrInvalidConfig indicates that the provided configuration
	// is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")
)
