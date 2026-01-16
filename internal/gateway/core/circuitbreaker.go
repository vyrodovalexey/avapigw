package core

import (
	"context"
	"errors"

	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CircuitBreakerCore provides protocol-agnostic circuit breaker functionality.
type CircuitBreakerCore struct {
	registry  *circuitbreaker.Registry
	logger    *zap.Logger
	skipPaths map[string]bool
	nameFunc  func(identifier string) string
}

// NewCircuitBreakerCore creates a new CircuitBreakerCore with the given configuration.
func NewCircuitBreakerCore(config CircuitBreakerCoreConfig) *CircuitBreakerCore {
	config.InitSkipPaths()

	registry := config.Registry
	if registry == nil {
		registry = circuitbreaker.NewRegistry(nil, nil)
	}

	return &CircuitBreakerCore{
		registry:  registry,
		logger:    config.GetLogger(),
		skipPaths: config.skipPathMap,
		nameFunc:  config.NameFunc,
	}
}

// Execute executes the given function with circuit breaker protection.
// Returns the error from the function or ErrCircuitOpen if the circuit is open.
func (c *CircuitBreakerCore) Execute(ctx context.Context, name string, fn func() error) error {
	// Apply name function if provided
	if c.nameFunc != nil {
		name = c.nameFunc(name)
	}

	cb := c.registry.GetOrCreate(name)
	return cb.Execute(ctx, fn)
}

// Allow checks if a request is allowed through the circuit breaker.
// Returns true if the request is allowed, false if the circuit is open.
func (c *CircuitBreakerCore) Allow(name string) bool {
	// Apply name function if provided
	if c.nameFunc != nil {
		name = c.nameFunc(name)
	}

	cb := c.registry.GetOrCreate(name)
	allowed := cb.Allow()

	if !allowed {
		c.logger.Debug("circuit breaker open",
			zap.String("name", name),
			zap.String("state", cb.State().String()),
		)
	}

	return allowed
}

// RecordSuccess records a successful request for the given circuit breaker.
func (c *CircuitBreakerCore) RecordSuccess(name string) {
	// Apply name function if provided
	if c.nameFunc != nil {
		name = c.nameFunc(name)
	}

	cb := c.registry.GetOrCreate(name)
	cb.RecordSuccess()
}

// RecordFailure records a failed request for the given circuit breaker.
func (c *CircuitBreakerCore) RecordFailure(name string) {
	// Apply name function if provided
	if c.nameFunc != nil {
		name = c.nameFunc(name)
	}

	cb := c.registry.GetOrCreate(name)
	cb.RecordFailure()
}

// RecordResult records the result of a request based on the error.
// If the error is considered a failure, it records a failure; otherwise, success.
func (c *CircuitBreakerCore) RecordResult(name string, err error) {
	if c.IsFailure(err) {
		c.RecordFailure(name)
	} else {
		c.RecordSuccess(name)
	}
}

// IsFailure determines if an error should count as a circuit breaker failure.
// This handles both HTTP status codes and gRPC status codes.
func (c *CircuitBreakerCore) IsFailure(err error) bool {
	if err == nil {
		return false
	}

	// Check for circuit breaker errors (not failures)
	if errors.Is(err, circuitbreaker.ErrCircuitOpen) ||
		errors.Is(err, circuitbreaker.ErrTooManyRequests) {
		return false
	}

	// Check for gRPC status codes
	if st, ok := status.FromError(err); ok {
		return isGRPCFailureCode(st.Code())
	}

	// Default: any error is a failure
	return true
}

// IsHTTPFailure determines if an HTTP status code should count as a failure.
func (c *CircuitBreakerCore) IsHTTPFailure(statusCode int) bool {
	return statusCode >= 500
}

// ShouldSkip checks if the given identifier should skip circuit breaker.
func (c *CircuitBreakerCore) ShouldSkip(identifier string) bool {
	if c.skipPaths == nil {
		return false
	}
	return c.skipPaths[identifier]
}

// GetCircuitBreaker returns the circuit breaker for the given name.
func (c *CircuitBreakerCore) GetCircuitBreaker(name string) *circuitbreaker.CircuitBreaker {
	// Apply name function if provided
	if c.nameFunc != nil {
		name = c.nameFunc(name)
	}
	return c.registry.GetOrCreate(name)
}

// Registry returns the underlying circuit breaker registry.
func (c *CircuitBreakerCore) Registry() *circuitbreaker.Registry {
	return c.registry
}

// isGRPCFailureCode determines if a gRPC status code should count as a failure.
func isGRPCFailureCode(code codes.Code) bool {
	switch code {
	case codes.Unavailable,
		codes.ResourceExhausted,
		codes.Internal,
		codes.Unknown,
		codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

// ErrCircuitOpen is re-exported for convenience.
var ErrCircuitOpen = circuitbreaker.ErrCircuitOpen
