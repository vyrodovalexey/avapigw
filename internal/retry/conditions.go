package retry

import (
	"errors"
	"io"
	"net"
	"net/url"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StatusCodeCondition retries on specific HTTP status codes.
type StatusCodeCondition struct {
	codes map[int]bool
}

// RetryOnStatusCodes creates a condition that retries on specific HTTP status codes.
func RetryOnStatusCodes(statusCodes ...int) *StatusCodeCondition {
	codeMap := make(map[int]bool)
	for _, code := range statusCodes {
		codeMap[code] = true
	}
	return &StatusCodeCondition{codes: codeMap}
}

// ShouldRetry implements RetryCondition.
func (c *StatusCodeCondition) ShouldRetry(err error, statusCode int) bool {
	return c.codes[statusCode]
}

// Retry5xxCondition retries on 5xx status codes.
type Retry5xxCondition struct{}

// RetryOn5xx creates a condition that retries on 5xx status codes.
func RetryOn5xx() *Retry5xxCondition {
	return &Retry5xxCondition{}
}

// ShouldRetry implements RetryCondition.
func (c *Retry5xxCondition) ShouldRetry(err error, statusCode int) bool {
	return statusCode >= 500 && statusCode < 600
}

// RetryableStatusCodes returns common retryable HTTP status codes.
func RetryableStatusCodes() *StatusCodeCondition {
	return RetryOnStatusCodes(
		408, // Request Timeout
		429, // Too Many Requests
		500, // Internal Server Error
		502, // Bad Gateway
		503, // Service Unavailable
		504, // Gateway Timeout
	)
}

// ErrorTypeCondition retries on specific error types.
type ErrorTypeCondition struct {
	errors []error
}

// RetryOnErrors creates a condition that retries on specific errors.
func RetryOnErrors(errs ...error) *ErrorTypeCondition {
	return &ErrorTypeCondition{errors: errs}
}

// ShouldRetry implements RetryCondition.
func (c *ErrorTypeCondition) ShouldRetry(err error, statusCode int) bool {
	if err == nil {
		return false
	}

	for _, target := range c.errors {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}

// NetworkErrorCondition retries on network errors.
type NetworkErrorCondition struct{}

// RetryOnNetworkErrors creates a condition that retries on network errors.
func RetryOnNetworkErrors() *NetworkErrorCondition {
	return &NetworkErrorCondition{}
}

// ShouldRetry implements RetryCondition.
func (c *NetworkErrorCondition) ShouldRetry(err error, statusCode int) bool {
	if err == nil {
		return false
	}

	// Check for common network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Note: netErr.Temporary() is deprecated since Go 1.18
		// We only check for timeout errors now
		return netErr.Timeout()
	}

	// Check for specific error types
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Timeout() || urlErr.Temporary()
	}

	// Check for connection reset
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	// Check for connection refused
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}

	// Check for EOF (connection closed)
	if errors.Is(err, io.EOF) {
		return true
	}

	// Check for unexpected EOF
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	return false
}

// GRPCStatusCondition retries on specific gRPC status codes.
type GRPCStatusCondition struct {
	codes map[codes.Code]bool
}

// RetryOnGRPCCodes creates a condition that retries on specific gRPC status codes.
func RetryOnGRPCCodes(grpcCodes ...codes.Code) *GRPCStatusCondition {
	codeMap := make(map[codes.Code]bool)
	for _, code := range grpcCodes {
		codeMap[code] = true
	}
	return &GRPCStatusCondition{codes: codeMap}
}

// ShouldRetry implements RetryCondition.
func (c *GRPCStatusCondition) ShouldRetry(err error, statusCode int) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	return c.codes[st.Code()]
}

// RetryableGRPCCodes returns common retryable gRPC status codes.
func RetryableGRPCCodes() *GRPCStatusCondition {
	return RetryOnGRPCCodes(
		codes.Unavailable,
		codes.ResourceExhausted,
		codes.Aborted,
		codes.DeadlineExceeded,
	)
}

// TimeoutCondition retries on timeout errors.
type TimeoutCondition struct{}

// RetryOnTimeout creates a condition that retries on timeout errors.
func RetryOnTimeout() *TimeoutCondition {
	return &TimeoutCondition{}
}

// ShouldRetry implements RetryCondition.
func (c *TimeoutCondition) ShouldRetry(err error, statusCode int) bool {
	if err == nil {
		return false
	}

	// Check for net.Error timeout
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Check for url.Error timeout
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return true
	}

	// Check for gRPC deadline exceeded
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.DeadlineExceeded {
		return true
	}

	return false
}

// CompositeCondition combines multiple conditions with OR logic.
type CompositeCondition struct {
	conditions []RetryCondition
}

// RetryOnAny creates a condition that retries if any of the conditions match.
func RetryOnAny(conditions ...RetryCondition) *CompositeCondition {
	return &CompositeCondition{conditions: conditions}
}

// ShouldRetry implements RetryCondition.
func (c *CompositeCondition) ShouldRetry(err error, statusCode int) bool {
	for _, condition := range c.conditions {
		if condition.ShouldRetry(err, statusCode) {
			return true
		}
	}
	return false
}

// AllCondition combines multiple conditions with AND logic.
type AllCondition struct {
	conditions []RetryCondition
}

// RetryOnAll creates a condition that retries only if all conditions match.
func RetryOnAll(conditions ...RetryCondition) *AllCondition {
	return &AllCondition{conditions: conditions}
}

// ShouldRetry implements RetryCondition.
func (c *AllCondition) ShouldRetry(err error, statusCode int) bool {
	if len(c.conditions) == 0 {
		return false
	}

	for _, condition := range c.conditions {
		if !condition.ShouldRetry(err, statusCode) {
			return false
		}
	}
	return true
}

// NeverRetryCondition never retries.
type NeverRetryCondition struct{}

// NeverRetry creates a condition that never retries.
func NeverRetry() *NeverRetryCondition {
	return &NeverRetryCondition{}
}

// ShouldRetry implements RetryCondition.
func (c *NeverRetryCondition) ShouldRetry(err error, statusCode int) bool {
	return false
}

// AlwaysRetryCondition always retries (up to max retries).
type AlwaysRetryCondition struct{}

// AlwaysRetry creates a condition that always retries.
func AlwaysRetry() *AlwaysRetryCondition {
	return &AlwaysRetryCondition{}
}

// ShouldRetry implements RetryCondition.
func (c *AlwaysRetryCondition) ShouldRetry(err error, statusCode int) bool {
	return err != nil || statusCode >= 400
}

// IdempotentMethodCondition only retries for idempotent HTTP methods.
type IdempotentMethodCondition struct {
	method    string
	condition RetryCondition
}

// RetryIfIdempotent creates a condition that only retries for idempotent methods.
func RetryIfIdempotent(method string, condition RetryCondition) *IdempotentMethodCondition {
	return &IdempotentMethodCondition{
		method:    method,
		condition: condition,
	}
}

// ShouldRetry implements RetryCondition.
func (c *IdempotentMethodCondition) ShouldRetry(err error, statusCode int) bool {
	// Check if method is idempotent
	switch c.method {
	case "GET", "HEAD", "OPTIONS", "PUT", "DELETE":
		return c.condition.ShouldRetry(err, statusCode)
	default:
		return false
	}
}
