// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"errors"
	"fmt"
)

// Sentinel errors for proxy operations.
var (
	// ErrNoDestination indicates that no destination is configured for a route.
	ErrNoDestination = errors.New("no destination configured")

	// ErrNoDestinationAvailable indicates that no destination is available.
	ErrNoDestinationAvailable = errors.New("no destination available")

	// ErrInvalidTargetURL indicates that the target URL is invalid.
	ErrInvalidTargetURL = errors.New("invalid target URL")

	// ErrRouteNotFound indicates that no matching route was found.
	ErrRouteNotFound = errors.New("no matching route found")

	// ErrProxyFailed indicates that the proxy request failed.
	ErrProxyFailed = errors.New("proxy request failed")

	// ErrUpstreamTimeout indicates that the upstream request timed out.
	ErrUpstreamTimeout = errors.New("upstream request timed out")

	// ErrUpstreamUnavailable indicates that the upstream is unavailable.
	ErrUpstreamUnavailable = errors.New("upstream unavailable")
)

// ProxyError represents a proxy-related error with details.
type ProxyError struct {
	Op      string // Operation that failed
	Route   string // Route name if applicable
	Target  string // Target URL if applicable
	Message string // Human-readable message
	Cause   error  // Underlying error
}

// Error implements the error interface.
func (e *ProxyError) Error() string {
	if e.Route != "" && e.Target != "" {
		return e.formatWithRouteAndTarget()
	}
	if e.Route != "" {
		return e.formatWithRoute()
	}
	return e.formatBasic()
}

// formatWithRouteAndTarget formats error with route and target info.
func (e *ProxyError) formatWithRouteAndTarget() string {
	if e.Cause != nil {
		return fmt.Sprintf("proxy error [%s] route=%s target=%s: %s: %v",
			e.Op, e.Route, e.Target, e.Message, e.Cause)
	}
	return fmt.Sprintf("proxy error [%s] route=%s target=%s: %s",
		e.Op, e.Route, e.Target, e.Message)
}

// formatWithRoute formats error with route info.
func (e *ProxyError) formatWithRoute() string {
	if e.Cause != nil {
		return fmt.Sprintf("proxy error [%s] route=%s: %s: %v",
			e.Op, e.Route, e.Message, e.Cause)
	}
	return fmt.Sprintf("proxy error [%s] route=%s: %s", e.Op, e.Route, e.Message)
}

// formatBasic formats error without route/target info.
func (e *ProxyError) formatBasic() string {
	if e.Cause != nil {
		return fmt.Sprintf("proxy error [%s]: %s: %v", e.Op, e.Message, e.Cause)
	}
	return fmt.Sprintf("proxy error [%s]: %s", e.Op, e.Message)
}

// Unwrap returns the underlying error.
func (e *ProxyError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ProxyError) Is(target error) bool {
	_, ok := target.(*ProxyError)
	return ok || errors.Is(e.Cause, target)
}

// NewProxyError creates a new ProxyError.
func NewProxyError(op, route, target, message string, cause error) *ProxyError {
	return &ProxyError{
		Op:      op,
		Route:   route,
		Target:  target,
		Message: message,
		Cause:   cause,
	}
}

// NewNoDestinationError creates an error for missing destination.
func NewNoDestinationError(route string) *ProxyError {
	return &ProxyError{
		Op:      "select_destination",
		Route:   route,
		Message: "no destinations configured",
		Cause:   ErrNoDestination,
	}
}

// NewNoDestinationAvailableError creates an error for unavailable destination.
func NewNoDestinationAvailableError(route string) *ProxyError {
	return &ProxyError{
		Op:      "select_destination",
		Route:   route,
		Message: "no destination available",
		Cause:   ErrNoDestinationAvailable,
	}
}

// NewInvalidTargetError creates an error for invalid target URL.
func NewInvalidTargetError(route, target string, cause error) *ProxyError {
	return &ProxyError{
		Op:      "parse_target",
		Route:   route,
		Target:  target,
		Message: "invalid target URL",
		Cause:   cause,
	}
}

// NewRouteNotFoundError creates an error for route not found.
func NewRouteNotFoundError(path, method string, cause error) *ProxyError {
	return &ProxyError{
		Op:      "match_route",
		Message: fmt.Sprintf("no route found for %s %s", method, path),
		Cause:   cause,
	}
}

// IsProxyError checks if an error is a ProxyError.
func IsProxyError(err error) bool {
	var proxyErr *ProxyError
	return errors.As(err, &proxyErr)
}

// IsNoDestinationError checks if an error indicates no destination.
func IsNoDestinationError(err error) bool {
	return errors.Is(err, ErrNoDestination) || errors.Is(err, ErrNoDestinationAvailable)
}

// IsRouteNotFoundError checks if an error indicates route not found.
func IsRouteNotFoundError(err error) bool {
	return errors.Is(err, ErrRouteNotFound)
}
