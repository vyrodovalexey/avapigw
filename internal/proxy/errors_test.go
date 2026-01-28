package proxy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *ProxyError
		expected string
	}{
		{
			name: "with route and target and cause",
			err: &ProxyError{
				Op:      "proxy",
				Route:   "test-route",
				Target:  "http://backend:8080",
				Message: "connection failed",
				Cause:   errors.New("dial tcp: connection refused"),
			},
			expected: "proxy error [proxy] route=test-route target=http://backend:8080: connection failed: dial tcp: connection refused",
		},
		{
			name: "with route and target without cause",
			err: &ProxyError{
				Op:      "proxy",
				Route:   "test-route",
				Target:  "http://backend:8080",
				Message: "connection failed",
			},
			expected: "proxy error [proxy] route=test-route target=http://backend:8080: connection failed",
		},
		{
			name: "with route only and cause",
			err: &ProxyError{
				Op:      "select_destination",
				Route:   "test-route",
				Message: "no destinations configured",
				Cause:   ErrNoDestination,
			},
			expected: "proxy error [select_destination] route=test-route: no destinations configured: no destination configured",
		},
		{
			name: "with route only without cause",
			err: &ProxyError{
				Op:      "select_destination",
				Route:   "test-route",
				Message: "no destinations configured",
			},
			expected: "proxy error [select_destination] route=test-route: no destinations configured",
		},
		{
			name: "basic with cause",
			err: &ProxyError{
				Op:      "match_route",
				Message: "no route found for GET /api",
				Cause:   ErrRouteNotFound,
			},
			expected: "proxy error [match_route]: no route found for GET /api: no matching route found",
		},
		{
			name: "basic without cause",
			err: &ProxyError{
				Op:      "match_route",
				Message: "no route found for GET /api",
			},
			expected: "proxy error [match_route]: no route found for GET /api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestProxyError_Unwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := &ProxyError{
		Op:      "test",
		Message: "test message",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestProxyError_Unwrap_NilCause(t *testing.T) {
	t.Parallel()

	err := &ProxyError{
		Op:      "test",
		Message: "test message",
	}

	assert.Nil(t, err.Unwrap())
}

func TestProxyError_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *ProxyError
		target   error
		expected bool
	}{
		{
			name: "matches ProxyError type",
			err: &ProxyError{
				Op:      "test",
				Message: "test",
			},
			target:   &ProxyError{},
			expected: true,
		},
		{
			name: "matches cause",
			err: &ProxyError{
				Op:      "test",
				Message: "test",
				Cause:   ErrNoDestination,
			},
			target:   ErrNoDestination,
			expected: true,
		},
		{
			name: "does not match different error",
			err: &ProxyError{
				Op:      "test",
				Message: "test",
				Cause:   ErrNoDestination,
			},
			target:   ErrRouteNotFound,
			expected: false,
		},
		{
			name: "does not match nil cause",
			err: &ProxyError{
				Op:      "test",
				Message: "test",
			},
			target:   ErrNoDestination,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Is(tt.target))
		})
	}
}

func TestNewProxyError(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := NewProxyError("proxy", "test-route", "http://backend:8080", "connection failed", cause)

	assert.Equal(t, "proxy", err.Op)
	assert.Equal(t, "test-route", err.Route)
	assert.Equal(t, "http://backend:8080", err.Target)
	assert.Equal(t, "connection failed", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewNoDestinationError(t *testing.T) {
	t.Parallel()

	err := NewNoDestinationError("test-route")

	assert.Equal(t, "select_destination", err.Op)
	assert.Equal(t, "test-route", err.Route)
	assert.Equal(t, "no destinations configured", err.Message)
	assert.True(t, errors.Is(err, ErrNoDestination))
}

func TestNewNoDestinationAvailableError(t *testing.T) {
	t.Parallel()

	err := NewNoDestinationAvailableError("test-route")

	assert.Equal(t, "select_destination", err.Op)
	assert.Equal(t, "test-route", err.Route)
	assert.Equal(t, "no destination available", err.Message)
	assert.True(t, errors.Is(err, ErrNoDestinationAvailable))
}

func TestNewInvalidTargetError(t *testing.T) {
	t.Parallel()

	cause := errors.New("invalid URL")
	err := NewInvalidTargetError("test-route", "invalid://url", cause)

	assert.Equal(t, "parse_target", err.Op)
	assert.Equal(t, "test-route", err.Route)
	assert.Equal(t, "invalid://url", err.Target)
	assert.Equal(t, "invalid target URL", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewRouteNotFoundError(t *testing.T) {
	t.Parallel()

	cause := ErrRouteNotFound
	err := NewRouteNotFoundError("/api/users", "GET", cause)

	assert.Equal(t, "match_route", err.Op)
	assert.Equal(t, "no route found for GET /api/users", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestIsProxyError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "is ProxyError",
			err:      &ProxyError{Op: "test", Message: "test"},
			expected: true,
		},
		{
			name:     "wrapped ProxyError",
			err:      errors.New("wrapped: " + (&ProxyError{Op: "test", Message: "test"}).Error()),
			expected: false,
		},
		{
			name:     "not ProxyError",
			err:      errors.New("regular error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsProxyError(tt.err))
		})
	}
}

func TestIsNoDestinationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrNoDestination",
			err:      ErrNoDestination,
			expected: true,
		},
		{
			name:     "ErrNoDestinationAvailable",
			err:      ErrNoDestinationAvailable,
			expected: true,
		},
		{
			name:     "ProxyError with ErrNoDestination cause",
			err:      NewNoDestinationError("test-route"),
			expected: true,
		},
		{
			name:     "ProxyError with ErrNoDestinationAvailable cause",
			err:      NewNoDestinationAvailableError("test-route"),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("other error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsNoDestinationError(tt.err))
		})
	}
}

func TestIsRouteNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrRouteNotFound",
			err:      ErrRouteNotFound,
			expected: true,
		},
		{
			name:     "ProxyError with ErrRouteNotFound cause",
			err:      NewRouteNotFoundError("/api", "GET", ErrRouteNotFound),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("other error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsRouteNotFoundError(tt.err))
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrNoDestination",
			err:      ErrNoDestination,
			expected: "no destination configured",
		},
		{
			name:     "ErrNoDestinationAvailable",
			err:      ErrNoDestinationAvailable,
			expected: "no destination available",
		},
		{
			name:     "ErrInvalidTargetURL",
			err:      ErrInvalidTargetURL,
			expected: "invalid target URL",
		},
		{
			name:     "ErrRouteNotFound",
			err:      ErrRouteNotFound,
			expected: "no matching route found",
		},
		{
			name:     "ErrProxyFailed",
			err:      ErrProxyFailed,
			expected: "proxy request failed",
		},
		{
			name:     "ErrUpstreamTimeout",
			err:      ErrUpstreamTimeout,
			expected: "upstream request timed out",
		},
		{
			name:     "ErrUpstreamUnavailable",
			err:      ErrUpstreamUnavailable,
			expected: "upstream unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestProxyError_ErrorsAs(t *testing.T) {
	t.Parallel()

	proxyErr := &ProxyError{
		Op:      "test",
		Route:   "test-route",
		Message: "test message",
		Cause:   ErrNoDestination,
	}

	var target *ProxyError
	assert.True(t, errors.As(proxyErr, &target))
	assert.Equal(t, "test", target.Op)
	assert.Equal(t, "test-route", target.Route)
}

func TestProxyError_ErrorsIs(t *testing.T) {
	t.Parallel()

	proxyErr := &ProxyError{
		Op:      "test",
		Route:   "test-route",
		Message: "test message",
		Cause:   ErrNoDestination,
	}

	assert.True(t, errors.Is(proxyErr, ErrNoDestination))
	assert.False(t, errors.Is(proxyErr, ErrRouteNotFound))
}
