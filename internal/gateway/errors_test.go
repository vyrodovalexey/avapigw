package gateway

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGatewaySentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrGatewayNotStopped",
			err:      ErrGatewayNotStopped,
			expected: "gateway is not in stopped state",
		},
		{
			name:     "ErrGatewayNotRunning",
			err:      ErrGatewayNotRunning,
			expected: "gateway is not running",
		},
		{
			name:     "ErrNilConfig",
			err:      ErrNilConfig,
			expected: "configuration is required",
		},
		{
			name:     "ErrInvalidConfig",
			err:      ErrInvalidConfig,
			expected: "invalid configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestGatewaySentinelErrors_AreDistinct(t *testing.T) {
	t.Parallel()

	sentinelErrors := []error{
		ErrGatewayNotStopped,
		ErrGatewayNotRunning,
		ErrNilConfig,
		ErrInvalidConfig,
	}

	for i, err1 := range sentinelErrors {
		for j, err2 := range sentinelErrors {
			if i == j {
				assert.True(t, errors.Is(err1, err2))
			} else {
				assert.False(t, errors.Is(err1, err2),
					"expected %v and %v to be distinct",
					err1, err2,
				)
			}
		}
	}
}

func TestGatewaySentinelErrors_Wrapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sentinel error
	}{
		{
			name:     "wrapped ErrGatewayNotStopped",
			sentinel: ErrGatewayNotStopped,
		},
		{
			name:     "wrapped ErrGatewayNotRunning",
			sentinel: ErrGatewayNotRunning,
		},
		{
			name:     "wrapped ErrNilConfig",
			sentinel: ErrNilConfig,
		},
		{
			name:     "wrapped ErrInvalidConfig",
			sentinel: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wrapped := fmt.Errorf("context: %w", tt.sentinel)
			assert.True(t, errors.Is(wrapped, tt.sentinel))
		})
	}
}
