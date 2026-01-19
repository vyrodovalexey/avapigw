package circuitbreaker

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 5, config.MaxFailures)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.HalfOpenMax)
	assert.Equal(t, 2, config.SuccessThreshold)
	assert.Equal(t, 0.0, config.FailureRatio) // Default is 0 (disabled)
	assert.Equal(t, 10, config.MinRequests)
	assert.Equal(t, 1*time.Minute, config.SamplingDuration)
	assert.Nil(t, config.IsSuccessful) // Default is nil
}

func TestDefaultConfig_IsSuccessful(t *testing.T) {
	config := DefaultConfig()

	// Default IsSuccessful is nil, so we need to set one for testing
	config.IsSuccessful = func(err error) bool { return err == nil }

	t.Run("nil error is successful", func(t *testing.T) {
		assert.True(t, config.IsSuccessful(nil))
	})

	t.Run("non-nil error is not successful", func(t *testing.T) {
		assert.False(t, config.IsSuccessful(errors.New("test error")))
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "valid custom config",
			config: &Config{
				MaxFailures:      10,
				Timeout:          1 * time.Minute,
				HalfOpenMax:      5,
				SuccessThreshold: 3,
				FailureRatio:     0.6,
				MinRequests:      20,
				SamplingDuration: 30 * time.Second,
				IsSuccessful:     func(err error) bool { return err == nil },
			},
			wantErr: false,
		},
		{
			name: "zero MaxFailures is valid",
			config: &Config{
				MaxFailures:      0,
				Timeout:          30 * time.Second,
				HalfOpenMax:      3,
				SuccessThreshold: 2,
				FailureRatio:     0.5,
				MinRequests:      10,
				SamplingDuration: 10 * time.Second,
				IsSuccessful:     func(err error) bool { return err == nil },
			},
			wantErr: false,
		},
		{
			name: "negative MaxFailures is valid (uses ratio-based)",
			config: &Config{
				MaxFailures:      -1,
				Timeout:          30 * time.Second,
				HalfOpenMax:      3,
				SuccessThreshold: 2,
				FailureRatio:     0.5,
				MinRequests:      10,
				SamplingDuration: 10 * time.Second,
				IsSuccessful:     func(err error) bool { return err == nil },
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_WithMaxFailures(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 5, config.MaxFailures)

	result := config.WithMaxFailures(10)

	assert.Same(t, config, result)
	assert.Equal(t, 10, config.MaxFailures)
}

func TestConfig_WithTimeout(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 30*time.Second, config.Timeout)

	result := config.WithTimeout(1 * time.Minute)

	assert.Same(t, config, result)
	assert.Equal(t, 1*time.Minute, config.Timeout)
}

func TestConfig_WithHalfOpenMax(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 3, config.HalfOpenMax)

	result := config.WithHalfOpenMax(5)

	assert.Same(t, config, result)
	assert.Equal(t, 5, config.HalfOpenMax)
}

func TestConfig_WithSuccessThreshold(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 2, config.SuccessThreshold)

	result := config.WithSuccessThreshold(4)

	assert.Same(t, config, result)
	assert.Equal(t, 4, config.SuccessThreshold)
}

func TestConfig_WithIsSuccessful(t *testing.T) {
	config := DefaultConfig()

	customFn := func(err error) bool {
		return err == nil || err.Error() == "expected"
	}

	result := config.WithIsSuccessful(customFn)

	assert.Same(t, config, result)
	assert.True(t, config.IsSuccessful(nil))
	assert.True(t, config.IsSuccessful(errors.New("expected")))
	assert.False(t, config.IsSuccessful(errors.New("unexpected")))
}

func TestConfig_WithOnStateChange(t *testing.T) {
	config := DefaultConfig()
	assert.Nil(t, config.OnStateChange)

	var callbackCalled bool
	var capturedName string
	var capturedFrom, capturedTo State

	callback := func(name string, from, to State) {
		callbackCalled = true
		capturedName = name
		capturedFrom = from
		capturedTo = to
	}

	result := config.WithOnStateChange(callback)

	assert.Same(t, config, result)
	assert.NotNil(t, config.OnStateChange)

	// Test the callback
	config.OnStateChange("test-breaker", StateClosed, StateOpen)
	assert.True(t, callbackCalled)
	assert.Equal(t, "test-breaker", capturedName)
	assert.Equal(t, StateClosed, capturedFrom)
	assert.Equal(t, StateOpen, capturedTo)
}

func TestConfig_WithFailureRatio(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 0.0, config.FailureRatio) // Default is 0 (disabled)

	result := config.WithFailureRatio(0.75)

	assert.Same(t, config, result)
	assert.Equal(t, 0.75, config.FailureRatio)
}

func TestConfig_WithMinRequests(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 10, config.MinRequests)

	result := config.WithMinRequests(20)

	assert.Same(t, config, result)
	assert.Equal(t, 20, config.MinRequests)
}

func TestConfig_WithSamplingDuration(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, 1*time.Minute, config.SamplingDuration)

	result := config.WithSamplingDuration(30 * time.Second)

	assert.Same(t, config, result)
	assert.Equal(t, 30*time.Second, config.SamplingDuration)
}

func TestConfig_BuilderChaining(t *testing.T) {
	config := DefaultConfig().
		WithMaxFailures(10).
		WithTimeout(1 * time.Minute).
		WithHalfOpenMax(5).
		WithSuccessThreshold(3).
		WithFailureRatio(0.6).
		WithMinRequests(20).
		WithSamplingDuration(30 * time.Second)

	assert.Equal(t, 10, config.MaxFailures)
	assert.Equal(t, 1*time.Minute, config.Timeout)
	assert.Equal(t, 5, config.HalfOpenMax)
	assert.Equal(t, 3, config.SuccessThreshold)
	assert.Equal(t, 0.6, config.FailureRatio)
	assert.Equal(t, 20, config.MinRequests)
	assert.Equal(t, 30*time.Second, config.SamplingDuration)
}

func TestConfig_WithNilIsSuccessful(t *testing.T) {
	config := DefaultConfig()

	result := config.WithIsSuccessful(nil)

	assert.Same(t, config, result)
	assert.Nil(t, config.IsSuccessful)
}

func TestConfig_WithNilOnStateChange(t *testing.T) {
	config := DefaultConfig()

	// First set a callback
	config.WithOnStateChange(func(name string, from, to State) {})
	assert.NotNil(t, config.OnStateChange)

	// Then set it to nil
	result := config.WithOnStateChange(nil)

	assert.Same(t, config, result)
	assert.Nil(t, config.OnStateChange)
}
