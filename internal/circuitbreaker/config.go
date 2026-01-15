// Package circuitbreaker provides circuit breaker functionality for the API Gateway.
// It implements the circuit breaker pattern to prevent cascading failures.
package circuitbreaker

import (
	"time"
)

// Config holds configuration for a circuit breaker.
type Config struct {
	// MaxFailures is the number of consecutive failures before opening the circuit.
	MaxFailures int

	// Timeout is the duration the circuit stays open before transitioning to half-open.
	Timeout time.Duration

	// HalfOpenMax is the maximum number of requests allowed in half-open state.
	HalfOpenMax int

	// SuccessThreshold is the number of consecutive successes needed to close the circuit
	// from half-open state.
	SuccessThreshold int

	// IsSuccessful is a function that determines if an error should be counted as a failure.
	// If nil, all non-nil errors are counted as failures.
	IsSuccessful func(err error) bool

	// OnStateChange is called when the circuit breaker state changes.
	OnStateChange func(name string, from, to State)

	// FailureRatio is the failure ratio threshold (0.0 to 1.0) for opening the circuit.
	// If set, the circuit opens when the failure ratio exceeds this threshold.
	// This is an alternative to MaxFailures for ratio-based triggering.
	FailureRatio float64

	// MinRequests is the minimum number of requests required before the failure ratio
	// is evaluated. This prevents the circuit from opening on the first few failures.
	MinRequests int

	// SamplingDuration is the duration over which failures are counted.
	// After this duration, the failure count is reset.
	SamplingDuration time.Duration
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		MaxFailures:      5,
		Timeout:          30 * time.Second,
		HalfOpenMax:      3,
		SuccessThreshold: 2,
		FailureRatio:     0,
		MinRequests:      10,
		SamplingDuration: time.Minute,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.MaxFailures < 1 {
		c.MaxFailures = 5
	}
	if c.Timeout < time.Millisecond {
		c.Timeout = 30 * time.Second
	}
	if c.HalfOpenMax < 1 {
		c.HalfOpenMax = 3
	}
	if c.SuccessThreshold < 1 {
		c.SuccessThreshold = 2
	}
	if c.FailureRatio < 0 || c.FailureRatio > 1 {
		c.FailureRatio = 0
	}
	if c.MinRequests < 1 {
		c.MinRequests = 10
	}
	if c.SamplingDuration < time.Second {
		c.SamplingDuration = time.Minute
	}
	return nil
}

// WithMaxFailures sets the maximum failures.
func (c *Config) WithMaxFailures(n int) *Config {
	c.MaxFailures = n
	return c
}

// WithTimeout sets the timeout duration.
func (c *Config) WithTimeout(d time.Duration) *Config {
	c.Timeout = d
	return c
}

// WithHalfOpenMax sets the maximum half-open requests.
func (c *Config) WithHalfOpenMax(n int) *Config {
	c.HalfOpenMax = n
	return c
}

// WithSuccessThreshold sets the success threshold.
func (c *Config) WithSuccessThreshold(n int) *Config {
	c.SuccessThreshold = n
	return c
}

// WithIsSuccessful sets the success check function.
func (c *Config) WithIsSuccessful(fn func(err error) bool) *Config {
	c.IsSuccessful = fn
	return c
}

// WithOnStateChange sets the state change callback.
func (c *Config) WithOnStateChange(fn func(name string, from, to State)) *Config {
	c.OnStateChange = fn
	return c
}

// WithFailureRatio sets the failure ratio threshold.
func (c *Config) WithFailureRatio(ratio float64) *Config {
	c.FailureRatio = ratio
	return c
}

// WithMinRequests sets the minimum requests for ratio calculation.
func (c *Config) WithMinRequests(n int) *Config {
	c.MinRequests = n
	return c
}

// WithSamplingDuration sets the sampling duration.
func (c *Config) WithSamplingDuration(d time.Duration) *Config {
	c.SamplingDuration = d
	return c
}
