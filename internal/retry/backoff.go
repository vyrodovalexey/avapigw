package retry

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// Backoff defines the interface for backoff strategies.
type Backoff interface {
	// Next returns the duration to wait before the next retry attempt.
	Next(attempt int) time.Duration

	// Reset resets the backoff state.
	Reset()
}

// ExponentialBackoff implements exponential backoff with optional jitter.
type ExponentialBackoff struct {
	initial time.Duration
	max     time.Duration
	factor  float64
	jitter  float64

	mu   sync.Mutex
	rand *rand.Rand
}

// NewExponentialBackoff creates a new exponential backoff.
func NewExponentialBackoff(initial, max time.Duration, factor, jitter float64) *ExponentialBackoff {
	return &ExponentialBackoff{
		initial: initial,
		max:     max,
		factor:  factor,
		jitter:  jitter,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Next implements Backoff.
func (b *ExponentialBackoff) Next(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	// Calculate base backoff: initial * factor^attempt
	backoff := float64(b.initial) * math.Pow(b.factor, float64(attempt))

	// Apply maximum
	if backoff > float64(b.max) {
		backoff = float64(b.max)
	}

	// Apply jitter
	if b.jitter > 0 {
		b.mu.Lock()
		jitterRange := backoff * b.jitter
		jitterValue := (b.rand.Float64() * 2 * jitterRange) - jitterRange
		backoff += jitterValue
		b.mu.Unlock()
	}

	// Ensure non-negative
	if backoff < 0 {
		backoff = 0
	}

	return time.Duration(backoff)
}

// Reset implements Backoff.
func (b *ExponentialBackoff) Reset() {
	// ExponentialBackoff is stateless, nothing to reset
}

// ConstantBackoff implements constant backoff.
type ConstantBackoff struct {
	interval time.Duration
}

// NewConstantBackoff creates a new constant backoff.
func NewConstantBackoff(interval time.Duration) *ConstantBackoff {
	return &ConstantBackoff{
		interval: interval,
	}
}

// Next implements Backoff.
func (b *ConstantBackoff) Next(attempt int) time.Duration {
	return b.interval
}

// Reset implements Backoff.
func (b *ConstantBackoff) Reset() {
	// ConstantBackoff is stateless, nothing to reset
}

// LinearBackoff implements linear backoff.
type LinearBackoff struct {
	initial   time.Duration
	increment time.Duration
	max       time.Duration
}

// NewLinearBackoff creates a new linear backoff.
func NewLinearBackoff(initial, increment, max time.Duration) *LinearBackoff {
	return &LinearBackoff{
		initial:   initial,
		increment: increment,
		max:       max,
	}
}

// Next implements Backoff.
func (b *LinearBackoff) Next(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	backoff := b.initial + time.Duration(attempt)*b.increment

	if backoff > b.max {
		backoff = b.max
	}

	return backoff
}

// Reset implements Backoff.
func (b *LinearBackoff) Reset() {
	// LinearBackoff is stateless, nothing to reset
}

// FibonacciBackoff implements Fibonacci backoff.
type FibonacciBackoff struct {
	initial time.Duration
	max     time.Duration
}

// NewFibonacciBackoff creates a new Fibonacci backoff.
func NewFibonacciBackoff(initial, max time.Duration) *FibonacciBackoff {
	return &FibonacciBackoff{
		initial: initial,
		max:     max,
	}
}

// Next implements Backoff.
func (b *FibonacciBackoff) Next(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	// Calculate Fibonacci number
	fib := fibonacci(attempt + 1)
	backoff := time.Duration(fib) * b.initial

	if backoff > b.max {
		backoff = b.max
	}

	return backoff
}

// Reset implements Backoff.
func (b *FibonacciBackoff) Reset() {
	// FibonacciBackoff is stateless, nothing to reset
}

// fibonacci returns the nth Fibonacci number.
func fibonacci(n int) int {
	if n <= 0 {
		return 0
	}
	if n == 1 {
		return 1
	}

	a, b := 0, 1
	for i := 2; i <= n; i++ {
		a, b = b, a+b
	}
	return b
}

// DecorrelatedJitterBackoff implements AWS-style decorrelated jitter backoff.
type DecorrelatedJitterBackoff struct {
	initial time.Duration
	max     time.Duration

	mu      sync.Mutex
	rand    *rand.Rand
	current time.Duration
}

// NewDecorrelatedJitterBackoff creates a new decorrelated jitter backoff.
func NewDecorrelatedJitterBackoff(initial, max time.Duration) *DecorrelatedJitterBackoff {
	return &DecorrelatedJitterBackoff{
		initial: initial,
		max:     max,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
		current: initial,
	}
}

// Next implements Backoff.
func (b *DecorrelatedJitterBackoff) Next(attempt int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	if attempt == 0 {
		b.current = b.initial
		return b.current
	}

	// sleep = min(cap, random_between(base, sleep * 3))
	minBackoff := float64(b.initial)
	maxBackoff := float64(b.current) * 3

	backoff := minBackoff + b.rand.Float64()*(maxBackoff-minBackoff)

	if backoff > float64(b.max) {
		backoff = float64(b.max)
	}

	b.current = time.Duration(backoff)
	return b.current
}

// Reset implements Backoff.
func (b *DecorrelatedJitterBackoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.current = b.initial
}

// BackoffConfig holds configuration for creating backoff strategies.
type BackoffConfig struct {
	// Type is the backoff strategy type.
	Type BackoffType

	// InitialInterval is the initial backoff interval.
	InitialInterval time.Duration

	// MaxInterval is the maximum backoff interval.
	MaxInterval time.Duration

	// Multiplier is the factor by which the backoff increases (for exponential).
	Multiplier float64

	// Jitter is the random jitter factor (0.0 to 1.0).
	Jitter float64

	// Increment is the linear increment (for linear backoff).
	Increment time.Duration
}

// BackoffType represents the type of backoff strategy.
type BackoffType string

const (
	// BackoffTypeExponential uses exponential backoff with optional jitter.
	BackoffTypeExponential BackoffType = "exponential"

	// BackoffTypeDecorrelatedJitter uses AWS-style decorrelated jitter backoff.
	BackoffTypeDecorrelatedJitter BackoffType = "decorrelated_jitter"

	// BackoffTypeConstant uses constant backoff.
	BackoffTypeConstant BackoffType = "constant"

	// BackoffTypeLinear uses linear backoff.
	BackoffTypeLinear BackoffType = "linear"

	// BackoffTypeFibonacci uses Fibonacci backoff.
	BackoffTypeFibonacci BackoffType = "fibonacci"
)

// DefaultBackoffConfig returns a BackoffConfig with default values.
// Uses decorrelated jitter backoff which is recommended for preventing
// thundering herd problems in distributed systems.
func DefaultBackoffConfig() *BackoffConfig {
	return &BackoffConfig{
		Type:            BackoffTypeDecorrelatedJitter,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          0.2,
		Increment:       100 * time.Millisecond,
	}
}

// ExternalServiceBackoffConfig returns a BackoffConfig optimized for
// external service connections (Vault, Redis, etc.).
func ExternalServiceBackoffConfig() *BackoffConfig {
	return &BackoffConfig{
		Type:            BackoffTypeDecorrelatedJitter,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     60 * time.Second,
		Multiplier:      2.0,
		Jitter:          0.3,
	}
}

// NewBackoffFromConfig creates a Backoff from the given configuration.
func NewBackoffFromConfig(config *BackoffConfig) Backoff {
	if config == nil {
		config = DefaultBackoffConfig()
	}

	switch config.Type {
	case BackoffTypeExponential:
		return NewExponentialBackoff(
			config.InitialInterval,
			config.MaxInterval,
			config.Multiplier,
			config.Jitter,
		)
	case BackoffTypeDecorrelatedJitter:
		return NewDecorrelatedJitterBackoff(
			config.InitialInterval,
			config.MaxInterval,
		)
	case BackoffTypeConstant:
		return NewConstantBackoff(config.InitialInterval)
	case BackoffTypeLinear:
		return NewLinearBackoff(
			config.InitialInterval,
			config.Increment,
			config.MaxInterval,
		)
	case BackoffTypeFibonacci:
		return NewFibonacciBackoff(
			config.InitialInterval,
			config.MaxInterval,
		)
	default:
		// Default to decorrelated jitter
		return NewDecorrelatedJitterBackoff(
			config.InitialInterval,
			config.MaxInterval,
		)
	}
}

// FullJitterBackoff implements full jitter backoff strategy.
// sleep = random_between(0, min(cap, base * 2^attempt))
// This provides the best distribution for preventing thundering herd.
type FullJitterBackoff struct {
	initial time.Duration
	max     time.Duration

	mu   sync.Mutex
	rand *rand.Rand
}

// NewFullJitterBackoff creates a new full jitter backoff.
func NewFullJitterBackoff(initial, max time.Duration) *FullJitterBackoff {
	return &FullJitterBackoff{
		initial: initial,
		max:     max,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec
	}
}

// Next implements Backoff.
func (b *FullJitterBackoff) Next(attempt int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	if attempt < 0 {
		attempt = 0
	}

	// Calculate exponential backoff ceiling
	ceiling := float64(b.initial) * math.Pow(2, float64(attempt))
	if ceiling > float64(b.max) {
		ceiling = float64(b.max)
	}

	// Full jitter: random between 0 and ceiling
	backoff := b.rand.Float64() * ceiling

	return time.Duration(backoff)
}

// Reset implements Backoff.
func (b *FullJitterBackoff) Reset() {
	// FullJitterBackoff is stateless, nothing to reset
}

// EqualJitterBackoff implements equal jitter backoff strategy.
// sleep = (base * 2^attempt) / 2 + random_between(0, (base * 2^attempt) / 2)
// This provides a balance between full jitter and no jitter.
type EqualJitterBackoff struct {
	initial time.Duration
	max     time.Duration

	mu   sync.Mutex
	rand *rand.Rand
}

// NewEqualJitterBackoff creates a new equal jitter backoff.
func NewEqualJitterBackoff(initial, max time.Duration) *EqualJitterBackoff {
	return &EqualJitterBackoff{
		initial: initial,
		max:     max,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec
	}
}

// Next implements Backoff.
func (b *EqualJitterBackoff) Next(attempt int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	if attempt < 0 {
		attempt = 0
	}

	// Calculate exponential backoff
	expBackoff := float64(b.initial) * math.Pow(2, float64(attempt))
	if expBackoff > float64(b.max) {
		expBackoff = float64(b.max)
	}

	// Equal jitter: half fixed + half random
	halfBackoff := expBackoff / 2
	backoff := halfBackoff + b.rand.Float64()*halfBackoff

	return time.Duration(backoff)
}

// Reset implements Backoff.
func (b *EqualJitterBackoff) Reset() {
	// EqualJitterBackoff is stateless, nothing to reset
}
