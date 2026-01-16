package vault

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BackoffFunc calculates the backoff duration for a given attempt.
type BackoffFunc func(attempt int) time.Duration

// BackoffType represents the type of backoff strategy.
type BackoffType string

const (
	// BackoffTypeExponential uses exponential backoff with jitter.
	BackoffTypeExponential BackoffType = "exponential"

	// BackoffTypeDecorrelatedJitter uses AWS-style decorrelated jitter backoff.
	// This is recommended for preventing thundering herd problems.
	BackoffTypeDecorrelatedJitter BackoffType = "decorrelated_jitter"

	// BackoffTypeFullJitter uses full jitter backoff.
	BackoffTypeFullJitter BackoffType = "full_jitter"

	// BackoffTypeEqualJitter uses equal jitter backoff.
	BackoffTypeEqualJitter BackoffType = "equal_jitter"

	// BackoffTypeConstant uses constant backoff.
	BackoffTypeConstant BackoffType = "constant"

	// BackoffTypeLinear uses linear backoff.
	BackoffTypeLinear BackoffType = "linear"
)

// RetryConfig holds configuration for retry operations.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int

	// WaitMin is the minimum wait time between retries.
	WaitMin time.Duration

	// WaitMax is the maximum wait time between retries.
	WaitMax time.Duration

	// BackoffType is the type of backoff strategy to use.
	// If empty, defaults to decorrelated jitter.
	BackoffType BackoffType

	// BackoffMultiplier is the multiplier for exponential backoff.
	// Default is 2.0.
	BackoffMultiplier float64

	// Jitter is the jitter factor (0.0 to 1.0) for exponential backoff.
	// Default is 0.2.
	Jitter float64

	// BackoffFunc is the function to calculate backoff duration.
	// If nil, a backoff function is created based on BackoffType.
	BackoffFunc BackoffFunc

	// RetryIf is a function that determines if an error is retryable.
	// If nil, IsRetryable is used.
	RetryIf func(error) bool

	// OperationName is the name of the operation for logging and metrics.
	OperationName string

	// Logger for logging retry attempts.
	Logger *zap.Logger
}

// DefaultRetryConfig returns a RetryConfig with default values.
// Uses decorrelated jitter backoff which is recommended for preventing
// thundering herd problems in distributed systems.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:        3,
		WaitMin:           500 * time.Millisecond,
		WaitMax:           30 * time.Second,
		BackoffType:       BackoffTypeDecorrelatedJitter,
		BackoffMultiplier: 2.0,
		Jitter:            0.2,
		OperationName:     "vault_operation",
	}
}

// ExternalServiceRetryConfig returns a RetryConfig optimized for
// external service connections (Vault, Redis, etc.).
func ExternalServiceRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:        5,
		WaitMin:           500 * time.Millisecond,
		WaitMax:           60 * time.Second,
		BackoffType:       BackoffTypeDecorrelatedJitter,
		BackoffMultiplier: 2.0,
		Jitter:            0.3,
		OperationName:     "external_service",
	}
}

// WithRetry executes a function with retry logic.
func WithRetry(ctx context.Context, config *RetryConfig, fn func() error) error {
	rc := normalizeRetryConfig(config)
	startTime := time.Now()

	var lastErr error
	for attempt := 0; attempt <= rc.maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := fn()
		if err == nil {
			logRetrySuccess(rc.logger, rc.operationName, attempt, startTime)
			return nil
		}

		lastErr = err
		if !rc.retryIf(err) {
			rc.logger.Debug("error is not retryable", zap.String("operation", rc.operationName), zap.Error(err))
			return err
		}

		if attempt >= rc.maxRetries {
			logRetryExhausted(rc.logger, rc.operationName, rc.maxRetries, startTime, lastErr)
			break
		}

		if err := waitForRetryBackoff(ctx, rc, attempt, lastErr); err != nil {
			return err
		}
	}

	return buildRetryExhaustedError(lastErr)
}

// retryContext holds normalized retry configuration.
type retryContext struct {
	backoff       BackoffFunc
	retryIf       func(error) bool
	operationName string
	logger        *zap.Logger
	maxRetries    int
}

// normalizeRetryConfig creates a normalized retry context from config.
func normalizeRetryConfig(config *RetryConfig) *retryContext {
	if config == nil {
		config = DefaultRetryConfig()
	}

	rc := &retryContext{
		backoff:       config.BackoffFunc,
		retryIf:       config.RetryIf,
		operationName: config.OperationName,
		logger:        config.Logger,
		maxRetries:    config.MaxRetries,
	}

	if rc.backoff == nil {
		rc.backoff = createBackoffFunc(config)
	}
	if rc.retryIf == nil {
		rc.retryIf = IsRetryable
	}
	if rc.operationName == "" {
		rc.operationName = "vault_operation"
	}
	if rc.logger == nil {
		rc.logger = zap.NewNop()
	}

	return rc
}

// logRetrySuccess logs successful operation after retries.
func logRetrySuccess(logger *zap.Logger, operationName string, attempt int, startTime time.Time) {
	if attempt > 0 {
		logger.Info("operation succeeded after retry",
			zap.String("operation", operationName),
			zap.Int("attempt", attempt+1),
			zap.Duration("total_duration", time.Since(startTime)),
		)
	}
}

// logRetryExhausted logs when all retry attempts are exhausted.
func logRetryExhausted(logger *zap.Logger, operationName string, maxRetries int, startTime time.Time, lastErr error) {
	logger.Warn("retry attempts exhausted",
		zap.String("operation", operationName),
		zap.Int("max_retries", maxRetries),
		zap.Duration("total_duration", time.Since(startTime)),
		zap.Error(lastErr),
	)
}

// waitForRetryBackoff waits for the backoff duration before retrying.
func waitForRetryBackoff(ctx context.Context, rc *retryContext, attempt int, err error) error {
	wait := rc.backoff(attempt)

	rc.logger.Debug("retrying operation",
		zap.String("operation", rc.operationName),
		zap.Int("attempt", attempt+1),
		zap.Int("max_retries", rc.maxRetries),
		zap.Duration("backoff", wait),
		zap.Error(err),
	)

	RecordRetry(rc.operationName, attempt+1)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

// buildRetryExhaustedError creates the final error when retries are exhausted.
func buildRetryExhaustedError(lastErr error) error {
	msg := ""
	if lastErr != nil {
		msg = lastErr.Error()
	}
	return &VaultError{
		Op:      "retry",
		Err:     ErrRetryExhausted,
		Message: msg,
	}
}

// createBackoffFunc creates a backoff function based on the configuration.
func createBackoffFunc(config *RetryConfig) BackoffFunc {
	multiplier := config.BackoffMultiplier
	if multiplier <= 0 {
		multiplier = 2.0
	}

	jitter := config.Jitter
	if jitter < 0 || jitter > 1 {
		jitter = 0.2
	}

	switch config.BackoffType {
	case BackoffTypeExponential:
		return ExponentialBackoffWithJitter(config.WaitMin, config.WaitMax, multiplier, jitter)
	case BackoffTypeDecorrelatedJitter:
		return DecorrelatedJitterBackoff(config.WaitMin, config.WaitMax)
	case BackoffTypeFullJitter:
		return FullJitterBackoff(config.WaitMin, config.WaitMax)
	case BackoffTypeEqualJitter:
		return EqualJitterBackoff(config.WaitMin, config.WaitMax)
	case BackoffTypeConstant:
		return ConstantBackoff(config.WaitMin)
	case BackoffTypeLinear:
		return LinearBackoff(config.WaitMin, config.WaitMin, config.WaitMax)
	default:
		// Default to decorrelated jitter for best thundering herd prevention
		return DecorrelatedJitterBackoff(config.WaitMin, config.WaitMax)
	}
}

// ExponentialBackoffWithJitter returns a backoff function that implements
// exponential backoff with jitter.
func ExponentialBackoffWithJitter(minWait, maxWait time.Duration, factor, jitter float64) BackoffFunc {
	var mu sync.Mutex
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // weak random is acceptable for jitter

	return func(attempt int) time.Duration {
		// Calculate base backoff: minWait * factor^attempt
		backoff := float64(minWait) * math.Pow(factor, float64(attempt))

		// Apply maximum
		if backoff > float64(maxWait) {
			backoff = float64(maxWait)
		}

		// Apply jitter
		if jitter > 0 {
			mu.Lock()
			jitterRange := backoff * jitter
			jitterValue := (r.Float64() * 2 * jitterRange) - jitterRange
			backoff += jitterValue
			mu.Unlock()
		}

		// Ensure non-negative and at least minWait
		if backoff < float64(minWait) {
			backoff = float64(minWait)
		}

		return time.Duration(backoff)
	}
}

// ConstantBackoff returns a backoff function that always returns the same duration.
func ConstantBackoff(d time.Duration) BackoffFunc {
	return func(attempt int) time.Duration {
		return d
	}
}

// LinearBackoff returns a backoff function that increases linearly.
func LinearBackoff(initial, increment, maxWait time.Duration) BackoffFunc {
	return func(attempt int) time.Duration {
		backoff := initial + time.Duration(attempt)*increment
		if backoff > maxWait {
			backoff = maxWait
		}
		return backoff
	}
}

// DecorrelatedJitterBackoff returns a backoff function that implements
// AWS-style decorrelated jitter backoff.
// This is the recommended strategy for preventing thundering herd problems.
// Formula: sleep = min(cap, random_between(base, sleep * 3))
func DecorrelatedJitterBackoff(minWait, maxWait time.Duration) BackoffFunc {
	var mu sync.Mutex
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // weak random is acceptable for jitter timing
	current := minWait

	return func(attempt int) time.Duration {
		mu.Lock()
		defer mu.Unlock()

		if attempt == 0 {
			current = minWait
			return current
		}

		// Calculate backoff using decorrelated jitter formula
		minBackoff := float64(minWait)
		maxBackoff := float64(current) * 3

		backoff := minBackoff + r.Float64()*(maxBackoff-minBackoff)

		if backoff > float64(maxWait) {
			backoff = float64(maxWait)
		}

		current = time.Duration(backoff)
		return current
	}
}

// FullJitterBackoff returns a backoff function that implements full jitter.
// Formula: sleep = random_between(0, min(cap, base * 2^attempt))
// This provides the best distribution for preventing thundering herd.
func FullJitterBackoff(minWait, maxWait time.Duration) BackoffFunc {
	var mu sync.Mutex
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // weak random is acceptable for jitter timing

	return func(attempt int) time.Duration {
		mu.Lock()
		defer mu.Unlock()

		if attempt < 0 {
			attempt = 0
		}

		// Calculate exponential backoff ceiling
		ceiling := float64(minWait) * math.Pow(2, float64(attempt))
		if ceiling > float64(maxWait) {
			ceiling = float64(maxWait)
		}

		// Full jitter: random between 0 and ceiling
		backoff := r.Float64() * ceiling

		// Ensure at least minWait
		if backoff < float64(minWait) {
			backoff = float64(minWait)
		}

		return time.Duration(backoff)
	}
}

// EqualJitterBackoff returns a backoff function that implements equal jitter.
// Formula: sleep = (base * 2^attempt) / 2 + random_between(0, (base * 2^attempt) / 2)
// This provides a balance between full jitter and no jitter.
func EqualJitterBackoff(minWait, maxWait time.Duration) BackoffFunc {
	var mu sync.Mutex
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // weak random is acceptable for jitter timing

	return func(attempt int) time.Duration {
		mu.Lock()
		defer mu.Unlock()

		if attempt < 0 {
			attempt = 0
		}

		// Calculate exponential backoff
		expBackoff := float64(minWait) * math.Pow(2, float64(attempt))
		if expBackoff > float64(maxWait) {
			expBackoff = float64(maxWait)
		}

		// Equal jitter: half fixed + half random
		halfBackoff := expBackoff / 2
		backoff := halfBackoff + r.Float64()*halfBackoff

		return time.Duration(backoff)
	}
}

// RetryableOperation wraps an operation with retry logic.
type RetryableOperation struct {
	config *RetryConfig
}

// NewRetryableOperation creates a new RetryableOperation.
func NewRetryableOperation(config *RetryConfig) *RetryableOperation {
	if config == nil {
		config = DefaultRetryConfig()
	}
	return &RetryableOperation{config: config}
}

// Do executes the operation with retry logic.
func (r *RetryableOperation) Do(ctx context.Context, fn func() error) error {
	return WithRetry(ctx, r.config, fn)
}

// DoWithResult executes an operation that returns a result with retry logic.
func DoWithResult[T any](ctx context.Context, config *RetryConfig, fn func() (T, error)) (T, error) {
	var result T
	err := WithRetry(ctx, config, func() error {
		var fnErr error
		result, fnErr = fn()
		return fnErr
	})
	return result, err
}
