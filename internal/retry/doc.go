// Package retry provides exponential backoff retry functionality for
// the API Gateway.
//
// This package implements configurable retry logic with exponential
// backoff and jitter for resilient communication with external
// services.
//
// # Features
//
//   - Configurable maximum retry attempts
//   - Exponential backoff with configurable base and maximum
//   - Jitter factor to prevent thundering herd
//   - Context-aware cancellation support
//   - Customizable retry condition functions
//
// # Usage
//
// Execute an operation with retry:
//
//	cfg := retry.DefaultConfig()
//	err := retry.Do(ctx, cfg, func(ctx context.Context) error {
//	    return callExternalService(ctx)
//	})
//
// # Configuration
//
// Customize retry behavior:
//
//	cfg := &retry.Config{
//	    MaxRetries:     5,
//	    InitialBackoff: 200 * time.Millisecond,
//	    MaxBackoff:     10 * time.Second,
//	    JitterFactor:   0.25,
//	}
package retry
