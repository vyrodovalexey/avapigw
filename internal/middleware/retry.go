package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// RetryConfig contains retry configuration.
type RetryConfig struct {
	Attempts      int
	PerTryTimeout time.Duration
	RetryOn       []string
	BackoffBase   time.Duration
	BackoffMax    time.Duration
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		Attempts:      3,
		PerTryTimeout: 10 * time.Second,
		RetryOn:       []string{"5xx", "reset", "connect-failure"},
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    10 * time.Second,
	}
}

// Retry returns a middleware that retries failed requests.
func Retry(cfg RetryConfig, logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes := readRequestBody(r)
			executeWithRetry(w, r, next, cfg, bodyBytes, logger)
		})
	}
}

// readRequestBody reads and buffers the request body.
func readRequestBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	bodyBytes, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	return bodyBytes
}

// executeWithRetry executes the request with retry logic.
func executeWithRetry(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	cfg RetryConfig,
	bodyBytes []byte,
	logger observability.Logger,
) {
	var lastStatus int

	for attempt := 0; attempt < cfg.Attempts; attempt++ {
		if len(bodyBytes) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		rw := &retryResponseWriter{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
			status:         http.StatusOK,
		}

		ctx := applyPerTryTimeout(r.Context(), cfg.PerTryTimeout)
		next.ServeHTTP(rw, r.WithContext(ctx))

		lastStatus = rw.status

		if !shouldRetry(rw.status, cfg.RetryOn) {
			writeResponse(w, rw)
			return
		}

		logRetryAttempt(logger, r, attempt, cfg.Attempts, rw.status)

		if attempt < cfg.Attempts-1 {
			backoff := calculateBackoff(attempt, cfg.BackoffBase, cfg.BackoffMax)
			time.Sleep(backoff)
		}
	}

	writeRetryExhaustedResponse(w, r, cfg.Attempts, lastStatus, logger)
}

// applyPerTryTimeout applies timeout to context if configured.
func applyPerTryTimeout(ctx context.Context, timeout time.Duration) context.Context {
	if timeout > 0 {
		ctx, _ = context.WithTimeout(ctx, timeout) //nolint:govet // cancel handled by request completion
	}
	return ctx
}

// writeResponse writes the captured response to the client.
func writeResponse(w http.ResponseWriter, rw *retryResponseWriter) {
	if !rw.headerWritten {
		w.WriteHeader(rw.status)
	}
	_, _ = w.Write(rw.body.Bytes())
}

// logRetryAttempt logs a retry attempt.
func logRetryAttempt(logger observability.Logger, r *http.Request, attempt, maxAttempts, status int) {
	logger.Warn("retrying request",
		observability.String("path", r.URL.Path),
		observability.Int("attempt", attempt+1),
		observability.Int("max_attempts", maxAttempts),
		observability.Int("status", status),
	)
}

// writeRetryExhaustedResponse writes the response when all retries are exhausted.
func writeRetryExhaustedResponse(
	w http.ResponseWriter,
	r *http.Request,
	attempts, lastStatus int,
	logger observability.Logger,
) {
	logger.Error("all retries exhausted",
		observability.String("path", r.URL.Path),
		observability.Int("attempts", attempts),
		observability.Int("last_status", lastStatus),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, `{"error":"bad gateway","message":"all retries exhausted"}`)
}

// retryResponseWriter captures the response for potential retries.
type retryResponseWriter struct {
	http.ResponseWriter
	body          *bytes.Buffer
	status        int
	headerWritten bool
}

// WriteHeader captures the status code.
func (rw *retryResponseWriter) WriteHeader(code int) {
	rw.status = code
}

// Write captures the response body.
func (rw *retryResponseWriter) Write(b []byte) (int, error) {
	return rw.body.Write(b)
}

// shouldRetry determines if a request should be retried based on status.
func shouldRetry(status int, retryOn []string) bool {
	for _, condition := range retryOn {
		if matchRetryCondition(status, condition) {
			return true
		}
	}
	return false
}

// matchRetryCondition checks if status matches a retry condition.
func matchRetryCondition(status int, condition string) bool {
	switch condition {
	case "5xx":
		return status >= 500 && status < 600
	case "retriable-4xx":
		return status == 408 || status == 429
	default:
		return false
	}
}

// calculateBackoff calculates exponential backoff with jitter.
func calculateBackoff(attempt int, base, maxBackoff time.Duration) time.Duration {
	backoff := float64(base) * math.Pow(2, float64(attempt))
	jitter := backoff * 0.25 * secureRandomFloat()
	backoff += jitter

	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	return time.Duration(backoff)
}

// secureRandomFloat returns a cryptographically secure random float64 between 0 and 1.
func secureRandomFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5 // fallback to middle value
	}
	return float64(binary.LittleEndian.Uint64(b[:])) / float64(^uint64(0))
}

// RetryFromConfig creates retry middleware from gateway config.
func RetryFromConfig(
	cfg *config.RetryPolicy,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if cfg == nil || cfg.Attempts <= 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	retryConfig := RetryConfig{
		Attempts:      cfg.Attempts,
		PerTryTimeout: cfg.PerTryTimeout.Duration(),
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    10 * time.Second,
	}

	if cfg.RetryOn != "" {
		retryConfig.RetryOn = strings.Split(cfg.RetryOn, ",")
	} else {
		retryConfig.RetryOn = []string{"5xx", "reset", "connect-failure"}
	}

	return Retry(retryConfig, logger)
}
