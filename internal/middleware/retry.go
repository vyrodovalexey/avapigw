package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// DefaultMaxBodySize is the default maximum body size for retry buffering (1MB).
const DefaultMaxBodySize = 1 << 20 // 1MB

// RetryConfig contains retry configuration.
type RetryConfig struct {
	Attempts      int
	PerTryTimeout time.Duration
	RetryOn       []string
	BackoffBase   time.Duration
	BackoffMax    time.Duration
	// MaxBodySize is the maximum request body size to buffer for retries.
	// Requests with bodies larger than this will not be retried.
	// Default is 1MB.
	MaxBodySize int64
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		Attempts:      3,
		PerTryTimeout: 10 * time.Second,
		RetryOn:       []string{"5xx", "reset", "connect-failure"},
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    10 * time.Second,
		MaxBodySize:   DefaultMaxBodySize,
	}
}

// Retry returns a middleware that retries failed requests.
func Retry(cfg RetryConfig, logger observability.Logger) func(http.Handler) http.Handler {
	// Ensure MaxBodySize has a sensible default
	maxBodySize := cfg.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = DefaultMaxBodySize
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip retry for WebSocket upgrade requests
			// WebSocket connections cannot be retried and require direct access to the connection
			if isWebSocketUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}

			bodyBytes, canRetry := readRequestBodyWithLimit(r, maxBodySize, logger)
			if !canRetry {
				// Body too large for retry buffering, execute without retry
				next.ServeHTTP(w, r)
				return
			}
			executeWithRetry(w, r, next, cfg, bodyBytes, logger)
		})
	}
}

// readRequestBodyWithLimit reads and buffers the request body up to maxSize.
// Returns the body bytes and a boolean indicating if the request can be retried.
// If the body exceeds maxSize, returns nil and false, and the original body is preserved.
func readRequestBodyWithLimit(r *http.Request, maxSize int64, logger observability.Logger) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}

	// Check Content-Length header first for early rejection
	if r.ContentLength > maxSize {
		logger.Debug("request body too large for retry buffering",
			observability.Int64("content_length", r.ContentLength),
			observability.Int64("max_size", maxSize),
		)
		return nil, false
	}

	// Read up to maxSize + 1 to detect if body exceeds limit
	limitedReader := io.LimitReader(r.Body, maxSize+1)
	bodyBytes, err := io.ReadAll(limitedReader)
	_ = r.Body.Close()

	if err != nil {
		logger.Warn("failed to read request body for retry",
			observability.Error(err),
		)
		return nil, false
	}

	// Check if body exceeded the limit
	if int64(len(bodyBytes)) > maxSize {
		logger.Debug("request body too large for retry buffering",
			observability.Int64("body_size", int64(len(bodyBytes))),
			observability.Int64("max_size", maxSize),
		)
		// Restore the body for the single attempt
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil, false
	}

	return bodyBytes, true
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
			header:         make(http.Header),
			status:         http.StatusOK,
		}

		ctxWithCancel := applyPerTryTimeout(r.Context(), cfg.PerTryTimeout)
		//nolint:contextcheck // Derived context with timeout is correct
		next.ServeHTTP(rw, r.WithContext(ctxWithCancel.ctx))
		ctxWithCancel.cancel() // Release context resources after request completion

		lastStatus = rw.status

		if !shouldRetry(rw.status, cfg.RetryOn) {
			if attempt > 0 {
				GetMiddlewareMetrics().retrySuccessTotal.WithLabelValues(
					r.URL.Path,
				).Inc()
			}
			writeResponse(w, rw)
			return
		}

		logRetryAttempt(logger, r, attempt, cfg.Attempts, rw.status)

		if attempt < cfg.Attempts-1 {
			backoff := retry.CalculateBackoff(
				attempt, cfg.BackoffBase, cfg.BackoffMax,
				retry.DefaultJitterFactor,
			)
			select {
			case <-time.After(backoff):
				// Continue with retry
			case <-r.Context().Done():
				// Client disconnected, stop retrying
				writeRetryExhaustedResponse(w, r, cfg.Attempts, lastStatus, logger)
				return
			}
		}
	}

	writeRetryExhaustedResponse(w, r, cfg.Attempts, lastStatus, logger)
}

// contextWithCancel holds a context and its cancel function.
type contextWithCancel struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// applyPerTryTimeout applies timeout to context if configured.
// Returns the new context and a cancel function that must be called to release resources.
func applyPerTryTimeout(ctx context.Context, timeout time.Duration) contextWithCancel {
	if timeout > 0 {
		newCtx, cancel := context.WithTimeout(ctx, timeout)
		return contextWithCancel{ctx: newCtx, cancel: cancel}
	}
	return contextWithCancel{ctx: ctx, cancel: func() {}}
}

// writeResponse writes the captured response to the client.
func writeResponse(w http.ResponseWriter, rw *retryResponseWriter) {
	// Copy captured headers to the actual ResponseWriter
	for key, values := range rw.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(rw.status)
	_, _ = w.Write(rw.body.Bytes())
}

// logRetryAttempt logs a retry attempt.
func logRetryAttempt(
	logger observability.Logger,
	r *http.Request,
	attempt, maxAttempts, status int,
) {
	logger.Warn("retrying request",
		observability.String("path", r.URL.Path),
		observability.Int("attempt", attempt+1),
		observability.Int("max_attempts", maxAttempts),
		observability.Int("status", status),
	)

	GetMiddlewareMetrics().retryAttemptsTotal.WithLabelValues(
		r.URL.Path,
	).Inc()

	// Record route-level retry attempt
	routeName := util.RouteFromContext(r.Context())
	if routeName == "" {
		routeName = unknownRoute
	}
	routepkg.GetRouteMetrics().RecordRetry(routeName, r.Method)
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

	// Record route-level retry exhaustion
	routeName := util.RouteFromContext(r.Context())
	if routeName == "" {
		routeName = unknownRoute
	}
	routepkg.GetRouteMetrics().RecordRetryExhausted(
		routeName, r.Method,
	)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, ErrBadGateway)
}

// retryResponseWriter captures the response for potential retries.
type retryResponseWriter struct {
	http.ResponseWriter
	body          *bytes.Buffer
	header        http.Header
	status        int
	headerWritten bool
}

// Header returns the captured response headers.
func (rw *retryResponseWriter) Header() http.Header {
	return rw.header
}

// WriteHeader captures the status code and marks headers as written.
func (rw *retryResponseWriter) WriteHeader(code int) {
	if rw.headerWritten {
		return
	}
	rw.headerWritten = true
	rw.status = code
}

// Write captures the response body.
func (rw *retryResponseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.body.Write(b)
}

// Flush implements http.Flusher interface.
// This is intentionally a no-op because retryResponseWriter buffers
// the entire response body for potential retry attempts. Flushing
// mid-response would prevent retries from working correctly.
func (rw *retryResponseWriter) Flush() {
	// no-op: response is buffered for retry, cannot flush mid-response
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
	case "reset":
		return status == http.StatusBadGateway
	case "connect-failure":
		return status == http.StatusBadGateway || status == http.StatusServiceUnavailable
	default:
		return false
	}
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
