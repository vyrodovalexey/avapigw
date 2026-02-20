package middleware

import (
	"io"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// BodyLimit returns a middleware that limits the request body size.
// If the request body exceeds the limit, it returns a 413 Request Entity Too Large error.
func BodyLimit(maxSize int64, logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check Content-Length header first for early rejection
			if r.ContentLength > maxSize {
				logger.Warn("request body too large",
					observability.Int64("content_length", r.ContentLength),
					observability.Int64("max_size", maxSize),
					observability.String("path", r.URL.Path),
				)

				GetMiddlewareMetrics().bodyLimitRejected.Inc()

				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = io.WriteString(w, ErrRequestEntityTooLarge)
				return
			}

			// Wrap the body with a limited reader to enforce the limit during reading
			if r.Body != nil {
				r.Body = &limitedReadCloser{
					ReadCloser: r.Body,
					remaining:  maxSize,
					exceeded:   false,
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimitFromConfig creates body limit middleware from gateway config.
func BodyLimitFromConfig(cfg *config.RequestLimitsConfig, logger observability.Logger) func(http.Handler) http.Handler {
	maxSize := cfg.GetEffectiveMaxBodySize()
	return BodyLimit(maxSize, logger)
}

// BodyLimitFromRequestLimits creates body limit middleware from RequestLimitsConfig.
// This function supports both global and route-level limits.
// If cfg is nil, default limits are used.
func BodyLimitFromRequestLimits(
	cfg *config.RequestLimitsConfig,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = config.DefaultRequestLimits()
	}
	return BodyLimitFromConfig(cfg, logger)
}

// limitedReadCloser wraps an io.ReadCloser and limits the number of bytes that can be read.
type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
	exceeded  bool
}

// Read reads up to len(p) bytes into p, respecting the remaining limit.
func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	if l.remaining <= 0 {
		l.exceeded = true
		return 0, &bodySizeExceededError{}
	}

	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}

	n, err = l.ReadCloser.Read(p)
	l.remaining -= int64(n)

	return n, err
}

// bodySizeExceededError is returned when the body size limit is exceeded.
type bodySizeExceededError struct{}

func (e *bodySizeExceededError) Error() string {
	return "request body size exceeded"
}
