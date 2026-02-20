package middleware

import (
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/encoding"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// EncodingFromConfig creates an HTTP middleware that performs content
// negotiation and records encoding metrics (negotiation, decode for
// incoming request bodies, encode for outgoing response bodies).
// Full transcoding between formats can be added later.
func EncodingFromConfig(
	cfg *config.EncodingConfig,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if cfg == nil || cfg.IsEmpty() {
		return func(next http.Handler) http.Handler { return next }
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	metrics := encoding.GetEncodingMetrics()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recordDecodeMetric(r, metrics, logger)
			negotiateContentType(w, r, cfg, metrics, logger)

			next.ServeHTTP(w, r)

			recordEncodeMetric(w, r, metrics, logger)
		})
	}
}

// recordDecodeMetric records a decode metric when the incoming request
// carries a body with a supported content type.
func recordDecodeMetric(
	r *http.Request,
	metrics *encoding.EncodingMetrics,
	logger observability.Logger,
) {
	reqContentType := r.Header.Get("Content-Type")
	if reqContentType == "" || r.ContentLength <= 0 {
		return
	}

	normalized := encoding.NormalizeContentType(reqContentType)
	if !encoding.IsSupportedEncoding(normalized) {
		return
	}

	metrics.RecordDecode(normalized, "success")
	logger.Debug("request decode metric recorded",
		observability.String("path", r.URL.Path),
		observability.String("content_type", normalized),
	)
}

// negotiateContentType performs content negotiation when enabled and
// records the negotiation metric. It also sets the X-Content-Type-Negotiated
// response header as a hint for downstream consumers.
func negotiateContentType(
	w http.ResponseWriter,
	r *http.Request,
	cfg *config.EncodingConfig,
	metrics *encoding.EncodingMetrics,
	logger observability.Logger,
) {
	if !cfg.EnableContentNegotiation {
		return
	}

	acceptHeader := r.Header.Get("Accept")
	negotiated := encoding.GetContentTypeFromConfig(cfg, acceptHeader)

	if negotiated == "" {
		return
	}

	metrics.RecordNegotiation(negotiated, "success")
	w.Header().Set("X-Content-Type-Negotiated", negotiated)
	logger.Debug("content negotiation completed",
		observability.String("path", r.URL.Path),
		observability.String("accept", acceptHeader),
		observability.String("negotiated", negotiated),
	)
}

// recordEncodeMetric records an encode metric after the downstream handler
// has written its response headers, provided the response content type is
// a supported encoding.
func recordEncodeMetric(
	w http.ResponseWriter,
	r *http.Request,
	metrics *encoding.EncodingMetrics,
	logger observability.Logger,
) {
	respContentType := w.Header().Get("Content-Type")
	if respContentType == "" {
		return
	}

	normalized := encoding.NormalizeContentType(respContentType)
	if !encoding.IsSupportedEncoding(normalized) {
		return
	}

	metrics.RecordEncode(normalized, "success")
	logger.Debug("response encode metric recorded",
		observability.String("path", r.URL.Path),
		observability.String("content_type", normalized),
	)
}
