package middleware

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
)

// maxTransformBodySize is the maximum body size that will be buffered for
// transformation. Request or response bodies exceeding this limit are
// passed through without transformation.
const maxTransformBodySize = 10 << 20 // 10MB

// Transform metric label values, kept in sync with the transform package's
// pre-registered label combinations (see internal/transform/metrics.go).
const (
	directionRequest  = "request"
	directionResponse = "response"

	resultSuccess     = "success"
	resultError       = "error"
	resultPassthrough = "passthrough"

	errorTypeGeneral = "general"
)

// TransformFromConfig creates an HTTP middleware that applies request and/or
// response transformations based on the provided configuration.
// Request transforms are applied before the handler; response transforms
// are applied after the handler completes.
func TransformFromConfig(
	cfg *config.TransformConfig,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if cfg == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	// The request and response transformers are stateless and reusable across
	// requests (they only hold the fixed logger and stateless helpers), so
	// they are constructed once here rather than per-request in the hot path.
	reqTransformer := transform.NewRequestTransformer(logger)
	respTransformer := transform.NewResponseTransformer(logger)
	metrics := transform.GetTransformMetrics()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply request transformation
			if cfg.Request != nil && !cfg.Request.IsEmpty() {
				if err := applyRequestTransform(r, reqTransformer, cfg.Request, metrics); err != nil {
					logger.Warn("request transform failed, passing through",
						observability.String("path", r.URL.Path),
						observability.Error(err),
					)
					// Continue without transformation — do not crash
				}
			}

			// If response transformation is needed, capture the response
			if cfg.Response != nil && !cfg.Response.IsEmpty() {
				recorder := &transformResponseRecorder{
					ResponseWriter: w,
					statusCode:     http.StatusOK,
					body:           &bytes.Buffer{},
					header:         make(http.Header),
				}

				next.ServeHTTP(recorder, r)

				// If the response body exceeded the buffer limit, it was
				// already forwarded directly to the client — skip transformation.
				if recorder.bufferExceeded {
					logger.Debug("response body exceeded max transform body size, skipping transform",
						observability.String("path", r.URL.Path),
					)
					return
				}

				applyResponseTransform(w, r, recorder, respTransformer, cfg.Response, logger, metrics)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// applyRequestTransform reads the request body, applies the transform, and
// replaces the body with the transformed result.
func applyRequestTransform(
	r *http.Request,
	rt transform.RequestTransformer,
	cfg *config.RequestTransformConfig,
	metrics *transform.TransformMetrics,
) error {
	start := time.Now()

	if r.Body == nil || r.ContentLength == 0 {
		// No body to transform — apply transform with nil data
		_, err := rt.TransformRequest(r.Context(), nil, cfg)
		recordRequestResult(metrics, start, err)
		return err
	}

	limitedBody := io.LimitReader(r.Body, maxTransformBodySize+1)
	bodyBytes, err := io.ReadAll(limitedBody)
	if err != nil {
		recordRequestResult(metrics, start, err)
		return err
	}
	_ = r.Body.Close()

	// If the body exceeds the transform limit, restore it and skip transformation
	if int64(len(bodyBytes)) > maxTransformBodySize {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		metrics.RecordOperation(directionRequest, resultPassthrough)
		metrics.RecordError(directionRequest, errorTypeGeneral)
		metrics.RecordDuration(directionRequest, time.Since(start))
		return nil
	}

	var data interface{}
	if unmarshalErr := json.Unmarshal(bodyBytes, &data); unmarshalErr != nil {
		// Body is not JSON — restore original body and skip transform.
		// This is not an error condition: non-JSON bodies are passed through unchanged.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		metrics.RecordOperation(directionRequest, resultPassthrough)
		metrics.RecordDuration(directionRequest, time.Since(start))
		return nil //nolint:nilerr // intentional: non-JSON body is not an error
	}

	transformed, err := rt.TransformRequest(r.Context(), data, cfg)
	if err != nil {
		// Restore original body on error
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		recordRequestResult(metrics, start, err)
		return err
	}

	newBody, err := json.Marshal(transformed)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		recordRequestResult(metrics, start, err)
		return err
	}

	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))

	recordRequestResult(metrics, start, nil)
	return nil
}

// recordRequestResult records the outcome of a request transform operation:
// success or error (with the general error type), plus the duration.
func recordRequestResult(metrics *transform.TransformMetrics, start time.Time, err error) {
	if err != nil {
		metrics.RecordOperation(directionRequest, resultError)
		metrics.RecordError(directionRequest, errorTypeGeneral)
	} else {
		metrics.RecordOperation(directionRequest, resultSuccess)
	}
	metrics.RecordDuration(directionRequest, time.Since(start))
}

// applyResponseTransform applies the response transformation to the captured
// response and writes the result to the original ResponseWriter.
func applyResponseTransform(
	w http.ResponseWriter,
	r *http.Request,
	recorder *transformResponseRecorder,
	rt transform.ResponseTransformer,
	cfg *config.ResponseTransformConfig,
	logger observability.Logger,
	metrics *transform.TransformMetrics,
) {
	// If the connection was hijacked (e.g. WebSocket upgrade), the caller
	// owns the connection; any further writes are invalid. Skip processing.
	if recorder.hijacked {
		return
	}

	start := time.Now()
	bodyBytes := recorder.body.Bytes()

	var data interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		// Not JSON — write original response as-is (passthrough, not an error).
		metrics.RecordOperation(directionResponse, resultPassthrough)
		metrics.RecordDuration(directionResponse, time.Since(start))
		writeRecordedResponse(w, recorder, bodyBytes)
		return
	}

	transformed, err := rt.TransformResponse(r.Context(), data, cfg)
	if err != nil {
		logger.Warn("response transform failed, returning original",
			observability.String("path", r.URL.Path),
			observability.Error(err),
		)
		metrics.RecordOperation(directionResponse, resultError)
		metrics.RecordError(directionResponse, errorTypeGeneral)
		metrics.RecordDuration(directionResponse, time.Since(start))
		writeRecordedResponse(w, recorder, bodyBytes)
		return
	}

	newBody, err := json.Marshal(transformed)
	if err != nil {
		metrics.RecordOperation(directionResponse, resultError)
		metrics.RecordError(directionResponse, errorTypeGeneral)
		metrics.RecordDuration(directionResponse, time.Since(start))
		writeRecordedResponse(w, recorder, bodyBytes)
		return
	}

	metrics.RecordOperation(directionResponse, resultSuccess)
	metrics.RecordDuration(directionResponse, time.Since(start))

	// Copy original headers, excluding Content-Length: the transformed
	// body almost always differs in size from the backend's original body,
	// so the recorded Content-Length would be wrong. Writing it verbatim
	// makes clients wait for bytes that never arrive (unexpected EOF).
	copyRecordedHeaders(w.Header(), recorder.header, true)
	w.Header().Set("Content-Type", "application/json")
	// Set the Content-Length to match the transformed body so the response
	// is framed correctly for the client.
	w.Header().Set("Content-Length", strconv.Itoa(len(newBody)))
	w.WriteHeader(recorder.statusCode)
	_, _ = w.Write(newBody)
}

// writeRecordedResponse writes the captured response back to the client unchanged.
func writeRecordedResponse(w http.ResponseWriter, recorder *transformResponseRecorder, body []byte) {
	copyRecordedHeaders(w.Header(), recorder.header, false)
	w.WriteHeader(recorder.statusCode)
	_, _ = w.Write(body)
}

// copyRecordedHeaders copies the recorded headers into dst using
// replace-per-key semantics: each captured key is first deleted from dst and
// then re-assigned, so headers already set by outer middleware are not
// duplicated. Multi-value headers are preserved. When skipContentLength is
// true, the Content-Length header is not copied (the caller sets it to match
// the transformed body).
func copyRecordedHeaders(dst, recorded http.Header, skipContentLength bool) {
	for k, vals := range recorded {
		if skipContentLength && http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		// Del then assign: replace any values an outer layer may have set.
		dst.Del(k)
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// transformResponseRecorder captures the response for transformation.
type transformResponseRecorder struct {
	http.ResponseWriter
	statusCode     int
	body           *bytes.Buffer
	header         http.Header
	headerWritten  bool
	bufferExceeded bool
	hijacked       bool
}

// Header returns the captured header map.
func (r *transformResponseRecorder) Header() http.Header {
	return r.header
}

// WriteHeader captures the status code.
func (r *transformResponseRecorder) WriteHeader(code int) {
	// Once the connection has been hijacked the underlying ResponseWriter
	// must not be used for status writes; ignore to avoid noisy net/http logs.
	if r.hijacked {
		return
	}
	if !r.headerWritten {
		r.statusCode = code
		r.headerWritten = true
	}
}

// Write captures the body bytes. If the accumulated body exceeds
// maxTransformBodySize, buffering stops: the already-buffered data and
// all subsequent writes are forwarded directly to the underlying
// ResponseWriter, bypassing transformation.
func (r *transformResponseRecorder) Write(b []byte) (int, error) {
	// After hijacking the connection is owned by the caller; writes through
	// the recorder are invalid and would trigger net/http errors.
	if r.hijacked {
		return 0, http.ErrHijacked
	}

	if !r.headerWritten {
		r.statusCode = http.StatusOK
		r.headerWritten = true
	}

	// Once the buffer limit is exceeded, forward directly to the client.
	if r.bufferExceeded {
		return r.ResponseWriter.Write(b)
	}

	if int64(r.body.Len())+int64(len(b)) > maxTransformBodySize {
		r.bufferExceeded = true

		// Flush captured headers and status to the underlying writer,
		// replacing per-key to avoid duplicating headers set by outer layers.
		copyRecordedHeaders(r.ResponseWriter.Header(), r.header, false)
		r.ResponseWriter.WriteHeader(r.statusCode)

		// Flush already-buffered data
		if r.body.Len() > 0 {
			_, _ = r.ResponseWriter.Write(r.body.Bytes())
			r.body.Reset()
		}

		// Forward the current chunk
		return r.ResponseWriter.Write(b)
	}

	return r.body.Write(b)
}

// Flush implements http.Flusher for streaming support.
func (r *transformResponseRecorder) Flush() {
	// After hijacking the underlying writer must not be touched.
	if r.hijacked {
		return
	}

	// While buffering for transformation there is nothing to flush: the
	// body is held in memory until the transform completes. This is an
	// intentional no-op in buffered mode.
	if !r.bufferExceeded {
		return
	}

	// Once buffering has been exceeded, writes are streamed directly to the
	// underlying ResponseWriter, so delegate Flush to it when supported.
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker for WebSocket support.
func (r *transformResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := h.Hijack()
		if err == nil {
			// Mark hijacked so subsequent WriteHeader/Write/Flush calls and
			// post-processing become no-ops on the now caller-owned connection.
			r.hijacked = true
		}
		return conn, rw, err
	}
	return nil, nil, http.ErrNotSupported
}
