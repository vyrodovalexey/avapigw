package middleware

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
)

// maxTransformBodySize is the maximum body size that will be buffered for
// transformation. Request or response bodies exceeding this limit are
// passed through without transformation.
const maxTransformBodySize = 10 << 20 // 10MB

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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply request transformation
			if cfg.Request != nil && !cfg.Request.IsEmpty() {
				if err := applyRequestTransform(r, cfg.Request, logger); err != nil {
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

				applyResponseTransform(w, r, recorder, cfg.Response, logger)
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
	cfg *config.RequestTransformConfig,
	logger observability.Logger,
) error {
	if r.Body == nil || r.ContentLength == 0 {
		// No body to transform — apply transform with nil data
		rt := transform.NewRequestTransformer(logger)
		_, err := rt.TransformRequest(r.Context(), nil, cfg)
		return err
	}

	limitedBody := io.LimitReader(r.Body, maxTransformBodySize+1)
	bodyBytes, err := io.ReadAll(limitedBody)
	if err != nil {
		return err
	}
	_ = r.Body.Close()

	// If the body exceeds the transform limit, restore it and skip transformation
	if int64(len(bodyBytes)) > maxTransformBodySize {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	var data interface{}
	if unmarshalErr := json.Unmarshal(bodyBytes, &data); unmarshalErr != nil {
		// Body is not JSON — restore original body and skip transform.
		// This is not an error condition: non-JSON bodies are passed through unchanged.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil //nolint:nilerr // intentional: non-JSON body is not an error
	}

	rt := transform.NewRequestTransformer(logger)
	transformed, err := rt.TransformRequest(r.Context(), data, cfg)
	if err != nil {
		// Restore original body on error
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return err
	}

	newBody, err := json.Marshal(transformed)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return err
	}

	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))

	return nil
}

// applyResponseTransform applies the response transformation to the captured
// response and writes the result to the original ResponseWriter.
func applyResponseTransform(
	w http.ResponseWriter,
	r *http.Request,
	recorder *transformResponseRecorder,
	cfg *config.ResponseTransformConfig,
	logger observability.Logger,
) {
	bodyBytes := recorder.body.Bytes()

	var data interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		// Not JSON — write original response as-is
		writeRecordedResponse(w, recorder, bodyBytes)
		return
	}

	rt := transform.NewResponseTransformer(logger)
	transformed, err := rt.TransformResponse(r.Context(), data, cfg)
	if err != nil {
		logger.Warn("response transform failed, returning original",
			observability.String("path", r.URL.Path),
			observability.Error(err),
		)
		writeRecordedResponse(w, recorder, bodyBytes)
		return
	}

	newBody, err := json.Marshal(transformed)
	if err != nil {
		writeRecordedResponse(w, recorder, bodyBytes)
		return
	}

	// Copy original headers
	for k, vals := range recorder.header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(recorder.statusCode)
	_, _ = w.Write(newBody)
}

// writeRecordedResponse writes the captured response back to the client unchanged.
func writeRecordedResponse(w http.ResponseWriter, recorder *transformResponseRecorder, body []byte) {
	for k, vals := range recorder.header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(recorder.statusCode)
	_, _ = w.Write(body)
}

// transformResponseRecorder captures the response for transformation.
type transformResponseRecorder struct {
	http.ResponseWriter
	statusCode     int
	body           *bytes.Buffer
	header         http.Header
	headerWritten  bool
	bufferExceeded bool
}

// Header returns the captured header map.
func (r *transformResponseRecorder) Header() http.Header {
	return r.header
}

// WriteHeader captures the status code.
func (r *transformResponseRecorder) WriteHeader(code int) {
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

		// Flush captured headers and status to the underlying writer
		for k, vals := range r.header {
			for _, v := range vals {
				r.ResponseWriter.Header().Add(k, v)
			}
		}
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
	// no-op: response is fully buffered for transformation
}

// Hijack implements http.Hijacker for WebSocket support.
func (r *transformResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
