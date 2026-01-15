package transform

import (
	"bytes"
	"io"
	"net/http"
)

// ResponseTransformer transforms HTTP responses.
type ResponseTransformer struct {
	headerModifier  *HeaderModifier
	bodyTransformer *BodyTransformer
}

// BodyTransformer transforms response bodies.
type BodyTransformer struct {
	transformers []BodyTransformFunc
}

// BodyTransformFunc is a function that transforms a response body.
type BodyTransformFunc func(body []byte) ([]byte, error)

// NewResponseTransformer creates a new response transformer.
func NewResponseTransformer() *ResponseTransformer {
	return &ResponseTransformer{
		headerModifier:  &HeaderModifier{set: make(map[string]string), add: make(map[string]string)},
		bodyTransformer: &BodyTransformer{transformers: make([]BodyTransformFunc, 0)},
	}
}

// Transform applies all transformations to the response.
func (t *ResponseTransformer) Transform(resp *http.Response) error {
	// Apply header modifications
	t.headerModifier.Modify(resp.Header)

	// Apply body transformations if any
	if len(t.bodyTransformer.transformers) > 0 {
		if err := t.transformBody(resp); err != nil {
			return err
		}
	}

	return nil
}

// SetHeaderModifications sets header modifications.
func (t *ResponseTransformer) SetHeaderModifications(set, add map[string]string, remove []string) {
	t.headerModifier.set = set
	t.headerModifier.add = add
	t.headerModifier.remove = remove
}

// AddBodyTransformer adds a body transformer.
func (t *ResponseTransformer) AddBodyTransformer(transformer BodyTransformFunc) {
	t.bodyTransformer.transformers = append(t.bodyTransformer.transformers, transformer)
}

// ClearBodyTransformers clears all body transformers.
func (t *ResponseTransformer) ClearBodyTransformers() {
	t.bodyTransformer.transformers = make([]BodyTransformFunc, 0)
}

// transformBody applies body transformations.
func (t *ResponseTransformer) transformBody(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}

	// Read the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Apply transformations
	for _, transformer := range t.bodyTransformer.transformers {
		body, err = transformer(body)
		if err != nil {
			return err
		}
	}

	// Replace the body
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", string(rune(len(body))))

	return nil
}

// ResponseWriter wraps http.ResponseWriter to capture and transform responses.
type ResponseWriter struct {
	http.ResponseWriter
	transformer   *ResponseTransformer
	statusCode    int
	body          *bytes.Buffer
	headerWritten bool
	transformBody bool
}

// NewResponseWriter creates a new response writer wrapper.
func NewResponseWriter(w http.ResponseWriter, transformer *ResponseTransformer, transformBody bool) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		transformer:    transformer,
		body:           &bytes.Buffer{},
		transformBody:  transformBody,
	}
}

// WriteHeader captures the status code and applies header transformations.
func (rw *ResponseWriter) WriteHeader(statusCode int) {
	if rw.headerWritten {
		return
	}

	rw.statusCode = statusCode

	// Apply header transformations
	if rw.transformer != nil {
		rw.transformer.headerModifier.Modify(rw.Header())
	}

	if !rw.transformBody {
		rw.ResponseWriter.WriteHeader(statusCode)
		rw.headerWritten = true
	}
}

// Write captures the body for transformation.
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if rw.transformBody {
		return rw.body.Write(b)
	}

	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}

	return rw.ResponseWriter.Write(b)
}

// Flush writes the transformed response.
func (rw *ResponseWriter) Flush() error {
	if !rw.transformBody {
		return nil
	}

	body := rw.body.Bytes()

	// Apply body transformations
	if rw.transformer != nil && len(rw.transformer.bodyTransformer.transformers) > 0 {
		var err error
		for _, transformer := range rw.transformer.bodyTransformer.transformers {
			body, err = transformer(body)
			if err != nil {
				return err
			}
		}
	}

	// Write the response
	rw.ResponseWriter.WriteHeader(rw.statusCode)
	_, err := rw.ResponseWriter.Write(body)
	return err
}

// StatusCode returns the captured status code.
func (rw *ResponseWriter) StatusCode() int {
	if rw.statusCode == 0 {
		return http.StatusOK
	}
	return rw.statusCode
}

// Body returns the captured body.
func (rw *ResponseWriter) Body() []byte {
	return rw.body.Bytes()
}

// ModifyResponseHeaders modifies response headers.
func ModifyResponseHeaders(header http.Header, set, add map[string]string, remove []string) {
	// Remove headers first
	for _, name := range remove {
		header.Del(name)
	}

	// Set headers (overwrites existing)
	for name, value := range set {
		header.Set(name, value)
	}

	// Add headers
	for name, value := range add {
		header.Add(name, value)
	}
}

// AddSecurityHeaders adds common security headers to the response.
func AddSecurityHeaders(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-XSS-Protection", "1; mode=block")
	header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// AddCacheHeaders adds cache control headers.
func AddCacheHeaders(header http.Header, maxAge int, public bool) {
	var cacheControl string
	if public {
		cacheControl = "public"
	} else {
		cacheControl = "private"
	}
	if maxAge > 0 {
		cacheControl += ", max-age=" + string(rune(maxAge))
	}
	header.Set("Cache-Control", cacheControl)
}

// AddNoCacheHeaders adds headers to prevent caching.
func AddNoCacheHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	header.Set("Pragma", "no-cache")
	header.Set("Expires", "0")
}
