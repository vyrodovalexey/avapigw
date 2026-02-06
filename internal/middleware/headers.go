package middleware

import (
	"bufio"
	"net"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// HeadersConfig contains header manipulation configuration.
type HeadersConfig struct {
	RequestSet     map[string]string
	RequestAdd     map[string]string
	RequestRemove  []string
	ResponseSet    map[string]string
	ResponseAdd    map[string]string
	ResponseRemove []string
}

// Headers returns a middleware that manipulates headers.
func Headers(cfg HeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Manipulate request headers
			for key, value := range cfg.RequestSet {
				r.Header.Set(key, value)
			}
			for key, value := range cfg.RequestAdd {
				r.Header.Add(key, value)
			}
			for _, key := range cfg.RequestRemove {
				r.Header.Del(key)
			}

			// Wrap response writer to manipulate response headers
			rw := &headerResponseWriter{
				ResponseWriter: w,
				cfg:            cfg,
				headerWritten:  false,
			}

			next.ServeHTTP(rw, r)
		})
	}
}

// headerResponseWriter wraps http.ResponseWriter to manipulate response headers.
type headerResponseWriter struct {
	http.ResponseWriter
	cfg           HeadersConfig
	headerWritten bool
}

// WriteHeader manipulates headers before writing.
func (rw *headerResponseWriter) WriteHeader(code int) {
	if !rw.headerWritten {
		rw.manipulateResponseHeaders()
		rw.headerWritten = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write ensures headers are manipulated before writing body.
func (rw *headerResponseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.manipulateResponseHeaders()
		rw.headerWritten = true
	}
	return rw.ResponseWriter.Write(b)
}

// manipulateResponseHeaders applies response header manipulations.
func (rw *headerResponseWriter) manipulateResponseHeaders() {
	for key, value := range rw.cfg.ResponseSet {
		rw.ResponseWriter.Header().Set(key, value)
	}
	for key, value := range rw.cfg.ResponseAdd {
		rw.ResponseWriter.Header().Add(key, value)
	}
	for _, key := range rw.cfg.ResponseRemove {
		rw.ResponseWriter.Header().Del(key)
	}
}

// Flush implements http.Flusher interface for streaming support.
func (rw *headerResponseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker interface for WebSocket support.
func (rw *headerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// HeadersFromConfig creates Headers middleware from gateway config.
func HeadersFromConfig(cfg *config.HeaderManipulation) func(http.Handler) http.Handler {
	if cfg == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	headersConfig := HeadersConfig{}

	if cfg.Request != nil {
		headersConfig.RequestSet = cfg.Request.Set
		headersConfig.RequestAdd = cfg.Request.Add
		headersConfig.RequestRemove = cfg.Request.Remove
	}

	if cfg.Response != nil {
		headersConfig.ResponseSet = cfg.Response.Set
		headersConfig.ResponseAdd = cfg.Response.Add
		headersConfig.ResponseRemove = cfg.Response.Remove
	}

	return Headers(headersConfig)
}
