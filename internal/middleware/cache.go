package middleware

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// maxCacheBodySize is the maximum response body size that will be buffered
// for caching. Responses exceeding this limit are still forwarded to the
// client but are not stored in cache.
const maxCacheBodySize = 10 << 20 // 10MB

// cachedResponse holds a serialized HTTP response for cache storage.
type cachedResponse struct {
	StatusCode int                 `json:"statusCode"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
}

// cacheMiddleware holds the state for the caching middleware.
type cacheMiddleware struct {
	cache  cache.Cache
	logger observability.Logger
	ttl    time.Duration
}

// CacheFromConfig creates an HTTP caching middleware from the given cache
// instance and configuration. Only GET requests are cached by default.
// Responses with non-2xx status codes are not cached. Cache-Control
// directives no-store and no-cache are respected.
func CacheFromConfig(
	c cache.Cache,
	cfg *config.CacheConfig,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if c == nil || cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	ttl := cfg.TTL.Duration()
	if ttl == 0 {
		ttl = 60 * time.Second // sensible default
	}

	cm := &cacheMiddleware{cache: c, logger: logger, ttl: ttl}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cm.isCacheable(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := buildCacheKey(r)

			if cm.serveCachedResponse(w, r, key) {
				return
			}

			// Record route-level cache miss
			routeName := util.RouteFromContext(r.Context())
			if routeName == "" {
				routeName = unknownRoute
			}
			routepkg.GetRouteMetrics().RecordCacheMiss(
				routeName, r.Method,
			)

			cm.captureAndCache(w, r, next, key)
		})
	}
}

// isCacheable returns true if the request is eligible for caching.
func (cm *cacheMiddleware) isCacheable(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	cc := r.Header.Get("Cache-Control")
	return !strings.Contains(cc, "no-store") && !strings.Contains(cc, "no-cache")
}

// serveCachedResponse attempts to serve a response from cache.
// Returns true if a cached response was served, false on cache miss.
func (cm *cacheMiddleware) serveCachedResponse(w http.ResponseWriter, r *http.Request, key string) bool {
	data, err := cm.cache.Get(r.Context(), key)
	if err != nil {
		return false
	}

	var cached cachedResponse
	if jsonErr := json.Unmarshal(data, &cached); jsonErr != nil {
		cm.logger.Debug("cache deserialization failed, treating as miss",
			observability.String("key", key),
		)
		return false
	}

	writeCachedResponse(w, &cached)
	cm.logger.Debug("cache hit",
		observability.String("key", key),
		observability.String("path", r.URL.Path),
	)

	// Record route-level cache hit
	routeName := util.RouteFromContext(r.Context())
	if routeName == "" {
		routeName = unknownRoute
	}
	routepkg.GetRouteMetrics().RecordCacheHit(routeName, r.Method)

	return true
}

// writeCachedResponse writes a cached response to the ResponseWriter.
func writeCachedResponse(w http.ResponseWriter, cached *cachedResponse) {
	for k, vals := range cached.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Cache", "HIT")
	w.WriteHeader(cached.StatusCode)
	_, _ = w.Write(cached.Body)
}

// captureAndCache wraps the handler to capture the response and store it in cache.
func (cm *cacheMiddleware) captureAndCache(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	key string,
) {
	recorder := &cacheResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	next.ServeHTTP(recorder, r)

	// Only cache 2xx responses
	if recorder.statusCode < http.StatusOK || recorder.statusCode >= http.StatusMultipleChoices {
		return
	}

	// Skip caching if the response body exceeded the buffer limit
	if recorder.bufferExceeded {
		cm.logger.Debug("response body exceeded max cache body size, skipping cache",
			observability.String("key", key),
			observability.String("path", r.URL.Path),
		)
		return
	}

	cm.storeResponse(r, key, recorder)
}

// storeResponse serializes and stores the captured response in cache.
// Headers are read from recorder.Header() which delegates to the embedded
// ResponseWriter — this is the canonical source for response headers set
// by downstream handlers.
func (cm *cacheMiddleware) storeResponse(
	r *http.Request,
	key string,
	recorder *cacheResponseRecorder,
) {
	cached := cachedResponse{
		StatusCode: recorder.statusCode,
		Headers:    cloneHeaders(recorder.Header()),
		Body:       recorder.body.Bytes(),
	}

	serialized, err := json.Marshal(cached)
	if err != nil {
		return
	}

	if setErr := cm.cache.Set(r.Context(), key, serialized, cm.ttl); setErr != nil {
		cm.logger.Debug("failed to store response in cache",
			observability.String("key", key),
			observability.Error(setErr),
		)
	} else {
		cm.logger.Debug("cached response",
			observability.String("key", key),
			observability.String("path", r.URL.Path),
		)
	}
}

// buildCacheKey generates a deterministic cache key from the request's
// method, path, and sorted query parameters.
func buildCacheKey(r *http.Request) string {
	var sb strings.Builder
	sb.WriteString(r.Method)
	sb.WriteByte(':')
	sb.WriteString(r.URL.Path)

	query := r.URL.Query()
	if len(query) > 0 {
		keys := make([]string, 0, len(query))
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sb.WriteByte('?')
		first := true
		for _, k := range keys {
			vals := query[k]
			sort.Strings(vals)
			for _, v := range vals {
				if !first {
					sb.WriteByte('&')
				}
				sb.WriteString(k)
				sb.WriteByte('=')
				sb.WriteString(v)
				first = false
			}
		}
	}

	return sb.String()
}

// cloneHeaders creates a deep copy of HTTP headers.
func cloneHeaders(h http.Header) map[string][]string {
	clone := make(map[string][]string, len(h))
	for k, v := range h {
		vc := make([]string, len(v))
		copy(vc, v)
		clone[k] = vc
	}
	return clone
}

// cacheResponseRecorder captures the response for caching while also
// writing it to the underlying ResponseWriter.
type cacheResponseRecorder struct {
	http.ResponseWriter
	statusCode     int
	body           *bytes.Buffer
	headerWritten  bool
	bufferExceeded bool
}

// WriteHeader captures the status code and forwards it to the underlying
// ResponseWriter exactly once. Duplicate calls are suppressed to avoid
// "superfluous response.WriteHeader" warnings from net/http.
func (r *cacheResponseRecorder) WriteHeader(code int) {
	if !r.headerWritten {
		r.statusCode = code
		r.headerWritten = true
		r.ResponseWriter.WriteHeader(code)
	}
}

// Write captures the body for caching and writes it through to the client.
// If the accumulated body exceeds maxCacheBodySize, buffering stops but
// the data is still forwarded to the underlying ResponseWriter.
// An implicit 200 status is sent if WriteHeader has not been called yet.
func (r *cacheResponseRecorder) Write(b []byte) (int, error) {
	if !r.headerWritten {
		r.statusCode = http.StatusOK
		r.headerWritten = true
		r.ResponseWriter.WriteHeader(http.StatusOK)
	}

	if !r.bufferExceeded {
		if int64(r.body.Len())+int64(len(b)) > maxCacheBodySize {
			r.bufferExceeded = true
			r.body.Reset()
		} else {
			r.body.Write(b)
		}
	}

	return r.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming support.
func (r *cacheResponseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker for WebSocket support.
func (r *cacheResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
