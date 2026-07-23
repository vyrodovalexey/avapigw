package middleware

import (
	"bufio"
	"bytes"
	"context"
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

// cacheFillTimeout bounds the cache fill write after the response has been
// sent to the client. The fill is detached from the client's request
// context (a disconnect right after receiving the response must not cancel
// the fill), so this timeout is its only bound.
const cacheFillTimeout = 5 * time.Second

// uncacheableHeaders lists response headers that must never be stored in a
// shared cache entry, in canonical form:
//
//   - Per-request CORS headers: the CORS middleware runs BEFORE this cache
//     middleware on the request path (see RouteMiddlewareManager
//     buildMiddlewareChain: CORS wraps cache) and applies its response
//     headers authoritatively at response-write time. A grant issued to
//     the origin that filled the cache (e.g. Access-Control-Allow-Origin)
//     — or emitted by the backend — must never be replayed to other
//     origins; the live CORS middleware is the single source of truth on
//     every request, including cache hits.
//   - Set-Cookie: per-client credential material.
//   - X-Cache: replay marker, set per response.
//   - Hop-by-hop headers (RFC 9110 section 7.6.1): connection-scoped, not
//     part of the cacheable representation.
var uncacheableHeaders = map[string]struct{}{
	"Access-Control-Allow-Origin":      {},
	"Access-Control-Allow-Credentials": {},
	"Access-Control-Expose-Headers":    {},
	"Access-Control-Allow-Methods":     {},
	"Access-Control-Allow-Headers":     {},
	"Access-Control-Max-Age":           {},
	"Set-Cookie":                       {},
	"X-Cache":                          {},
	"Connection":                       {},
	"Keep-Alive":                       {},
	"Proxy-Authenticate":               {},
	"Proxy-Authorization":              {},
	"Te":                               {},
	"Trailer":                          {},
	"Transfer-Encoding":                {},
	"Upgrade":                          {},
}

// isUncacheableHeader reports whether a response header must be excluded
// from cached entries and from cache replay.
func isUncacheableHeader(key string) bool {
	_, ok := uncacheableHeaders[http.CanonicalHeaderKey(key)]
	return ok
}

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
//
// Headers already present on the live response writer win over cached
// values: per-request middlewares (CORS, security headers) run before this
// cache middleware and have already set the correct values for THIS
// request, so cached values must neither override nor duplicate them (the
// stored Vary value, for example, is only emitted when the live chain did
// not set its own). Uncacheable headers are also skipped on replay as
// defense in depth against entries stored by older gateway versions.
func writeCachedResponse(w http.ResponseWriter, cached *cachedResponse) {
	liveHeaders := w.Header()
	for k, vals := range cached.Headers {
		canonical := http.CanonicalHeaderKey(k)
		if isUncacheableHeader(canonical) {
			continue
		}
		if _, exists := liveHeaders[canonical]; exists {
			continue
		}
		for _, v := range vals {
			liveHeaders.Add(canonical, v)
		}
	}
	liveHeaders.Set("X-Cache", "HIT")
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
// Headers are taken from the recorder's WriteHeader-time snapshot (what was
// actually sent, isolated from later mutations of the live header map) with
// per-request and hop-by-hop headers stripped so a cache entry filled by
// one request never leaks another request's CORS grants or cookies.
func (cm *cacheMiddleware) storeResponse(
	r *http.Request,
	key string,
	recorder *cacheResponseRecorder,
) {
	cached := cachedResponse{
		StatusCode: recorder.statusCode,
		Headers:    cacheableHeaders(recorder.headerSnapshot),
		Body:       recorder.body.Bytes(),
	}

	serialized, err := json.Marshal(cached)
	if err != nil {
		return
	}

	// Detach the fill write from the client's request context: the client
	// has already received the response, and a disconnect at this point
	// must not cancel the fill. Context values (trace metadata) are
	// preserved; the write is bounded by cacheFillTimeout instead.
	fillCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), cacheFillTimeout)
	defer cancel()

	if setErr := cm.cache.Set(fillCtx, key, serialized, cm.ttl); setErr != nil {
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

// cacheableHeaders deep-copies snapshot headers, dropping per-request and
// hop-by-hop headers that must not be shared across requests.
func cacheableHeaders(h http.Header) map[string][]string {
	clone := make(map[string][]string, len(h))
	for k, v := range h {
		if isUncacheableHeader(k) {
			continue
		}
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

	// headerSnapshot is a deep copy of the response headers taken at
	// WriteHeader time. The live header map is shared with per-request
	// middlewares (CORS in particular) and may be mutated after the
	// response is written, so the cached entry is built from this
	// snapshot rather than from the live map.
	headerSnapshot http.Header
}

// WriteHeader captures the status code, snapshots the response headers as
// sent, and forwards the call to the underlying ResponseWriter exactly
// once. Duplicate calls are suppressed to avoid "superfluous
// response.WriteHeader" warnings from net/http.
func (r *cacheResponseRecorder) WriteHeader(code int) {
	if !r.headerWritten {
		r.statusCode = code
		r.headerWritten = true
		r.headerSnapshot = cloneHeaders(r.ResponseWriter.Header())
		r.ResponseWriter.WriteHeader(code)
	}
}

// Write captures the body for caching and writes it through to the client.
// If the accumulated body exceeds maxCacheBodySize, buffering stops but
// the data is still forwarded to the underlying ResponseWriter.
// An implicit 200 status is sent if WriteHeader has not been called yet.
func (r *cacheResponseRecorder) Write(b []byte) (int, error) {
	if !r.headerWritten {
		r.WriteHeader(http.StatusOK)
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
