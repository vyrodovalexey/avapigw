package middleware

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// corsOwnedHeaders are the CORS response headers owned by the gateway when
// a CORS policy is configured: the configured policy is authoritative, so
// values produced by inner handlers (proxied backends in particular) are
// replaced by the gateway's own grant decision. When no CORS policy is
// configured on a route, this middleware is absent from the chain and
// backend CORS headers pass through untouched.
var corsOwnedHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Credentials",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
}

// CORSConfig contains CORS configuration.
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSConfig returns default CORS configuration.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		MaxAge:       86400,
	}
}

// corsHeaders holds pre-computed CORS header values.
type corsHeaders struct {
	allowOrigins     map[string]bool
	wildcardPatterns []string // Patterns like "*.example.com"
	allowAllOrigins  bool
	allowMethods     string
	allowHeaders     string
	exposeHeaders    string
	maxAge           string
	allowCredentials bool
	hasAllowMethods  bool
	hasAllowHeaders  bool
	hasExposeHeaders bool
	hasMaxAge        bool
}

// newCORSHeaders creates pre-computed CORS headers from config.
func newCORSHeaders(cfg CORSConfig) *corsHeaders {
	allowOrigins := make(map[string]bool)
	var wildcardPatterns []string
	allowAllOrigins := false

	for _, origin := range cfg.AllowOrigins {
		switch {
		case origin == "*":
			allowAllOrigins = true
		case strings.HasPrefix(origin, "*."):
			// Wildcard subdomain pattern like "*.example.com"
			wildcardPatterns = append(wildcardPatterns, origin)
		default:
			allowOrigins[origin] = true
		}
	}

	return &corsHeaders{
		allowOrigins:     allowOrigins,
		wildcardPatterns: wildcardPatterns,
		allowAllOrigins:  allowAllOrigins,
		allowMethods:     strings.Join(cfg.AllowMethods, ", "),
		allowHeaders:     strings.Join(cfg.AllowHeaders, ", "),
		exposeHeaders:    strings.Join(cfg.ExposeHeaders, ", "),
		maxAge:           strconv.Itoa(cfg.MaxAge),
		allowCredentials: cfg.AllowCredentials,
		hasAllowMethods:  len(cfg.AllowMethods) > 0,
		hasAllowHeaders:  len(cfg.AllowHeaders) > 0,
		hasExposeHeaders: len(cfg.ExposeHeaders) > 0,
		hasMaxAge:        cfg.MaxAge > 0,
	}
}

// isOriginAllowed checks if the given origin is allowed.
func (h *corsHeaders) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	// Check for allow all origins
	if h.allowAllOrigins {
		return true
	}

	// Check exact match
	if h.allowOrigins[origin] {
		return true
	}

	// Check wildcard patterns (e.g., "*.example.com")
	for _, pattern := range h.wildcardPatterns {
		if matchWildcardOrigin(origin, pattern) {
			return true
		}
	}

	return false
}

// matchWildcardOrigin checks if an origin matches a wildcard pattern.
// Pattern format: "*.example.com" matches "sub.example.com", "api.example.com", etc.
func matchWildcardOrigin(origin, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	// Extract the domain suffix from the pattern (e.g., ".example.com" from "*.example.com")
	suffix := pattern[1:] // Remove the "*" to get ".example.com"

	// Parse the origin to extract the host
	// Origin format: "https://sub.example.com" or "http://sub.example.com:8080"
	host := origin

	// Remove protocol prefix if present
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check if the host ends with the suffix
	// Also ensure there's at least one character before the suffix (the subdomain)
	return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
}

// setCORSHeaders sets CORS headers on the response.
func (h *corsHeaders) setCORSHeaders(w http.ResponseWriter, origin string) {
	if h.isOriginAllowed(origin) {
		// Always echo the specific origin for better security and compatibility
		// This also handles the case where credentials are allowed (which requires specific origin)
		w.Header().Set("Access-Control-Allow-Origin", origin)
		addVaryOrigin(w.Header())
	}

	if h.hasAllowMethods {
		w.Header().Set("Access-Control-Allow-Methods", h.allowMethods)
	}

	if h.hasAllowHeaders {
		w.Header().Set("Access-Control-Allow-Headers", h.allowHeaders)
	}

	if h.hasExposeHeaders {
		w.Header().Set("Access-Control-Expose-Headers", h.exposeHeaders)
	}

	if h.allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if h.hasMaxAge {
		w.Header().Set("Access-Control-Max-Age", h.maxAge)
	}
}

// addVaryOrigin appends "Origin" to the Vary header unless it is already
// listed. Backend Vary values (e.g. Accept-Encoding) are preserved: Vary
// has broader caching semantics than CORS, so it is merged, never replaced.
func addVaryOrigin(h http.Header) {
	for _, v := range h.Values("Vary") {
		for _, member := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(member), "Origin") {
				return
			}
		}
	}
	h.Add("Vary", "Origin")
}

// CORS returns a middleware that handles CORS. The configured policy is
// authoritative for the Access-Control-* response headers: on actual
// (non-preflight) requests, headers produced by inner handlers — proxied
// backend responses in particular — are stripped and replaced by the
// gateway's own grant decision just before the response headers are
// written, so a denied origin can never receive a backend-issued grant
// through the gateway.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	return CORSWithSkipper(cfg, nil)
}

// CORSWithSkipper returns a CORS middleware like CORS, except requests for
// which skip returns true bypass this policy entirely: no preflight answer
// and no header authority. The gateway uses this at the GLOBAL middleware
// layer so routes that define their own route-level CORS policy are handled
// exclusively by the route chain's CORS middleware — the route policy takes
// precedence for both preflight OPTIONS and actual requests, while routes
// without a route policy keep the global behavior. A nil skip never skips.
func CORSWithSkipper(cfg CORSConfig, skip func(*http.Request) bool) func(http.Handler) http.Handler {
	headers := newCORSHeaders(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip != nil && skip(r) {
				// The matched route owns CORS end-to-end (preflight
				// short-circuit and authority semantics) via its own
				// route-level CORS middleware.
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")

			// Handle preflight request: answered entirely by the gateway,
			// the inner handler never runs.
			if r.Method == http.MethodOptions {
				headers.setCORSHeaders(w, origin)
				GetMiddlewareMetrics().corsRequestsTotal.WithLabelValues(
					"preflight",
				).Inc()
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if origin != "" {
				GetMiddlewareMetrics().corsRequestsTotal.WithLabelValues(
					"actual",
				).Inc()
			}

			// Defer the policy application to response-write time so
			// upstream Access-Control-* values are replaced, not merged.
			aw := newCORSAuthorityWriter(w, headers, origin)
			next.ServeHTTP(aw, r)
			// Handlers that return without writing rely on net/http's
			// implicit 200; the headers are still mutable here.
			aw.enforcePolicy()
		})
	}
}

// corsAuthorityWriter wraps the response writer to apply the gateway's
// CORS policy exactly once, immediately before response headers are
// flushed. It removes Access-Control-* headers set by inner handlers
// (backend responses copied by the reverse proxy) and applies the
// configured policy, making the gateway authoritative for CORS.
type corsAuthorityWriter struct {
	http.ResponseWriter
	headers  *corsHeaders
	origin   string
	enforced bool
}

// newCORSAuthorityWriter wraps w with write-time CORS policy enforcement
// for the given request origin.
func newCORSAuthorityWriter(w http.ResponseWriter, h *corsHeaders, origin string) *corsAuthorityWriter {
	return &corsAuthorityWriter{ResponseWriter: w, headers: h, origin: origin}
}

// enforcePolicy strips upstream Access-Control-* headers and applies the
// gateway policy. It is idempotent; only the first call has effect.
func (w *corsAuthorityWriter) enforcePolicy() {
	if w.enforced {
		return
	}
	w.enforced = true

	h := w.ResponseWriter.Header()
	dropped := false
	for _, name := range corsOwnedHeaders {
		if _, ok := h[name]; ok {
			h.Del(name)
			dropped = true
		}
	}
	if dropped {
		GetMiddlewareMetrics().corsUpstreamHeadersDropped.Inc()
	}

	w.headers.setCORSHeaders(w.ResponseWriter, w.origin)
}

// WriteHeader applies the CORS policy, then writes the status code.
func (w *corsAuthorityWriter) WriteHeader(code int) {
	w.enforcePolicy()
	w.ResponseWriter.WriteHeader(code)
}

// Write applies the CORS policy (covering the implicit 200 path), then
// writes the body bytes.
func (w *corsAuthorityWriter) Write(b []byte) (int, error) {
	w.enforcePolicy()
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming responses (SSE, chunked).
func (w *corsAuthorityWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so WebSocket upgrades keep working on
// routes with a CORS policy configured.
func (w *corsAuthorityWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Unwrap exposes the underlying writer for http.ResponseController.
func (w *corsAuthorityWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Compile-time interface assertions.
var (
	_ http.Flusher  = (*corsAuthorityWriter)(nil)
	_ http.Hijacker = (*corsAuthorityWriter)(nil)
)

// CORSFromConfig creates CORS middleware from gateway config.
func CORSFromConfig(cfg *config.CORSConfig) func(http.Handler) http.Handler {
	return CORSFromConfigWithSkipper(cfg, nil)
}

// CORSFromConfigWithSkipper creates CORS middleware from gateway config
// with a request skipper (see CORSWithSkipper for the semantics).
func CORSFromConfigWithSkipper(
	cfg *config.CORSConfig,
	skip func(*http.Request) bool,
) func(http.Handler) http.Handler {
	if cfg == nil {
		return CORSWithSkipper(DefaultCORSConfig(), skip)
	}

	corsConfig := CORSConfig{
		AllowOrigins:     cfg.AllowOrigins,
		AllowMethods:     cfg.AllowMethods,
		AllowHeaders:     cfg.AllowHeaders,
		ExposeHeaders:    cfg.ExposeHeaders,
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           cfg.MaxAge,
	}

	// Set defaults if not specified
	if len(corsConfig.AllowOrigins) == 0 {
		corsConfig.AllowOrigins = []string{"*"}
	}
	if len(corsConfig.AllowMethods) == 0 {
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	}
	if len(corsConfig.AllowHeaders) == 0 {
		corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"}
	}

	return CORSWithSkipper(corsConfig, skip)
}
