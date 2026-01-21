package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

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
	for _, origin := range cfg.AllowOrigins {
		allowOrigins[origin] = true
	}

	return &corsHeaders{
		allowOrigins:     allowOrigins,
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

// setCORSHeaders sets CORS headers on the response.
func (h *corsHeaders) setCORSHeaders(w http.ResponseWriter, origin string) {
	if origin != "" && (h.allowOrigins["*"] || h.allowOrigins[origin]) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
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

// CORS returns a middleware that handles CORS.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	headers := newCORSHeaders(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headers.setCORSHeaders(w, r.Header.Get("Origin"))

			// Handle preflight request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSFromConfig creates CORS middleware from gateway config.
func CORSFromConfig(cfg *config.CORSConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		return CORS(DefaultCORSConfig())
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

	return CORS(corsConfig)
}
