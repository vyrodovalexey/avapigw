package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSConfig holds configuration for the CORS middleware.
type CORSConfig struct {
	// AllowOrigins is a list of origins that may access the resource.
	// Use "*" to allow all origins.
	AllowOrigins []string

	// AllowMethods is a list of methods allowed when accessing the resource.
	AllowMethods []string

	// AllowHeaders is a list of headers that can be used when making the actual request.
	AllowHeaders []string

	// ExposeHeaders is a list of headers that browsers are allowed to access.
	ExposeHeaders []string

	// AllowCredentials indicates whether the request can include user credentials.
	AllowCredentials bool

	// MaxAge indicates how long the results of a preflight request can be cached.
	MaxAge int

	// AllowWildcard allows to add origins like http://*.domain.com
	AllowWildcard bool

	// AllowBrowserExtensions allows usage from browser extensions
	AllowBrowserExtensions bool

	// AllowWebSockets allows WebSocket requests
	AllowWebSockets bool

	// AllowFiles allows file:// origins
	AllowFiles bool
}

// DefaultCORSConfig returns a CORS config with default values.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{},
		AllowCredentials: false,
		MaxAge:           86400, // 24 hours
	}
}

// CORS returns a middleware that handles CORS requests.
func CORS() gin.HandlerFunc {
	return CORSWithConfig(DefaultCORSConfig())
}

// corsContext holds pre-computed values for CORS middleware.
type corsContext struct {
	config           CORSConfig
	allowAllOrigins  bool
	allowMethodsStr  string
	allowHeadersStr  string
	exposeHeadersStr string
	maxAgeStr        string
}

// newCORSContext creates and initializes the CORS context with pre-computed values.
func newCORSContext(config CORSConfig) *corsContext {
	// Normalize configuration
	if len(config.AllowOrigins) == 0 {
		config.AllowOrigins = []string{"*"}
	}
	if len(config.AllowMethods) == 0 {
		config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	}
	if len(config.AllowHeaders) == 0 {
		config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}
	}

	allowAllOrigins := false
	for _, origin := range config.AllowOrigins {
		if origin == "*" {
			allowAllOrigins = true
			break
		}
	}

	return &corsContext{
		config:           config,
		allowAllOrigins:  allowAllOrigins,
		allowMethodsStr:  strings.Join(config.AllowMethods, ", "),
		allowHeadersStr:  strings.Join(config.AllowHeaders, ", "),
		exposeHeadersStr: strings.Join(config.ExposeHeaders, ", "),
		maxAgeStr:        strconv.Itoa(config.MaxAge),
	}
}

// setCommonCORSHeaders sets the common CORS headers for both preflight and actual requests.
func (ctx *corsContext) setCommonCORSHeaders(c *gin.Context, origin string) {
	if ctx.allowAllOrigins && !ctx.config.AllowCredentials {
		c.Header("Access-Control-Allow-Origin", "*")
	} else {
		c.Header("Access-Control-Allow-Origin", origin)
	}

	if ctx.config.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}

	if ctx.exposeHeadersStr != "" {
		c.Header("Access-Control-Expose-Headers", ctx.exposeHeadersStr)
	}
}

// setPreflightHeaders sets headers specific to preflight (OPTIONS) requests.
func (ctx *corsContext) setPreflightHeaders(c *gin.Context) {
	c.Header("Access-Control-Allow-Methods", ctx.allowMethodsStr)
	c.Header("Access-Control-Allow-Headers", ctx.allowHeadersStr)
	c.Header("Access-Control-Max-Age", ctx.maxAgeStr)
}

// CORSWithConfig returns a CORS middleware with custom configuration.
func CORSWithConfig(config CORSConfig) gin.HandlerFunc {
	ctx := newCORSContext(config)

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Skip if no origin header
		if origin == "" {
			c.Next()
			return
		}

		// Check if origin is allowed
		allowed := ctx.allowAllOrigins
		if !allowed {
			allowed = isOriginAllowed(origin, ctx.config.AllowOrigins, ctx.config.AllowWildcard)
		}

		if !allowed {
			c.Next()
			return
		}

		// Set common CORS headers
		ctx.setCommonCORSHeaders(c, origin)

		// Handle preflight request
		if c.Request.Method == http.MethodOptions {
			ctx.setPreflightHeaders(c)
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// isOriginAllowed checks if the origin is in the allowed list.
func isOriginAllowed(origin string, allowedOrigins []string, allowWildcard bool) bool {
	for _, allowed := range allowedOrigins {
		if allowed == origin {
			return true
		}

		if allowWildcard && strings.Contains(allowed, "*") {
			// Convert wildcard pattern to check
			pattern := strings.ReplaceAll(allowed, "*", "")
			if strings.HasPrefix(allowed, "*") && strings.HasSuffix(origin, pattern) {
				return true
			}
			if strings.HasSuffix(allowed, "*") && strings.HasPrefix(origin, pattern) {
				return true
			}
		}
	}
	return false
}

// AllowAllOrigins returns a CORS middleware that allows all origins.
func AllowAllOrigins() gin.HandlerFunc {
	return CORSWithConfig(CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: false,
		MaxAge:           86400,
	})
}

// AllowOrigins returns a CORS middleware that allows specific origins.
func AllowOrigins(origins ...string) gin.HandlerFunc {
	return CORSWithConfig(CORSConfig{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           86400,
	})
}
