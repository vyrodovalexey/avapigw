package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
)

// RateLimitConfig holds configuration for the rate limit middleware.
type RateLimitConfig struct {
	// Limiter is the rate limiter to use.
	Limiter ratelimit.Limiter

	// KeyFunc extracts the rate limit key from the request.
	KeyFunc ratelimit.KeyFunc

	// Logger for logging rate limit events.
	Logger *zap.Logger

	// SkipPaths is a list of paths to skip rate limiting.
	SkipPaths []string

	// ErrorHandler is called when rate limit is exceeded.
	ErrorHandler gin.HandlerFunc

	// IncludeHeaders determines whether to include rate limit headers.
	IncludeHeaders bool
}

// DefaultRateLimitConfig returns a RateLimitConfig with default values.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		KeyFunc:        ratelimit.IPKeyFunc,
		IncludeHeaders: true,
	}
}

// RateLimitMiddleware returns a middleware that applies rate limiting.
func RateLimitMiddleware(limiter ratelimit.Limiter, keyFunc ratelimit.KeyFunc) gin.HandlerFunc {
	return RateLimitMiddlewareWithConfig(RateLimitConfig{
		Limiter:        limiter,
		KeyFunc:        keyFunc,
		IncludeHeaders: true,
	})
}

// setRateLimitHeaders sets the rate limit headers on the response.
func setRateLimitHeaders(c *gin.Context, result *core.RateLimitResult) {
	c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(result.ResetAfter).Unix(), 10))
}

// handleRateLimitExceeded handles the case when rate limit is exceeded.
func handleRateLimitExceeded(
	c *gin.Context,
	result *core.RateLimitResult,
	rateLimitCore *core.RateLimitCore,
	key string,
	errorHandler gin.HandlerFunc,
) {
	if rateLimitCore.IncludeHeaders() {
		c.Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	}

	rateLimitCore.LogExceeded(key, result.Limit)

	// Call custom error handler if provided
	if errorHandler != nil {
		errorHandler(c)
		return
	}

	// Default error response
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error":       "Too Many Requests",
		"message":     "Rate limit exceeded",
		"retry_after": int(result.RetryAfter.Seconds()),
	})
}

// RateLimitMiddlewareWithConfig returns a rate limit middleware with custom configuration.
func RateLimitMiddlewareWithConfig(config RateLimitConfig) gin.HandlerFunc {
	rateLimitCore := core.NewRateLimitCore(core.RateLimitCoreConfig{
		BaseConfig: core.BaseConfig{
			Logger:    config.Logger,
			SkipPaths: config.SkipPaths,
		},
		Limiter:        config.Limiter,
		IncludeHeaders: config.IncludeHeaders,
	})

	keyFunc := config.KeyFunc
	if keyFunc == nil {
		keyFunc = ratelimit.IPKeyFunc
	}

	return func(c *gin.Context) {
		if rateLimitCore.ShouldSkip(c.Request.URL.Path) {
			c.Next()
			return
		}

		key := keyFunc(c.Request)
		result, err := rateLimitCore.Check(c.Request.Context(), key)
		if err != nil {
			c.Next()
			return
		}

		if rateLimitCore.IncludeHeaders() {
			setRateLimitHeaders(c, result)
		}

		if !result.Allowed {
			handleRateLimitExceeded(c, result, rateLimitCore, key, config.ErrorHandler)
			return
		}

		c.Next()
	}
}

// RateLimitMiddlewareWithCore returns a rate limit middleware using the core package directly.
func RateLimitMiddlewareWithCore(coreConfig core.RateLimitCoreConfig, keyFunc ratelimit.KeyFunc) gin.HandlerFunc {
	rateLimitCore := core.NewRateLimitCore(coreConfig)

	if keyFunc == nil {
		keyFunc = ratelimit.IPKeyFunc
	}

	return func(c *gin.Context) {
		// Skip rate limiting for certain paths
		if rateLimitCore.ShouldSkip(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get rate limit key
		key := keyFunc(c.Request)

		// Check rate limit using core
		result, err := rateLimitCore.Check(c.Request.Context(), key)
		if err != nil {
			// Allow request on error to avoid blocking
			c.Next()
			return
		}

		// Set rate limit headers
		if rateLimitCore.IncludeHeaders() {
			c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(result.ResetAfter).Unix(), 10))
		}

		if !result.Allowed {
			if rateLimitCore.IncludeHeaders() {
				c.Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
			}

			rateLimitCore.LogExceeded(key, result.Limit)

			// Default error response
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too Many Requests",
				"message":     "Rate limit exceeded",
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			return
		}

		c.Next()
	}
}

// PerRouteRateLimitMiddleware returns a middleware that applies per-route rate limiting.
func PerRouteRateLimitMiddleware(limiter ratelimit.Limiter, routeName string) gin.HandlerFunc {
	keyFunc := ratelimit.PerRouteKeyFunc(routeName, ratelimit.IPKeyFunc)
	return RateLimitMiddleware(limiter, keyFunc)
}

// PerEndpointRateLimitMiddleware returns a middleware that applies per-endpoint rate limiting.
func PerEndpointRateLimitMiddleware(limiter ratelimit.Limiter) gin.HandlerFunc {
	keyFunc := ratelimit.PerEndpointKeyFunc(ratelimit.IPKeyFunc)
	return RateLimitMiddleware(limiter, keyFunc)
}

// APIKeyRateLimitMiddleware returns a middleware that applies rate limiting based on API key.
func APIKeyRateLimitMiddleware(limiter ratelimit.Limiter, headerName, queryParam string) gin.HandlerFunc {
	keyFunc := ratelimit.APIKeyFunc(headerName, queryParam)
	return RateLimitMiddleware(limiter, keyFunc)
}

// JWTRateLimitMiddleware returns a middleware that applies rate limiting based on JWT claim.
func JWTRateLimitMiddleware(limiter ratelimit.Limiter, claim string) gin.HandlerFunc {
	keyFunc := ratelimit.JWTClaimKeyFunc(claim)
	return RateLimitMiddleware(limiter, keyFunc)
}
