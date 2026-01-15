package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
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

// RateLimitMiddlewareWithConfig returns a rate limit middleware with custom configuration.
func RateLimitMiddlewareWithConfig(config RateLimitConfig) gin.HandlerFunc {
	if config.Limiter == nil {
		config.Limiter = ratelimit.NewNoopLimiter()
	}
	if config.KeyFunc == nil {
		config.KeyFunc = ratelimit.IPKeyFunc
	}

	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	return func(c *gin.Context) {
		// Skip rate limiting for certain paths
		if skipPaths[c.Request.URL.Path] {
			c.Next()
			return
		}

		// Get rate limit key
		key := config.KeyFunc(c.Request)

		// Check rate limit
		result, err := config.Limiter.Allow(c.Request.Context(), key)
		if err != nil {
			if config.Logger != nil {
				config.Logger.Error("rate limit check failed",
					zap.String("key", key),
					zap.Error(err),
				)
			}
			// Allow request on error to avoid blocking
			c.Next()
			return
		}

		// Set rate limit headers
		if config.IncludeHeaders {
			c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(result.ResetAfter).Unix(), 10))
		}

		if !result.Allowed {
			if config.IncludeHeaders {
				c.Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
			}

			if config.Logger != nil {
				config.Logger.Debug("rate limit exceeded",
					zap.String("key", key),
					zap.Int("limit", result.Limit),
				)
			}

			// Call custom error handler if provided
			if config.ErrorHandler != nil {
				config.ErrorHandler(c)
				return
			}

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
