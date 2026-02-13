// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"strconv"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// parseRateLimitConfig parses rate limit annotations into a RateLimitConfig.
// Returns nil if no rate limit annotations are present.
func parseRateLimitConfig(annotations map[string]string) *config.RateLimitConfig {
	enabledStr, hasEnabled := annotations[AnnotationRateLimitEnabled]
	if !hasEnabled {
		return nil
	}

	rl := &config.RateLimitConfig{
		Enabled: enabledStr == annotationValueTrue,
	}

	if v, ok := annotations[AnnotationRateLimitRPS]; ok {
		if rps, err := strconv.Atoi(v); err == nil {
			rl.RequestsPerSecond = rps
		}
	}
	if v, ok := annotations[AnnotationRateLimitBurst]; ok {
		if burst, err := strconv.Atoi(v); err == nil {
			rl.Burst = burst
		}
	}
	if v, ok := annotations[AnnotationRateLimitPerClient]; ok {
		rl.PerClient = v == annotationValueTrue
	}

	return rl
}

// parseCORSConfig parses CORS annotations into a CORSConfig.
// Returns nil if no CORS annotations are present.
func parseCORSConfig(annotations map[string]string) *config.CORSConfig {
	origins, hasOrigins := annotations[AnnotationCORSAllowOrigins]
	if !hasOrigins {
		return nil
	}

	cors := &config.CORSConfig{
		AllowOrigins: splitCSV(origins),
	}

	if v, ok := annotations[AnnotationCORSAllowMethods]; ok {
		cors.AllowMethods = splitCSV(v)
	}
	if v, ok := annotations[AnnotationCORSAllowHeaders]; ok {
		cors.AllowHeaders = splitCSV(v)
	}
	if v, ok := annotations[AnnotationCORSExposeHeaders]; ok {
		cors.ExposeHeaders = splitCSV(v)
	}
	if v, ok := annotations[AnnotationCORSMaxAge]; ok {
		if maxAge, err := strconv.Atoi(v); err == nil {
			cors.MaxAge = maxAge
		}
	}
	if v, ok := annotations[AnnotationCORSAllowCredentials]; ok {
		cors.AllowCredentials = v == annotationValueTrue
	}

	return cors
}

// parseSecurityConfig parses security annotations into a SecurityConfig.
// Returns nil if no security annotations are present.
func parseSecurityConfig(annotations map[string]string) *config.SecurityConfig {
	enabledStr, hasEnabled := annotations[AnnotationSecurityEnabled]
	if !hasEnabled {
		return nil
	}

	sec := &config.SecurityConfig{
		Enabled: enabledStr == annotationValueTrue,
	}

	xFrame, hasXFrame := annotations[AnnotationSecurityXFrameOptions]
	xContent, hasXContent := annotations[AnnotationSecurityXContentType]
	xXSS, hasXXSS := annotations[AnnotationSecurityXXSSProtection]

	if hasXFrame || hasXContent || hasXXSS {
		headers := &config.SecurityHeadersConfig{Enabled: true}
		if hasXFrame {
			headers.XFrameOptions = xFrame
		}
		if hasXContent {
			headers.XContentTypeOptions = xContent
		}
		if hasXXSS {
			headers.XXSSProtection = xXSS
		}
		sec.Headers = headers
	}

	return sec
}

// parseEncodingConfig parses encoding annotations into an EncodingConfig.
// Returns nil if no encoding annotations are present.
func parseEncodingConfig(annotations map[string]string) *config.EncodingConfig {
	reqCT, hasReq := annotations[AnnotationEncodingRequestContentType]
	resCT, hasRes := annotations[AnnotationEncodingResponseContentType]

	if !hasReq && !hasRes {
		return nil
	}

	enc := &config.EncodingConfig{}
	if hasReq {
		enc.RequestEncoding = reqCT
	}
	if hasRes {
		enc.ResponseEncoding = resCT
	}
	return enc
}

// parseCacheConfig parses cache annotations into a CacheConfig.
// Returns nil if no cache annotations are present.
func parseCacheConfig(annotations map[string]string) *config.CacheConfig {
	enabledStr, hasEnabled := annotations[AnnotationCacheEnabled]
	if !hasEnabled {
		return nil
	}

	cache := &config.CacheConfig{
		Enabled: enabledStr == annotationValueTrue,
	}
	if v, ok := annotations[AnnotationCacheTTL]; ok {
		cache.TTL = parseDuration(v)
	}
	return cache
}

// parseCircuitBreakerConfig parses circuit breaker annotations into a CircuitBreakerConfig.
// Returns nil if no circuit breaker annotations are present.
func parseCircuitBreakerConfig(annotations map[string]string) *config.CircuitBreakerConfig {
	enabledStr, hasEnabled := annotations[AnnotationCircuitBreakerEnabled]
	if !hasEnabled {
		return nil
	}

	cb := &config.CircuitBreakerConfig{
		Enabled: enabledStr == annotationValueTrue,
	}
	if v, ok := annotations[AnnotationCircuitBreakerThreshold]; ok {
		if t, err := strconv.Atoi(v); err == nil {
			cb.Threshold = t
		}
	}
	if v, ok := annotations[AnnotationCircuitBreakerTimeout]; ok {
		cb.Timeout = parseDuration(v)
	}
	if v, ok := annotations[AnnotationCircuitBreakerHalfOpen]; ok {
		if h, err := strconv.Atoi(v); err == nil {
			cb.HalfOpenRequests = h
		}
	}
	return cb
}

// parseRetryPolicy parses retry annotations into a RetryPolicy.
// Returns nil if no retry annotations are present.
func parseRetryPolicy(annotations map[string]string) *config.RetryPolicy {
	attemptsStr, hasAttempts := annotations[AnnotationRetryAttempts]
	perTryTimeout, hasPerTry := annotations[AnnotationRetryPerTryTimeout]
	retryOn, hasRetryOn := annotations[AnnotationRetryOn]

	if !hasAttempts && !hasPerTry && !hasRetryOn {
		return nil
	}

	retry := &config.RetryPolicy{}
	if hasAttempts {
		if v, err := strconv.Atoi(attemptsStr); err == nil {
			retry.Attempts = v
		}
	}
	if hasPerTry {
		retry.PerTryTimeout = parseDuration(perTryTimeout)
	}
	if hasRetryOn {
		retry.RetryOn = retryOn
	}
	return retry
}
