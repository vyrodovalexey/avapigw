// Package webhook provides admission webhooks for validating avapigw resources.
package webhook

import (
	"fmt"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// This file contains CRD/data-plane parity validation and transparency
// warnings: validation for CRD fields that map 1:1 onto gateway
// configuration, plus "accepted but not applied" admission warnings for
// fields the current gateway version does not consume. The warnings mirror
// the established warnBackendCacheReserved / warnRateLimitRedisStoreUnapplied
// pattern so users are never left with silently dropped configuration.

// validateRedisTLSSpec validates the Redis client TLS configuration used by
// route caching, distributed rate limiting, and the authorization decision
// cache. A client certificate and its private key must be configured
// together.
func validateRedisTLSSpec(tls *avapigwv1alpha1.RedisTLSSpec, fieldPath string) error {
	if tls == nil {
		return nil
	}

	if (tls.CertFile != "") != (tls.KeyFile != "") {
		return fmt.Errorf("%s.certFile and %s.keyFile must be specified together", fieldPath, fieldPath)
	}

	return nil
}

// validateAuthzCacheRedis validates the authorization decision cache Redis
// connection configuration (authorization.cache.redis) against the same
// rules the gateway applies: redis requires type=redis, is mutually
// exclusive with the deprecated sentinel field, and needs exactly one of
// url or sentinel.
//
//nolint:staticcheck // SA1019: mutual-exclusion check must read the deprecated sentinel field
func validateAuthzCacheRedis(cache *avapigwv1alpha1.AuthzCacheConfig) error {
	if cache.Redis == nil {
		return nil
	}

	if cache.Type != CacheTypeRedis {
		return fmt.Errorf("authorization.cache.redis is only valid when type is 'redis'")
	}

	if cache.Sentinel != nil {
		return fmt.Errorf(
			"authorization.cache.redis and authorization.cache.sentinel are mutually exclusive; " +
				"use authorization.cache.redis.sentinel")
	}

	if err := validateRedisConnectionSpec(redisConnectionSpec{
		fieldPath:      "authorization.cache.redis",
		url:            cache.Redis.URL,
		sentinel:       cache.Redis.Sentinel,
		connectTimeout: cache.Redis.ConnectTimeout,
		readTimeout:    cache.Redis.ReadTimeout,
		writeTimeout:   cache.Redis.WriteTimeout,
		retry:          cache.Redis.Retry,
		tls:            cache.Redis.TLS,
	}); err != nil {
		return err
	}

	if cache.Redis.TTLJitter != nil && (*cache.Redis.TTLJitter < 0.0 || *cache.Redis.TTLJitter > 1.0) {
		return fmt.Errorf("authorization.cache.redis.ttlJitter must be between 0.0 and 1.0")
	}

	return nil
}

// validateRouteTransform validates the route-level transform configuration
// shared by APIRoutes. It mirrors the gateway's transformer construction
// rules for the advanced request/response options.
func validateRouteTransform(transform *avapigwv1alpha1.TransformConfig) error {
	if transform == nil {
		return nil
	}

	if err := validateRequestTransform(transform.Request); err != nil {
		return err
	}

	return validateResponseTransform(transform.Response)
}

// validateRequestTransform validates request transformation configuration.
func validateRequestTransform(request *avapigwv1alpha1.RequestTransform) error {
	if request == nil {
		return nil
	}

	for i, injection := range request.InjectFields {
		if injection.Value == nil && injection.Source == "" {
			return fmt.Errorf(
				"transform.request.injectFields[%d] requires either value or source", i)
		}
	}

	return nil
}

// validateResponseTransform validates response transformation configuration.
func validateResponseTransform(response *avapigwv1alpha1.ResponseTransform) error {
	if response == nil {
		return nil
	}

	if len(response.AllowFields) > 0 && len(response.DenyFields) > 0 {
		return fmt.Errorf("transform.response cannot have both allowFields and denyFields specified")
	}

	for i, op := range response.ArrayOperations {
		if op.Operation == arrayOperationFilter && op.Condition == "" {
			return fmt.Errorf(
				"transform.response.arrayOperations[%d].condition is required for the filter operation", i)
		}
	}

	return nil
}

// arrayOperationFilter is the array operation requiring a CEL condition.
const arrayOperationFilter = "filter"

// Resource kind names used in parity warnings.
const (
	kindAPIRoute       = "APIRoute"
	kindGRPCRoute      = "GRPCRoute"
	kindGraphQLRoute   = "GraphQLRoute"
	kindBackend        = "Backend"
	kindGRPCBackend    = "GRPCBackend"
	kindGraphQLBackend = "GraphQLBackend"
)

// warnFieldNotApplied returns an "accepted but not applied" warning for a
// CRD field that has no counterpart in the gateway configuration yet. The
// field is accepted for forward compatibility instead of being silently
// dropped without a trace.
func warnFieldNotApplied(field, kind string) []string {
	return []string{fmt.Sprintf(
		"%s is accepted but not applied for %s yet: the gateway configuration has no "+
			"corresponding option, so the field currently has no effect. It is accepted "+
			"for forward compatibility.", field, kind)}
}

// warnCacheKeyComponentsUnapplied returns a warning when the deprecated
// cache.keyComponents field is set: the gateway has no counterpart and
// ignores it. cache.keyConfig is the supported replacement.
//
//nolint:staticcheck // SA1019: the warning exists precisely to surface the deprecated field
func warnCacheKeyComponentsUnapplied(cache *avapigwv1alpha1.CacheConfig, kind string) []string {
	if cache == nil || len(cache.KeyComponents) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"cache.keyComponents on %s is deprecated and not applied: the gateway has no "+
			"corresponding option. Use cache.keyConfig (includeMethod, includePath, "+
			"includeQueryParams, includeHeaders, includeBodyHash, keyTemplate) instead.", kind)}
}

// warnAuthzCacheRedisWithoutConnection returns a warning when the
// authorization decision cache selects the redis type without any Redis
// connection configuration. The configuration is genuinely unusable as a
// distributed cache: the gateway falls back to the in-memory decision cache,
// so the redis type selection has no effect.
//
//nolint:staticcheck // SA1019: the deprecated sentinel field still counts as a usable connection
func warnAuthzCacheRedisWithoutConnection(authz *avapigwv1alpha1.AuthorizationConfig, kind string) []string {
	if authz == nil || authz.Cache == nil || authz.Cache.Type != CacheTypeRedis {
		return nil
	}
	if authz.Cache.Redis != nil || authz.Cache.Sentinel != nil {
		return nil
	}
	return []string{fmt.Sprintf(
		"authorization.cache.type=redis on %s has no Redis connection configuration: the "+
			"gateway falls back to the in-memory decision cache, so the redis type selection "+
			"is not applied. Configure authorization.cache.redis (url or sentinel) to enable "+
			"the distributed decision cache.", kind)}
}

// warnAuthzCacheSentinelDeprecated returns a deprecation warning when the
// legacy authorization.cache.sentinel field is used. The operator converts
// the field into the gateway's authorization.cache.redis.sentinel shape, so
// the configuration still takes effect, but manifests should migrate.
//
//nolint:staticcheck // SA1019: the warning exists precisely to surface the deprecated field
func warnAuthzCacheSentinelDeprecated(authz *avapigwv1alpha1.AuthorizationConfig) []string {
	if authz == nil || authz.Cache == nil || authz.Cache.Sentinel == nil {
		return nil
	}
	return []string{
		"authorization.cache.sentinel is deprecated: use authorization.cache.redis.sentinel " +
			"instead. The operator converts the legacy field to the gateway's " +
			"authorization.cache.redis shape, but the field will be removed in a future API revision.",
	}
}

// warnAuthzCacheSecrets returns plaintext-secret warnings for the
// authorization decision cache Redis Sentinel configuration, covering both
// the preferred redis.sentinel block and the deprecated sentinel block.
//
//nolint:staticcheck // SA1019: plaintext-secret scanning must keep covering the deprecated field
func warnAuthzCacheSecrets(authz *avapigwv1alpha1.AuthorizationConfig) []string {
	if authz == nil || authz.Cache == nil {
		return nil
	}

	var warnings []string
	if authz.Cache.Redis != nil && authz.Cache.Redis.Sentinel != nil {
		warnings = append(warnings, warnPlaintextSentinelSecrets(authz.Cache.Redis.Sentinel)...)
	}
	if authz.Cache.Sentinel != nil {
		warnings = append(warnings, warnPlaintextSentinelSecrets(authz.Cache.Sentinel)...)
	}
	return warnings
}

// warnBackendRateLimitUnapplied returns a warning when a rate limit is
// enabled on a backend kind whose gateway configuration type has no rateLimit
// option at all (GRPCBackend, GraphQLBackend). Unlike
// warnRateLimitRedisStoreUnapplied (which covers only store=redis), this
// warning covers the whole field for kinds where it cannot take effect.
func warnBackendRateLimitUnapplied(rl *avapigwv1alpha1.RateLimitConfig, kind string) []string {
	if rl == nil || !rl.Enabled {
		return nil
	}
	return warnFieldNotApplied("spec.rateLimit", kind)
}
