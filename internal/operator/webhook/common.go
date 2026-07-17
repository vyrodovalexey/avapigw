// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"fmt"
	"strings"
	"time"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
)

// Policy constants.
const policyAllow = "allow"

// policyDeny is the deny policy effect.
const policyDeny = "deny"

// TLS version constants.
const (
	tlsVersion12 = "TLS12"
	tlsVersion13 = "TLS13"
)

// defaultGRPCHealthCheckHTTPPath mirrors the CRD schema default for
// GRPCBackend spec.healthCheck.httpPath (+kubebuilder:default="/healthz" in
// api/v1alpha1/grpcbackend_types.go). The API server applies structural
// defaulting BEFORE validating webhooks run, so every GRPCBackend with a
// healthCheck block reaches the webhook with this value populated even when
// the user never set it. It must therefore be tolerated when useHTTP is
// false, where it is inert.
const defaultGRPCHealthCheckHTTPPath = "/healthz"

// Validation boundary constants for webhook validation.
const (
	// MinPort is the minimum valid port number.
	MinPort = 1

	// MaxPort is the maximum valid port number.
	MaxPort = 65535

	// MinWeight is the minimum valid weight for load balancing.
	MinWeight = 0

	// MaxWeight is the maximum valid weight for load balancing.
	MaxWeight = 100

	// MinRetryAttempts is the minimum number of retry attempts.
	MinRetryAttempts = 1

	// MaxRetryAttempts is the maximum number of retry attempts.
	MaxRetryAttempts = 10

	// MinStatusCode is the minimum valid HTTP status code.
	MinStatusCode = 100

	// MaxStatusCode is the maximum valid HTTP status code.
	MaxStatusCode = 599

	// TotalWeightExpected is the expected total weight when multiple destinations are configured.
	TotalWeightExpected = 100

	// CacheTypeMemory is the memory cache type.
	CacheTypeMemory = "memory"

	// CacheTypeRedis is the Redis cache type.
	CacheTypeRedis = "redis"

	// TLSModeInsecure is the insecure TLS mode value.
	TLSModeInsecure = "INSECURE"
)

// validateDuration validates a duration string using Go's time.ParseDuration.
// This is safer than regex-based validation and avoids potential ReDoS vulnerabilities.
// Negative durations are rejected as they don't make sense for timeout/interval configurations.
func validateDuration(d string) error {
	if d == "" {
		return nil
	}
	duration, err := time.ParseDuration(d)
	if err != nil {
		return fmt.Errorf("invalid duration format: %q (expected format like '30s', '5m', '1h'): %w", d, err)
	}
	// Reject negative durations as they don't make sense for configuration values
	if duration < 0 {
		return fmt.Errorf("invalid duration: %q (negative durations are not allowed)", d)
	}
	return nil
}

// validateRateLimit validates rate limit configuration.
func validateRateLimit(rl *avapigwv1alpha1.RateLimitConfig) error {
	if rl.Enabled {
		if rl.RequestsPerSecond < 1 {
			return fmt.Errorf("rateLimit.requestsPerSecond must be at least 1")
		}

		if rl.Burst < 1 {
			return fmt.Errorf("rateLimit.burst must be at least 1")
		}
	}

	// Store selection is validated even when rate limiting is disabled so
	// configuration errors surface before the limiter is switched on.
	return validateRateLimitStore(rl)
}

// validateRateLimitStore validates the rate limiter store selection and the
// Redis connection configuration of the distributed rate limiter, mirroring
// the gateway's own configuration validation rules.
func validateRateLimitStore(rl *avapigwv1alpha1.RateLimitConfig) error {
	switch rl.Store {
	case "", CacheTypeMemory:
		if rl.Redis != nil {
			return fmt.Errorf("rateLimit.redis is only valid when rateLimit.store is 'redis'")
		}
		return nil
	case CacheTypeRedis:
		// Valid store; connection configuration is validated below.
	default:
		return fmt.Errorf("rateLimit.store must be 'memory' or 'redis'")
	}

	if rl.Redis == nil {
		return fmt.Errorf("rateLimit.redis is required when rateLimit.store is 'redis'")
	}

	return validateRedisConnectionSpec(redisConnectionSpec{
		fieldPath:      "rateLimit.redis",
		url:            rl.Redis.URL,
		sentinel:       rl.Redis.Sentinel,
		connectTimeout: rl.Redis.ConnectTimeout,
		readTimeout:    rl.Redis.ReadTimeout,
		writeTimeout:   rl.Redis.WriteTimeout,
		retry:          rl.Redis.Retry,
	})
}

// redisConnectionSpec carries the connection fields shared by the route
// cache and rate limiter Redis specifications for common validation.
type redisConnectionSpec struct {
	fieldPath      string
	url            string
	sentinel       *avapigwv1alpha1.RedisSentinelSpec
	connectTimeout avapigwv1alpha1.Duration
	readTimeout    avapigwv1alpha1.Duration
	writeTimeout   avapigwv1alpha1.Duration
	retry          *avapigwv1alpha1.RedisRetrySpec
}

// validateRedisConnectionSpec validates the shared standalone-vs-sentinel
// Redis connection rules: url and sentinel are mutually exclusive, at least
// one must be configured, and sentinel requires masterName plus addresses.
func validateRedisConnectionSpec(spec redisConnectionSpec) error {
	hasURL := spec.url != ""
	hasSentinel := spec.sentinel != nil

	if hasURL && hasSentinel {
		return fmt.Errorf("%s.url and %s.sentinel are mutually exclusive", spec.fieldPath, spec.fieldPath)
	}
	if !hasURL && !hasSentinel {
		return fmt.Errorf("%s requires either url or sentinel", spec.fieldPath)
	}

	if err := validateRedisSentinelSpec(spec.sentinel, spec.fieldPath+".sentinel"); err != nil {
		return err
	}

	durations := map[string]avapigwv1alpha1.Duration{
		"connectTimeout": spec.connectTimeout,
		"readTimeout":    spec.readTimeout,
		"writeTimeout":   spec.writeTimeout,
	}
	if err := validateDurationFields(spec.fieldPath, durations); err != nil {
		return err
	}

	return validateRedisRetrySpec(spec.retry, spec.fieldPath+".retry")
}

// validateDurationFields validates a set of named duration fields.
func validateDurationFields(fieldPath string, durations map[string]avapigwv1alpha1.Duration) error {
	for name, d := range durations {
		if d == "" {
			continue
		}
		if err := validateDuration(string(d)); err != nil {
			return fmt.Errorf("%s.%s is invalid: %w", fieldPath, name, err)
		}
	}
	return nil
}

// validateRedisRetrySpec validates Redis connection retry configuration.
func validateRedisRetrySpec(retrySpec *avapigwv1alpha1.RedisRetrySpec, fieldPath string) error {
	if retrySpec == nil {
		return nil
	}

	if retrySpec.MaxRetries < 0 {
		return fmt.Errorf("%s.maxRetries must be non-negative", fieldPath)
	}

	return validateDurationFields(fieldPath, map[string]avapigwv1alpha1.Duration{
		"initialBackoff": retrySpec.InitialBackoff,
		"maxBackoff":     retrySpec.MaxBackoff,
	})
}

// validateRouteCacheConfig validates route-level cache configuration shared
// by the APIRoute, GRPCRoute and GraphQLRoute webhooks, mirroring the
// gateway's own configuration validation rules.
func validateRouteCacheConfig(cache *avapigwv1alpha1.CacheConfig) error {
	if cache.TTL != "" {
		if err := validateDuration(string(cache.TTL)); err != nil {
			return fmt.Errorf("cache.ttl is invalid: %w", err)
		}
	}

	if cache.StaleWhileRevalidate != "" {
		if err := validateDuration(string(cache.StaleWhileRevalidate)); err != nil {
			return fmt.Errorf("cache.staleWhileRevalidate is invalid: %w", err)
		}
	}

	if err := validateCacheType(cache.Type, "cache"); err != nil {
		return err
	}

	return validateRouteCacheRedis(cache)
}

// validateRouteCacheRedis validates the Redis backend selection rules of a
// route-level cache: the redis block is required (and only valid) for
// type=redis, url and sentinel are mutually exclusive, and jitter stays
// within [0.0, 1.0].
func validateRouteCacheRedis(cache *avapigwv1alpha1.CacheConfig) error {
	if cache.Type != CacheTypeRedis {
		if cache.Redis != nil {
			return fmt.Errorf("cache.redis is only valid when cache.type is 'redis'")
		}
		return nil
	}

	if cache.Redis == nil {
		return fmt.Errorf("cache.redis is required when cache.type is 'redis'")
	}

	if err := validateRedisConnectionSpec(redisConnectionSpec{
		fieldPath:      "cache.redis",
		url:            cache.Redis.URL,
		sentinel:       cache.Redis.Sentinel,
		connectTimeout: cache.Redis.ConnectTimeout,
		readTimeout:    cache.Redis.ReadTimeout,
		writeTimeout:   cache.Redis.WriteTimeout,
		retry:          cache.Redis.Retry,
	}); err != nil {
		return err
	}

	if cache.Redis.TTLJitter != nil && (*cache.Redis.TTLJitter < 0.0 || *cache.Redis.TTLJitter > 1.0) {
		return fmt.Errorf("cache.redis.ttlJitter must be between 0.0 and 1.0")
	}

	return nil
}

// validateCORS validates CORS configuration.
func validateCORS(cors *avapigwv1alpha1.CORSConfig) error {
	// Validate allowed methods
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, methodDELETE: true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}
	for _, method := range cors.AllowMethods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("cors.allowMethods contains invalid method: %q", method)
		}
	}

	// Validate max age
	if cors.MaxAge < 0 {
		return fmt.Errorf("cors.maxAge must be non-negative")
	}

	return nil
}

// validateMaxSessions validates max sessions configuration.
func validateMaxSessions(ms *avapigwv1alpha1.MaxSessionsConfig) error {
	if !ms.Enabled {
		return nil
	}

	if ms.MaxConcurrent < 1 {
		return fmt.Errorf("maxSessions.maxConcurrent must be at least 1")
	}

	if ms.QueueSize < 0 {
		return fmt.Errorf("maxSessions.queueSize must be non-negative")
	}

	if ms.QueueTimeout != "" {
		if err := validateDuration(string(ms.QueueTimeout)); err != nil {
			return fmt.Errorf("maxSessions.queueTimeout is invalid: %w", err)
		}
	}

	return nil
}

// validateRouteTLS validates route TLS configuration.
func validateRouteTLS(tls *avapigwv1alpha1.RouteTLSConfig) error {
	// Validate TLS version
	validVersions := map[string]bool{tlsVersion12: true, tlsVersion13: true, "": true}
	if !validVersions[tls.MinVersion] {
		return fmt.Errorf("tls.minVersion must be 'TLS12' or 'TLS13'")
	}
	if !validVersions[tls.MaxVersion] {
		return fmt.Errorf("tls.maxVersion must be 'TLS12' or 'TLS13'")
	}

	// Validate min <= max
	if tls.MinVersion == tlsVersion13 && tls.MaxVersion == tlsVersion12 {
		return fmt.Errorf("tls.minVersion cannot be greater than tls.maxVersion")
	}

	// Validate client validation
	if tls.ClientValidation != nil {
		if tls.ClientValidation.Enabled && tls.ClientValidation.CAFile == "" {
			return fmt.Errorf("tls.clientValidation.caFile is required when client validation is enabled")
		}
	}

	// Validate Vault configuration
	if tls.Vault != nil && tls.Vault.Enabled {
		if tls.Vault.PKIMount == "" {
			return fmt.Errorf("tls.vault.pkiMount is required when Vault is enabled")
		}
		if tls.Vault.Role == "" {
			return fmt.Errorf("tls.vault.role is required when Vault is enabled")
		}
	}

	return nil
}

// validateBackendTLS validates backend TLS configuration.
//
//nolint:gocognit,gocyclo // TLS validation requires checking mode, version, and mTLS settings
func validateBackendTLS(tls *avapigwv1alpha1.BackendTLSConfig) error {
	if !tls.Enabled {
		return nil
	}

	// Validate TLS mode
	validModes := map[string]bool{"SIMPLE": true, "MUTUAL": true, "INSECURE": true, "": true}
	if !validModes[tls.Mode] {
		return fmt.Errorf("tls.mode must be 'SIMPLE', 'MUTUAL', or 'INSECURE'")
	}

	// Validate TLS version
	validVersions := map[string]bool{tlsVersion12: true, tlsVersion13: true, "": true}
	if !validVersions[tls.MinVersion] {
		return fmt.Errorf("tls.minVersion must be 'TLS12' or 'TLS13'")
	}
	if !validVersions[tls.MaxVersion] {
		return fmt.Errorf("tls.maxVersion must be 'TLS12' or 'TLS13'")
	}

	// Validate min <= max
	if tls.MinVersion == tlsVersion13 && tls.MaxVersion == tlsVersion12 {
		return fmt.Errorf("tls.minVersion cannot be greater than tls.maxVersion")
	}

	// Validate mTLS configuration
	if tls.Mode == "MUTUAL" {
		if tls.CertFile == "" && (tls.Vault == nil || !tls.Vault.Enabled) {
			return fmt.Errorf("tls.certFile or tls.vault is required for MUTUAL TLS mode")
		}
		if tls.KeyFile == "" && (tls.Vault == nil || !tls.Vault.Enabled) {
			return fmt.Errorf("tls.keyFile or tls.vault is required for MUTUAL TLS mode")
		}
	}

	// Validate Vault configuration
	if tls.Vault != nil && tls.Vault.Enabled {
		if tls.Vault.PKIMount == "" {
			return fmt.Errorf("tls.vault.pkiMount is required when Vault is enabled")
		}
		if tls.Vault.Role == "" {
			return fmt.Errorf("tls.vault.role is required when Vault is enabled")
		}
	}

	return nil
}

// validateCircuitBreaker validates circuit breaker configuration.
func validateCircuitBreaker(cb *avapigwv1alpha1.CircuitBreakerConfig) error {
	if !cb.Enabled {
		return nil
	}

	if cb.Threshold < 1 {
		return fmt.Errorf("circuitBreaker.threshold must be at least 1")
	}

	if cb.Timeout == "" {
		return fmt.Errorf("circuitBreaker.timeout is required")
	}
	if err := validateDuration(string(cb.Timeout)); err != nil {
		return fmt.Errorf("circuitBreaker.timeout is invalid: %w", err)
	}

	if cb.HalfOpenRequests < 0 {
		return fmt.Errorf("circuitBreaker.halfOpenRequests must be non-negative")
	}

	return nil
}

// validateLoadBalancer validates load balancer configuration.
func validateLoadBalancer(lb *avapigwv1alpha1.LoadBalancerConfig) error {
	validAlgorithms := map[avapigwv1alpha1.LoadBalancerAlgorithm]bool{
		avapigwv1alpha1.LoadBalancerRoundRobin: true,
		avapigwv1alpha1.LoadBalancerWeighted:   true,
		avapigwv1alpha1.LoadBalancerLeastConn:  true,
		avapigwv1alpha1.LoadBalancerRandom:     true,
		"":                                     true,
	}

	if !validAlgorithms[lb.Algorithm] {
		return fmt.Errorf("loadBalancer.algorithm must be one of: roundRobin, weighted, leastConn, random")
	}

	return nil
}

// validateBackendHosts validates backend host configurations.
func validateBackendHosts(hosts []avapigwv1alpha1.BackendHost) error {
	if len(hosts) == 0 {
		return fmt.Errorf("at least one host is required")
	}

	totalWeight := 0
	for i, host := range hosts {
		if host.Address == "" {
			return fmt.Errorf("hosts[%d].address is required", i)
		}
		if host.Port < MinPort || host.Port > MaxPort {
			return fmt.Errorf("hosts[%d].port must be between %d and %d", i, MinPort, MaxPort)
		}
		if host.Weight < MinWeight || host.Weight > MaxWeight {
			return fmt.Errorf("hosts[%d].weight must be between %d and %d", i, MinWeight, MaxWeight)
		}
		totalWeight += host.Weight
	}

	// If weights are specified, they should sum to 100
	if len(hosts) > 1 && totalWeight > 0 && totalWeight != TotalWeightExpected {
		return fmt.Errorf("total weight of all hosts must equal %d (got %d)", TotalWeightExpected, totalWeight)
	}

	return nil
}

// validateHealthCheck validates health check configuration.
func validateHealthCheck(hc *avapigwv1alpha1.HealthCheckConfig) error {
	if hc.Path == "" {
		return fmt.Errorf("healthCheck.path is required")
	}

	if hc.Interval != "" {
		if err := validateDuration(string(hc.Interval)); err != nil {
			return fmt.Errorf("healthCheck.interval is invalid: %w", err)
		}
	}

	if hc.Timeout != "" {
		if err := validateDuration(string(hc.Timeout)); err != nil {
			return fmt.Errorf("healthCheck.timeout is invalid: %w", err)
		}
	}

	if hc.HealthyThreshold < 0 {
		return fmt.Errorf("healthCheck.healthyThreshold must be non-negative")
	}

	if hc.UnhealthyThreshold < 0 {
		return fmt.Errorf("healthCheck.unhealthyThreshold must be non-negative")
	}

	return nil
}

// validateGRPCHealthCheck validates gRPC health check configuration.
func validateGRPCHealthCheck(hc *avapigwv1alpha1.GRPCHealthCheckConfig) error {
	if hc.Interval != "" {
		if err := validateDuration(string(hc.Interval)); err != nil {
			return fmt.Errorf("healthCheck.interval is invalid: %w", err)
		}
	}

	if hc.Timeout != "" {
		if err := validateDuration(string(hc.Timeout)); err != nil {
			return fmt.Errorf("healthCheck.timeout is invalid: %w", err)
		}
	}

	if hc.HealthyThreshold < 0 {
		return fmt.Errorf("healthCheck.healthyThreshold must be non-negative")
	}

	if hc.UnhealthyThreshold < 0 {
		return fmt.Errorf("healthCheck.unhealthyThreshold must be non-negative")
	}

	return validateGRPCHealthCheckHTTPMode(hc)
}

// validateGRPCHealthCheckHTTPMode validates the HTTP-mode fields of a gRPC
// health check (httpPath/httpPort) against the useHTTP toggle.
func validateGRPCHealthCheckHTTPMode(hc *avapigwv1alpha1.GRPCHealthCheckConfig) error {
	if hc.UseHTTP {
		if hc.HTTPPath != "" && !strings.HasPrefix(hc.HTTPPath, "/") {
			return fmt.Errorf("healthCheck.httpPath must start with '/'")
		}

		if hc.HTTPPort != 0 &&
			(hc.HTTPPort < MinPort || hc.HTTPPort > MaxPort) {
			return fmt.Errorf(
				"healthCheck.httpPort must be between %d and %d",
				MinPort, MaxPort,
			)
		}

		return nil
	}

	// Tolerate the CRD schema default: the API server defaults httpPath to
	// "/healthz" before this webhook runs, so only an explicit non-default
	// path signals user misconfiguration.
	if hc.HTTPPath != "" && hc.HTTPPath != defaultGRPCHealthCheckHTTPPath {
		return fmt.Errorf(
			"healthCheck.httpPath must not be set when useHTTP is false",
		)
	}

	if hc.HTTPPort != 0 {
		return fmt.Errorf(
			"healthCheck.httpPort must not be set when useHTTP is false",
		)
	}

	return nil
}

// validateBackendAuth validates backend authentication configuration.
func validateBackendAuth(auth *avapigwv1alpha1.BackendAuthConfig) error {
	validTypes := map[string]bool{"jwt": true, "basic": true, "mtls": true}
	if !validTypes[auth.Type] {
		return fmt.Errorf("authentication.type must be one of: jwt, basic, mtls")
	}

	switch auth.Type {
	case "jwt":
		if auth.JWT == nil {
			return fmt.Errorf("authentication.jwt is required when type is 'jwt'")
		}
		if err := validateJWTAuth(auth.JWT); err != nil {
			return err
		}
	case "basic":
		if auth.Basic == nil {
			return fmt.Errorf("authentication.basic is required when type is 'basic'")
		}
		if err := validateBasicAuth(auth.Basic); err != nil {
			return err
		}
	case "mtls":
		if auth.MTLS == nil {
			return fmt.Errorf("authentication.mtls is required when type is 'mtls'")
		}
		if err := validateMTLSAuth(auth.MTLS); err != nil {
			return err
		}
	}

	return nil
}

// validateJWTAuth validates JWT authentication configuration.
func validateJWTAuth(jwt *avapigwv1alpha1.BackendJWTAuthConfig) error {
	if !jwt.Enabled {
		return nil
	}

	validSources := map[string]bool{"static": true, "vault": true, "oidc": true}
	if !validSources[jwt.TokenSource] {
		return fmt.Errorf("authentication.jwt.tokenSource must be one of: static, vault, oidc")
	}

	switch jwt.TokenSource {
	case "static":
		if jwt.StaticToken == "" {
			return fmt.Errorf("authentication.jwt.staticToken is required when tokenSource is 'static'")
		}
	case "vault":
		if jwt.VaultPath == "" {
			return fmt.Errorf("authentication.jwt.vaultPath is required when tokenSource is 'vault'")
		}
	case "oidc":
		if jwt.OIDC == nil {
			return fmt.Errorf("authentication.jwt.oidc is required when tokenSource is 'oidc'")
		}
		if jwt.OIDC.IssuerURL == "" {
			return fmt.Errorf("authentication.jwt.oidc.issuerUrl is required")
		}
		if jwt.OIDC.ClientID == "" {
			return fmt.Errorf("authentication.jwt.oidc.clientId is required")
		}
	}

	return nil
}

// validateBasicAuth validates Basic authentication configuration.
func validateBasicAuth(basic *avapigwv1alpha1.BackendBasicAuthConfig) error {
	if !basic.Enabled {
		return nil
	}

	// Either static credentials or Vault path must be provided
	hasStatic := basic.Username != "" && basic.Password != ""
	hasVault := basic.VaultPath != ""

	if !hasStatic && !hasVault {
		return fmt.Errorf("authentication.basic requires either username/password or vaultPath")
	}

	return nil
}

// validateMTLSAuth validates mTLS authentication configuration.
func validateMTLSAuth(mtls *avapigwv1alpha1.BackendMTLSAuthConfig) error {
	if !mtls.Enabled {
		return nil
	}

	// Either file-based or Vault-based certificates must be provided
	hasFiles := mtls.CertFile != "" && mtls.KeyFile != ""
	hasVault := mtls.Vault != nil && mtls.Vault.Enabled

	if !hasFiles && !hasVault {
		return fmt.Errorf("authentication.mtls requires either certFile/keyFile or vault configuration")
	}

	if hasVault {
		if mtls.Vault.PKIMount == "" {
			return fmt.Errorf("authentication.mtls.vault.pkiMount is required")
		}
		if mtls.Vault.Role == "" {
			return fmt.Errorf("authentication.mtls.vault.role is required")
		}
	}

	return nil
}

// validateAuthentication validates route-level authentication configuration.
//
//nolint:gocognit,gocyclo // Authentication validation requires checking JWT, API key, mTLS, and OIDC
func validateAuthentication(auth *avapigwv1alpha1.AuthenticationConfig) error {
	if !auth.Enabled {
		return nil
	}

	// Check if at least one authentication method is configured
	hasJWT := auth.JWT != nil && auth.JWT.Enabled
	hasAPIKey := auth.APIKey != nil && auth.APIKey.Enabled
	hasMTLS := auth.MTLS != nil && auth.MTLS.Enabled
	hasOIDC := auth.OIDC != nil && auth.OIDC.Enabled

	if !hasJWT && !hasAPIKey && !hasMTLS && !hasOIDC && !auth.AllowAnonymous {
		return fmt.Errorf("authentication is enabled but no authentication method is configured")
	}

	// Validate JWT configuration
	if auth.JWT != nil && auth.JWT.Enabled {
		if err := validateRouteJWTAuth(auth.JWT); err != nil {
			return err
		}
	}

	// Validate API Key configuration
	if auth.APIKey != nil && auth.APIKey.Enabled {
		if err := validateRouteAPIKeyAuth(auth.APIKey); err != nil {
			return err
		}
	}

	// Validate mTLS configuration
	if auth.MTLS != nil && auth.MTLS.Enabled {
		if err := validateRouteMTLSAuth(auth.MTLS); err != nil {
			return err
		}
	}

	// Validate OIDC configuration
	if auth.OIDC != nil && auth.OIDC.Enabled {
		if err := validateRouteOIDCAuth(auth.OIDC); err != nil {
			return err
		}
	}

	return nil
}

// validateRouteJWTAuth validates route-level JWT authentication configuration.
func validateRouteJWTAuth(jwt *avapigwv1alpha1.JWTAuthConfig) error {
	// At least one of JWKS URL, secret, or public key must be provided
	hasJWKS := jwt.JWKSURL != ""
	hasSecret := jwt.Secret != ""
	hasPublicKey := jwt.PublicKey != ""

	if !hasJWKS && !hasSecret && !hasPublicKey {
		return fmt.Errorf("authentication.jwt requires at least one of jwksUrl, secret, or publicKey")
	}

	// Validate algorithm if specified
	if jwt.Algorithm != "" {
		validAlgorithms := map[string]bool{
			"HS256": true, "HS384": true, "HS512": true,
			"RS256": true, "RS384": true, "RS512": true,
			"ES256": true, "ES384": true, "ES512": true,
		}
		if !validAlgorithms[jwt.Algorithm] {
			return fmt.Errorf("authentication.jwt.algorithm is invalid: %s", jwt.Algorithm)
		}
	}

	return nil
}

// validateRouteAPIKeyAuth validates route-level API key authentication configuration.
func validateRouteAPIKeyAuth(apiKey *avapigwv1alpha1.APIKeyAuthConfig) error {
	// At least header or query must be specified
	if apiKey.Header == "" && apiKey.Query == "" {
		return fmt.Errorf("authentication.apiKey requires at least one of header or query")
	}

	// Validate hash algorithm if specified
	if apiKey.HashAlgorithm != "" {
		validAlgorithms := map[string]bool{
			"sha256": true, "sha512": true, "bcrypt": true,
		}
		if !validAlgorithms[apiKey.HashAlgorithm] {
			return fmt.Errorf("authentication.apiKey.hashAlgorithm must be one of: sha256, sha512, bcrypt")
		}
	}

	return nil
}

// validateRouteMTLSAuth validates route-level mTLS authentication configuration.
//
// A missing caFile is intentionally NOT an error: the gateway accepts an mTLS
// config whose CA comes from a gateway-level source (Vault-managed PKI or an
// inline CA cert — see internal/auth/mtls.Config.hasCASource), and the CRD
// carries no field for those sources, so the webhook cannot know whether a
// gateway-level CA is in play. warnMTLSMissingCAFile surfaces the situation
// as an admission WARNING instead.
func validateRouteMTLSAuth(mtls *avapigwv1alpha1.MTLSAuthConfig) error {
	// Validate extract identity if specified
	if mtls.ExtractIdentity != "" {
		validMethods := map[string]bool{
			"cn": true, "san": true, "ou": true,
		}
		if !validMethods[mtls.ExtractIdentity] {
			return fmt.Errorf("authentication.mtls.extractIdentity must be one of: cn, san, ou")
		}
	}

	return nil
}

// validateRouteOIDCAuth validates route-level OIDC authentication configuration.
func validateRouteOIDCAuth(oidc *avapigwv1alpha1.OIDCAuthConfig) error {
	if len(oidc.Providers) == 0 {
		return fmt.Errorf("authentication.oidc.providers is required when OIDC is enabled")
	}

	for i, provider := range oidc.Providers {
		if provider.Name == "" {
			return fmt.Errorf("authentication.oidc.providers[%d].name is required", i)
		}
		if provider.IssuerURL == "" {
			return fmt.Errorf("authentication.oidc.providers[%d].issuerUrl is required", i)
		}
		if provider.ClientID == "" {
			return fmt.Errorf("authentication.oidc.providers[%d].clientId is required", i)
		}
	}

	return nil
}

// validateAuthorization validates route-level authorization configuration.
//
//nolint:gocognit,gocyclo // Authorization validation requires checking RBAC, ABAC, and external authz
func validateAuthorization(authz *avapigwv1alpha1.AuthorizationConfig) error {
	if !authz.Enabled {
		return nil
	}

	// Validate default policy
	if authz.DefaultPolicy != "" {
		validPolicies := map[string]bool{policyAllow: true, policyDeny: true}
		if !validPolicies[authz.DefaultPolicy] {
			return fmt.Errorf("authorization.defaultPolicy must be 'allow' or 'deny'")
		}
	}

	// Check if at least one authorization method is configured
	hasRBAC := authz.RBAC != nil && authz.RBAC.Enabled
	hasABAC := authz.ABAC != nil && authz.ABAC.Enabled
	hasExternal := authz.External != nil && authz.External.Enabled

	if !hasRBAC && !hasABAC && !hasExternal {
		return fmt.Errorf("authorization is enabled but no authorization method is configured")
	}

	// Validate RBAC configuration
	if authz.RBAC != nil && authz.RBAC.Enabled {
		if err := validateRBACConfig(authz.RBAC); err != nil {
			return err
		}
	}

	// Validate ABAC configuration
	if authz.ABAC != nil && authz.ABAC.Enabled {
		if err := validateABACConfig(authz.ABAC); err != nil {
			return err
		}
	}

	// Validate External configuration
	if authz.External != nil && authz.External.Enabled {
		if err := validateExternalAuthzConfig(authz.External); err != nil {
			return err
		}
	}

	// Validate cache configuration
	if authz.Cache != nil && authz.Cache.Enabled {
		if err := validateAuthzCacheConfig(authz.Cache); err != nil {
			return err
		}
	}

	return nil
}

// validateRBACConfig validates RBAC configuration.
func validateRBACConfig(rbac *avapigwv1alpha1.RBACConfig) error {
	for i, policy := range rbac.Policies {
		if policy.Name == "" {
			return fmt.Errorf("authorization.rbac.policies[%d].name is required", i)
		}

		// Validate effect if specified
		if policy.Effect != "" {
			validEffects := map[string]bool{policyAllow: true, policyDeny: true}
			if !validEffects[policy.Effect] {
				return fmt.Errorf("authorization.rbac.policies[%d].effect must be 'allow' or 'deny'", i)
			}
		}

		// Validate priority
		if policy.Priority < 0 {
			return fmt.Errorf("authorization.rbac.policies[%d].priority must be non-negative", i)
		}
	}

	return nil
}

// validateABACConfig validates ABAC configuration.
func validateABACConfig(abac *avapigwv1alpha1.ABACConfig) error {
	for i, policy := range abac.Policies {
		if policy.Name == "" {
			return fmt.Errorf("authorization.abac.policies[%d].name is required", i)
		}
		if policy.Expression == "" {
			return fmt.Errorf("authorization.abac.policies[%d].expression is required", i)
		}

		// Validate CEL expression
		if err := validateCELExpression(policy.Expression); err != nil {
			return fmt.Errorf("authorization.abac.policies[%d].expression is invalid: %w", i, err)
		}

		// Validate effect if specified
		if policy.Effect != "" {
			validEffects := map[string]bool{policyAllow: true, policyDeny: true}
			if !validEffects[policy.Effect] {
				return fmt.Errorf("authorization.abac.policies[%d].effect must be 'allow' or 'deny'", i)
			}
		}

		// Validate priority
		if policy.Priority < 0 {
			return fmt.Errorf("authorization.abac.policies[%d].priority must be non-negative", i)
		}
	}

	return nil
}

// validateCELExpression validates a CEL expression for ABAC policies.
// It compiles the expression against the SAME CEL environment the gateway's
// ABAC engine evaluates policies with (see internal/authz/abac.NewCELEnv), so
// admission-time validation exactly mirrors runtime compilation. The shared
// environment declares: subject (map), request (map), resource (string),
// action (string), environment (map), now (timestamp), and the custom
// functions ip_in_range and has_role.
func validateCELExpression(expr string) error {
	env, err := abac.NewCELEnv()
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	_, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("invalid CEL expression: %w", issues.Err())
	}
	return nil
}

// validateExternalAuthzConfig validates external authorization configuration.
func validateExternalAuthzConfig(external *avapigwv1alpha1.ExternalAuthzConfig) error {
	// OPA is currently the only supported external authorization
	if external.OPA == nil {
		return fmt.Errorf("authorization.external.opa is required when external authorization is enabled")
	}

	if external.OPA.URL == "" {
		return fmt.Errorf("authorization.external.opa.url is required")
	}

	// Validate timeout if specified
	if external.Timeout != "" {
		if err := validateDuration(string(external.Timeout)); err != nil {
			return fmt.Errorf("authorization.external.timeout is invalid: %w", err)
		}
	}

	return nil
}

// validateAuthzCacheConfig validates authorization cache configuration.
func validateAuthzCacheConfig(cache *avapigwv1alpha1.AuthzCacheConfig) error {
	// Validate TTL if specified
	if cache.TTL != "" {
		if err := validateDuration(string(cache.TTL)); err != nil {
			return fmt.Errorf("authorization.cache.ttl is invalid: %w", err)
		}
	}

	// Validate max size
	if cache.MaxSize < 0 {
		return fmt.Errorf("authorization.cache.maxSize must be non-negative")
	}

	// Validate cache type
	if err := validateCacheType(cache.Type, "authorization.cache"); err != nil {
		return err
	}

	// Validate sentinel configuration for redis cache type
	if cache.Sentinel != nil {
		if cache.Type != CacheTypeRedis {
			return fmt.Errorf("authorization.cache.sentinel is only valid when type is 'redis'")
		}
		if err := validateRedisSentinelSpec(cache.Sentinel, "authorization.cache.sentinel"); err != nil {
			return err
		}
	}

	return nil
}

// validateCacheType validates that the cache type is valid.
func validateCacheType(cacheType, fieldPath string) error {
	if cacheType == "" {
		return nil
	}
	validTypes := map[string]bool{CacheTypeMemory: true, CacheTypeRedis: true}
	if !validTypes[cacheType] {
		return fmt.Errorf("%s.type must be 'memory' or 'redis'", fieldPath)
	}
	return nil
}

// validateRedisSentinelSpec validates Redis Sentinel configuration.
func validateRedisSentinelSpec(sentinel *avapigwv1alpha1.RedisSentinelSpec, fieldPath string) error {
	if sentinel == nil {
		return nil
	}

	if sentinel.MasterName == "" {
		return fmt.Errorf("%s.masterName is required", fieldPath)
	}

	if len(sentinel.SentinelAddrs) == 0 {
		return fmt.Errorf("%s.sentinelAddrs must have at least one address", fieldPath)
	}

	for i, addr := range sentinel.SentinelAddrs {
		if addr == "" {
			return fmt.Errorf("%s.sentinelAddrs[%d] cannot be empty", fieldPath, i)
		}
	}

	if sentinel.DB < 0 || sentinel.DB > 15 {
		return fmt.Errorf("%s.db must be between 0 and 15", fieldPath)
	}

	return nil
}

// validateBackendTransform validates backend transform configuration.
func validateBackendTransform(transform *avapigwv1alpha1.BackendTransformConfig) error {
	// Request transform validation is currently a no-op as template validation
	// would require parsing the Go template which is beyond basic validation scope.
	// The template will be validated at runtime when the configuration is applied.

	// Response transform validation
	if transform.Response != nil {
		// Validate that allow and deny fields are not both specified
		if len(transform.Response.AllowFields) > 0 && len(transform.Response.DenyFields) > 0 {
			return fmt.Errorf("transform.response cannot have both allowFields and denyFields specified")
		}
	}

	return nil
}

// validateBackendCache validates backend cache configuration.
func validateBackendCache(cache *avapigwv1alpha1.BackendCacheConfig) error {
	if !cache.Enabled {
		return nil
	}

	if err := validateBackendCacheDurations(cache); err != nil {
		return err
	}

	if err := validateCacheType(cache.Type, "cache"); err != nil {
		return err
	}

	if err := validateBackendCacheRedisConfig(cache); err != nil {
		return err
	}

	return nil
}

// validateBackendCacheDurations validates duration fields in backend cache configuration.
func validateBackendCacheDurations(cache *avapigwv1alpha1.BackendCacheConfig) error {
	if cache.TTL != "" {
		if err := validateDuration(string(cache.TTL)); err != nil {
			return fmt.Errorf("cache.ttl is invalid: %w", err)
		}
	}

	if cache.StaleWhileRevalidate != "" {
		if err := validateDuration(string(cache.StaleWhileRevalidate)); err != nil {
			return fmt.Errorf("cache.staleWhileRevalidate is invalid: %w", err)
		}
	}

	return nil
}

// validateBackendCacheRedisConfig validates Redis-specific backend cache configuration.
func validateBackendCacheRedisConfig(cache *avapigwv1alpha1.BackendCacheConfig) error {
	// Validate sentinel configuration for redis cache type
	if cache.Sentinel != nil {
		if cache.Type != CacheTypeRedis {
			return fmt.Errorf("cache.sentinel is only valid when cache.type is 'redis'")
		}
		if err := validateRedisSentinelSpec(cache.Sentinel, "cache.sentinel"); err != nil {
			return err
		}
	}

	// Validate TTLJitter if specified (must be between 0.0 and 1.0)
	if cache.TTLJitter != nil && (*cache.TTLJitter < 0.0 || *cache.TTLJitter > 1.0) {
		return fmt.Errorf("cache.ttlJitter must be between 0.0 and 1.0")
	}

	// Validate PasswordVaultPath is only used with redis cache type
	if cache.PasswordVaultPath != "" && cache.Type != CacheTypeRedis {
		return fmt.Errorf("cache.passwordVaultPath is only valid when cache.type is 'redis'")
	}

	return nil
}

// validateBackendEncoding validates backend encoding configuration.
func validateBackendEncoding(encoding *avapigwv1alpha1.BackendEncodingConfig) error {
	// Validate request encoding
	if encoding.Request != nil {
		if err := validateEncodingSettings(encoding.Request, "encoding.request"); err != nil {
			return err
		}
	}

	// Validate response encoding
	if encoding.Response != nil {
		if err := validateEncodingSettings(encoding.Response, "encoding.response"); err != nil {
			return err
		}
	}

	return nil
}

// validateEncodingSettings validates encoding settings.
func validateEncodingSettings(settings *avapigwv1alpha1.BackendEncodingSettings, fieldPath string) error {
	// Validate compression if specified
	if settings.Compression != "" {
		validCompressions := map[string]bool{
			"gzip": true, "deflate": true, "br": true, "none": true,
		}
		if !validCompressions[settings.Compression] {
			return fmt.Errorf("%s.compression must be one of: gzip, deflate, br, none", fieldPath)
		}
	}

	return nil
}

// validateGRPCBackendTransform validates gRPC backend transform configuration.
func validateGRPCBackendTransform(transform *avapigwv1alpha1.GRPCBackendTransformConfig) error {
	// Field mask validation
	if transform.FieldMask != nil {
		// Validate field paths format (basic validation)
		for i, path := range transform.FieldMask.Paths {
			if path == "" {
				return fmt.Errorf("transform.fieldMask.paths[%d] cannot be empty", i)
			}
		}
	}

	// Metadata validation
	if transform.Metadata != nil {
		// Validate static metadata keys
		for key := range transform.Metadata.Static {
			if key == "" {
				return fmt.Errorf("transform.metadata.static keys cannot be empty")
			}
		}

		// Validate dynamic metadata keys
		for key := range transform.Metadata.Dynamic {
			if key == "" {
				return fmt.Errorf("transform.metadata.dynamic keys cannot be empty")
			}
		}
	}

	return nil
}

// validateRequestLimits validates request limits configuration.
func validateRequestLimits(limits *avapigwv1alpha1.RequestLimitsConfig) error {
	if limits.MaxBodySize < 0 {
		return fmt.Errorf("requestLimits.maxBodySize must be non-negative")
	}

	if limits.MaxHeaderSize < 0 {
		return fmt.Errorf("requestLimits.maxHeaderSize must be non-negative")
	}

	return nil
}

// warnPlaintextAuthSecrets returns warnings for plaintext secrets found in
// authentication configuration. These are warnings (not errors) because the
// configuration is technically valid but insecure for production use.
func warnPlaintextAuthSecrets(auth *avapigwv1alpha1.AuthenticationConfig) []string {
	var warnings []string

	// Warn about plaintext HMAC secret in JWT config
	if auth.JWT != nil && auth.JWT.Enabled && auth.JWT.Secret != "" {
		warnings = append(warnings,
			"SECURITY WARNING: authentication.jwt.secret contains a plaintext HMAC secret. "+
				"Consider using JWKS URL or Vault for secret management in production environments.")
	}

	// Warn about plaintext client secret in OIDC providers
	if auth.OIDC != nil && auth.OIDC.Enabled {
		for i, provider := range auth.OIDC.Providers {
			if provider.ClientSecret != "" && provider.ClientSecretRef == nil {
				warnings = append(warnings,
					fmt.Sprintf("SECURITY WARNING: authentication.oidc.providers[%d].clientSecret "+
						"contains a plaintext client secret. "+
						"Consider using clientSecretRef to reference a Kubernetes Secret instead.", i))
			}
		}
	}

	return warnings
}

// warnMTLSMissingCAFile returns a warning when route-level mTLS is enabled
// without a caFile. The configuration is valid when the gateway resolves the
// client CA from a gateway-level source (e.g. Vault-managed PKI), which the
// webhook cannot observe — so this is a warning rather than a rejection.
func warnMTLSMissingCAFile(auth *avapigwv1alpha1.AuthenticationConfig) []string {
	if auth == nil || auth.MTLS == nil || !auth.MTLS.Enabled || auth.MTLS.CAFile != "" {
		return nil
	}
	return []string{
		"authentication.mtls is enabled without caFile: client certificate validation will rely on a " +
			"gateway-level CA source (e.g. Vault-managed PKI). If no gateway-level CA is configured, " +
			"mTLS authentication will fail at runtime.",
	}
}

// warnPlaintextBackendAuthSecrets returns warnings for plaintext secrets found in
// backend authentication configuration.
func warnPlaintextBackendAuthSecrets(auth *avapigwv1alpha1.BackendAuthConfig) []string {
	var warnings []string

	// Warn about plaintext password in basic auth
	if auth.Basic != nil && auth.Basic.Enabled && auth.Basic.Password != "" && auth.Basic.VaultPath == "" {
		warnings = append(warnings,
			"SECURITY WARNING: authentication.basic.password contains a plaintext password. "+
				"Consider using Vault (vaultPath) for credential management in production environments.")
	}

	// Warn about plaintext client secret in backend OIDC config
	if auth.JWT != nil && auth.JWT.Enabled && auth.JWT.OIDC != nil {
		if auth.JWT.OIDC.ClientSecret != "" && auth.JWT.OIDC.ClientSecretRef == nil {
			warnings = append(warnings,
				"SECURITY WARNING: authentication.jwt.oidc.clientSecret contains a plaintext client secret. "+
					"Consider using clientSecretRef to reference a Kubernetes Secret instead.")
		}
	}

	return warnings
}

// warnRouteCacheSentinelSecrets returns plaintext-secret warnings for the
// route-level cache Redis Sentinel configuration.
func warnRouteCacheSentinelSecrets(cache *avapigwv1alpha1.CacheConfig) []string {
	if cache == nil || cache.Redis == nil || cache.Redis.Sentinel == nil {
		return nil
	}
	return warnPlaintextSentinelSecrets(cache.Redis.Sentinel)
}

// warnRateLimitSentinelSecrets returns plaintext-secret warnings for the
// rate limiter Redis Sentinel configuration.
func warnRateLimitSentinelSecrets(rl *avapigwv1alpha1.RateLimitConfig) []string {
	if rl == nil || rl.Redis == nil || rl.Redis.Sentinel == nil {
		return nil
	}
	return warnPlaintextSentinelSecrets(rl.Redis.Sentinel)
}

// warnBackendCacheReserved returns a warning when the reserved backend
// cache configuration is set. The gateway data path does not implement
// backend-level response caching; the setting is accepted for forward
// compatibility but currently has no effect.
func warnBackendCacheReserved(cache *avapigwv1alpha1.BackendCacheConfig) []string {
	if cache == nil || !cache.Enabled {
		return nil
	}
	return []string{
		"spec.cache is RESERVED and currently has no effect: the gateway does not implement " +
			"backend-level response caching yet. Use route-level caching " +
			"(APIRoute/GRPCRoute/GraphQLRoute spec.cache) instead.",
	}
}

// warnRateLimitRedisStoreUnapplied returns a warning when rateLimit.store
// is set to "redis" on a resource whose data path does not use the
// distributed limiter yet (gRPC routes use an in-memory per-route limiter;
// backends do not enforce this limiter). GraphQL routes are NOT warned:
// their requests run through the shared route middleware chain
// (gateway.RouteMiddlewareManager via GraphQLRoute.ToMiddlewareRoute), which
// enforces the configured store, including redis-backed distributed limiting.
func warnRateLimitRedisStoreUnapplied(rl *avapigwv1alpha1.RateLimitConfig, kind string) []string {
	if rl == nil || rl.Store != CacheTypeRedis {
		return nil
	}
	return []string{fmt.Sprintf(
		"rateLimit.store=redis is not applied for %s yet; distributed rate limiting is currently "+
			"enforced for the gateway-level rate limit, HTTP APIRoutes, and GraphQL routes. The "+
			"configuration is accepted for forward compatibility.", kind),
	}
}

// warnRouteCacheRedisTypeUnapplied returns a warning when cache.type is set
// to "redis" on a route kind whose data path does not implement response
// caching yet (gRPC routes). GraphQL routes use the dedicated
// warnGraphQLRouteCacheIneffective warning instead: their middleware chain
// does build the cache, but GET-only caching semantics make it ineffective.
func warnRouteCacheRedisTypeUnapplied(cache *avapigwv1alpha1.CacheConfig, kind string) []string {
	if cache == nil || cache.Type != CacheTypeRedis {
		return nil
	}
	return []string{fmt.Sprintf(
		"cache.type=redis is not applied for %s yet; response caching (memory and redis) is "+
			"currently enforced for HTTP APIRoutes. The configuration is accepted for forward "+
			"compatibility.", kind),
	}
}

// warnGraphQLRouteCacheIneffective returns a warning when cache.type is set
// to "redis" on a GraphQLRoute. Unlike gRPC routes, the GraphQL data path
// DOES build the configured cache middleware (the shared route middleware
// chain is applied via GraphQLRoute.ToMiddlewareRoute), but response caching
// only serves GET requests while GraphQL operations are sent as POST
// requests with a JSON body to the GraphQL endpoint — so cached responses
// are never stored or served for GraphQL operations in practice.
func warnGraphQLRouteCacheIneffective(cache *avapigwv1alpha1.CacheConfig) []string {
	if cache == nil || cache.Type != CacheTypeRedis {
		return nil
	}
	return []string{
		"cache.type=redis on GraphQLRoute currently has no effect: the route middleware chain " +
			"builds the redis cache, but response caching applies to GET requests only and GraphQL " +
			"operations are POST requests, so GraphQL responses are never cached. The configuration " +
			"is accepted for forward compatibility.",
	}
}

// warnPlaintextSentinelSecrets returns warnings for plaintext secrets found in
// Redis Sentinel configuration.
func warnPlaintextSentinelSecrets(sentinel *avapigwv1alpha1.RedisSentinelSpec) []string {
	var warnings []string

	if sentinel.Password != "" && sentinel.PasswordVaultPath == "" {
		warnings = append(warnings,
			"SECURITY WARNING: sentinel.password contains a plaintext Redis password. "+
				"Consider using passwordVaultPath for secret management in production environments.")
	}

	if sentinel.SentinelPassword != "" && sentinel.SentinelPasswordVaultPath == "" {
		warnings = append(warnings,
			"SECURITY WARNING: sentinel.sentinelPassword contains a plaintext Sentinel password. "+
				"Consider using sentinelPasswordVaultPath for secret management in production environments.")
	}

	return warnings
}
