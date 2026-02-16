// Package controller provides Kubernetes controllers for the operator.
package controller

// annotationValueTrue is the string value used for boolean true in annotations.
const annotationValueTrue = "true"

// DefaultHTTPPort is the default HTTP port used when a service port cannot be resolved.
const DefaultHTTPPort = 80

// IngressClass controller constants.
const (
	// IngressControllerName is the controller name used in IngressClass resources
	// to identify this ingress controller.
	IngressControllerName = "avapigw.io/ingress-controller"

	// DefaultIngressClassName is the default IngressClass name.
	DefaultIngressClassName = "avapigw"

	// IngressFinalizerName is the finalizer name for Ingress resources managed by this controller.
	IngressFinalizerName = "ingress.avapigw.io/finalizer"
)

// Annotation prefix and keys for avapigw Ingress annotations.
const (
	// AnnotationPrefix is the prefix for all avapigw-specific annotations.
	AnnotationPrefix = "avapigw.io/"

	// AnnotationIngressClass is the legacy annotation for specifying the ingress class.
	AnnotationIngressClass = "kubernetes.io/ingress.class"

	// AnnotationAppliedRoutes tracks the routes applied by this Ingress for cleanup.
	AnnotationAppliedRoutes = AnnotationPrefix + "applied-routes"

	// AnnotationObservedGeneration tracks the last reconciled generation for skip logic.
	AnnotationObservedGeneration = AnnotationPrefix + "observed-generation"
)

// Timeout and retry annotations.
const (
	// AnnotationTimeout sets the request timeout for routes derived from this Ingress.
	AnnotationTimeout = AnnotationPrefix + "timeout"

	// AnnotationRetryAttempts sets the number of retry attempts.
	AnnotationRetryAttempts = AnnotationPrefix + "retry-attempts"

	// AnnotationRetryPerTryTimeout sets the per-try timeout for retries.
	AnnotationRetryPerTryTimeout = AnnotationPrefix + "retry-per-try-timeout"

	// AnnotationRetryOn sets the retry conditions (comma-separated).
	AnnotationRetryOn = AnnotationPrefix + "retry-on"
)

// Rate limiting annotations.
const (
	// AnnotationRateLimitEnabled enables rate limiting.
	AnnotationRateLimitEnabled = AnnotationPrefix + "rate-limit-enabled"

	// AnnotationRateLimitRPS sets the requests per second limit.
	AnnotationRateLimitRPS = AnnotationPrefix + "rate-limit-rps"

	// AnnotationRateLimitBurst sets the burst size for rate limiting.
	AnnotationRateLimitBurst = AnnotationPrefix + "rate-limit-burst"

	// AnnotationRateLimitPerClient enables per-client rate limiting.
	AnnotationRateLimitPerClient = AnnotationPrefix + "rate-limit-per-client"
)

// CORS annotations.
const (
	// AnnotationCORSAllowOrigins sets the allowed origins (comma-separated).
	AnnotationCORSAllowOrigins = AnnotationPrefix + "cors-allow-origins"

	// AnnotationCORSAllowMethods sets the allowed methods (comma-separated).
	AnnotationCORSAllowMethods = AnnotationPrefix + "cors-allow-methods"

	// AnnotationCORSAllowHeaders sets the allowed headers (comma-separated).
	AnnotationCORSAllowHeaders = AnnotationPrefix + "cors-allow-headers"

	// AnnotationCORSExposeHeaders sets the exposed headers (comma-separated).
	AnnotationCORSExposeHeaders = AnnotationPrefix + "cors-expose-headers"

	// AnnotationCORSMaxAge sets the max age for preflight cache in seconds.
	AnnotationCORSMaxAge = AnnotationPrefix + "cors-max-age"

	// AnnotationCORSAllowCredentials enables credentials in CORS.
	AnnotationCORSAllowCredentials = AnnotationPrefix + "cors-allow-credentials"
)

// Rewrite and redirect annotations.
const (
	// AnnotationRewriteURI sets the URI rewrite target.
	AnnotationRewriteURI = AnnotationPrefix + "rewrite-uri"

	// AnnotationRewriteAuthority sets the authority (host) rewrite target.
	AnnotationRewriteAuthority = AnnotationPrefix + "rewrite-authority"

	// AnnotationRedirectURI sets the redirect URI.
	AnnotationRedirectURI = AnnotationPrefix + "redirect-uri"

	// AnnotationRedirectCode sets the redirect HTTP status code.
	AnnotationRedirectCode = AnnotationPrefix + "redirect-code"

	// AnnotationRedirectScheme sets the redirect scheme (http/https).
	AnnotationRedirectScheme = AnnotationPrefix + "redirect-scheme"
)

// Health check annotations.
const (
	// AnnotationHealthCheckPath sets the health check path for backends.
	AnnotationHealthCheckPath = AnnotationPrefix + "health-check-path"

	// AnnotationHealthCheckInterval sets the health check interval.
	AnnotationHealthCheckInterval = AnnotationPrefix + "health-check-interval"

	// AnnotationHealthCheckTimeout sets the health check timeout.
	AnnotationHealthCheckTimeout = AnnotationPrefix + "health-check-timeout"

	// AnnotationHealthCheckHealthyThreshold sets the healthy threshold.
	AnnotationHealthCheckHealthyThreshold = AnnotationPrefix + "health-check-healthy-threshold"

	// AnnotationHealthCheckUnhealthyThreshold sets the unhealthy threshold.
	AnnotationHealthCheckUnhealthyThreshold = AnnotationPrefix + "health-check-unhealthy-threshold"
)

// Load balancer annotations.
const (
	// AnnotationLoadBalancerAlgorithm sets the load balancing algorithm.
	AnnotationLoadBalancerAlgorithm = AnnotationPrefix + "load-balancer-algorithm"
)

// Circuit breaker annotations.
const (
	// AnnotationCircuitBreakerEnabled enables the circuit breaker.
	AnnotationCircuitBreakerEnabled = AnnotationPrefix + "circuit-breaker-enabled"

	// AnnotationCircuitBreakerThreshold sets the failure threshold.
	AnnotationCircuitBreakerThreshold = AnnotationPrefix + "circuit-breaker-threshold"

	// AnnotationCircuitBreakerTimeout sets the circuit breaker timeout.
	AnnotationCircuitBreakerTimeout = AnnotationPrefix + "circuit-breaker-timeout"

	// AnnotationCircuitBreakerHalfOpen sets the half-open request count.
	AnnotationCircuitBreakerHalfOpen = AnnotationPrefix + "circuit-breaker-half-open"
)

// TLS annotations.
const (
	// AnnotationTLSMinVersion sets the minimum TLS version.
	AnnotationTLSMinVersion = AnnotationPrefix + "tls-min-version"

	// AnnotationTLSMaxVersion sets the maximum TLS version.
	AnnotationTLSMaxVersion = AnnotationPrefix + "tls-max-version"
)

// Security annotations.
const (
	// AnnotationSecurityEnabled enables security headers.
	AnnotationSecurityEnabled = AnnotationPrefix + "security-enabled"

	// AnnotationSecurityXFrameOptions sets the X-Frame-Options header.
	AnnotationSecurityXFrameOptions = AnnotationPrefix + "security-x-frame-options"

	// AnnotationSecurityXContentType sets the X-Content-Type-Options header.
	AnnotationSecurityXContentType = AnnotationPrefix + "security-x-content-type-options"

	// AnnotationSecurityXXSSProtection sets the X-XSS-Protection header.
	AnnotationSecurityXXSSProtection = AnnotationPrefix + "security-x-xss-protection"
)

// Encoding annotations.
const (
	// AnnotationEncodingRequestContentType sets the request content type.
	AnnotationEncodingRequestContentType = AnnotationPrefix + "encoding-request-content-type"

	// AnnotationEncodingResponseContentType sets the response content type.
	AnnotationEncodingResponseContentType = AnnotationPrefix + "encoding-response-content-type"
)

// Cache annotations.
const (
	// AnnotationCacheEnabled enables caching.
	AnnotationCacheEnabled = AnnotationPrefix + "cache-enabled"

	// AnnotationCacheTTL sets the cache TTL.
	AnnotationCacheTTL = AnnotationPrefix + "cache-ttl"
)

// Max sessions annotations.
const (
	// AnnotationMaxSessionsEnabled enables max sessions limiting.
	AnnotationMaxSessionsEnabled = AnnotationPrefix + "max-sessions-enabled"

	// AnnotationMaxSessionsMaxConcurrent sets the maximum concurrent sessions.
	AnnotationMaxSessionsMaxConcurrent = AnnotationPrefix + "max-sessions-max-concurrent"

	// AnnotationMaxSessionsQueueSize sets the queue size.
	AnnotationMaxSessionsQueueSize = AnnotationPrefix + "max-sessions-queue-size"

	// AnnotationMaxSessionsQueueTimeout sets the queue timeout.
	AnnotationMaxSessionsQueueTimeout = AnnotationPrefix + "max-sessions-queue-timeout"
)

// Max body size annotation.
const (
	// AnnotationMaxBodySize sets the maximum request body size in bytes.
	AnnotationMaxBodySize = AnnotationPrefix + "max-body-size"
)

// Authentication annotations.
const (
	// AnnotationAuthEnabled enables authentication.
	AnnotationAuthEnabled = AnnotationPrefix + "auth-enabled"

	// AnnotationAuthType sets the authentication type (jwt, apiKey, mtls).
	AnnotationAuthType = AnnotationPrefix + "auth-type"
)

// Protocol annotations for gRPC support.
const (
	// AnnotationProtocol specifies the backend protocol (http, grpc, h2c).
	// When set to "grpc", the Ingress will be converted to GRPCRoute and GRPCBackend.
	AnnotationProtocol = AnnotationPrefix + "protocol"

	// AnnotationGRPCService specifies the gRPC service name pattern for matching.
	// Supports exact match or prefix match (e.g., "api.v1.UserService" or "api.v1").
	AnnotationGRPCService = AnnotationPrefix + "grpc-service"

	// AnnotationGRPCServiceMatchType specifies the match type for gRPC service (exact, prefix, regex).
	AnnotationGRPCServiceMatchType = AnnotationPrefix + "grpc-service-match-type"

	// AnnotationGRPCMethod specifies the gRPC method name pattern for matching.
	AnnotationGRPCMethod = AnnotationPrefix + "grpc-method"

	// AnnotationGRPCMethodMatchType specifies the match type for gRPC method (exact, prefix, regex).
	AnnotationGRPCMethodMatchType = AnnotationPrefix + "grpc-method-match-type"
)

// gRPC retry annotations.
const (
	// AnnotationGRPCRetryOn sets the gRPC retry conditions (comma-separated).
	// Valid values: canceled, deadline-exceeded, internal, resource-exhausted,
	// unavailable, unknown, data-loss, aborted, out-of-range, unauthenticated,
	// permission-denied, not-found, already-exists, failed-precondition, unimplemented.
	AnnotationGRPCRetryOn = AnnotationPrefix + "grpc-retry-on"

	// AnnotationGRPCBackoffBaseInterval sets the base interval for exponential backoff.
	AnnotationGRPCBackoffBaseInterval = AnnotationPrefix + "grpc-backoff-base-interval"

	// AnnotationGRPCBackoffMaxInterval sets the maximum interval for exponential backoff.
	AnnotationGRPCBackoffMaxInterval = AnnotationPrefix + "grpc-backoff-max-interval"
)

// gRPC health check annotations (for backend).
const (
	// AnnotationGRPCHealthCheckEnabled enables gRPC health checking.
	AnnotationGRPCHealthCheckEnabled = AnnotationPrefix + "grpc-health-check-enabled"

	// AnnotationGRPCHealthCheckService specifies the gRPC service name for health check.
	// Empty string means overall health check.
	AnnotationGRPCHealthCheckService = AnnotationPrefix + "grpc-health-check-service"

	// AnnotationGRPCHealthCheckInterval sets the gRPC health check interval.
	AnnotationGRPCHealthCheckInterval = AnnotationPrefix + "grpc-health-check-interval"

	// AnnotationGRPCHealthCheckTimeout sets the gRPC health check timeout.
	AnnotationGRPCHealthCheckTimeout = AnnotationPrefix + "grpc-health-check-timeout"

	// AnnotationGRPCHealthCheckHealthyThreshold sets the healthy threshold.
	AnnotationGRPCHealthCheckHealthyThreshold = AnnotationPrefix + "grpc-health-check-healthy-threshold"

	// AnnotationGRPCHealthCheckUnhealthyThreshold sets the unhealthy threshold.
	AnnotationGRPCHealthCheckUnhealthyThreshold = AnnotationPrefix + "grpc-health-check-unhealthy-threshold"
)

// gRPC connection pool annotations (for backend).
const (
	// AnnotationGRPCMaxIdleConns sets the maximum idle connections per host.
	AnnotationGRPCMaxIdleConns = AnnotationPrefix + "grpc-max-idle-conns"

	// AnnotationGRPCMaxConnsPerHost sets the maximum connections per host.
	AnnotationGRPCMaxConnsPerHost = AnnotationPrefix + "grpc-max-conns-per-host"

	// AnnotationGRPCIdleConnTimeout sets the idle connection timeout.
	AnnotationGRPCIdleConnTimeout = AnnotationPrefix + "grpc-idle-conn-timeout"
)

// Protocol values.
const (
	// ProtocolHTTP is the HTTP protocol value.
	ProtocolHTTP = "http"

	// ProtocolGRPC is the gRPC protocol value.
	ProtocolGRPC = "grpc"

	// ProtocolH2C is the HTTP/2 cleartext protocol value.
	ProtocolH2C = "h2c"
)

// Match type values.
const (
	// MatchTypeExact is the exact match type.
	MatchTypeExact = "exact"

	// MatchTypePrefix is the prefix match type.
	MatchTypePrefix = "prefix"

	// MatchTypeRegex is the regex match type.
	MatchTypeRegex = "regex"
)

// Event reasons for ingress controller.
const (
	// EventReasonIngressReconciled is the event reason when an Ingress is reconciled.
	EventReasonIngressReconciled = "IngressReconciled"

	// EventReasonIngressReconcileFailed is the event reason when Ingress reconciliation fails.
	EventReasonIngressReconcileFailed = "IngressReconcileFailed"

	// EventReasonIngressDeleted is the event reason when an Ingress is deleted.
	EventReasonIngressDeleted = "IngressDeleted"

	// EventReasonIngressCleanupFailed is the event reason when Ingress cleanup fails.
	EventReasonIngressCleanupFailed = "IngressCleanupFailed"

	// EventReasonIngressClassMismatch is the event reason when IngressClass does not match.
	EventReasonIngressClassMismatch = "IngressClassMismatch"

	// EventReasonIngressConversionFailed is the event reason when Ingress conversion fails.
	EventReasonIngressConversionFailed = "IngressConversionFailed"
)

// Status messages for ingress controller.
const (
	// MessageIngressApplied is the message when an Ingress is successfully applied.
	MessageIngressApplied = "Ingress routes successfully applied"

	// MessageIngressDeleted is the message when an Ingress is successfully deleted.
	MessageIngressDeleted = "Ingress routes successfully deleted"

	// MessageIngressConversionFailed is the message when Ingress conversion fails.
	MessageIngressConversionFailed = "Failed to convert Ingress to gateway configuration"
)
