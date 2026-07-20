// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// APIRouteSpec defines the desired state of APIRoute.
type APIRouteSpec struct {
	// Match contains the matching conditions for this route.
	// +optional
	Match []RouteMatch `json:"match,omitempty"`

	// Route contains the destination(s) for matched requests.
	// +optional
	Route []RouteDestination `json:"route,omitempty"`

	// Timeout is the request timeout for this route.
	// +optional
	Timeout Duration `json:"timeout,omitempty"`

	// Retries contains retry policy configuration.
	// +optional
	Retries *RetryPolicy `json:"retries,omitempty"`

	// Redirect contains HTTP redirect configuration.
	// +optional
	Redirect *RedirectConfig `json:"redirect,omitempty"`

	// Rewrite contains URL rewrite configuration.
	// +optional
	Rewrite *RewriteConfig `json:"rewrite,omitempty"`

	// DirectResponse contains direct response configuration.
	// +optional
	DirectResponse *DirectResponseConfig `json:"directResponse,omitempty"`

	// Headers contains header manipulation configuration.
	// +optional
	Headers *HeaderManipulation `json:"headers,omitempty"`

	// Mirror contains traffic mirroring configuration.
	// +optional
	Mirror *MirrorConfig `json:"mirror,omitempty"`

	// Aggregate contains aggregate (fan-out) mirroring configuration.
	// +optional
	Aggregate *AggregateConfig `json:"aggregate,omitempty"`

	// Fault contains fault injection configuration.
	// +optional
	Fault *FaultInjection `json:"fault,omitempty"`

	// RateLimit contains route-level rate limiting configuration.
	// +optional
	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`

	// Transform contains transformation configuration.
	// +optional
	Transform *TransformConfig `json:"transform,omitempty"`

	// Cache contains caching configuration.
	// +optional
	Cache *CacheConfig `json:"cache,omitempty"`

	// Encoding contains encoding configuration.
	// +optional
	Encoding *EncodingConfig `json:"encoding,omitempty"`

	// RequestLimits configures request size limits for this route.
	// +optional
	RequestLimits *RequestLimitsConfig `json:"requestLimits,omitempty"`

	// CORS configures CORS for this route.
	// +optional
	CORS *CORSConfig `json:"cors,omitempty"`

	// Security configures security headers for this route.
	// +optional
	Security *SecurityConfig `json:"security,omitempty"`

	// MaxSessions configures maximum concurrent sessions for this route.
	// +optional
	MaxSessions *MaxSessionsConfig `json:"maxSessions,omitempty"`

	// TLS configures route-level TLS certificate override.
	// +optional
	TLS *RouteTLSConfig `json:"tls,omitempty"`

	// Authentication configures route-level authentication.
	// +optional
	Authentication *AuthenticationConfig `json:"authentication,omitempty"`

	// Authorization configures route-level authorization.
	// +optional
	Authorization *AuthorizationConfig `json:"authorization,omitempty"`

	// OpenAPIValidation configures OpenAPI request validation for this route.
	// +optional
	OpenAPIValidation *OpenAPIValidationConfig `json:"openAPIValidation,omitempty"`
}

// RouteMatch represents matching conditions for a route.
type RouteMatch struct {
	// URI contains URI matching configuration.
	// +optional
	URI *URIMatch `json:"uri,omitempty"`

	// Methods is the list of HTTP methods to match.
	// +optional
	Methods []string `json:"methods,omitempty"`

	// Headers contains header matching conditions.
	// +optional
	Headers []HeaderMatch `json:"headers,omitempty"`

	// QueryParams contains query parameter matching conditions.
	// +optional
	QueryParams []QueryParamMatch `json:"queryParams,omitempty"`
}

// URIMatch represents URI matching configuration.
type URIMatch struct {
	// Exact matches the URI exactly.
	// +optional
	Exact string `json:"exact,omitempty"`

	// Prefix matches URIs starting with this prefix.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Regex matches URIs using a regular expression.
	// +optional
	Regex string `json:"regex,omitempty"`
}

// QueryParamMatch represents query parameter matching configuration.
type QueryParamMatch struct {
	// Name is the query parameter name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Exact matches the parameter value exactly.
	// +optional
	Exact string `json:"exact,omitempty"`

	// Regex matches parameter values using a regular expression.
	// +optional
	Regex string `json:"regex,omitempty"`

	// Present matches if the parameter is present (regardless of value).
	// +optional
	Present *bool `json:"present,omitempty"`
}

// RedirectConfig represents HTTP redirect configuration.
type RedirectConfig struct {
	// URI is the redirect URI.
	// +optional
	URI string `json:"uri,omitempty"`

	// Code is the HTTP redirect status code.
	// +kubebuilder:validation:Enum=301;302;303;307;308
	// +kubebuilder:default=302
	// +optional
	Code int `json:"code,omitempty"`

	// Scheme is the redirect scheme (http or https).
	// +kubebuilder:validation:Enum=http;https
	// +optional
	Scheme string `json:"scheme,omitempty"`

	// Host is the redirect host.
	// +optional
	Host string `json:"host,omitempty"`

	// Port is the redirect port.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int `json:"port,omitempty"`

	// StripQuery removes query parameters from the redirect.
	// +optional
	StripQuery bool `json:"stripQuery,omitempty"`
}

// RewriteConfig represents URL rewrite configuration.
type RewriteConfig struct {
	// URI is the rewritten URI.
	// +optional
	URI string `json:"uri,omitempty"`

	// Authority is the rewritten authority (host).
	// +optional
	Authority string `json:"authority,omitempty"`
}

// DirectResponseConfig represents direct response configuration.
type DirectResponseConfig struct {
	// Status is the HTTP status code.
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	// +kubebuilder:validation:Required
	Status int `json:"status"`

	// Body is the response body.
	// +optional
	Body string `json:"body,omitempty"`

	// Headers are the response headers.
	// +optional
	Headers map[string]string `json:"headers,omitempty"`
}

// FaultInjection represents fault injection configuration.
type FaultInjection struct {
	// Delay contains delay fault injection configuration.
	// +optional
	Delay *FaultDelay `json:"delay,omitempty"`

	// Abort contains abort fault injection configuration.
	// +optional
	Abort *FaultAbort `json:"abort,omitempty"`
}

// FaultDelay represents delay fault injection.
type FaultDelay struct {
	// FixedDelay is the fixed delay duration.
	// +kubebuilder:validation:Required
	FixedDelay Duration `json:"fixedDelay"`

	// Percentage is the percentage of requests to delay (0-100).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	// +optional
	Percentage int `json:"percentage,omitempty"`
}

// FaultAbort represents abort fault injection.
type FaultAbort struct {
	// HTTPStatus is the HTTP status code to return.
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	// +kubebuilder:validation:Required
	HTTPStatus int `json:"httpStatus"`

	// Percentage is the percentage of requests to abort (0-100).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	// +optional
	Percentage int `json:"percentage,omitempty"`
}

// TransformConfig represents transformation configuration.
type TransformConfig struct {
	// Request contains request transformation configuration.
	// +optional
	Request *RequestTransform `json:"request,omitempty"`

	// Response contains response transformation configuration.
	// +optional
	Response *ResponseTransform `json:"response,omitempty"`
}

// RequestTransform represents request transformation configuration.
// The JSON shape matches the gateway's request transform configuration so it
// round-trips to the data plane unchanged.
type RequestTransform struct {
	// Template is a Go template for transforming the request body.
	// +optional
	Template string `json:"template,omitempty"`

	// PassthroughBody passes the request body unchanged to the backend.
	// +optional
	PassthroughBody bool `json:"passthroughBody,omitempty"`

	// StaticHeaders defines headers to add with static values.
	// +optional
	StaticHeaders map[string]string `json:"staticHeaders,omitempty"`

	// DynamicHeaders defines headers to add with values sourced from request
	// context (e.g. JWT claims or request metadata).
	// +optional
	DynamicHeaders []TransformDynamicHeader `json:"dynamicHeaders,omitempty"`

	// InjectFields defines fields to inject into the request body.
	// +optional
	InjectFields []TransformFieldInjection `json:"injectFields,omitempty"`

	// RemoveFields specifies fields to remove from the request body.
	// Uses dot notation for nested fields.
	// +optional
	RemoveFields []string `json:"removeFields,omitempty"`

	// DefaultValues defines default values for request body fields when the
	// field is not present. Values may be any valid JSON value.
	// +optional
	DefaultValues map[string]apiextensionsv1.JSON `json:"defaultValues,omitempty"`

	// ValidateBeforeTransform validates the request before transformation.
	// +optional
	ValidateBeforeTransform bool `json:"validateBeforeTransform,omitempty"`
}

// TransformDynamicHeader defines a header whose value is sourced from
// request context.
type TransformDynamicHeader struct {
	// Name is the header name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Source is the context path of the value.
	// Examples: "jwt.claim.sub", "context.request_id", "metadata.key".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Source string `json:"source"`
}

// TransformFieldInjection defines a field to inject into the request body.
type TransformFieldInjection struct {
	// Field is the dot-notation path where the value is injected.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Field string `json:"field"`

	// Value is a static JSON value to inject.
	// +optional
	Value *apiextensionsv1.JSON `json:"value,omitempty"`

	// Source is the context path of a dynamic value.
	// Examples: "jwt.claim.sub", "context.request_id".
	// +optional
	Source string `json:"source,omitempty"`
}

// TransformFieldGroup groups multiple fields into a nested object.
type TransformFieldGroup struct {
	// Name is the name of the new nested object.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Fields is the list of field paths to include in the group.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Fields []string `json:"fields"`
}

// TransformArrayOperation defines an operation to perform on an array field.
type TransformArrayOperation struct {
	// Field is the dot-notation path to the array field.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Field string `json:"field"`

	// Operation is the type of operation to perform.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=append;prepend;filter;sort;limit;deduplicate
	Operation string `json:"operation"`

	// Value is the JSON value used by append/prepend/sort/limit operations.
	// +optional
	Value *apiextensionsv1.JSON `json:"value,omitempty"`

	// Condition is a CEL expression for filter operations.
	// +optional
	Condition string `json:"condition,omitempty"`
}

// ResponseTransform represents response transformation configuration.
// The JSON shape matches the gateway's response transform configuration so it
// round-trips to the data plane unchanged.
type ResponseTransform struct {
	// AllowFields is the list of fields to allow in the response.
	// +optional
	AllowFields []string `json:"allowFields,omitempty"`

	// DenyFields is the list of fields to deny in the response.
	// +optional
	DenyFields []string `json:"denyFields,omitempty"`

	// FieldMappings maps field names.
	// +optional
	FieldMappings map[string]string `json:"fieldMappings,omitempty"`

	// GroupFields defines how to group multiple fields into nested objects.
	// +optional
	GroupFields []TransformFieldGroup `json:"groupFields,omitempty"`

	// FlattenFields specifies nested objects to flatten into the parent.
	// Uses dot notation (e.g. "metadata" flattens metadata.* to root level).
	// +optional
	FlattenFields []string `json:"flattenFields,omitempty"`

	// ArrayOperations defines operations to perform on array fields.
	// +optional
	ArrayOperations []TransformArrayOperation `json:"arrayOperations,omitempty"`

	// Template is a Go template string for custom response formatting.
	// When set, it overrides other transformation rules.
	// +optional
	Template string `json:"template,omitempty"`

	// MergeStrategy defines how to merge responses from multiple backends.
	// +kubebuilder:validation:Enum=deep;shallow;replace;ndjson
	// +optional
	MergeStrategy string `json:"mergeStrategy,omitempty"`
}

// CacheConfig represents caching configuration.
type CacheConfig struct {
	// Enabled enables caching.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// TTL is the cache time-to-live.
	// +optional
	TTL Duration `json:"ttl,omitempty"`

	// KeyComponents are the components used to generate the cache key.
	//
	// Deprecated: the gateway has no corresponding option and ignores this
	// field. Use KeyConfig instead; setting KeyComponents produces an
	// admission warning.
	// +optional
	KeyComponents []string `json:"keyComponents,omitempty"`

	// MaxEntries is the maximum number of entries for the memory cache.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxEntries int `json:"maxEntries,omitempty"`

	// KeyConfig configures cache key generation.
	// +optional
	KeyConfig *CacheKeyConfig `json:"keyConfig,omitempty"`

	// HonorCacheControl respects Cache-Control headers when caching.
	// +optional
	HonorCacheControl bool `json:"honorCacheControl,omitempty"`

	// StaleWhileRevalidate allows serving stale content while revalidating.
	// +optional
	StaleWhileRevalidate Duration `json:"staleWhileRevalidate,omitempty"`

	// NegativeCacheTTL is the time-to-live for caching error responses.
	// +optional
	NegativeCacheTTL Duration `json:"negativeCacheTTL,omitempty"`

	// Type is the cache backend type (memory, redis).
	// +kubebuilder:validation:Enum=memory;redis
	// +kubebuilder:default=memory
	// +optional
	Type string `json:"type,omitempty"`

	// Redis contains Redis-specific cache configuration.
	// Required when Type is "redis"; must be omitted otherwise.
	// +optional
	Redis *RedisCacheSpec `json:"redis,omitempty"`
}

// CacheKeyConfig configures cache key generation. The JSON shape matches the
// gateway's cache key configuration so it round-trips to the data plane
// unchanged.
type CacheKeyConfig struct {
	// IncludeMethod includes the HTTP method in the cache key.
	// +optional
	IncludeMethod bool `json:"includeMethod,omitempty"`

	// IncludePath includes the request path in the cache key.
	// +optional
	IncludePath bool `json:"includePath,omitempty"`

	// IncludeQueryParams specifies query parameters to include in the cache key.
	// +optional
	IncludeQueryParams []string `json:"includeQueryParams,omitempty"`

	// IncludeHeaders specifies headers to include in the cache key.
	// +optional
	IncludeHeaders []string `json:"includeHeaders,omitempty"`

	// IncludeBodyHash includes a hash of the request body in the cache key.
	// +optional
	IncludeBodyHash bool `json:"includeBodyHash,omitempty"`

	// KeyTemplate is a custom template for generating cache keys.
	// Supports placeholders: {{.Method}}, {{.Path}}, {{.Query.param}}, {{.Header.name}}
	// +optional
	KeyTemplate string `json:"keyTemplate,omitempty"`
}

// EncodingConfig represents encoding configuration.
type EncodingConfig struct {
	// Request contains request encoding configuration.
	// +optional
	Request *EncodingSettings `json:"request,omitempty"`

	// Response contains response encoding configuration.
	// +optional
	Response *EncodingSettings `json:"response,omitempty"`
}

// EncodingSettings represents encoding settings.
type EncodingSettings struct {
	// ContentType is the content type.
	// +optional
	ContentType string `json:"contentType,omitempty"`
}

// APIRouteStatus defines the observed state of APIRoute.
type APIRouteStatus struct {
	// Conditions represent the latest available observations of the APIRoute's state.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// AppliedGateways is the list of gateways where this route has been applied.
	// +optional
	AppliedGateways []AppliedGateway `json:"appliedGateways,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ar
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// APIRoute is the Schema for the apiroutes API.
type APIRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIRouteSpec   `json:"spec,omitempty"`
	Status APIRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIRouteList contains a list of APIRoute.
type APIRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIRoute{}, &APIRouteList{})
}
